//go:build linux

package plugins

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeLimitsProbe replaces the systemd probe and its cached answer for one test
func fakeLimitsProbe(t *testing.T, run func() ([]string, string)) {
	t.Helper()
	reset := func() {
		limitsProbe.mu.Lock()
		wait := limitsProbe.flight
		limitsProbe.mu.Unlock()
		if wait != nil {
			<-wait
		}
		limitsProbe.mu.Lock()
		limitsProbe.known, limitsProbe.at, limitsProbe.base, limitsProbe.problem = false, time.Time{}, nil, ""
		limitsProbe.mu.Unlock()
	}
	reset()
	old := limitsProbeRun
	limitsProbeRun = run
	t.Cleanup(func() {
		reset()
		limitsProbeRun = old
	})
}

func TestLimitsScopeNeverCarriesTheCommandLineAsDescription(t *testing.T) {
	fakeLimitsProbe(t, func() ([]string, string) {
		return []string{"/usr/bin/systemd-run", "--scope", "--quiet", "--collect"}, ""
	})
	m := &Manager{}
	fakeLeftoverKill(t)
	const secret = `-configure={"api_key":"SECRETPROBE"}`
	cmd := exec.Command("/opt/plugins/x/x", secret)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1234, Gid: 1234}}
	note, problem := m.wrapWithLimits(cmd, "com.example/evil id\n$(reboot)", PluginPolicy{MemoryMaxMB: 64, CPUQuotaPercent: 50, TasksMax: 20})
	if problem != "" || note == "" {
		t.Fatalf("note %q problem %q", note, problem)
	}
	sep := -1
	for i, a := range cmd.Args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("no -- in %q", cmd.Args)
	}
	desc, unit := "", ""
	for _, a := range cmd.Args[:sep] {
		if strings.Contains(a, "-configure=") || strings.Contains(a, "SECRETPROBE") {
			t.Fatalf("an option of systemd-run carries the configuration of the plugin: %q", a)
		}
		if strings.HasPrefix(a, "--description=") {
			desc = strings.TrimPrefix(a, "--description=")
		}
		if strings.HasPrefix(a, "--unit=") {
			unit = strings.TrimPrefix(a, "--unit=")
		}
	}
	// A unit name of its own, made of safe characters only, different for every start
	if !regexp.MustCompile(`^zoraxy-plugin-com\.example_evil_id___reboot_-` + m.scopeInstanceTag() + `-[0-9a-f]{8}\.scope$`).MatchString(unit) {
		t.Fatalf("unit name of the scope: %q", unit)
	}
	if other := scopeUnitName(m.scopeInstanceTag(), "com.example/evil id\n$(reboot)"); other == unit {
		t.Fatalf("two starts got the same unit name %q", unit)
	}
	// Without --description systemd uses the command line, secrets included, as the
	// description of the scope and logs it
	if desc != "Zoraxy plugin com.example_evil_id___reboot_" {
		t.Fatalf("description of the scope: %q", desc)
	}
	if got := cmd.Args[sep+1:]; len(got) != 2 || got[0] != "/opt/plugins/x/x" || got[1] != secret {
		t.Fatalf("the plugin command changed: %q", got)
	}
	if len(scopeDescription(strings.Repeat("a", 500))) > 100 {
		t.Fatal("the description is not bounded")
	}
}

func TestFaultLimitsScopeDescriptionOnThisHost(t *testing.T) {
	m := newFaultManager(t)
	if support, note := m.limitsSupport(); support != "systemd" {
		t.Skip("needs systemd scopes on this host: " + note)
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		t.Skip("systemctl was not found")
	}
	own, _ := os.ReadFile("/proc/self/cgroup")
	// The marker stands where a legacy plugin has -configure=<secrets>
	cmd := exec.Command("/bin/sh", "-c", "sleep 30", "-configure=REVIEWPROBE-"+strconv.Itoa(os.Getpid()))
	if _, problem := m.wrapWithLimits(cmd, "test.review.scope", PluginPolicy{TasksMax: 50}); problem != "" {
		t.Fatal(problem)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	unit := ""
	eventually(t, 5*time.Second, "the process to be moved into its scope", func() bool {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup")
		if err != nil || string(raw) == string(own) {
			return false
		}
		line := strings.TrimSpace(string(raw))
		unit = line[strings.LastIndex(line, "/")+1:]
		return strings.HasSuffix(unit, ".scope")
	})
	args := []string{"show", "-p", "Description", "--value", unit}
	if os.Geteuid() != 0 {
		args = append([]string{"--user"}, args...)
	}
	out, err := exec.Command(systemctl, args...).CombinedOutput()
	if err != nil {
		t.Skipf("systemctl show %s: %v %s", unit, err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "Zoraxy plugin test.review.scope" {
		t.Fatalf("description of %s: %q", unit, got)
	}
	if !strings.HasPrefix(unit, "zoraxy-plugin-test.review.scope-") {
		t.Fatalf("the scope has no name of its own: %q", unit)
	}
	// Nothing systemd knows about the scope may hold the command line of the plugin
	showAll := []string{"show", "--all", "--no-pager", unit}
	if os.Geteuid() != 0 {
		showAll = append([]string{"--user"}, showAll...)
	}
	all, err := exec.Command(systemctl, showAll...).CombinedOutput()
	if err != nil {
		t.Skipf("systemctl show --all %s: %v %s", unit, err, all)
	}
	if strings.Contains(string(all), "REVIEWPROBE") || strings.Contains(string(all), "-configure=") {
		t.Fatalf("a property of %s holds the command line of the plugin:\n%s", unit, all)
	}
}

func TestLimitsProbeRunsOnceAndNeverBlocksOnceKnown(t *testing.T) {
	var runs atomic.Int32
	gate := make(chan struct{})
	fakeLimitsProbe(t, func() ([]string, string) {
		n := runs.Add(1)
		<-gate
		if n == 1 {
			return nil, "no bus"
		}
		return []string{"/usr/bin/systemd-run", "--scope"}, ""
	})

	//First use: everyone waits for the same probe
	var wg sync.WaitGroup
	problems := make([]string, 8)
	for i := range problems {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, problems[i] = systemdScopeBase()
		}()
	}
	time.Sleep(100 * time.Millisecond)
	if n := runs.Load(); n != 1 {
		t.Fatalf("%d probes ran for concurrent callers, want 1", n)
	}
	gate <- struct{}{}
	wg.Wait()
	for _, problem := range problems {
		if problem != "no bus" {
			t.Fatalf("problem %q", problem)
		}
	}

	//A failure is cached like a success
	if _, problem := systemdScopeBase(); problem != "no bus" || runs.Load() != 1 {
		t.Fatalf("a cached failure was probed again: %q, %d runs", problem, runs.Load())
	}

	//Expired: the old answer is served at once while one new probe runs in the background
	limitsProbe.mu.Lock()
	limitsProbe.at = time.Now().Add(-2 * limitsProbeCache)
	limitsProbe.mu.Unlock()
	for i := 0; i < 5; i++ {
		start := time.Now()
		if _, problem := (&Manager{}).limitsSupport(); !strings.Contains(problem, "no bus") || time.Since(start) > 200*time.Millisecond {
			t.Fatalf("an expired answer made the caller wait %s (%q)", time.Since(start), problem)
		}
	}
	eventually(t, 2*time.Second, "the background probe to start", func() bool { return runs.Load() == 2 })
	gate <- struct{}{}
	eventually(t, 2*time.Second, "the new answer", func() bool {
		base, _ := systemdScopeBase()
		return base != nil
	})
	if runs.Load() != 2 {
		t.Fatalf("%d probes, want 2", runs.Load())
	}
}

func TestProcessGroupIsEndedBeforeThePIDIsFree(t *testing.T) {
	// The leader ends at once and leaves a child in its group behind
	cmd := exec.Command("/bin/sh", "-c", "sleep 300 & echo $!")
	setProcessGroup(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _ := out.Read(buf)
	child, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil || !pidAlive(child) {
		t.Fatalf("child pid %q: %v", buf[:n], err)
	}
	proc := &pluginProc{cmd: cmd, pid: cmd.Process.Pid}

	// The exit can be seen while the leader is still a zombie that pins its PID
	if !waitExitNoReap(proc.pid) {
		t.Fatal("waitid(WNOWAIT) does not work here")
	}
	if err := syscall.Kill(proc.pid, 0); err != nil {
		t.Fatalf("the ended leader was reaped by the look at its exit: %v", err)
	}
	if !pidAlive(child) {
		t.Fatal("the child ended by itself, the test proves nothing")
	}
	if err := waitPluginProcess(proc); err != nil {
		t.Fatalf("wait: %v", err)
	}
	eventually(t, 3*time.Second, "the child left behind to be killed", func() bool { return !pidAlive(child) })

	// After the reap the PID may belong to anyone: no signal goes to it any more
	if !proc.groupClosed {
		t.Fatal("the group is not marked as closed after the reap")
	}
	stranger := exec.Command("/bin/sleep", "300")
	setProcessGroup(stranger)
	if err := stranger.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stranger.Process.Kill()
		stranger.Wait()
	}()
	proc.pid = stranger.Process.Pid //what PID reuse looks like
	if err := signalPluginProcess(proc, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !pidAlive(stranger.Process.Pid) {
		t.Fatal("a signal for an ended plugin killed the process that got its PID")
	}
}

/* A plugin with limits must not outlive Zoraxy (its systemd scope is outside the cgroup of Zoraxy) */

// fakeLeftoverKill replaces the systemctl call that kills leftover scopes and records the patterns
func fakeLeftoverKill(t *testing.T) *[]string {
	t.Helper()
	var patterns []string
	old := killLeftoverScopes
	killLeftoverScopes = func(pattern string) { patterns = append(patterns, pattern) }
	t.Cleanup(func() { killLeftoverScopes = old })
	return &patterns
}

func TestSystemdUnitOfCgroup(t *testing.T) {
	for _, c := range []struct {
		name   string
		cgroup string
		euid   int
		want   string
	}{
		{"root in the reference unit", "0::/system.slice/zoraxy.service\n", 0, "zoraxy.service"},
		{"root, instance of a template", "0::/system.slice/system-zoraxy.slice/zoraxy@dev.service\n", 0, "zoraxy@dev.service"},
		{"root, delegated sub group", "0::/system.slice/zoraxy.service/main\n", 0, "zoraxy.service"},
		{"root, escaped name", "0::/system.slice/_cgroup.service\n", 0, "cgroup.service"},
		{"root, cgroup v1", "12:pids:/system.slice/zoraxy.service\n1:name=systemd:/system.slice/zoraxy.service\n", 0, "zoraxy.service"},
		{"root in a terminal session", "0::/user.slice/user-0.slice/session-3.scope\n", 0, ""},
		{"root in a service of its own user manager: the scopes are system scopes", "0::/user.slice/user-0.slice/user@0.service/app.slice/zoraxy.service\n", 0, ""},
		{"system service that does not run as root: the scopes are user scopes", "0::/system.slice/zoraxy.service\n", 1000, ""},
		{"user service", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/zoraxy.service\n", 1000, "zoraxy.service"},
		{"user service of another user", "0::/user.slice/user-1001.slice/user@1001.service/app.slice/zoraxy.service\n", 1000, ""},
		{"user in a terminal session", "0::/user.slice/user-1000.slice/session-3.scope\n", 1000, ""},
		{"user in a scope of the user manager: the manager itself is not the unit", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p1-i2.scope\n", 1000, ""},
		{"container without systemd", "0::/\n", 0, ""},
		{"unexpected characters", "0::/system.slice/zo raxy.service\n", 0, ""},
		{"empty", "", 0, ""},
	} {
		if got := systemdUnitOfCgroup(c.cgroup, c.euid); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestScopePatternMatchesOnlyThePluginOfThisInstance(t *testing.T) {
	a := &Manager{Options: &ManagerOptions{PluginDir: "/opt/zoraxy/plugins"}}
	b := &Manager{Options: &ManagerOptions{PluginDir: "/opt/zoraxy-dev/plugins"}}
	if a.scopeInstanceTag() == b.scopeInstanceTag() || !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(a.scopeInstanceTag()) {
		t.Fatalf("instance tags %q %q", a.scopeInstanceTag(), b.scopeInstanceTag())
	}
	if again := (&Manager{Options: &ManagerOptions{PluginDir: "/opt/zoraxy/plugins"}}); again.scopeInstanceTag() != a.scopeInstanceTag() {
		t.Fatal("the instance tag changes between two starts of the same install")
	}
	match := func(pattern, unit string) bool {
		ok, err := path.Match(pattern, unit)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	pattern := scopeUnitPattern(a.scopeInstanceTag(), "com.example.a")
	if !match(pattern, scopeUnitName(a.scopeInstanceTag(), "com.example.a")) {
		t.Fatalf("%q does not match a scope of its own plugin", pattern)
	}
	for what, unit := range map[string]string{
		"the same plugin of another install":   scopeUnitName(b.scopeInstanceTag(), "com.example.a"),
		"a plugin whose ID starts the same":    scopeUnitName(a.scopeInstanceTag(), "com.example.a-b"),
		"a plugin whose ID continues with -":   scopeUnitName(a.scopeInstanceTag(), "com.example.a-"+a.scopeInstanceTag()),
		"another plugin":                       scopeUnitName(a.scopeInstanceTag(), "com.example.b"),
		"a unit that is not a scope of Zoraxy": "com.example.a.service",
	} {
		if match(pattern, unit) {
			t.Errorf("%q matches %s (%s)", pattern, what, unit)
		}
	}
}

func TestLimitsStartKillsLeftoverScopesAndBindsOnlyWhenTheProbeAllowsIt(t *testing.T) {
	patterns := fakeLeftoverKill(t)
	m := &Manager{Options: &ManagerOptions{PluginDir: "/opt/zoraxy/plugins"}}
	has := func(args []string, want string) bool {
		for _, a := range args {
			if a == want {
				return true
			}
		}
		return false
	}

	//Bound prefix from the probe: every scope carries it, and the leftovers of this plugin are killed first
	fakeLimitsProbe(t, func() ([]string, string) {
		return append([]string{"/usr/bin/systemd-run", "--scope", "--quiet", "--collect"}, scopeBindArgs("zoraxy.service")...), ""
	})
	cmd := exec.Command("/opt/zoraxy/plugins/x/x")
	if _, problem := m.wrapWithLimits(cmd, "com.example.x", PluginPolicy{TasksMax: 20}); problem != "" {
		t.Fatal(problem)
	}
	if len(*patterns) != 1 || (*patterns)[0] != "zoraxy-plugin-com.example.x-"+m.scopeInstanceTag()+"-????????.scope" {
		t.Fatalf("leftover scopes killed before the start: %q", *patterns)
	}
	if !has(cmd.Args, "BindsTo=zoraxy.service") || !has(cmd.Args, "KillSignal=SIGCONT") || !has(cmd.Args, "TimeoutStopSec=40") {
		t.Fatalf("the scope is not bound to the service of Zoraxy: %q", cmd.Args)
	}
	for _, a := range cmd.Args {
		if strings.HasPrefix(a, "After=") {
			t.Fatalf("After= makes a stop of Zoraxy wait for the plugin: %q", cmd.Args)
		}
	}
	if _, note := m.limitsSupport(); !strings.Contains(note, "zoraxy.service") {
		t.Fatalf("the note does not name the unit the scopes are bound to: %q", note)
	}

	//No limits that need a scope: nothing is touched
	*patterns = nil
	plain := exec.Command("/opt/zoraxy/plugins/x/x")
	if note, problem := m.wrapWithLimits(plain, "com.example.x", PluginPolicy{MaxOpenFiles: 64}); note != "" || problem != "" || len(plain.Args) != 1 || len(*patterns) != 0 {
		t.Fatalf("a plugin without cgroup limits was touched: %q %q %q %q", note, problem, plain.Args, *patterns)
	}

	//No systemd: the plugin starts as it is, nothing is killed
	fakeLimitsProbe(t, func() ([]string, string) { return nil, "no bus" })
	none := exec.Command("/opt/zoraxy/plugins/x/x")
	if _, problem := m.wrapWithLimits(none, "com.example.x", PluginPolicy{TasksMax: 20}); !strings.Contains(problem, "NOT enforced") || len(none.Args) != 1 || len(*patterns) != 0 {
		t.Fatalf("without systemd: %q %q %q", problem, none.Args, *patterns)
	}
}

// systemctlHere runs systemctl against the manager the scopes of this process live in
func systemctlHere(args ...string) ([]byte, error) {
	if os.Geteuid() != 0 {
		args = append([]string{"--user"}, args...)
	}
	return exec.Command("systemctl", args...).CombinedOutput()
}

// startScoped starts "sleep" through wrapWithLimits, as a plugin with a task limit, and reaps it when it ends
func startScoped(t *testing.T, m *Manager, pluginID string) (cmd *exec.Cmd, ended chan struct{}) {
	t.Helper()
	own, _ := os.ReadFile("/proc/self/cgroup")
	cmd = exec.Command("/bin/sleep", "300")
	if _, problem := m.wrapWithLimits(cmd, pluginID, PluginPolicy{TasksMax: 50}); problem != "" {
		t.Fatal(problem)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended = make(chan struct{})
	go func() {
		cmd.Wait()
		close(ended)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-ended
	})
	eventually(t, 5*time.Second, "the process to be moved into its scope", func() bool {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup")
		return err == nil && string(raw) != string(own) && strings.Contains(string(raw), "zoraxy-plugin-")
	})
	return cmd, ended
}

func isEnded(ended chan struct{}) bool {
	select {
	case <-ended:
		return true
	default:
		return false
	}
}

// TestFaultLimitedPluginEndsWithTheServiceOfZoraxy uses a transient service as the
// stand-in for Zoraxy: the scope of a plugin with limits is bound to it.
func TestFaultLimitedPluginEndsWithTheServiceOfZoraxy(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl was not found")
	}
	if base, problem := probeSystemdScope(); base == nil {
		t.Skip("needs systemd scopes on this host: " + problem)
	}
	oldGrace := scopeOrphanGrace
	scopeOrphanGrace = 3 * time.Second
	t.Cleanup(func() { scopeOrphanGrace = oldGrace })

	for i, how := range []string{"killed", "stopped"} {
		t.Run("the service is "+how, func(t *testing.T) {
			standIn := "zoraxy-test-standin-" + strconv.Itoa(os.Getpid()) + "-" + strconv.Itoa(i) + ".service"
			run := []string{"--quiet", "--collect", "--unit=" + standIn, "/bin/sleep", "300"}
			if os.Geteuid() != 0 {
				run = append([]string{"--user"}, run...)
			}
			if out, err := exec.Command("systemd-run", run...).CombinedOutput(); err != nil {
				t.Skipf("the stand-in service could not be started: %v %s", err, out)
			}
			t.Cleanup(func() {
				systemctlHere("stop", standIn)
				systemctlHere("reset-failed", standIn)
			})
			oldUnit := ownSystemdUnit
			ownSystemdUnit = func() string { return standIn }
			t.Cleanup(func() { ownSystemdUnit = oldUnit })
			fakeLimitsProbe(t, probeSystemdScope) //the real probe, with the stand-in as the unit of Zoraxy

			m := newFaultManager(t)
			if _, note := m.limitsSupport(); !strings.Contains(note, standIn) {
				t.Fatalf("the probe did not accept the binding to %s: %q", standIn, note)
			}
			cmd, ended := startScoped(t, m, "test.bound."+how)

			begin := time.Now()
			if how == "killed" {
				//What a crash, the OOM killer or kill -9 does to Zoraxy
				out, err := systemctlHere("show", "-p", "MainPID", "--value", standIn)
				pid, convErr := strconv.Atoi(strings.TrimSpace(string(out)))
				if err != nil || convErr != nil || pid <= 1 {
					t.Fatalf("main PID of the stand-in: %q %v", out, err)
				}
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			} else if out, err := systemctlHere("stop", standIn); err != nil {
				t.Fatalf("systemctl stop: %v %s", err, out)
			}
			//Not at once: during a normal stop Zoraxy still needs its plugins while it drains
			time.Sleep(time.Second)
			if isEnded(ended) || !pidAlive(cmd.Process.Pid) {
				t.Fatalf("the plugin was ended %s after the service was %s, before the grace time of %s", time.Since(begin), how, scopeOrphanGrace)
			}
			//But for certain once the grace time is over
			eventually(t, scopeOrphanGrace+10*time.Second, "systemd to end the plugin of a Zoraxy that is gone", func() bool { return isEnded(ended) })
		})
	}
}

// TestFaultLeftoverScopeIsKilledAtTheNextStart covers what the binding cannot:
// Zoraxy not in a service, or the orphan still inside its grace time.
func TestFaultLeftoverScopeIsKilledAtTheNextStart(t *testing.T) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl was not found")
	}
	oldUnit := ownSystemdUnit
	ownSystemdUnit = func() string { return "" }
	t.Cleanup(func() { ownSystemdUnit = oldUnit })
	fakeLimitsProbe(t, probeSystemdScope)
	dead := newFaultManager(t)
	if support, note := dead.limitsSupport(); support != "systemd" {
		t.Skip("needs systemd scopes on this host: " + note)
	}
	other := newFaultManager(t) //another Zoraxy install on the same host with the same plugin
	_, orphanEnded := startScoped(t, dead, "test.leftover")
	_, longerIDEnded := startScoped(t, dead, "test.leftover-two")
	_, otherEnded := startScoped(t, other, "test.leftover")

	//The Zoraxy that started the orphan is gone; the next one runs from the same folder
	next := newFaultManager(t)
	next.Options.PluginDir = filepath.Join(dead.Options.PluginDir, ".", "")
	_, newEnded := startScoped(t, next, "test.leftover")
	eventually(t, 5*time.Second, "the process a dead Zoraxy left behind to be killed", func() bool { return isEnded(orphanEnded) })
	time.Sleep(300 * time.Millisecond)
	if isEnded(newEnded) {
		t.Fatal("the new process of the plugin was killed too")
	}
	if isEnded(otherEnded) {
		t.Fatal("the plugin of another Zoraxy install was killed")
	}
	if isEnded(longerIDEnded) {
		t.Fatal("another plugin of the same install was killed")
	}
}

// TestFaultCloseWaitsForAnAutomaticRestartThatIsUnderWay: Close used to look at
// IsRunning without the start / stop lock, skipped a plugin whose automatic
// restart was in the middle of its start, and that process was never stopped.
func TestFaultCloseWaitsForAnAutomaticRestartThatIsUnderWay(t *testing.T) {
	m := newFaultManager(t)
	fastSupervisor(m)
	endSupervision(t, m)
	fakeLeftoverKill(t)
	p := loadChaosStopped(t, m, "lateclose", "mode=ok\n", "t")
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.Restart = RestartOnFailure })
	mustStart(t, m, p)
	waitHealth(t, p, HealthOK)

	//The next start is slow: it waits for the first systemd probe (up to 5 s on a real host)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fakeLimitsProbe(t, func() ([]string, string) {
		once.Do(func() { close(entered) })
		<-release
		return nil, "no bus"
	})
	setPolicy(t, m, p, func(pp *PluginPolicy) { pp.TasksMax = 100 }) //applies at the next start

	killPID(p.Status().PID)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the automatic restart did not begin")
	}
	closed := make(chan struct{})
	go func() {
		m.Close()
		close(closed)
	}()
	time.Sleep(200 * time.Millisecond) //Close is now past its look at the plugin, or waits for the start
	close(release)
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not return")
	}
	//Give a start that Close did not wait for the time to finish
	time.Sleep(700 * time.Millisecond)
	st := p.Status()
	if st.StartCount != 2 {
		t.Fatalf("the automatic restart did not start a process (starts: %d), the test proves nothing", st.StartCount)
	}
	if p.IsRunning() || st.State == StateRunning {
		t.Fatalf("a plugin process (PID %d) is still running after Close: %+v", st.PID, st)
	}
}
