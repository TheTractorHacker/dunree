//go:build linux

package plugins

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

/*
	Resource limits for plugin processes (Linux only, opt-in per plugin)

	Memory, CPU and task limits need a cgroup. Dunree does not write to cgroupfs
	itself (the reference unit runs with ProtectControlGroups=yes): it starts the
	plugin through "systemd-run --scope", which asks systemd to create a transient
	scope with the limits and then becomes the plugin process (same PID, so stop,
	signals and exit codes work as without it). As root that is a system scope, as
	another user a scope of the user manager (needs a user session bus).

	A scope is a cgroup of its own, outside the cgroup of Dunree, so KillMode=control-group
	of the Dunree unit does not reach it. Two things keep such a plugin from outliving
	Dunree (a crash, a SIGKILL, a shutdown step that was abandoned):

	- When Dunree itself runs in a service of the same systemd manager, the scope is
	  bound to that service (BindsTo): when the service is gone, systemd ends the scope
	  after scopeOrphanGrace. See scopeBindArgs for why it waits.
	- Before a plugin with limits is started, every scope an earlier process of this
	  plugin of this Dunree instance left behind is killed (killLeftoverScopes).

	The open file limit is a plain rlimit set with prlimit(2) on the started process.
	RLIMIT_AS is not used: it breaks Go programs, which reserve far more address
	space than they use.
*/

const limitsProbeCache = 5 * time.Minute

var limitsProbe struct {
	mu      sync.Mutex
	known   bool          //a probe has finished at least once
	at      time.Time     //when the last probe finished
	base    []string      //command prefix that works, nil when systemd scopes cannot be used
	problem string        //
	flight  chan struct{} //non-nil while a probe runs, closed when it is done
}

// limitsProbeRun is the probe itself (replaced in tests)
var limitsProbeRun = probeSystemdScope

// systemdScopeBase returns the "systemd-run --scope ..." prefix that works on this host.
//
// The probe starts a process and can take seconds on a slow or missing bus, so it
// never runs while the lock is held and never more than once at a time. The first
// caller of the process waits for it (together with everyone who asks meanwhile);
// after that the last answer is served at once, also when it is older than
// limitsProbeCache: then a new probe runs in the background for the next caller.
// A failure is cached exactly like a success.
func systemdScopeBase() ([]string, string) {
	limitsProbe.mu.Lock()
	fresh := limitsProbe.known && time.Since(limitsProbe.at) < limitsProbeCache
	if !fresh && limitsProbe.flight == nil {
		done := make(chan struct{})
		limitsProbe.flight = done
		go func() {
			base, problem := limitsProbeRun()
			limitsProbe.mu.Lock()
			limitsProbe.base, limitsProbe.problem = base, problem
			limitsProbe.known, limitsProbe.at = true, time.Now()
			limitsProbe.flight = nil
			limitsProbe.mu.Unlock()
			close(done)
		}()
	}
	if limitsProbe.known {
		base, problem := limitsProbe.base, limitsProbe.problem
		limitsProbe.mu.Unlock()
		return base, problem
	}
	wait := limitsProbe.flight
	limitsProbe.mu.Unlock()
	<-wait
	limitsProbe.mu.Lock()
	defer limitsProbe.mu.Unlock()
	return limitsProbe.base, limitsProbe.problem
}

// scopeOrphanGrace is how long systemd waits before it kills a bound scope whose
// Dunree service is gone or is being stopped. It must be longer than the longest
// stop of Dunree (28 s, see shutdown.go): during a normal stop Dunree ends its
// plugins itself, after the requests in flight are done.
var scopeOrphanGrace = 40 * time.Second

// ownSystemdUnit returns the systemd service this process runs in when a scope
// started by this process can be bound to it, else "" (replaced in tests)
var ownSystemdUnit = func() string {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	return systemdUnitOfCgroup(string(raw), os.Geteuid())
}

// systemdUnitOfCgroup reads the service unit out of the content of /proc/<pid>/cgroup.
// It only answers for a unit of the manager the scopes are created in: as root the
// system manager (a service outside every user manager), as another user the user
// manager of that user. A session scope, a container without systemd or a system
// service that does not run as root (its scopes would be user scopes, and the user
// manager does not know the system unit) give "".
func systemdUnitOfCgroup(procCgroup string, euid int) string {
	path := ""
	for _, line := range strings.Split(procCgroup, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" { //cgroup v2
			path = parts[2]
			break
		}
		if parts[1] == "name=systemd" { //cgroup v1 and hybrid
			path = parts[2]
		}
	}
	if path == "" {
		return ""
	}
	comps := strings.Split(path, "/")
	userManager := -1
	for i, c := range comps {
		if strings.HasPrefix(c, "user@") && strings.HasSuffix(c, ".service") {
			userManager = i
		}
	}
	if euid == 0 {
		if userManager >= 0 {
			return ""
		}
	} else if userManager < 0 || comps[userManager] != "user@"+strconv.Itoa(euid)+".service" {
		return ""
	}
	for i := len(comps) - 1; i > userManager; i-- {
		unit := strings.TrimPrefix(comps[i], "_") //systemd escapes some names with a leading underscore
		if !strings.HasSuffix(unit, ".service") || len(unit) > 255 {
			continue
		}
		for j := 0; j < len(unit); j++ {
			c := unit[j]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '@', c == ':', c == '\\':
			default:
				return ""
			}
		}
		return unit
	}
	return ""
}

// scopeBindArgs are the systemd-run options that tie a plugin scope to the service
// of Dunree.
//
// BindsTo: the scope is stopped when the service is stopped or suddenly gone.
// There is deliberately no After=: with it systemd would stop the scope before the
// service, and a stop of Dunree would wait for the plugin.
//
// KillSignal=SIGCONT and TimeoutStopSec: "stopping" the scope must not end the
// plugin at once. On "systemctl stop dunree" systemd stops the scope at the same
// moment as the service, and a SIGTERM to the plugin then would take it out of the
// request path (fail-open filters let requests pass) while Dunree still drains.
// So the stop signal is one that does nothing, and the SIGKILL comes after
// scopeOrphanGrace. Dunree stops the plugin itself long before that; only a plugin
// whose Dunree is gone lives until the timeout.
func scopeBindArgs(unit string) []string {
	return []string{
		"-p", "BindsTo=" + unit,
		"-p", "KillSignal=SIGCONT",
		"-p", "TimeoutStopSec=" + strconv.Itoa(int(scopeOrphanGrace/time.Second)),
	}
}

// scopeBoundUnit returns the unit a scope started with this prefix is bound to, "" for none
func scopeBoundUnit(base []string) string {
	for _, a := range base {
		if strings.HasPrefix(a, "BindsTo=") {
			return strings.TrimPrefix(a, "BindsTo=")
		}
	}
	return ""
}

// probeSystemdScope tries "systemd-run --scope" with a harmless command: first
// bound to the service of Dunree (when there is one), then without. The binding is
// only used when the try with it worked, so it can never be the reason a plugin
// does not start.
func probeSystemdScope() ([]string, string) {
	bin, err := exec.LookPath("systemd-run")
	if err != nil {
		return nil, "systemd-run was not found"
	}
	trueBin, err := exec.LookPath("true")
	if err != nil {
		return nil, "the test command \"true\" was not found"
	}
	base := []string{bin, "--scope", "--quiet", "--collect"}
	if os.Geteuid() != 0 {
		base = append(base, "--user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	try := func(ctx context.Context, base []string) (string, error) {
		args := append(append([]string{}, base[1:]...), "--description=Dunree plugin limits check", "--", trueBin)
		out, err := exec.CommandContext(ctx, base[0], args...).CombinedOutput()
		return string(out), err
	}
	if unit := ownSystemdUnit(); unit != "" {
		bound := append(append([]string{}, base...), scopeBindArgs(unit)...)
		short, cancelShort := context.WithTimeout(ctx, 2*time.Second)
		_, err := try(short, bound)
		cancelShort()
		if err == nil {
			return bound, ""
		}
	}
	if msg, err := try(ctx, base); err != nil {
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, "systemd-run --scope does not work here (" + err.Error() + ") " + msg
	}
	return base, ""
}

// scopeDescription is the description of the systemd scope of a plugin. It must
// be given: without it systemd uses the whole command line as the description,
// writes it to the journal and shows it to every local user, and for a plugin
// that gets its configuration with -configure= that command line holds its API
// key and invoke token.
func scopeDescription(pluginID string) string {
	return "Dunree plugin " + scopeSafeID(pluginID)
}

// scopeUnitName is the name of the systemd scope of one plugin process, so that
// it can be found ("systemctl status 'zoraxy-plugin-*'") instead of being an
// anonymous run-p123-i456.scope: zoraxy-plugin-<id>-<instance>-<random>.scope.
// The instance part (scopeInstanceTag) keeps two Dunree installs on one host
// apart. The random part keeps two starts of the same plugin apart: the scope of
// the last process can still exist for a moment.
func scopeUnitName(instance string, pluginID string) string {
	var rnd [4]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		binary.LittleEndian.PutUint32(rnd[:], uint32(time.Now().UnixNano()))
	}
	return scopeUnitPrefix(instance, pluginID) + hex.EncodeToString(rnd[:]) + ".scope"
}

func scopeUnitPrefix(instance string, pluginID string) string {
	return "zoraxy-plugin-" + scopeSafeID(pluginID) + "-" + instance + "-"
}

// scopeUnitPattern matches every scope of this plugin of this instance, and of no
// other plugin: the instance and the random part have a fixed length and no
// hyphen, so the scopes of "a-b" do not match the pattern of "a".
func scopeUnitPattern(instance string, pluginID string) string {
	return scopeUnitPrefix(instance, pluginID) + "????????.scope"
}

// scopeInstanceTag tells the scopes of this Dunree install from those of another
// one on the same host: 8 hex digits made from the absolute plugin directory.
func (m *Manager) scopeInstanceTag() string {
	dir := ""
	if m != nil && m.Options != nil {
		dir = m.Options.PluginDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	sum := sha256.Sum256([]byte(dir))
	return hex.EncodeToString(sum[:4])
}

// killLeftoverScopes kills (SIGKILL, all processes) the scopes that match the
// pattern. It is called under the start / stop lock of the plugin right before a
// new process of it is started, when no process of the plugin belongs to this
// Dunree: whatever is still in such a scope was left behind by a Dunree that
// crashed, was killed or gave up on its shutdown. Replaced in tests.
var killLeftoverScopes = func(pattern string) {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return
	}
	args := []string{"kill", "--signal=SIGKILL", pattern}
	if os.Geteuid() != 0 {
		args = append([]string{"--user"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exec.CommandContext(ctx, bin, args...).Run() //no match is not an error, and an error changes nothing for the start
}

// scopeSafeID is the plugin ID cut to 80 bytes, with everything that is not a
// letter, a digit, a dot, an underscore or a hyphen replaced: the ID comes from
// the manifest of the plugin and ends up in a unit name and in the journal.
func scopeSafeID(pluginID string) string {
	clean := make([]byte, 0, len(pluginID))
	for i := 0; i < len(pluginID) && len(clean) < 80; i++ {
		c := pluginID[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			clean = append(clean, c)
		default:
			clean = append(clean, '_')
		}
	}
	return string(clean)
}

// limitsSupport says what this host can enforce: "systemd" (memory, CPU, tasks and open files) or "rlimit" (open files only)
func (m *Manager) limitsSupport() (string, string) {
	base, problem := systemdScopeBase()
	if base == nil {
		return "rlimit", "Only the open file limit can be enforced: " + problem
	}
	note := "Limits are enforced with a systemd scope per plugin"
	if os.Geteuid() != 0 {
		note = "Limits are enforced with a systemd user scope per plugin"
	}
	if unit := scopeBoundUnit(base); unit != "" {
		note += ", which systemd ends when " + unit + " is gone"
	}
	return "systemd", note
}

// wrapWithLimits rewrites cmd so that the plugin starts inside a systemd scope with
// the cgroup limits of the policy. It returns a note for the status and an error
// text when a limit could not be arranged (the plugin is then started without it:
// a limit must not be the reason a plugin does not run).
func (m *Manager) wrapWithLimits(cmd *exec.Cmd, pluginID string, pol PluginPolicy) (note string, problem string) {
	if !pol.hasCgroupLimits() {
		return "", ""
	}
	base, why := systemdScopeBase()
	if base == nil {
		return "", "Memory, CPU and task limits are NOT enforced: " + why
	}
	instance := m.scopeInstanceTag()
	killLeftoverScopes(scopeUnitPattern(instance, pluginID))
	args := append([]string{}, base[1:]...)
	args = append(args, "--unit="+scopeUnitName(instance, pluginID), "--description="+scopeDescription(pluginID))
	note = "systemd scope:"
	if pol.MemoryMaxMB > 0 {
		args = append(args, "-p", "MemoryMax="+strconv.Itoa(pol.MemoryMaxMB)+"M", "-p", "MemorySwapMax=0")
		note += " memory " + strconv.Itoa(pol.MemoryMaxMB) + " MB"
	}
	if pol.CPUQuotaPercent > 0 {
		args = append(args, "-p", "CPUQuota="+strconv.Itoa(pol.CPUQuotaPercent)+"%")
		note += " CPU " + strconv.Itoa(pol.CPUQuotaPercent) + "%"
	}
	if pol.TasksMax > 0 {
		args = append(args, "-p", "TasksMax="+strconv.Itoa(pol.TasksMax))
		note += " tasks " + strconv.Itoa(pol.TasksMax)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		// -plugin_user: systemd-run has to talk to systemd as root, it switches to the plugin user itself
		cred := cmd.SysProcAttr.Credential
		args = append(args, "--uid="+strconv.FormatUint(uint64(cred.Uid), 10), "--gid="+strconv.FormatUint(uint64(cred.Gid), 10))
		cmd.SysProcAttr.Credential = nil
	}
	args = append(args, "--")
	args = append(args, cmd.Args...)
	cmd.Path = base[0]
	cmd.Args = append([]string{base[0]}, args...)
	return note, ""
}

type rlimit64 struct {
	Cur uint64
	Max uint64
}

const rlimitNOFILE = 7

// applyRlimits sets the rlimits of the policy on the started process
func applyRlimits(pid int, pol PluginPolicy) (note string, err error) {
	if pol.MaxOpenFiles <= 0 {
		return "", nil
	}
	lim := rlimit64{Cur: uint64(pol.MaxOpenFiles), Max: uint64(pol.MaxOpenFiles)}
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), rlimitNOFILE, uintptr(unsafe.Pointer(&lim)), 0, 0, 0)
	if errno != 0 {
		return "", errors.New("the open file limit could not be set: " + errno.Error())
	}
	return "open files " + strconv.Itoa(pol.MaxOpenFiles), nil
}
