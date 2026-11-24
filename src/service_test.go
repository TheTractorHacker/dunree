package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testKnown(name string) (bool, bool) {
	switch name {
	case "port", "webui_tls", "service_dir", "conf":
		return true, false
	case "noauth", "version", "doctor":
		return true, true
	}
	return false, false
}

func TestParseServiceCommand(t *testing.T) {
	abs := `C:\Data\Dunree`
	if runtime.GOOS != "windows" {
		abs = "/data/dunree"
	}
	good := []struct {
		in   []string
		want serviceCommand
	}{
		{[]string{"install"}, serviceCommand{Action: "install"}},
		{[]string{"INSTALL", "--manual"}, serviceCommand{Action: "install", Manual: true}},
		{[]string{"install", "--dir", abs}, serviceCommand{Action: "install", Dir: abs}},
		{[]string{"install", "--dir=" + abs, "--", "-port=:8000", "-noauth", "--webui_tls=auto"},
			serviceCommand{Action: "install", Dir: abs, Args: []string{"-port=:8000", "-noauth", "--webui_tls=auto"}}},
		{[]string{"uninstall"}, serviceCommand{Action: "uninstall"}},
		{[]string{"start"}, serviceCommand{Action: "start"}},
		{[]string{"stop"}, serviceCommand{Action: "stop"}},
		{[]string{"status"}, serviceCommand{Action: "status"}},
	}
	for _, c := range good {
		got, err := parseServiceCommand(c.in, testKnown)
		if err != nil {
			t.Errorf("%v: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(*got, c.want) {
			t.Errorf("%v: got %+v, want %+v", c.in, *got, c.want)
		}
	}
	bad := [][]string{
		{},
		{"restart"},
		{"start", "now"},
		{"install", "--dir"},
		{"install", "--dir", "relative/folder"},
		{"install", "-port=:8000"},                   //Dunree flags must follow "--"
		{"install", "--", "-nosuchflag=1"},           //would make every start fail
		{"install", "--", "-port", ":8000"},          //value must be attached
		{"install", "--", "-port"},                   //value missing
		{"install", "--", "-service_dir=" + abs},     //use --dir
		{"install", "--", "-version"},                //exits at once
		{"install", "--", "-doctor"},                 //exits at once
		{"install", "--", "-port=:8000", "leftover"}, //not a flag
	}
	for _, in := range bad {
		if got, err := parseServiceCommand(in, testKnown); err == nil {
			t.Errorf("%v: accepted as %+v", in, *got)
		}
	}
}

// Every real flag of the program is accepted in the form the help shows, and the flags that make
// the program exit at once are refused by their real names.
func TestServiceFlagsAgainstRealFlagSet(t *testing.T) {
	var pass []string
	flag.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "test.") {
			return
		}
		_, isBool := knownFlag(f.Name)
		arg := "-" + f.Name + "=" + f.DefValue
		if isBool {
			arg = "-" + f.Name
		}
		_, err := checkServiceFlags([]string{arg}, knownFlag)
		exits := map[string]bool{"version": true, "doctor": true, "reset_ac": true, "compact-db": true, "update_geoip": true, "updater_watchdog": true, "cluster_gen_secret": true, "service_dir": true}
		if exits[f.Name] {
			if err == nil {
				t.Errorf("-%s must be refused as a service flag", f.Name)
			}
			return
		}
		if err != nil {
			t.Errorf("-%s: %v", f.Name, err)
		}
		pass = append(pass, arg)
	})
	if len(pass) < 20 {
		t.Fatalf("only %d flags seen: the test is not looking at the real flag set", len(pass))
	}
	for _, name := range []string{"version", "doctor", "reset_ac", "compact-db", "update_geoip", "updater_watchdog", "cluster_gen_secret", "service_dir", "port", "conf", "dbpath", "log", "plugin"} {
		if flag.Lookup(name) == nil {
			t.Errorf("flag -%s no longer exists: update checkServiceFlags and the packaging files", name)
		}
	}
}

func TestDefaultServiceDirAndArgs(t *testing.T) {
	for in, want := range map[string]string{
		`C:\ProgramData`:  `C:\ProgramData\Dunree`,
		`D:\ProgramData\`: `D:\ProgramData\Dunree`,
		``:                `C:\ProgramData\Dunree`,
	} {
		if got := defaultServiceDir(in); got != want {
			t.Errorf("defaultServiceDir(%q) = %q, want %q", in, got, want)
		}
	}
	dir := `C:\Program Data\Dunree`
	args := serviceStartArgs(dir, []string{"-port=:8000"})
	if !reflect.DeepEqual(args, []string{`-service_dir=C:\Program Data\Dunree`, "-port=:8000"}) {
		t.Fatalf("args = %q", args)
	}
	//what the service reads back at start is what install wrote
	if got := serviceDirFromArgs(args); got != dir {
		t.Errorf("round trip: %q", got)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"-port=:8000"}, ""},
		{[]string{"--service_dir=X"}, "X"},
		{[]string{"-service_dir", "X", "-port=:1"}, "X"},
		{[]string{"-service_dir=A", "-service_dir=B"}, "B"},
		{[]string{"--", "-service_dir=X"}, ""},
		{[]string{"positional", "-service_dir=X"}, ""},
	} {
		if got := serviceDirFromArgs(c.args); got != c.want {
			t.Errorf("serviceDirFromArgs(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestRotateServiceLog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, serviceLogName)
	os.WriteFile(p, []byte("small"), 0o600)
	if err := rotateServiceLog(p, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Fatal("a small log must not be rotated")
	}
	os.WriteFile(p+".1", []byte("older"), 0o600)
	os.WriteFile(p, []byte("this one is larger than ten bytes"), 0o600)
	if err := rotateServiceLog(p, 10); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p + ".1"); string(b) != "this one is larger than ten bytes" {
		t.Fatalf("rotated file holds %q", b)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("the log must have been moved")
	}
	if err := rotateServiceLog(filepath.Join(dir, "missing.log"), 10); err != nil {
		t.Fatal(err)
	}
}

func TestRunServiceCommandUsageAndStub(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runServiceCommand([]string{"help"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "dunree service install") {
		t.Fatalf("help: code %d, out %q", code, out.String())
	}
	out.Reset()
	if code := runServiceCommand([]string{"bogus"}, &out, &errb); code != serviceExitUsage || !strings.Contains(errb.String(), "unknown action") {
		t.Fatalf("bogus: code %d, err %q", code, errb.String())
	}
	if runtime.GOOS == "windows" {
		return //the real service manager is not touched by a unit test
	}
	errb.Reset()
	if code := runServiceCommand([]string{"status"}, &out, &errb); code != serviceExitUsage || !strings.Contains(errb.String(), "only available on Windows") {
		t.Fatalf("status off Windows: code %d, err %q", code, errb.String())
	}
	if runUnderServiceManager() {
		t.Fatal("there is no service manager off Windows")
	}
}

// A normal start must go straight through serviceEntry, and the stop sequence must still end the
// process through exitProcess (the Windows service replaces it to report "stopped" first).
func TestServiceEntryIsInertAndStopUsesExitHook(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"dunree", "-port=:8000"}
	if runtime.GOOS != "windows" && serviceEntry() {
		t.Fatal("serviceEntry must return false for a normal start")
	}
	if serviceReadyHook != nil {
		t.Fatal("the ready hook must be unset outside a service")
	}
	serviceReady() //must not panic

	oldExit := exitProcess
	defer func() { exitProcess = oldExit }()
	got := make(chan int, 1)
	exitProcess = func(code int) { got <- code }
	c := make(chan os.Signal, 2)
	ran := false
	c <- os.Interrupt
	stopOnSignals(c, nil, func() { ran = true }, func(code int) { exitProcess(code) }, func(string) {})
	if code := <-got; code != 0 || !ran {
		t.Fatalf("stop: code %d, sequence ran %v", code, ran)
	}
	if cap(stopRequests) < 2 {
		t.Fatal("stopRequests must hold a second (force quit) request")
	}
}

// Inside a Windows service no SIGTERM handler may be registered: the runtime would deliver every
// user logoff (CTRL_LOGOFF_EVENT) as SIGTERM and the service would stop cleanly, without a restart.
func TestStopSignalsNotRegisteredInsideService(t *testing.T) {
	old := serviceActive
	defer func() { serviceActive = old }()
	var got []os.Signal
	calls := 0
	rec := func(_ chan<- os.Signal, sig ...os.Signal) { calls++; got = sig }
	c := make(chan os.Signal, 1)

	serviceActive = false
	notifyStopSignals(c, rec)
	if calls != 1 || !reflect.DeepEqual(got, stopSignals) {
		t.Fatalf("console start: notify called %d times with %v, want once with %v", calls, got, stopSignals)
	}
	serviceActive = true
	notifyStopSignals(c, rec)
	if calls != 1 {
		t.Fatal("inside a Windows service SIGINT/SIGTERM must not be subscribed")
	}
}
