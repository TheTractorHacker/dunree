package plugins

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/info/logger"
	dunreePlugin "github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
)

// TestStartPluginOutputReadersDoNotRaceProcessField starts a plugin that writes
// to stdout and stderr immediately. The output readers must not read
// Plugin.process while StartPlugin assigns it (run with -race), see #1326.
func TestStartPluginOutputReadersDoNotRaceProcessField(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a start.sh entry point")
	}
	dir := filepath.Join(t.TempDir(), "racer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\necho started\necho started >&2\nexec sleep 30\n"
	if err := os.WriteFile(filepath.Join(dir, "start.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	lg, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	p := &Plugin{RootDir: dir, Spec: &dunreePlugin.IntroSpect{ID: "racer", Name: "racer"}}
	m := &Manager{
		LoadedPlugins: map[string]*Plugin{"racer": p},
		Options: &ManagerOptions{
			SystemConst: &dunreePlugin.RuntimeConstantValue{},
			Logger:      lg,
		},
	}
	if err := m.StartPlugin("racer"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let both readers log their first line
	proc := p.currentProc()
	if proc == nil {
		t.Fatal("plugin has no process after StartPlugin")
	}
	_ = proc.cmd.Process.Kill()
	if !waitProcDone(proc, 5*time.Second) {
		t.Fatal("killed plugin process was not reaped")
	}
}

// TestPluginOutputForUnknownPluginDoesNotPanic covers a line that arrives after
// the plugin entry is gone: it must reach the [unknown:<pid>] branch.
func TestPluginOutputForUnknownPluginDoesNotPanic(t *testing.T) {
	lg, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{LoadedPlugins: map[string]*Plugin{}, Options: &ManagerOptions{Logger: lg}}
	m.handlePluginSTDOUT("gone", 1234, "late line")
	m.handlePluginSTDERR("gone", 1234, "late line")
}
