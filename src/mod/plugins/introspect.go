package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	zoraxyPlugin "imuslab.com/zoraxy/mod/plugins/zoraxy_plugin"
)

// checkSupportHotRebuild checks if a Makefile or main.go exists in the given directory
func checkSupportHotRebuild(dir string) bool {
	_, errMakefile := os.Stat(filepath.Join(dir, "Makefile"))
	_, errMainGo := os.Stat(filepath.Join(dir, "main.go"))
	return !os.IsNotExist(errMakefile) || !os.IsNotExist(errMainGo)
}

/*
LoadPluginSpec loads a plugin specification from the plugin directory
Zoraxy will start the plugin binary or the entry point script
with -introspect flag to get the plugin specification
*/
func (m *Manager) LoadPluginSpec(pluginPath string) (*Plugin, error) {
	pluginEntryPoint, err := m.GetPluginEntryPoint(pluginPath)
	if err != nil {
		return nil, err
	}

	pluginSpec, err := m.GetPluginSpec(pluginEntryPoint)
	if err != nil {
		return nil, err
	}

	err = validatePluginSpec(pluginSpec)
	if err != nil {
		return nil, err
	}

	for _, warn := range sanitizeHookSpec(pluginSpec) {
		m.logf(nil, "plugin "+pluginSpec.ID+": "+warn, nil)
	}

	for _, warn := range sanitizeSupervisionSpec(pluginSpec) {
		m.logf(nil, "plugin "+pluginSpec.ID+": "+warn, nil)
	}

	loaded := &Plugin{
		RootDir:           pluginPath,
		Spec:              pluginSpec,
		Enabled:           false,
		SupportHotRebuild: checkSupportHotRebuild(pluginPath),
	}
	m.loadPluginPolicy(loaded) //what the administrator set for this plugin ID (restart policy, limits, ...)
	return loaded, nil
}

// GetPluginEntryPoint returns the plugin entry point
func (m *Manager) GetPluginSpec(entryPoint string) (*zoraxyPlugin.IntroSpect, error) {
	pluginSpec := zoraxyPlugin.IntroSpect{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, entryPoint, "-introspect")
	output, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("plugin introspect timed out")
	}
	if err != nil {
		return nil, err
	}

	// Assuming the output is JSON and needs to be unmarshaled into pluginSpec
	err = json.Unmarshal(output, &pluginSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal plugin spec: %v", err)
	}

	return &pluginSpec, nil
}

// sanitizeSupervisionSpec checks the optional supervision fields of a manifest
// (health_path, configure_via). An invalid value is dropped, never guessed.
func sanitizeSupervisionSpec(spec *zoraxyPlugin.IntroSpect) []string {
	var warns []string
	if hp := spec.HealthPath; hp != "" {
		ok := len(hp) <= 256 && strings.HasPrefix(hp, "/") && !strings.Contains(hp, "//")
		for _, r := range hp {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/-_.~", r)) {
				ok = false
			}
		}
		if !ok {
			warns = append(warns, "health_path in the manifest is not a plain absolute path, the health check will use a TCP connect")
			spec.HealthPath = ""
		}
	}
	switch spec.ConfigureVia {
	case "", zoraxyPlugin.ConfigureViaStdin:
	default:
		warns = append(warns, "configure_via in the manifest has an unknown value, the configuration is passed on the command line")
		spec.ConfigureVia = ""
	}
	return warns
}
