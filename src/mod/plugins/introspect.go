package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	dunreePlugin "github.com/TheTractorHacker/dunree/mod/plugins/dunree_plugin"
)

// checkSupportHotRebuild checks if a Makefile or main.go exists in the given directory
func checkSupportHotRebuild(dir string) bool {
	_, errMakefile := os.Stat(filepath.Join(dir, "Makefile"))
	_, errMainGo := os.Stat(filepath.Join(dir, "main.go"))
	return !os.IsNotExist(errMakefile) || !os.IsNotExist(errMainGo)
}

/*
LoadPluginSpec loads a plugin specification from the plugin directory
Dunree will start the plugin binary or the entry point script
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

	for _, warn := range sanitizeContractSpec(pluginSpec) {
		m.logf(nil, "plugin "+pluginSpec.ID+": "+warn, nil)
	}
	if pc := contractOf(pluginSpec, m.Settings().ContractMode); pc.Note != "" {
		m.logf(nil, "plugin "+pluginSpec.ID+": "+pc.Note, nil)
	}

	// API permissions are not reviewed here: reviewPermissions is called by whoever
	// makes this manifest the loaded one (boot, a new plugin on reload, an update),
	// so a manifest that is read and then thrown away never changes an approval.

	loaded := &Plugin{
		RootDir:           pluginPath,
		Spec:              pluginSpec,
		Enabled:           false,
		SupportHotRebuild: checkSupportHotRebuild(pluginPath),
		mgr:               m,
	}
	m.loadPluginPolicy(loaded) //what the administrator set for this plugin ID (restart policy, limits, ...)
	return loaded, nil
}

// GetPluginSpec runs the plugin with -introspect and returns its manifest
func (m *Manager) GetPluginSpec(entryPoint string) (*dunreePlugin.IntroSpect, error) {
	return m.getPluginSpec(entryPoint, false)
}

// getPluginSpec runs a plugin binary with -introspect. asPluginUser: as the
// unprivileged plugin user when one is configured (-plugin_user). That is how a
// binary that was just downloaded is run for the first time (staging folder).
func (m *Manager) getPluginSpec(entryPoint string, asPluginUser bool) (*dunreePlugin.IntroSpect, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, entryPoint, "-introspect")
	if asPluginUser {
		if err := m.applyRunAs(cmd, entryPoint); err != nil {
			return nil, err
		}
	}
	output, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("plugin introspect timed out")
	}
	if err != nil {
		return nil, err
	}

	// Assuming the output is JSON and needs to be unmarshaled into pluginSpec
	spec, warns, err := decodeManifest(output)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal plugin spec: %v", err)
	}
	for _, warn := range warns {
		m.logf(nil, "plugin "+spec.ID+": "+warn, nil)
	}
	return spec, nil
}

// decodeManifest decodes the introspect output of a plugin. An api_version that
// is not a whole number in the range of an int (a string, a fraction, an object,
// a number that is too large) is dropped with a warning and the plugin is a
// legacy plugin: before api_version existed such a key was an unknown key and
// ignored, so a manifest that carries one must still load. Every other field is
// decoded as strictly as before.
func decodeManifest(output []byte) (*dunreePlugin.IntroSpect, []string, error) {
	spec := dunreePlugin.IntroSpect{}
	err := json.Unmarshal(output, &spec)
	if err == nil {
		return &spec, nil, nil
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) || !strings.EqualFold(typeErr.Field, "api_version") {
		return nil, nil, err
	}
	raw := map[string]json.RawMessage{}
	if json.Unmarshal(output, &raw) != nil {
		return nil, nil, err
	}
	for key := range raw {
		if strings.EqualFold(key, "api_version") {
			delete(raw, key)
		}
	}
	rest, mErr := json.Marshal(raw)
	if mErr != nil {
		return nil, nil, err
	}
	spec = dunreePlugin.IntroSpect{}
	if err := json.Unmarshal(rest, &spec); err != nil {
		return nil, nil, err
	}
	return &spec, []string{"api_version in the manifest is not a whole number, the plugin is treated as a legacy plugin"}, nil
}

// sanitizeSupervisionSpec checks the optional supervision fields of a manifest
// (health_path, configure_via). An invalid value is dropped, never guessed.
func sanitizeSupervisionSpec(spec *dunreePlugin.IntroSpect) []string {
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
	case "", dunreePlugin.ConfigureViaStdin:
	default:
		warns = append(warns, "configure_via in the manifest has an unknown value, the configuration is passed on the command line")
		spec.ConfigureVia = ""
	}
	return warns
}
