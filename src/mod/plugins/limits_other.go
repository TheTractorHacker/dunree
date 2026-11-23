//go:build !linux

package plugins

import "os/exec"

// Resource limits for plugin processes exist on Linux only (see limits_linux.go)

func (m *Manager) limitsSupport() (string, string) {
	return "none", "Resource limits for plugins are only available on Linux"
}

func (m *Manager) wrapWithLimits(cmd *exec.Cmd, pluginID string, pol PluginPolicy) (note string, problem string) {
	if pol.hasCgroupLimits() {
		return "", "Memory, CPU and task limits are NOT enforced: they are only available on Linux"
	}
	return "", ""
}

func applyRlimits(pid int, pol PluginPolicy) (note string, err error) {
	if pol.MaxOpenFiles > 0 {
		return "", errLimitsLinuxOnly
	}
	return "", nil
}
