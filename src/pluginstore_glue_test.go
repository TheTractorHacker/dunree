package main

import (
	"errors"
	"testing"

	"github.com/TheTractorHacker/dunree/mod/baseline"
)

// Only a start that finds nothing at all is a new installation (no store source);
// anything else, also what cannot be examined, keeps the store source it had.
func TestPluginStoreExistingInstallIsConservative(t *testing.T) {
	old := baselineProbe
	t.Cleanup(func() { baselineProbe = old })
	for _, c := range []struct {
		name     string
		probe    baseline.Probe
		existing bool
	}{
		{"nothing there", baseline.Probe{}, false},
		{"database of an earlier start", baseline.Probe{DBExisted: true}, true},
		{"schema stamp", baseline.Probe{SchemaStamp: 1}, true},
		{"files in the config folder", baseline.Probe{ConfFiles: 1}, true},
		{"database path unreadable", baseline.Probe{DBErr: errors.New("denied")}, true},
		{"config folder unreadable", baseline.Probe{ConfErr: errors.New("denied")}, true},
	} {
		baselineProbe = c.probe
		if got := pluginStoreExistingInstall(); got != c.existing {
			t.Errorf("%s: existing install = %v, want %v", c.name, got, c.existing)
		}
	}
}
