package legacycompat

import (
	"fmt"
	"strings"
	"testing"
)

func captureLog(t *testing.T) *[]string {
	t.Helper()
	var lines []string
	old := Logf
	Logf = func(format string, a ...any) { lines = append(lines, fmt.Sprintf(format, a...)) }
	resetEnvWarnings()
	t.Cleanup(func() { Logf = old; resetEnvWarnings() })
	return &lines
}

const oldTokenVar = "ZORAXY_METRICS_TOKEN" // legacy-compat: the name unit files of existing installs set

func TestEnvNewNameWins(t *testing.T) {
	lines := captureLog(t)
	t.Setenv("DUNREE_METRICS_TOKEN", " new ")
	t.Setenv(oldTokenVar, "old")
	v, src := LookupEnv("METRICS_TOKEN")
	if v != "new" || src != "DUNREE_METRICS_TOKEN" {
		t.Fatalf("got %q from %q", v, src)
	}
	if len(*lines) != 0 {
		t.Fatalf("no deprecation line expected when the new name is set: %v", *lines)
	}
}

func TestEnvLegacyFallbackLogsOnce(t *testing.T) {
	lines := captureLog(t)
	t.Setenv("DUNREE_METRICS_TOKEN", "")
	t.Setenv(oldTokenVar, "old-token")
	for i := 0; i < 5; i++ {
		if v, src := LookupEnv("METRICS_TOKEN"); v != "old-token" || src != oldTokenVar {
			t.Fatalf("fallback: got %q from %q", v, src)
		}
	}
	if Getenv("METRICS_TOKEN") != "old-token" {
		t.Fatal("Getenv must fall back too")
	}
	if len(*lines) != 1 {
		t.Fatalf("want exactly one deprecation line, got %d: %v", len(*lines), *lines)
	}
	l := (*lines)[0]
	if !strings.Contains(l, "DEPRECATED") || !strings.Contains(l, oldTokenVar) || !strings.Contains(l, "DUNREE_METRICS_TOKEN") {
		t.Fatalf("the line must name both variables: %q", l)
	}
	if strings.Contains(l, "old-token") {
		t.Fatal("the value of the variable must never be logged")
	}
	//another variable gets its own line
	t.Setenv("ZORAXY_OTHER", "x") // legacy-compat
	LookupEnv("OTHER")
	LookupEnv("OTHER")
	if len(*lines) != 2 {
		t.Fatalf("want one line per variable, got %v", *lines)
	}
}

func TestEnvUnset(t *testing.T) {
	lines := captureLog(t)
	t.Setenv("DUNREE_METRICS_TOKEN", "")
	t.Setenv(oldTokenVar, "  ")
	if v, src := LookupEnv("METRICS_TOKEN"); v != "" || src != "" {
		t.Fatalf("blank variables count as unset: %q %q", v, src)
	}
	if len(*lines) != 0 {
		t.Fatalf("nothing to log: %v", *lines)
	}
}
