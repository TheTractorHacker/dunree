package uservars

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetLookupDeletePersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf", "variables.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	changes := 0
	s.OnChange(func() { changes++ })
	if _, ok := s.Lookup("remote_office_ext_ip"); ok {
		t.Fatal("an undefined variable must not resolve")
	}
	if _, err := s.Set(Variable{Name: " remote_office_ext_ip ", Value: " 203.0.113.9 ", Description: "office"}, true); err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Lookup("remote_office_ext_ip"); !ok || v != "203.0.113.9" {
		t.Fatalf("lookup = %q %v", v, ok)
	}
	if _, err := s.Set(Variable{Name: "remote_office_ext_ip", Value: "1.1.1.1"}, true); err == nil {
		t.Fatal("create must refuse an existing name")
	}
	if _, err := s.Set(Variable{Name: "remote_office_ext_ip", Value: "198.51.100.1"}, false); err != nil {
		t.Fatal(err)
	}
	// a second store reads what was written
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s2.Lookup("remote_office_ext_ip"); v != "198.51.100.1" {
		t.Fatalf("persisted value = %q", v)
	}
	if l := s2.List(); len(l) != 1 || l[0].Description != "" || l[0].Updated == 0 {
		t.Fatalf("list = %+v", l)
	}
	if err := s.Delete("remote_office_ext_ip"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("remote_office_ext_ip"); err != ErrNotFound {
		t.Fatalf("second delete = %v", err)
	}
	if _, ok := s.Lookup("remote_office_ext_ip"); ok {
		t.Fatal("deleted variable still resolves")
	}
	if changes != 3 {
		t.Fatalf("OnChange ran %d times, want 3", changes)
	}
}

func TestValidation(t *testing.T) {
	s := NewMemory()
	bad := []Variable{
		{Name: "", Value: "x"},
		{Name: "Upper", Value: "x"},
		{Name: "1abc", Value: "x"},
		{Name: "a-b", Value: "x"},
		{Name: "a.b", Value: "x"},
		{Name: strings.Repeat("a", MaxNameLen+1), Value: "x"},
		{Name: "ok", Value: ""},
		{Name: "ok", Value: "a\r\nSet-Cookie: x"},
		{Name: "ok", Value: strings.Repeat("v", MaxValueLen+1)},
		{Name: "ok", Value: "x", Description: strings.Repeat("d", MaxDescLen+1)},
		// built-ins can never be shadowed
		{Name: "external_ip", Value: "1.2.3.4"},
		{Name: "host", Value: "x"},
		{Name: "client_ip", Value: "x"},
		{Name: "request_id", Value: "x"},
		{Name: "rule_name", Value: "x"},
	}
	for _, v := range bad {
		if _, err := s.Set(v, false); err == nil {
			t.Errorf("accepted %+v", v)
		} else if _, ok := err.(ValidationError); !ok {
			t.Errorf("%+v: error is not a ValidationError: %v", v, err)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("a rejected variable was stored")
	}
	for i := 0; i < MaxVariables; i++ {
		if _, err := s.Set(Variable{Name: "v" + strings.Repeat("x", i%20) + "_" + itoa(i), Value: "x"}, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Set(Variable{Name: "one_too_many", Value: "x"}, true); err == nil {
		t.Fatal("the variable limit is not enforced")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

func TestBuiltins(t *testing.T) {
	s := NewMemory()
	ip := ""
	s.SetBuiltin("external_ip", func() string { return ip })
	if _, ok := s.Lookup("external_ip"); ok {
		t.Fatal("an unknown public IP must not resolve")
	}
	ip = "198.51.100.77"
	if v, ok := s.Lookup("external_ip"); !ok || v != ip {
		t.Fatalf("external_ip = %q %v", v, ok)
	}
	if _, ok := s.LookupUser("external_ip"); ok {
		t.Fatal("LookupUser must only return user variables")
	}
	if b := s.Builtins(); len(b) != 1 || b[0].Name != "external_ip" || b[0].Value != ip {
		t.Fatalf("builtins = %+v", b)
	}
}

func TestRefName(t *testing.T) {
	for in, want := range map[string]string{"{{a}}": "a", " {{ office_ip }} ": "office_ip", "{{external_ip}}": "external_ip"} {
		if got, ok := RefName(in); !ok || got != want {
			t.Errorf("RefName(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "a", "{{}}", "{{A}}", "x{{a}}", "{{a}}/24", "{{a}}{{b}}", "{{a.b}}"} {
		if _, ok := RefName(in); ok {
			t.Errorf("RefName(%q) must not match", in)
		}
	}
}

func TestOpenBadFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "variables.json")
	os.WriteFile(p, []byte("{not json"), 0600)
	if s, err := Open(p); err == nil || s == nil || len(s.List()) != 0 {
		t.Fatalf("broken file: store %v err %v", s, err)
	}
	os.WriteFile(p, []byte(`{"version":1,"variables":[{"name":"good","value":"1"},{"name":"host","value":"x"},{"name":"good","value":"2"},{"name":"bad","value":"a\nb"}]}`), 0600)
	s, err := Open(p)
	if err == nil {
		t.Fatal("skipped entries must be reported")
	}
	if l := s.List(); len(l) != 1 || l[0].Name != "good" || l[0].Value != "1" {
		t.Fatalf("list = %+v", l)
	}
}

// A file that cannot be read completely is never overwritten: the first save moves it aside,
// and the store says what happened (shown on the Variables tab).
func TestBrokenFileIsKeptOnSave(t *testing.T) {
	for name, content := range map[string]string{
		"truncated": `{"version":1,"variables":[{"name":"office","value":"203.0.113.9"},{"name":"vpn","val`,
		"skipped":   `{"version":1,"variables":[{"name":"good","value":"1"},{"name":"Bad Name","value":"kept for the admin"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "variables.json")
			os.WriteFile(p, []byte(content), 0600)
			s, err := Open(p)
			if err == nil {
				t.Fatal("the load problem must be reported")
			}
			if problem, backup := s.LoadProblem(); problem == "" || backup != "" {
				t.Fatalf("LoadProblem before a save = %q %q", problem, backup)
			}
			// nothing is touched until something is saved
			if b, _ := os.ReadFile(p); string(b) != content {
				t.Fatal("the file changed without a save")
			}
			if _, err := s.Set(Variable{Name: "fresh", Value: "x"}, true); err != nil {
				t.Fatal(err)
			}
			problem, backup := s.LoadProblem()
			if problem == "" || !strings.HasPrefix(backup, "variables.json.broken-") {
				t.Fatalf("LoadProblem after a save = %q %q", problem, backup)
			}
			if b, _ := os.ReadFile(filepath.Join(dir, backup)); string(b) != content {
				t.Fatalf("the kept copy differs: %q", b)
			}
			// later saves do not create more copies
			if _, err := s.Set(Variable{Name: "second", Value: "y"}, true); err != nil {
				t.Fatal(err)
			}
			if m, _ := filepath.Glob(p + ".broken-*"); len(m) != 1 {
				t.Fatalf("kept copies: %v", m)
			}
			s2, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			if problem, _ := s2.LoadProblem(); problem != "" || len(s2.List()) < 2 {
				t.Fatalf("reopened: %q %+v", problem, s2.List())
			}
		})
	}
	// a clean store has nothing to report and creates no copy
	p := filepath.Join(t.TempDir(), "variables.json")
	s, _ := Open(p)
	s.Set(Variable{Name: "a", Value: "1"}, true)
	if problem, backup := s.LoadProblem(); problem != "" || backup != "" {
		t.Fatalf("clean store: %q %q", problem, backup)
	}
	if m, _ := filepath.Glob(p + ".broken-*"); len(m) != 0 {
		t.Fatalf("unexpected copies: %v", m)
	}
}
