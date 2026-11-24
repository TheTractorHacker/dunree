package uservars

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/*
	uservars.go

	User defined variables (upstream #370): free-form name = value pairs an admin maintains in one
	place and references as {{name}} in custom header values, redirect targets, static responses,
	error pages, the named lists of the rules engine and the IP entries of the access lists.

	The store also resolves the built-in variables that do not depend on a request (external_ip),
	so every consumer that works outside a request (rule lists, access lists) uses one Lookup.

	Nothing changes for an installation without variables: a {{name}} that is not defined keeps
	its old meaning everywhere (left untouched in templates, never matching in lists).
*/

const (
	MaxVariables = 200
	MaxNameLen   = 32
	MaxValueLen  = 256
	MaxDescLen   = 200

	maxFileSize = 1 << 20
	fileVersion = 1
)

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// refRe matches a text that is exactly one {{name}} reference
var refRe = regexp.MustCompile(`^\{\{\s*([a-z][a-z0-9_]*)\s*\}\}$`)

// reserved names are the built-in variables; a user variable can never shadow them
var reserved = map[string]bool{"host": true, "client_ip": true, "request_id": true, "rule_name": true, "external_ip": true, "node": true}

// Variable is one user defined variable
type Variable struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Updated     int64  `json:"updated"`
}

type file struct {
	Version   int        `json:"version"`
	Variables []Variable `json:"variables"`
}

// Store holds the variables. Lookup is lock free (one atomic load and a map read).
type Store struct {
	path string

	mu       sync.Mutex // serialises changes
	vars     atomic.Pointer[map[string]Variable]
	builtins atomic.Pointer[map[string]func() string]
	onChange []func()

	// what went wrong reading the file at Open ("" when nothing did). While quarantine is set the
	// file on disk still holds content the store did not take over; it is moved aside (backup)
	// before the first save instead of being overwritten.
	loadErr    string
	quarantine bool
	backup     string
}

// ValidationError is a problem with the input (the API answers 400)
type ValidationError struct{ Msg string }

func (v ValidationError) Error() string { return v.Msg }

// ErrNotFound is returned when the variable does not exist
var ErrNotFound = errors.New("variable not found")

func badf(format string, a ...any) error { return ValidationError{Msg: fmt.Sprintf(format, a...)} }

// NewMemory creates a store that is not persisted (tests)
func NewMemory() *Store {
	s := &Store{}
	m := map[string]Variable{}
	s.vars.Store(&m)
	b := map[string]func() string{}
	s.builtins.Store(&b)
	return s
}

// Open loads the variables from path (a missing file is an empty store). Entries that do not
// validate are skipped and reported in the returned error; the store is usable either way.
// After an error the file is never overwritten: the first save renames it to
// <name>.broken-<time> first (see LoadProblem), so nothing an admin wrote is lost.
func Open(path string) (*Store, error) {
	s, err := open(path)
	if err != nil {
		s.loadErr = err.Error()
		s.quarantine = true
	}
	return s, err
}

// LoadProblem reports what went wrong reading the file at start ("" when nothing did) and the
// name of the copy of that file that was kept when a later save replaced it ("" while the
// original is still in place).
func (s *Store) LoadProblem() (problem, backup string) {
	if s == nil {
		return "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadErr, s.backup
}

func open(path string) (*Store, error) {
	s := NewMemory()
	s.path = path
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return s, err
	}
	if st.Size() > maxFileSize {
		return s, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), maxFileSize)
	}
	var data file
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return s, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	m := map[string]Variable{}
	var skipped []string
	for _, v := range data.Variables {
		if _, dup := m[v.Name]; dup || len(m) >= MaxVariables || validate(&v) != nil {
			skipped = append(skipped, v.Name)
			continue
		}
		m[v.Name] = v
	}
	s.vars.Store(&m)
	if len(skipped) > 0 {
		return s, fmt.Errorf("%s: skipped invalid or duplicate variables: %s", filepath.Base(path), strings.Join(skipped, ", "))
	}
	return s, nil
}

// ValidName reports whether name can be used for a user variable
func ValidName(name string) bool {
	return len(name) <= MaxNameLen && nameRe.MatchString(name) && !reserved[name]
}

// RefName returns the variable name when s is exactly one {{name}} reference
func RefName(s string) (string, bool) {
	m := refRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return m[1], true
}

func validate(v *Variable) error {
	if reserved[v.Name] {
		return badf("%q is a built-in variable and cannot be redefined", v.Name)
	}
	if !ValidName(v.Name) {
		return badf("variable names are lower case letters, digits and _, starting with a letter, at most %d characters", MaxNameLen)
	}
	if v.Value == "" {
		return badf("the value is empty")
	}
	if len(v.Value) > MaxValueLen {
		return badf("the value is longer than %d characters", MaxValueLen)
	}
	for _, c := range v.Value {
		if c < 0x20 || c == 0x7f || c == 0x85 || c == 0x2028 || c == 0x2029 {
			return badf("the value contains a line break or control character")
		}
	}
	if len(v.Description) > MaxDescLen {
		return badf("the description is longer than %d characters", MaxDescLen)
	}
	if strings.ContainsAny(v.Description, "\x00\r\n") {
		return badf("the description contains a line break")
	}
	return nil
}

// SetBuiltin installs a request independent built-in variable (external_ip). An empty result
// means "not known right now".
func (s *Store) SetBuiltin(name string, f func() string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := map[string]func() string{}
	for k, v := range *s.builtins.Load() {
		b[k] = v
	}
	if f == nil {
		delete(b, name)
	} else {
		b[name] = f
	}
	s.builtins.Store(&b)
}

// OnChange registers f to run after every successful Set / Delete
func (s *Store) OnChange(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, f)
}

// Lookup resolves a user variable or a request independent built-in. ok is false when the name
// is not defined or the built-in has no value at the moment.
func (s *Store) Lookup(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	if f, ok := (*s.builtins.Load())[name]; ok {
		v := f()
		return v, v != ""
	}
	v, ok := (*s.vars.Load())[name]
	return v.Value, ok
}

// LookupUser resolves user variables only (the template expansion has its own built-ins)
func (s *Store) LookupUser(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	v, ok := (*s.vars.Load())[name]
	return v.Value, ok
}

// Builtin is a built-in variable as shown to the admin
type Builtin struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Builtins lists the request independent built-ins with their current value
func (s *Store) Builtins() []Builtin {
	out := []Builtin{}
	for name, f := range *s.builtins.Load() {
		out = append(out, Builtin{Name: name, Value: f()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// List returns the variables sorted by name
func (s *Store) List() []Variable {
	m := *s.vars.Load()
	out := make([]Variable, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) save(m map[string]Variable) error {
	if s.path == "" {
		return nil
	}
	data := file{Version: fileVersion, Variables: make([]Variable, 0, len(m))}
	for _, v := range m {
		data.Variables = append(data.Variables, v)
	}
	sort.Slice(data.Variables, func(i, j int) bool { return data.Variables[i].Name < data.Variables[j].Name })
	js, _ := json.MarshalIndent(data, "", "  ")
	if err := os.MkdirAll(filepath.Dir(s.path), 0775); err != nil {
		return err
	}
	if s.quarantine {
		// the file could not be read completely at start: keep it, never write over it
		keep := s.path + ".broken-" + time.Now().Format("20060102-150405")
		if err := os.Rename(s.path, keep); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("the unreadable %s could not be moved aside, nothing was saved: %w", filepath.Base(s.path), err)
		} else if err == nil {
			s.backup = filepath.Base(keep)
		}
		s.quarantine = false
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".variables-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(js)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0640)
	}
	if werr == nil {
		werr = os.Rename(name, s.path)
	}
	if werr != nil {
		os.Remove(name)
	}
	return werr
}

func (s *Store) changed(m map[string]Variable) error {
	if err := s.save(m); err != nil {
		return err
	}
	s.vars.Store(&m)
	for _, f := range s.onChange {
		f()
	}
	return nil
}

// Set creates or replaces a variable. With create set, an existing name is an error (so "New
// variable" never silently replaces one).
func (s *Store) Set(v Variable, create bool) (Variable, error) {
	v.Name = strings.TrimSpace(v.Name)
	v.Value = strings.TrimSpace(v.Value)
	v.Description = strings.TrimSpace(v.Description)
	if err := validate(&v); err != nil {
		return v, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := *s.vars.Load()
	_, exists := old[v.Name]
	if create && exists {
		return v, badf("a variable named %q already exists", v.Name)
	}
	if !exists && len(old) >= MaxVariables {
		return v, badf("at most %d variables", MaxVariables)
	}
	m := make(map[string]Variable, len(old)+1)
	for k, o := range old {
		m[k] = o
	}
	v.Updated = time.Now().Unix()
	m[v.Name] = v
	return v, s.changed(m)
}

// Delete removes a variable. References to it stop resolving (see the package comment).
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := *s.vars.Load()
	if _, ok := old[name]; !ok {
		return ErrNotFound
	}
	m := make(map[string]Variable, len(old))
	for k, o := range old {
		if k != name {
			m[k] = o
		}
	}
	return s.changed(m)
}
