package access

import (
	"strings"
	"sync/atomic"

	"github.com/foleyit/dunree/mod/netutils"
)

/*
	vars.go

	Variable references in the IP black / whitelist (upstream #370).

	An IP entry written {{name}} stands for the current value of that variable: the built-in
	{{external_ip}} or a variable the admin defined. The value is read on every check, so a
	change applies immediately. It may hold one or more addresses, IPv4 wildcards or CIDR
	networks separated by commas or spaces. A reference that does not resolve (variable
	deleted, public IP not known) matches nothing, which is also what such an entry did before
	this feature existed.
*/

var varResolver atomic.Pointer[func(name string) (string, bool)]

// SetVarResolver installs the source of the {{name}} entries. nil removes it.
func SetVarResolver(f func(name string) (string, bool)) {
	if f == nil {
		varResolver.Store(nil)
		return
	}
	varResolver.Store(&f)
}

// EntryVar returns the variable name when an IP list entry is exactly one {{name}} reference
func EntryVar(entry string) (string, bool) {
	if !strings.HasPrefix(entry, "{{") || !strings.HasSuffix(entry, "}}") {
		return "", false
	}
	name := strings.TrimSpace(entry[2 : len(entry)-2])
	if name == "" || len(name) > 32 {
		return "", false
	}
	for i, c := range name {
		if !(c >= 'a' && c <= 'z' || i > 0 && (c == '_' || c >= '0' && c <= '9')) {
			return "", false
		}
	}
	return name, true
}

// ResolveEntryVar returns the current value of a variable used in an IP list
func ResolveEntryVar(name string) (string, bool) {
	p := varResolver.Load()
	if p == nil {
		return "", false
	}
	v, ok := (*p)(name)
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

// matchVarEntry reports whether ipAddr is covered by the current value of the variable
func matchVarEntry(ipAddr, name string) bool {
	value, ok := ResolveEntryVar(name)
	if !ok {
		return false
	}
	return VarValueCovers(ipAddr, value)
}

// VarValueCovers reports whether ipAddr is one of the addresses, wildcards or networks a variable
// value holds (separated by commas, semicolons or spaces)
func VarValueCovers(ipAddr, value string) bool {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if part == ipAddr || netutils.MatchIpWildcard(ipAddr, part) || netutils.MatchIpCIDR(ipAddr, part) {
			return true
		}
	}
	return false
}
