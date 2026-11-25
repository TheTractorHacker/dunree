package dynamicproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/TheTractorHacker/dunree/mod/abuse"
	"github.com/TheTractorHacker/dunree/mod/pathmatch"
)

/*
	headerrules.go

	Header based access rules per proxy endpoint (upstream #1356): "require header X
	with value V (or matching a pattern), otherwise deny / drop / answer 404". They
	complement path rules and are evaluated right after them. Opt-in: an endpoint
	without HeaderRules behaves exactly as before.

	All rules of an endpoint must be satisfied (AND). A rule is satisfied when any of its
	alternative Values matches (OR), which allows rotating secrets: add the new value, deploy,
	remove the old one.

	Security notes
	  - "equals" compares SHA-256 digests with subtle.ConstantTimeCompare and always checks
	    every alternative, so neither the length nor a common prefix of a secret leaks through timing.
	  - Header values are never logged, only the rule number and the header name.
	  - "regex" uses RE2 (linear time) on a value capped at 4 KiB and is matched in full.
	  - A rule can be limited to a path prefix; the scope is matched with the same path
	    confusion hardening as path rules (encoded dots / slashes, ;params, ...).
	  - The Host header is not a valid rule target (it is part of routing).

	Options added for the rest of #1356, all off by default (a stored configuration without them
	behaves exactly as before):
	  - ProxyEndpoint.HeaderRulesMode "any": one passing rule is enough (OR across rules / headers).
	    Rules outside their path scope do not count; when no rule applies to the path the request passes.
	    When no rule passes, the action of the first rule that applies is used.
	  - HeaderRule.Negate turns the condition around: "present" + Negate = the header must be absent,
	    "equals" / "regex" + Negate = the header must not carry one of the values (an absent header passes).
	  - HeaderRule.StatusCode replaces the 403 of the "deny" action (400-499 or 503).
	  - HeaderRule.Strip removes the header from the request before it is forwarded, so a shared secret
	    does not reach the backend. It applies to every request that passes and is in the rule's path scope.
	  - ProxyEndpoint.HeaderRulesExcept: client addresses / CIDRs that skip the check. The address is the
	    one the endpoint's access rule sees (proxy headers only count when that access rule trusts them).
	    Strip still applies to excepted clients. A list that matches every IPv4 or every IPv6 address, in one
	    entry or in several, is refused.
*/

const (
	HeaderMatchEquals  = "equals"
	HeaderMatchRegex   = "regex"
	HeaderMatchPresent = "present"

	HeaderActionDeny     = "deny"     //403 (default)
	HeaderActionDrop     = "drop"     //close the connection without a response
	HeaderActionNotFound = "notfound" //404, hides that the resource exists

	maxHeaderRules     = 50
	maxHeaderValues    = 20
	maxHeaderValueLen  = 512
	maxHeaderRegexLen  = 200
	maxPresentedValue  = 4096
	maxPresentedValues = 8
	maxHeaderExcept    = 200

	HeaderRulesModeAll = "all" //every rule must pass (default, also "")
	HeaderRulesModeAny = "any" //one passing rule is enough
)

// HeaderRule is one entry of ProxyEndpoint.HeaderRules
type HeaderRule struct {
	Name       string   //Header name
	Match      string   //equals (default), regex, present
	Values     []string //Alternatives (equals: exact secrets, regex: patterns); unused for present
	PathPrefix string   //Optional: only requests below this path are checked
	Action     string   //deny (default), drop, notfound
	Comment    string   //Free text
	Negate     bool     `json:",omitempty"` //Turn the condition around (present: the header must be absent)
	StatusCode int      `json:",omitempty"` //Action deny only: answer this status instead of 403 (400-499 or 503)
	Strip      bool     `json:",omitempty"` //Remove the header before the request is forwarded
}

type compiledHeaderRule struct {
	HeaderRule
	canon  string
	hashes [][sha256.Size]byte
	res    []*regexp.Regexp
	scope  *compiledPathRule
}

var headerNameRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")

func compileHeaderRule(r *HeaderRule) (*compiledHeaderRule, error) {
	if r == nil {
		return nil, errors.New("empty rule")
	}
	c := &compiledHeaderRule{HeaderRule: *r}
	if !headerNameRe.MatchString(r.Name) {
		return nil, errors.New("invalid header name")
	}
	c.canon = http.CanonicalHeaderKey(r.Name)
	if strings.EqualFold(c.canon, "Host") {
		return nil, errors.New("the Host header cannot be used")
	}
	switch c.Match {
	case "":
		c.Match = HeaderMatchEquals
	case HeaderMatchEquals, HeaderMatchRegex, HeaderMatchPresent:
	default:
		return nil, errors.New("match must be equals, regex or present")
	}
	switch c.Action {
	case "":
		c.Action = HeaderActionDeny
	case HeaderActionDeny, HeaderActionDrop, HeaderActionNotFound:
	default:
		return nil, errors.New("action must be deny, drop or notfound")
	}
	if c.StatusCode != 0 {
		if c.Action != HeaderActionDeny {
			return nil, errors.New("a status code can only be set for the deny action")
		}
		if !(c.StatusCode >= 400 && c.StatusCode <= 499) && c.StatusCode != http.StatusServiceUnavailable {
			return nil, errors.New("status code must be 400-499 or 503")
		}
	}
	if len(r.Values) > maxHeaderValues {
		return nil, fmt.Errorf("too many values (max %d)", maxHeaderValues)
	}
	switch c.Match {
	case HeaderMatchEquals:
		if len(r.Values) == 0 {
			return nil, errors.New("at least one value is required")
		}
		for _, v := range r.Values {
			if v == "" || len(v) > maxHeaderValueLen {
				return nil, errors.New("values must be 1-512 characters")
			}
			c.hashes = append(c.hashes, sha256.Sum256([]byte(v)))
		}
	case HeaderMatchRegex:
		if len(r.Values) == 0 {
			return nil, errors.New("at least one pattern is required")
		}
		for _, v := range r.Values {
			if v == "" || len(v) > maxHeaderRegexLen {
				return nil, errors.New("patterns must be 1-200 characters")
			}
			re, err := regexp.Compile("^(?:" + v + ")$")
			if err != nil {
				return nil, fmt.Errorf("invalid regular expression: %v", err)
			}
			c.res = append(c.res, re)
		}
	}
	if p := strings.TrimSpace(r.PathPrefix); p != "" && p != "/" {
		s, err := compilePathRule(&PathRule{MatchMode: PathRuleMatchPrefix, Pattern: p, Action: PathRuleDeny})
		if err != nil {
			return nil, err
		}
		c.scope = s
	}
	return c, nil
}

// ValidateHeaderRuleSet checks the rules together with the rule set options (mode, exceptions) before they are stored
func ValidateHeaderRuleSet(rules []*HeaderRule, mode string, except []string) error {
	if err := ValidateHeaderRules(rules); err != nil {
		return err
	}
	if _, err := parseHeaderRulesMode(mode); err != nil {
		return err
	}
	_, err := parseHeaderExcept(except)
	return err
}

func parseHeaderRulesMode(mode string) (any bool, err error) {
	switch mode {
	case "", HeaderRulesModeAll:
		return false, nil
	case HeaderRulesModeAny:
		return true, nil
	}
	return false, errors.New("mode must be all or any")
}

func parseHeaderExcept(entries []string) ([]netip.Prefix, error) {
	if len(entries) > maxHeaderExcept {
		return nil, fmt.Errorf("too many exceptions (max %d)", maxHeaderExcept)
	}
	set, err := parsePeerSet(entries) //address or CIDR, refuses "every address"
	if err != nil {
		return nil, fmt.Errorf("exception: %w", err)
	}
	//"every address" in pieces (0.0.0.0/1 plus 128.0.0.0/1) would switch the check off just the same
	for _, all := range []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)} {
		if prefixesCover(set, all) {
			return nil, fmt.Errorf("exception: the entries together match every %s address, remove the rules instead", map[bool]string{true: "IPv4", false: "IPv6"}[all.Addr().Is4()])
		}
	}
	return set, nil
}

// prefixesCover reports whether the prefixes of set together contain every address of p
func prefixesCover(set []netip.Prefix, p netip.Prefix) bool {
	inside := make([]netip.Prefix, 0, len(set))
	for _, s := range set {
		if s.Addr().BitLen() != p.Addr().BitLen() {
			continue
		}
		if s.Bits() <= p.Bits() {
			if s.Contains(p.Addr()) {
				return true
			}
			continue
		}
		if p.Contains(s.Addr()) {
			inside = append(inside, s)
		}
	}
	if len(inside) < 2 || p.Bits() >= p.Addr().BitLen() {
		return false
	}
	//both halves of p must be covered; only entries inside p are passed down, so the work is bounded by them
	lo, err := p.Addr().Prefix(p.Bits() + 1)
	if err != nil {
		return false
	}
	b := lo.Addr().AsSlice()
	b[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	hiAddr, _ := netip.AddrFromSlice(b)
	return prefixesCover(inside, lo) && prefixesCover(inside, netip.PrefixFrom(hiAddr, p.Bits()+1))
}

// ValidateHeaderRules checks a list before it is stored
func ValidateHeaderRules(rules []*HeaderRule) error {
	if len(rules) > maxHeaderRules {
		return fmt.Errorf("too many rules (max %d)", maxHeaderRules)
	}
	for i, r := range rules {
		if _, err := compileHeaderRule(r); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

func (pe *ProxyEndpoint) initHeaderRules() {
	pe.headerRules, pe.headerRulesErr = nil, nil
	pe.headerRulesAny, pe.headerExcept = false, nil
	if len(pe.HeaderRules) == 0 {
		return
	}
	if len(pe.HeaderRules) > maxHeaderRules {
		pe.headerRulesErr = errors.New("too many header rules")
		return
	}
	//An unreadable mode or exception list refuses requests like an invalid rule does (never fails open)
	anyMode, err := parseHeaderRulesMode(pe.HeaderRulesMode)
	if err != nil {
		pe.headerRulesErr = fmt.Errorf("header rules: %w", err)
		return
	}
	except, err := parseHeaderExcept(pe.HeaderRulesExcept)
	if err != nil {
		pe.headerRulesErr = fmt.Errorf("header rules: %w", err)
		return
	}
	pe.headerRulesAny, pe.headerExcept = anyMode, except
	for i, r := range pe.HeaderRules {
		c, err := compileHeaderRule(r)
		if err != nil {
			pe.headerRulesErr = fmt.Errorf("header rule %d: %w", i+1, err)
			pe.headerRules = nil
			return
		}
		pe.headerRules = append(pe.headerRules, c)
	}
}

// satisfied reports whether the request passes the rule (the condition, turned around with Negate)
func (c *compiledHeaderRule) satisfied(h http.Header) bool {
	return c.matches(h) != c.Negate
}

// matches reports whether the request carries an acceptable header value
func (c *compiledHeaderRule) matches(h http.Header) bool {
	vals := h.Values(c.canon)
	if len(vals) > maxPresentedValues {
		vals = vals[:maxPresentedValues]
	}
	switch c.Match {
	case HeaderMatchPresent:
		for _, v := range vals {
			if v != "" {
				return true
			}
		}
		return false
	case HeaderMatchRegex:
		for _, v := range vals {
			if len(v) > maxPresentedValue {
				continue
			}
			for _, re := range c.res {
				if re.MatchString(v) {
					return true
				}
			}
		}
		return false
	}
	//equals: constant time, no early exit over values or alternatives
	ok := 0
	for _, v := range vals {
		if len(v) > maxPresentedValue {
			continue
		}
		d := sha256.Sum256([]byte(v))
		for i := range c.hashes {
			ok |= subtle.ConstantTimeCompare(d[:], c.hashes[i][:])
		}
	}
	return ok == 1
}

// handleHeaderRules enforces the endpoint's header rules. Returns true when the request was answered.
func (h *ProxyHandler) handleHeaderRules(w http.ResponseWriter, r *http.Request, sep *ProxyEndpoint) bool {
	if sep.headerRulesErr != nil {
		h.Parent.Option.Logger.PrintAndLog("proxy-headerrule", "Header rules of "+sep.RootOrMatchingDomain+" are invalid, refusing requests", sep.headerRulesErr)
		http.Error(w, "503 - Header rules misconfigured", http.StatusServiceUnavailable)
		return true
	}
	if len(sep.headerRules) == 0 {
		return false
	}
	//Rules that apply to this path
	var target string
	inScope := make([]int, 0, len(sep.headerRules))
	for i, rule := range sep.headerRules {
		if rule.scope != nil {
			if target == "" {
				target = pathmatch.RequestTarget(r)
			}
			if !rule.scope.matchesRequest(target, r.Method) {
				continue
			}
		}
		inScope = append(inScope, i)
	}
	if len(inScope) == 0 {
		return false
	}
	failed := -1
	if !h.headerRulesExcepted(r, sep) {
		//Every rule is evaluated (no early exit), so the answer time does not tell which rule failed
		passed := 0
		for _, i := range inScope {
			if sep.headerRules[i].satisfied(r.Header) {
				passed++
			} else if failed < 0 {
				failed = i
			}
		}
		if sep.headerRulesAny && passed > 0 {
			failed = -1
		}
	}
	if failed < 0 {
		//Passed: the headers marked "strip" do not travel to the backend
		for _, i := range inScope {
			if sep.headerRules[i].Strip {
				r.Header.Del(sep.headerRules[i].canon)
			}
		}
		return false
	}
	rule := sep.headerRules[failed]
	//Log the rule, never the presented value
	reason := fmt.Sprintf("header-rule-%d-%s", failed+1, rule.canon)
	switch {
	case rule.Action == HeaderActionDrop:
		h.Parent.logRequest(r, false, 444, reason+"-dropped", r.Host, "", sep)
		abuseNoteKind(r, abuse.KindForbidden)
		dropConnection(w)
	case rule.Action == HeaderActionNotFound || rule.StatusCode == http.StatusNotFound:
		h.Parent.logRequest(r, false, 404, reason, r.Host, "", sep)
		serveProxyRequestError(w, r, http.StatusNotFound, h.Parent, ErrorTemplateHostError)
	case rule.StatusCode != 0 && rule.StatusCode != http.StatusForbidden:
		//Own status code: a plain text answer, the block page says "403 Forbidden" and would contradict it
		h.Parent.logRequest(r, false, rule.StatusCode, reason, r.Host, "", sep)
		http.Error(w, fmt.Sprintf("%d %s", rule.StatusCode, http.StatusText(rule.StatusCode)), rule.StatusCode)
	default:
		h.Parent.logRequest(r, false, 403, reason, r.Host, "", sep)
		serveProxyRequestError(w, r, http.StatusForbidden, h.Parent, ErrorTemplateForbidden)
	}
	return true
}

// headerRulesExcepted reports whether the client address is on the endpoint's exception list
func (h *ProxyHandler) headerRulesExcepted(r *http.Request, sep *ProxyEndpoint) bool {
	if len(sep.headerExcept) == 0 {
		return false
	}
	a, err := netip.ParseAddr(h.Parent.GetClientIPForEndpoint(r, sep))
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	for _, p := range sep.headerExcept {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// MaskHeaderRuleSecrets blanks the secret values of "equals" rules. Call it on a COPY of the
// endpoint (CopyEndpoint) before the endpoint is serialised for the admin API.
func (pe *ProxyEndpoint) MaskHeaderRuleSecrets() {
	for i, hr := range pe.HeaderRules {
		if hr == nil || (hr.Match != "" && hr.Match != HeaderMatchEquals) {
			continue
		}
		c := *hr
		c.Values = make([]string, len(hr.Values))
		pe.HeaderRules[i] = &c
	}
}
