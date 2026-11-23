package crowdsec

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Decision types Zoraxy acts on. Anything else is counted and logged, never enforced.
const (
	TypeBan     = "ban"
	TypeCaptcha = "captcha"
)

// Scopes Zoraxy understands (LAPI scope names are "Ip" and "Range"); any other scope is counted and ignored.
const (
	ScopeIP    = "ip"
	ScopeRange = "range"
)

// Decision is one cached decision (fields as documented for the LAPI stream, expiry already computed)
type Decision struct {
	ID       int64     `json:"id"`
	Type     string    `json:"type"`
	Scope    string    `json:"scope"`
	Value    string    `json:"value"`
	Origin   string    `json:"origin"`
	Scenario string    `json:"scenario"`
	Expires  time.Time `json:"expires"`

	gen uint64 // pull that stored it (0 = none); a delete answer of the same pull never removes it (see Delete)
}

// lowPriority: decisions of community lists. When the cache is full they make room for local decisions.
func (d Decision) lowPriority() bool {
	o := strings.ToLower(d.Origin)
	return o == "capi" || strings.HasPrefix(o, "lists")
}

func (d Decision) rank() int {
	switch d.Type {
	case TypeBan:
		return 2
	case TypeCaptcha:
		return 1
	}
	return 0
}

// Cache is a bounded decision store. Exact addresses live in a map; ranges live in a map per prefix length, so a lookup
// is one map access per prefix length that is present (typically a handful) and deletes are cheap. IPv4 and IPv6 are separate.
type Cache struct {
	mu      sync.RWMutex
	ips     map[netip.Addr][]Decision
	ranges  map[netip.Prefix][]Decision
	lens4   [33]int // how many range keys exist per prefix length
	lens6   [129]int
	n       int
	max     int
	dropped uint64
	evicted uint64
}

// NewCache makes a cache holding at most max decisions
func NewCache(max int) *Cache {
	return &Cache{ips: map[netip.Addr][]Decision{}, ranges: map[netip.Prefix][]Decision{}, max: max}
}

// Len is the number of cached decisions
func (c *Cache) Len() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.n }

// Evicted is how many community-list decisions were removed to make room for local ones
func (c *Cache) Evicted() uint64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.evicted }

// Dropped is how many decisions were refused because the cache was full
func (c *Cache) Dropped() uint64 { c.mu.RLock(); defer c.mu.RUnlock(); return c.dropped }

type addResult int

const (
	addOK addResult = iota
	addInvalid
	addIgnoredScope
	addFull
)

// parseTarget turns scope+value into an address or a prefix
func parseTarget(scope, value string) (ip netip.Addr, pfx netip.Prefix, isRange bool, res addResult) {
	value = strings.TrimSpace(value)
	switch {
	case strings.EqualFold(scope, ScopeIP):
		a, err := netip.ParseAddr(value)
		if err != nil {
			return ip, pfx, false, addInvalid
		}
		return a.WithZone("").Unmap(), pfx, false, addOK
	case strings.EqualFold(scope, ScopeRange):
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Bits() == 0 { //a /0 would match every client: never accepted
			return ip, pfx, true, addInvalid
		}
		a := p.Addr().WithZone("")
		if a.Is4In6() { //::ffff:a.b.c.d/N is the IPv4 range /(N-96)
			if p.Bits() < 96+1 {
				return ip, pfx, true, addInvalid
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		} else {
			p = netip.PrefixFrom(a, p.Bits())
		}
		return ip, p.Masked(), true, addOK
	}
	return ip, pfx, false, addIgnoredScope
}

// Add stores d (d.Expires must be set). A decision with the same key and ID replaces the old one. When the cache is
// full a local decision (cscli, a scenario) evicts one community-list decision (CAPI, lists) instead of being refused.
func (c *Cache) Add(d Decision) addResult {
	ip, pfx, isRange, res := parseTarget(d.Scope, d.Value)
	if res != addOK {
		return res
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var list []Decision
	if isRange {
		list = c.ranges[pfx]
	} else {
		list = c.ips[ip]
	}
	if i := indexOfID(list, d.ID); i >= 0 && d.ID != 0 {
		list[i] = d
		return addOK
	}
	if c.n >= c.max {
		if d.lowPriority() || !c.evictLow() {
			c.dropped++
			return addFull
		}
		if isRange { //the eviction may have changed the list
			list = c.ranges[pfx]
		} else {
			list = c.ips[ip]
		}
	}
	if isRange {
		_, exists := c.ranges[pfx]
		c.ranges[pfx] = append(list, d)
		if !exists {
			c.bump(pfx, 1)
		}
	} else {
		c.ips[ip] = append(list, d)
	}
	c.n++
	return addOK
}

// evictLow removes one community-list decision (looking at a bounded number of entries). Caller holds the write lock.
func (c *Cache) evictLow() bool {
	seen := 0
	for k, list := range c.ips {
		for i := range list {
			if list[i].lowPriority() {
				c.removeAt(k, netip.Prefix{}, false, i)
				return true
			}
		}
		if seen++; seen > 256 {
			break
		}
	}
	seen = 0
	for k, list := range c.ranges {
		for i := range list {
			if list[i].lowPriority() {
				c.removeAt(netip.Addr{}, k, true, i)
				return true
			}
		}
		if seen++; seen > 256 {
			break
		}
	}
	return false
}

func (c *Cache) removeAt(ip netip.Addr, pfx netip.Prefix, isRange bool, i int) {
	if isRange {
		list := c.ranges[pfx]
		list = append(list[:i], list[i+1:]...)
		if len(list) == 0 {
			delete(c.ranges, pfx)
			c.bump(pfx, -1)
		} else {
			c.ranges[pfx] = list
		}
	} else {
		list := c.ips[ip]
		list = append(list[:i], list[i+1:]...)
		if len(list) == 0 {
			delete(c.ips, ip)
		} else {
			c.ips[ip] = list
		}
	}
	c.n--
	c.evicted++
}

func indexOfID(list []Decision, id int64) int {
	for i := range list {
		if list[i].ID == id {
			return i
		}
	}
	return -1
}

func (c *Cache) bump(p netip.Prefix, by int) {
	if p.Addr().Is4() {
		c.lens4[p.Bits()] += by
	} else {
		c.lens6[p.Bits()] += by
	}
}

// Delete removes the decisions of the target that match typ and, when id is not 0, the id. Returns how many were removed.
func (c *Cache) Delete(scope, value, typ string, id int64) int {
	return c.DeleteSparing(scope, value, typ, id, 0)
}

// DeleteSparing is Delete that leaves decisions stored by pull spare (not 0) alone. A LAPI answer may list "new"
// before "deleted" and a deleted entry may lack its id: it must not remove the replacement that came in the same answer.
func (c *Cache) DeleteSparing(scope, value, typ string, id int64, spare uint64) int {
	ip, pfx, isRange, res := parseTarget(scope, value)
	if res != addOK {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := func(d Decision) bool {
		if spare != 0 && d.gen == spare {
			return true
		}
		if id != 0 && d.ID != id {
			return true
		}
		return typ != "" && !strings.EqualFold(d.Type, typ)
	}
	removed := 0
	if isRange {
		list := c.ranges[pfx]
		out := list[:0]
		for _, d := range list {
			if keep(d) {
				out = append(out, d)
			} else {
				removed++
			}
		}
		if len(out) == 0 {
			if _, ok := c.ranges[pfx]; ok {
				delete(c.ranges, pfx)
				c.bump(pfx, -1)
			}
		} else {
			c.ranges[pfx] = out
		}
	} else {
		list := c.ips[ip]
		out := list[:0]
		for _, d := range list {
			if keep(d) {
				out = append(out, d)
			} else {
				removed++
			}
		}
		if len(out) == 0 {
			delete(c.ips, ip)
		} else {
			c.ips[ip] = out
		}
	}
	c.n -= removed
	return removed
}

// Lookup returns the strongest unexpired decision for ip (ban before captcha before others), or false
func (c *Cache) Lookup(ip netip.Addr, now time.Time) (Decision, bool) {
	ip = ip.WithZone("").Unmap()
	c.mu.RLock()
	defer c.mu.RUnlock()
	var best Decision
	found := false
	consider := func(list []Decision) {
		for _, d := range list {
			if !d.Expires.After(now) {
				continue
			}
			if !found || d.rank() > best.rank() {
				best, found = d, true
			}
		}
	}
	consider(c.ips[ip])
	if len(c.ranges) == 0 {
		return best, found
	}
	lens := c.lens6[:]
	if ip.Is4() {
		lens = c.lens4[:]
	}
	for bits, cnt := range lens {
		if cnt == 0 {
			continue
		}
		p, err := ip.Prefix(bits)
		if err != nil {
			continue
		}
		consider(c.ranges[p])
	}
	return best, found
}

// Sweep removes expired decisions and returns how many
func (c *Cache) Sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	prune := func(list []Decision) []Decision {
		out := list[:0]
		for _, d := range list {
			if d.Expires.After(now) {
				out = append(out, d)
			} else {
				removed++
			}
		}
		return out
	}
	for k, list := range c.ips {
		if out := prune(list); len(out) == 0 {
			delete(c.ips, k)
		} else {
			c.ips[k] = out
		}
	}
	for k, list := range c.ranges {
		if out := prune(list); len(out) == 0 {
			delete(c.ranges, k)
			c.bump(k, -1)
		} else {
			c.ranges[k] = out
		}
	}
	c.n -= removed
	return removed
}

// each calls fn for every unexpired decision that applies to ip (the exact address and every range containing it)
func (c *Cache) each(ip netip.Addr, now time.Time, fn func(Decision)) {
	ip = ip.WithZone("").Unmap()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, d := range c.ips[ip] {
		if d.Expires.After(now) {
			fn(d)
		}
	}
	if len(c.ranges) == 0 {
		return
	}
	lens := c.lens6[:]
	if ip.Is4() {
		lens = c.lens4[:]
	}
	for bits, cnt := range lens {
		if cnt == 0 {
			continue
		}
		p, err := ip.Prefix(bits)
		if err != nil {
			continue
		}
		for _, d := range c.ranges[p] {
			if d.Expires.After(now) {
				fn(d)
			}
		}
	}
}

// LookupAll returns every unexpired decision that applies to ip: exact matches first, then ranges from the widest to
// the narrowest. Lookup returns only the strongest of them.
func (c *Cache) LookupAll(ip netip.Addr, now time.Time) []Decision {
	var out []Decision
	c.each(ip, now, func(d Decision) { out = append(out, d) })
	return out
}

// NameCount is one line of a breakdown
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Composition says what the cache holds: where the decisions come from and what they are
type Composition struct {
	Total     int            `json:"total"`
	IPs       int            `json:"ips"`
	Ranges    int            `json:"ranges"`
	ByClass   map[string]int `json:"byClass"`  // origin class (crowdsec, cscli, capi, lists, other)
	ByOrigin  []NameCount    `json:"byOrigin"` // origin as the LAPI sent it; at most 16 names, the rest is "other"
	ByType    map[string]int `json:"byType"`
	Scenarios []NameCount    `json:"scenarios"` // the 10 most frequent
	// every distinct scenario name loaded (at most 256, the rest is "other"), most frequent first: lets the settings
	// page show how many loaded decisions a "scenario kept on log only" entry reaches
	AllScenarios []NameCount `json:"allScenarios"`
	At           time.Time   `json:"at"`
}

const (
	compOrigins   = 16
	compScenarios = 256
	compTopN      = 10
)

func topCounts(m map[string]int, n int) []NameCount {
	out := make([]NameCount, 0, len(m))
	for k, v := range m {
		out = append(out, NameCount{k, v})
	}
	sortNameCounts(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func sortNameCounts(l []NameCount) {
	sort.Slice(l, func(a, b int) bool {
		if l[a].Count != l[b].Count {
			return l[a].Count > l[b].Count
		}
		return l[a].Name < l[b].Name
	})
}

// ScenarioReach says how many of the loaded decisions (and how many distinct scenario names) a "scenario kept on log
// only" entry matches: the same test as the request path (the scenario contains the entry, upper or lower case).
// Decisions counted under "other" (more than 256 distinct names loaded) cannot be told apart and are not included.
func (c Composition) ScenarioReach(entry string) (decisions, names int) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" {
		return 0, 0
	}
	for _, sc := range c.AllScenarios {
		if sc.Name == "other" || sc.Name == "(none)" {
			continue
		}
		if strings.Contains(strings.ToLower(sc.Name), entry) {
			decisions += sc.Count
			names++
		}
	}
	return decisions, names
}

// Composition walks the cache once (expired entries are skipped)
func (c *Cache) Composition(now time.Time) Composition {
	out := Composition{ByClass: map[string]int{}, ByType: map[string]int{}, At: now}
	origins, scen := map[string]int{}, map[string]int{}
	bump := func(m map[string]int, k string, max int) {
		if k == "" {
			k = "(none)"
		}
		if _, ok := m[k]; !ok && len(m) >= max {
			k = "other"
		}
		m[k]++
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	add := func(d Decision, isRange bool) {
		if !d.Expires.After(now) {
			return
		}
		out.Total++
		if isRange {
			out.Ranges++
		} else {
			out.IPs++
		}
		out.ByClass[OriginClass(d.Origin)]++
		out.ByType[d.Type]++
		bump(origins, strings.ToLower(d.Origin), compOrigins)
		bump(scen, d.Scenario, compScenarios)
	}
	for _, l := range c.ips {
		for _, d := range l {
			add(d, false)
		}
	}
	for _, l := range c.ranges {
		for _, d := range l {
			add(d, true)
		}
	}
	out.ByOrigin = topCounts(origins, compOrigins+1)
	out.AllScenarios = topCounts(scen, compScenarios+1)
	out.Scenarios = out.AllScenarios
	if len(out.Scenarios) > compTopN {
		out.Scenarios = out.Scenarios[:compTopN:compTopN]
	}
	return out
}
