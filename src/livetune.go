package main

import (
	"encoding/json"
	"math"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/foleyit/dunree/mod/dynamicproxy"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	livetune.go

	GET /api/stats/livetune?window=10s|1m|5m|1h: the numbers behind the "Tune" panel of the Status page's
	Traffic map: per proxy rule (and in total) the average, peak and current requests per second over a
	window, and, for rules with a host level rate limit, the busiest client against the limit.

	ONE goroutine wakes every 5 seconds and reads counters that already exist (the per host daily counters
	of the statistic collector and the request counters of the rate limiter buckets). The request path is not
	touched: the rate limiter bumps two integers while it already holds the bucket lock.

	Memory bound (nothing is persisted, a restart starts empty):
	  - a ring of 720 five second slots (1 hour) per rule and one for the total: 720 x 8 bytes = 5.6 KiB
	  - rules tracked: at most 200 (the rest is reported as untracked)  -> 200 x 5.6 KiB = 1.1 MiB
	  - rules with a rate limit also keep a denied ring (5.6 KiB) and a busiest client ring (720 x 24 bytes = 17 KiB)
	  - clients tracked for the busiest client numbers: at most 5000 in total (about 0.5 MiB)
	  Total at most about 7 MiB (200 rules, all with a limit), usually a few hundred KiB.

	What is NOT measured: per client rates of rules without a rate limit (the proxy keeps no per client
	counter then and none is added), clients of path or ruleset rate limits (only the host level limit is read),
	and a client whose bucket was swept (idle) between two samples loses the requests of that short gap.
	Peaks have five second resolution: a burst shorter than 5 s is averaged over its slot.
*/

const (
	tuneSlotSec    = 5
	tuneSlots      = 720 // one hour
	tuneMaxRules   = 200
	tuneMaxClients = 5000
)

// slotRing is a fixed ring of per slot counts; slot ids only ever grow, so an entry from an older lap is told apart by its id
type slotRing struct {
	id  [tuneSlots]uint32
	val [tuneSlots]uint32
}

func (r *slotRing) add(slot uint32, n uint64) {
	i := slot % tuneSlots
	if r.id[i] != slot {
		r.id[i], r.val[i] = slot, 0
	}
	if s := uint64(r.val[i]) + n; s > math.MaxUint32 {
		r.val[i] = math.MaxUint32
	} else {
		r.val[i] = uint32(s)
	}
}

func (r *slotRing) at(slot uint32) uint32 {
	i := slot % tuneSlots
	if r.id[i] == slot {
		return r.val[i]
	}
	return 0
}

// windowStats is the sum, the busiest slot and the covered number of slots over the n slots ending at newest.
// first is the first slot the series existed in: slots before it are not history (they are not counted as idle).
func (r *slotRing) windowStats(newest, first uint32, n int) (sum uint64, peak uint32, peakSlot uint32, covered int) {
	if n > tuneSlots {
		n = tuneSlots
	}
	for k := 0; k < n; k++ {
		if uint32(k) > newest || newest-uint32(k) < first {
			break
		}
		s := newest - uint32(k)
		covered++
		v := r.at(s)
		sum += uint64(v)
		if v > peak {
			peak, peakSlot = v, s
		}
	}
	return
}

// TuneStats is the answer for one rule or for the total
type TuneStats struct {
	Avg     float64 `json:"avg"`     // requests per second over the covered part of the window
	Peak    float64 `json:"peak"`    // busiest 5 s slot, as requests per second
	PeakAt  int64   `json:"peakAt"`  // unix seconds of that slot, 0 when nothing happened
	Current float64 `json:"current"` // the last 10 s
	Covered int     `json:"coveredSeconds"`
}

func (r *slotRing) stats(newest, first uint32, n int, startUnix int64) TuneStats {
	sum, peak, peakSlot, covered := r.windowStats(newest, first, n)
	out := TuneStats{Covered: covered * tuneSlotSec}
	if covered > 0 {
		out.Avg = float64(sum) / float64(covered*tuneSlotSec)
	}
	out.Peak = float64(peak) / tuneSlotSec
	if peak > 0 {
		out.PeakAt = startUnix + int64(peakSlot-1)*tuneSlotSec
	}
	c, _, _, cc := r.windowStats(newest, first, 2)
	if cc > 0 {
		out.Current = float64(c) / float64(cc*tuneSlotSec)
	}
	return out
}

// ruleSeries is the history of one rule
type ruleSeries struct {
	first uint32
	prev  int64
	have  bool
	reqs  slotRing

	limited bool
	lim     *limSeries // allocated while a rate limit is enabled on the rule
}

// limSeries is the extra history of a rule with a host level rate limit
type limSeries struct {
	rate    int64 // configured limit, requests per second per client
	burst   int64
	dryRun  bool
	denied  slotRing
	busyCnt slotRing
	busyIP  [tuneSlots][16]byte
	busyLen [tuneSlots]uint8
}

// tuneLimiter is what the sampler learns about a rule with a rate limit
type tuneLimiter struct {
	Rate, Burst int64
	DryRun      bool                 // the limit only counts, nothing is rejected
	Clients     map[string][2]uint64 // client ip -> lifetime (allowed, denied) of its bucket
}

// tuneInput is one reading
type tuneInput struct {
	Total    int64
	Rules    map[string]int64 // rule -> today's request counter
	Limiters map[string]tuneLimiter
}

type tuneStore struct {
	mu        sync.Mutex
	startUnix int64
	started   bool
	lastTick  time.Time
	slot      uint32 // slot of the latest tick; slot 0 is never used
	total     ruleSeries
	rules     map[string]*ruleSeries
	clients   map[string][2]uint64 // "rule|ip" -> counters at the previous tick
}

func newTuneStore() *tuneStore {
	return &tuneStore{rules: map[string]*ruleSeries{}, clients: map[string][2]uint64{}}
}

// delta of a cumulative counter: a counter that went down (midnight, reset) is no traffic, never a spike
func counterDelta(cur int64, prev int64, have bool) int64 {
	if !have || cur < prev {
		return 0
	}
	return cur - prev
}

// tick records one reading taken at now
func (st *tuneStore) tick(now time.Time, in tuneInput) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.started {
		st.started, st.startUnix, st.slot = true, now.Unix(), 1
	} else {
		// one slot per tick; after a stall (suspend, overload) the gap is skipped as idle slots
		gap := int(math.Round(now.Sub(st.lastTick).Seconds() / tuneSlotSec))
		if gap < 1 {
			gap = 1
		}
		if gap > tuneSlots {
			gap = tuneSlots
		}
		st.slot += uint32(gap)
	}
	st.lastTick = now
	slot := st.slot

	if st.total.first == 0 {
		st.total.first = slot
	}
	st.total.reqs.add(slot, uint64(counterDelta(in.Total, st.total.prev, st.total.have)))
	st.total.prev, st.total.have = in.Total, true

	for name := range st.rules {
		if _, ok := in.Rules[name]; !ok {
			delete(st.rules, name)
		}
	}
	for name, cur := range in.Rules {
		rs := st.rules[name]
		if rs == nil {
			if len(st.rules) >= tuneMaxRules {
				continue
			}
			rs = &ruleSeries{first: slot}
			st.rules[name] = rs
		}
		rs.reqs.add(slot, uint64(counterDelta(cur, rs.prev, rs.have)))
		rs.prev, rs.have = cur, true

		lim, ok := in.Limiters[name]
		rs.limited = ok
		if !ok {
			rs.lim = nil
			continue
		}
		if rs.lim == nil {
			rs.lim = &limSeries{}
		}
		ls := rs.lim
		ls.rate, ls.burst, ls.dryRun = lim.Rate, lim.Burst, lim.DryRun
		var deniedSum, busiest uint64
		var busiestIP string
		for ip, c := range lim.Clients {
			key := name + "|" + ip
			prev, known := st.clients[key]
			if !known && len(st.clients) >= tuneMaxClients {
				continue
			}
			st.clients[key] = c
			if !known {
				continue // first sight: no baseline, no rate
			}
			var dReq, dDen uint64
			if c[0]+c[1] >= prev[0]+prev[1] && c[1] >= prev[1] {
				dReq, dDen = c[0]+c[1]-prev[0]-prev[1], c[1]-prev[1]
			} else {
				dReq, dDen = c[0]+c[1], c[1] // the bucket was swept and started again
			}
			deniedSum += dDen
			if dReq > busiest {
				busiest, busiestIP = dReq, ip
			}
		}
		ls.denied.add(slot, deniedSum)
		if busiest > 0 {
			i := slot % tuneSlots
			ls.busyCnt.add(slot, 0)
			if uint64(ls.busyCnt.val[i]) < busiest {
				ls.busyCnt.val[i] = uint32(busiest)
				if ip := net.ParseIP(busiestIP); ip != nil {
					copy(ls.busyIP[i][:], ip.To16())
					ls.busyLen[i] = 16
				} else {
					ls.busyLen[i] = 0
				}
			}
		}
	}
	// forget clients that are gone
	for key := range st.clients {
		i := 0
		for i < len(key) && key[i] != '|' {
			i++
		}
		name, ip := key[:i], key[i+1:]
		if lim, ok := in.Limiters[name]; !ok {
			delete(st.clients, key)
		} else if _, ok := lim.Clients[ip]; !ok {
			delete(st.clients, key)
		}
	}
}

// TuneClient is the busiest client of a rule in the window
type TuneClient struct {
	IP        string  `json:"ip"`
	Rps       float64 `json:"rps"` // requests per second in its busiest 5 s slot
	At        int64   `json:"at"`
	PerMinute float64 `json:"perMinute"`
}

// TuneLimiter is the rate limit view of a rule
type TuneLimiter struct {
	Enabled bool        `json:"enabled"`
	Rate    int64       `json:"rate"`             // requests per second per client
	Burst   int64       `json:"burst"`            // 0 = same as rate
	DryRun  bool        `json:"dryRun,omitempty"` // dry run: "denied" counts requests that would have been rejected, none was
	Denied  uint64      `json:"denied"`
	Busiest *TuneClient `json:"busiest,omitempty"`
	Hint    float64     `json:"suggestedRate,omitempty"` // a hint only, never applied
}

type TuneRule struct {
	Domain  string      `json:"domain"`
	Stats   TuneStats   `json:"stats"`
	Limiter TuneLimiter `json:"limiter"`
}

type TuneResult struct {
	Window  string      `json:"window"`
	Now     int64       `json:"now"`
	Stale   bool        `json:"stale"` // the sampler has not ticked for a while
	Started int64       `json:"started"`
	Total   TuneStats   `json:"total"`
	Rules   []*TuneRule `json:"rules"`
}

func tuneWindowSlots(w string) (string, int) {
	switch w {
	case "1m":
		return "1m", 12
	case "5m":
		return "5m", 60
	case "1h":
		return "1h", 720
	}
	return "10s", 2
}

// query answers for the window ending at the latest tick
func (st *tuneStore) query(now time.Time, window string) TuneResult {
	st.mu.Lock()
	defer st.mu.Unlock()
	wname, n := tuneWindowSlots(window)
	res := TuneResult{Window: wname, Now: now.Unix(), Rules: []*TuneRule{}}
	if !st.started {
		res.Stale = true
		return res
	}
	res.Started = st.startUnix
	res.Stale = now.Sub(st.lastTick) > 3*tuneSlotSec*time.Second
	newest := st.slot
	res.Total = st.total.reqs.stats(newest, st.total.first, n, st.startUnix)
	for name, rs := range st.rules {
		tr := &TuneRule{Domain: name, Stats: rs.reqs.stats(newest, rs.first, n, st.startUnix)}
		if rs.limited && rs.lim != nil {
			ls := rs.lim
			tr.Limiter = TuneLimiter{Enabled: true, Rate: ls.rate, Burst: ls.burst, DryRun: ls.dryRun}
			dsum, _, _, _ := ls.denied.windowStats(newest, rs.first, n)
			tr.Limiter.Denied = dsum
			_, peak, peakSlot, _ := ls.busyCnt.windowStats(newest, rs.first, n)
			if peak > 0 {
				i := peakSlot % tuneSlots
				c := &TuneClient{Rps: float64(peak) / tuneSlotSec, At: st.startUnix + int64(peakSlot-1)*tuneSlotSec}
				c.PerMinute = c.Rps * 60
				if ls.busyLen[i] == 16 {
					c.IP = net.IP(ls.busyIP[i][:]).String()
				}
				tr.Limiter.Busiest = c
				// a hint: twice the busiest client's 5 s rate, never below 1 req/s
				tr.Limiter.Hint = math.Max(1, math.Ceil(c.Rps*2))
			}
		}
		res.Rules = append(res.Rules, tr)
	}
	sort.Slice(res.Rules, func(a, b int) bool {
		if res.Rules[a].Stats.Peak != res.Rules[b].Stats.Peak {
			return res.Rules[a].Stats.Peak > res.Rules[b].Stats.Peak
		}
		return res.Rules[a].Domain < res.Rules[b].Domain
	})
	return res
}

var (
	liveTune     = newTuneStore()
	liveTuneStop chan struct{}
	liveTuneMu   sync.Mutex
)

// sampleTuneInput reads the existing counters (shared with the live map) and the rate limiter's client counters
func sampleTuneInput(now time.Time) tuneInput {
	s, _ := readLiveCounters(now)
	in := tuneInput{Total: s.total, Rules: map[string]int64{}, Limiters: map[string]tuneLimiter{}}
	if dynamicProxyRouter == nil {
		return in
	}
	limited := map[string]bool{}
	dynamicProxyRouter.ProxyEndpoints.Range(func(_, value interface{}) bool {
		ep := value.(*dynamicproxy.ProxyEndpoint)
		in.Rules[ep.RootOrMatchingDomain] = s.down[ep.RootOrMatchingDomain]
		if ep.RequireRateLimit && ep.RateLimit > 0 {
			limited[ep.RootOrMatchingDomain] = true
			in.Limiters[ep.RootOrMatchingDomain] = tuneLimiter{Rate: ep.RateLimit, Burst: ep.RateLimitBurst, DryRun: ep.RateLimitDryRun, Clients: map[string][2]uint64{}}
		}
		return true
	})
	if len(limited) > 0 {
		dynamicProxyRouter.RateLimitClientCounters(limited, func(endpoint, ip string, allowed, denied uint64) {
			if ip == "*overflow*" {
				return
			}
			in.Limiters[endpoint].Clients[ip] = [2]uint64{allowed, denied}
		})
	}
	return in
}

// startLiveSampler starts the single sampler goroutine (one tick every 5 s)
func startLiveSampler() {
	liveTuneMu.Lock()
	defer liveTuneMu.Unlock()
	if liveTuneStop != nil {
		return
	}
	stop := make(chan struct{})
	liveTuneStop = stop
	go func() {
		defer func() { recover() }()
		t := time.NewTicker(tuneSlotSec * time.Second)
		defer t.Stop()
		liveTune.tick(time.Now(), sampleTuneInput(time.Now()))
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				liveTune.tick(now, sampleTuneInput(now))
			}
		}
	}()
}

func stopLiveSampler() {
	liveTuneMu.Lock()
	defer liveTuneMu.Unlock()
	if liveTuneStop != nil {
		close(liveTuneStop)
		liveTuneStop = nil
	}
}

// HandleLiveTune serves GET /api/stats/livetune?window=10s|1m|5m|1h
func HandleLiveTune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}
	res := liveTune.query(time.Now(), r.URL.Query().Get("window"))
	js, _ := json.Marshal(res)
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(js))
}
