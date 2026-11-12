package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	livemap.go

	GET /api/stats/livemap: the numbers behind the Live mode of the Status page's Traffic map.

	Per proxy rule and per upstream: requests per second over the last ~10 s and the in-flight
	request count, plus the global requests / errors / blocked per second. Nothing runs in the
	background and nothing is added to the request path: the rates are derived by diffing the
	cumulative daily counters (the ones the Today mode shows) between two reads, and the
	in-flight numbers are the load balancer's existing atomic gauges.

	The answer is cached for a second, so any number of viewers cost one sample per second.
	A counter that goes down (midnight rollover, stats reset) counts as no traffic.
	Not available: per rule error / blocked rates (only global counters exist) and stream
	proxy connection counts (the stream proxy does not track them).
*/

const (
	liveWindow     = 10 * time.Second // the rate is averaged over about this long
	liveMaxAge     = 30 * time.Second // older samples are not used as a base (a stale base would hide a burst)
	liveCacheTTL   = time.Second
	liveMinElapsed = 500 * time.Millisecond
)

// liveSample is one reading of the cumulative counters
type liveSample struct {
	at      time.Time
	total   int64
	errors  int64
	blocked int64
	down    map[string]int64 // per rule (downstream host name)
	up      map[string]int64 // per upstream origin
}

// liveRates turns samples into per second rates
type liveRates struct {
	mu      sync.Mutex
	samples []liveSample // oldest first, within liveMaxAge

	cacheAt   time.Time
	cacheBody []byte
}

// liveRateSet is the result of comparing a sample with an earlier one
type liveRateSet struct {
	Warmup  bool // no usable earlier sample yet: every rate is 0 and means "unknown"
	Window  float64
	Total   float64
	Errors  float64
	Blocked float64
	Down    map[string]float64
	Up      map[string]float64
}

func rate(cur, base int64, secs float64) float64 {
	d := cur - base
	if d <= 0 || secs <= 0 { // a reset (midnight) is "no traffic", never a negative rate
		return 0
	}
	return float64(d) / secs
}

// push stores cur and returns its rates against the best earlier sample. Caller holds r.mu.
func (r *liveRates) push(cur liveSample) liveRateSet {
	// drop samples that are too old, in the future (clock change) or from before a counter reset
	keep := r.samples[:0]
	for _, s := range r.samples {
		age := cur.at.Sub(s.at)
		if age < 0 || age > liveMaxAge || s.total > cur.total {
			continue
		}
		keep = append(keep, s)
	}
	r.samples = keep

	// base: the oldest sample that is still inside the window, else the newest older one
	var base *liveSample
	for i := range r.samples {
		if cur.at.Sub(r.samples[i].at) <= liveWindow {
			base = &r.samples[i]
			break
		}
	}
	if base == nil && len(r.samples) > 0 {
		base = &r.samples[len(r.samples)-1]
	}

	out := liveRateSet{Down: map[string]float64{}, Up: map[string]float64{}}
	if base == nil || cur.at.Sub(base.at) < liveMinElapsed {
		out.Warmup = true
	} else {
		secs := cur.at.Sub(base.at).Seconds()
		out.Window = secs
		out.Total = rate(cur.total, base.total, secs)
		out.Errors = rate(cur.errors, base.errors, secs)
		out.Blocked = rate(cur.blocked, base.blocked, secs)
		for k, v := range cur.down {
			out.Down[k] = rate(v, base.down[k], secs)
		}
		for k, v := range cur.up {
			out.Up[k] = rate(v, base.up[k], secs)
		}
	}

	// keep a small history: at most one sample per half second
	if n := len(r.samples); n == 0 || cur.at.Sub(r.samples[n-1].at) >= liveMinElapsed {
		r.samples = append(r.samples, cur)
	}
	if len(r.samples) > 40 {
		r.samples = r.samples[len(r.samples)-40:]
	}
	return out
}

// LiveMapUpstream, LiveMapProxy and LiveMapData are the JSON answer
type LiveMapUpstream struct {
	Origin   string  `json:"origin"`
	Rps      float64 `json:"rps"`
	InFlight int64   `json:"inFlight"`
}

type LiveMapProxy struct {
	Domain    string             `json:"domain"`
	Kind      string             `json:"kind,omitempty"`
	Rps       float64            `json:"rps"`
	InFlight  int64              `json:"inFlight"`
	Upstreams []*LiveMapUpstream `json:"upstreams"`
}

type LiveMapData struct {
	Now           int64           `json:"now"`    // unix milliseconds of the sample
	Warmup        bool            `json:"warmup"` // first reading after a pause: rates are not known yet
	WindowSeconds float64         `json:"windowSeconds"`
	TotalRps      float64         `json:"totalRps"`
	TotalInFlight int64           `json:"totalInFlight"`
	ErrorsPerSec  float64         `json:"errorsPerSec"`
	BlockedPerSec float64         `json:"blockedPerSec"`
	Proxies       []*LiveMapProxy `json:"proxies"`
}

var liveMapRates liveRates

// get returns the JSON answer for now, sampling the counters with read at most once per liveCacheTTL
func (r *liveRates) get(now time.Time, read func(now time.Time) (liveSample, []*LiveMapProxy)) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cacheBody != nil && now.Sub(r.cacheAt) >= 0 && now.Sub(r.cacheAt) < liveCacheTTL {
		return r.cacheBody
	}
	cur, proxies := read(now)
	rs := r.push(cur)
	data := LiveMapData{Now: now.UnixMilli(), Warmup: rs.Warmup, WindowSeconds: rs.Window,
		TotalRps: rs.Total, ErrorsPerSec: rs.Errors, BlockedPerSec: rs.Blocked, Proxies: proxies}
	for _, p := range proxies {
		p.Rps = rs.Down[p.Domain]
		for _, u := range p.Upstreams {
			u.Rps = rs.Up[u.Origin]
			p.InFlight += u.InFlight
		}
		data.TotalInFlight += p.InFlight
	}
	body, _ := json.Marshal(data)
	r.cacheAt, r.cacheBody = now, body
	return body
}

// readLiveCounters reads today's cumulative counters and the in-flight gauges of every rule
func readLiveCounters(now time.Time) (liveSample, []*LiveMapProxy) {
	s := liveSample{at: now, down: map[string]int64{}, up: map[string]int64{}}
	proxies := []*LiveMapProxy{}
	if statisticCollector == nil || dynamicProxyRouter == nil {
		return s, proxies
	}
	ds := statisticCollector.GetCurrentDailySummary()
	s.total = atomic.LoadInt64(&ds.TotalRequest)
	s.errors = atomic.LoadInt64(&ds.ErrorRequest)
	s.blocked = atomic.LoadInt64(&ds.BlockedRequest)
	load := func(m interface{ Load(key interface{}) (interface{}, bool) }, key string) int64 {
		if v, ok := m.Load(key); ok {
			if c, ok := v.(int); ok {
				return int64(c)
			}
		}
		return 0
	}
	dynamicProxyRouter.ProxyEndpoints.Range(func(_, value interface{}) bool {
		ep := value.(*dynamicproxy.ProxyEndpoint)
		p := &LiveMapProxy{Domain: ep.RootOrMatchingDomain, Upstreams: []*LiveMapUpstream{}}
		s.down[p.Domain] = load(ds.DownstreamHostnames, p.Domain)
		for _, o := range ep.ActiveOrigins {
			p.Upstreams = append(p.Upstreams, &LiveMapUpstream{Origin: o.OriginIpOrDomain, InFlight: o.InFlight()})
			s.up[o.OriginIpOrDomain] = load(ds.UpstreamHostnames, o.OriginIpOrDomain)
		}
		proxies = append(proxies, p)
		return true
	})
	if streamProxyManager != nil {
		for _, sp := range streamProxyManager.Configs {
			proxies = append(proxies, &LiveMapProxy{Domain: "[stream] " + sp.Name, Kind: "stream",
				Upstreams: []*LiveMapUpstream{{Origin: sp.ProxyTargetAddr}}})
		}
	}
	return s, proxies
}

// HandleLiveMapData serves GET /api/stats/livemap
func HandleLiveMapData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.SendErrorResponse(w, "method not allowed")
		return
	}
	body := liveMapRates.get(time.Now(), readLiveCounters)
	w.Header().Set("Cache-Control", "no-store")
	utils.SendJSONResponse(w, string(body))
}
