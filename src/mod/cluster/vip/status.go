package vip

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Paths are the files the status reader looks at. They are fields, not
// constants, so tests point them at a temp root.
type Paths struct {
	KeepalivedBins []string
	EnabledLink    string
	PidFile        string
	ProcDir        string
	ConfFile       string
	ARPFile        string
	UFWConf        string
	RouteFile      string // /proc/net/route, for the address suggestions
	MarkerFile     string // written by the installer script, read for the install progress
}

// SystemPaths are the real locations on a Debian / Ubuntu host.
func SystemPaths() Paths {
	return Paths{
		KeepalivedBins: []string{"/usr/sbin/keepalived", "/usr/local/sbin/keepalived"},
		EnabledLink:    "/etc/systemd/system/multi-user.target.wants/keepalived.service",
		PidFile:        "/run/keepalived.pid",
		ProcDir:        "/proc",
		ConfFile:       "/etc/keepalived/keepalived.conf",
		ARPFile:        "/proc/net/arp",
		UFWConf:        "/etc/ufw/ufw.conf",
		RouteFile:      "/proc/net/route",
		MarkerFile:     "/etc/keepalived/dunree-installed",
	}
}

// RealInterfaces lists the host's interfaces through the net package.
type RealInterfaces struct{}

// Interfaces implements InterfaceLister.
func (RealInterfaces) Interfaces() ([]IfaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IfaceInfo
	for _, in := range ifs {
		ii := IfaceInfo{Name: in.Name, Up: in.Flags&net.FlagUp != 0}
		addrs, _ := in.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					ones, _ := ipn.Mask.Size()
					ii.Addrs = append(ii.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
				}
			}
		}
		out = append(out, ii)
	}
	return out, nil
}

// Tri is a fact that may be unknown. Unknown is normal (a file Dunree may not
// read) and is never shown as a problem.
type Tri string

// Tri values.
const (
	Yes     Tri = "yes"
	No      Tri = "no"
	Unknown Tri = "unknown"
)

// Status is the read-only picture of this node (section 4).
type Status struct {
	Configured      bool   `json:"configured"`
	Held            bool   `json:"held"`
	HeldInterface   string `json:"heldInterface,omitempty"`
	IsMember        bool   `json:"isMember"`
	MemberLabel     string `json:"memberLabel,omitempty"`
	Interface       string `json:"interface,omitempty"`
	Prefix          int    `json:"prefix,omitempty"`
	KeepalivedFound Tri    `json:"keepalivedInstalled"`
	KeepalivedOn    Tri    `json:"keepalivedEnabled"`
	KeepalivedUp    Tri    `json:"keepalivedRunning"`
	ConfigMatches   Tri    `json:"installedConfigMatches"`
	InstalledFinger string `json:"installedFingerprint,omitempty"`
	CurrentFinger   string `json:"fingerprint,omitempty"`
	// Installed is true when the installer script left its marker file.
	Installed    bool   `json:"installed"`
	MarkerFinger string `json:"markerFingerprint,omitempty"`
	MarkerAt     string `json:"installedAt,omitempty"`
	UFWEnabled   bool   `json:"ufwEnabled"`
	Error        string `json:"error,omitempty"`
}

// HeartbeatFact is the optional field a node adds to its heartbeat.
type HeartbeatFact struct {
	Held       bool `json:"held"`
	Keepalived Tri  `json:"keepalived"`
}

// ReadStatus gathers the facts. It runs no command. Any single failure leaves
// that line "unknown".
func ReadStatus(s *Shared, l *Local, lister InterfaceLister, p Paths, env *Env) Status {
	st := Status{KeepalivedFound: Unknown, KeepalivedOn: Unknown, KeepalivedUp: Unknown, ConfigMatches: Unknown}
	st.Configured = s != nil && s.VIP != ""
	st.UFWEnabled = ReadUFWEnabled(p.UFWConf)
	// installed
	st.KeepalivedFound = No
	for _, b := range p.KeepalivedBins {
		if fi, err := os.Stat(b); err == nil && fi.Mode().IsRegular() {
			st.KeepalivedFound = Yes
		}
	}
	if p.EnabledLink != "" {
		if _, err := os.Lstat(p.EnabledLink); err == nil {
			st.KeepalivedOn = Yes
		} else if os.IsNotExist(err) {
			st.KeepalivedOn = No
		}
	}
	st.KeepalivedUp = readRunning(p)
	if mk, ok := ReadMarker(p.MarkerFile); ok {
		st.Installed, st.MarkerFinger, st.MarkerAt = true, mk.Fingerprint, mk.InstalledAt
	}
	ifs, err := lister.Interfaces()
	if err != nil {
		st.Error = "cannot list network interfaces"
		return st
	}
	if st.Configured {
		if vip, err := netip.ParseAddr(s.VIP); err == nil {
			for _, in := range ifs {
				for _, a := range in.Addrs {
					if a.Addr() == vip {
						st.Held, st.HeldInterface = true, in.Name
					}
				}
			}
		}
		if self, err := Resolve(s, l, ifs); err == nil {
			st.IsMember = true
			st.MemberLabel = s.Members[self.Index].Label
			st.Interface, st.Prefix = self.Interface, self.Prefix
		}
		pass, perr := EffectivePassword(s, env)
		if perr == nil {
			st.CurrentFinger = Fingerprint(s, pass)
		}
		if b, err := os.ReadFile(p.ConfFile); err == nil {
			st.InstalledFinger = fingerprintOf(string(b))
			if st.InstalledFinger != "" && st.CurrentFinger != "" {
				st.ConfigMatches = No
				if st.InstalledFinger == st.CurrentFinger {
					st.ConfigMatches = Yes
				}
			}
		}
	}
	return st
}

func fingerprintOf(conf string) string {
	const key = "Settings fingerprint: "
	line := conf
	if i := strings.IndexByte(conf, '\n'); i >= 0 {
		line = conf[:i]
	}
	i := strings.Index(line, key)
	if i < 0 {
		return ""
	}
	f := strings.TrimSpace(line[i+len(key):])
	if len(f) != 8 {
		return ""
	}
	return f
}

func readRunning(p Paths) Tri {
	b, err := os.ReadFile(p.PidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return No
		}
		return Unknown
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid < 1 {
		return Unknown
	}
	c, err := os.ReadFile(filepath.Join(p.ProcDir, strconv.Itoa(pid), "comm"))
	if err != nil {
		if os.IsNotExist(err) {
			return No
		}
		return Unknown
	}
	if strings.TrimSpace(string(c)) == "keepalived" {
		return Yes
	}
	return No
}

// ReadUFWEnabled reads ENABLED=yes from ufw.conf (read only).
func ReadUFWEnabled(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.EqualFold(line, "ENABLED=yes") {
			return true
		}
	}
	return false
}

// Reader caches a status for a few seconds so a polling page does not rescan
// the host on every request.
type Reader struct {
	TTL time.Duration
	Now func() time.Time

	mu   sync.Mutex
	at   time.Time
	last Status
	ok   bool
}

// Get returns the cached status or builds a new one.
func (r *Reader) Get(build func() Status) Status {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	ttl := r.TTL
	if ttl == 0 {
		ttl = 2 * time.Second
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ok && now().Sub(r.at) < ttl {
		return r.last
	}
	r.last, r.at, r.ok = build(), now(), true
	return r.last
}

// Invalidate drops the cache (after a settings change).
func (r *Reader) Invalidate() {
	r.mu.Lock()
	r.ok = false
	r.mu.Unlock()
}
