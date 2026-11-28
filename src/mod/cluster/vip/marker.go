package vip

import (
	"io"
	"os"
	"regexp"
	"strings"
)

// MarkerMaxBytes is the size limit of the installer's marker file.
const MarkerMaxBytes = 1024

// Marker is what the installer script writes to /etc/keepalived/dunree-installed
// so the page can see install progress without reading the 0600 config. It
// holds no password.
type Marker struct {
	Fingerprint string `json:"fingerprint"`
	Member      string `json:"member,omitempty"`
	GeneratedBy string `json:"generatedBy,omitempty"`
	Version     string `json:"version,omitempty"`
	InstalledAt string `json:"installedAt,omitempty"`
}

var reMarkerValue = regexp.MustCompile(`^[A-Za-z0-9 ._:()+/-]{0,80}$`)

// ParseMarker reads the fixed key=value lines. Unknown keys and values outside
// the whitelist are ignored. ok is false when there is no usable fingerprint.
func ParseMarker(b []byte) (m Marker, ok bool) {
	if len(b) > MarkerMaxBytes {
		return Marker{}, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, found := strings.Cut(line, "=")
		if !found || !reMarkerValue.MatchString(v) {
			continue
		}
		switch k {
		case "fingerprint":
			if reScriptFP.MatchString(v) {
				m.Fingerprint = v
			}
		case "member":
			m.Member = v
		case "generatedBy":
			m.GeneratedBy = v
		case "version":
			m.Version = v
		case "installedAt":
			m.InstalledAt = v
		}
	}
	return m, m.Fingerprint != ""
}

// ReadMarker reads the marker file with the size limit. A missing, unreadable
// or oversized file means "not installed by the script".
func ReadMarker(path string) (Marker, bool) {
	if path == "" {
		return Marker{}, false
	}
	f, err := os.Open(path)
	if err != nil {
		return Marker{}, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MarkerMaxBytes+1))
	if err != nil {
		return Marker{}, false
	}
	return ParseMarker(b)
}

// Node states (docs/cluster/vip-simple-setup.md 10.1).
const (
	NodeUnknown    = "unknown"
	NodeOldVersion = "old-version"
	NodeWaiting    = "waiting"
	NodeOutdated   = "outdated"
	NodeStopped    = "stopped"
	NodeHolding    = "holding"
	NodeStandby    = "standby"
	NodeFault      = "fault"
)

// NodeFacts are the facts one member's state is computed from.
type NodeFacts struct {
	Reachable     bool // health JSON answered or a recent heartbeat exists
	OldVersion    bool
	Installed     bool   // marker present
	InstalledFP   string // marker fingerprint
	CurrentFP     string
	KeepalivedUp  Tri
	Held          bool
	SomeoneHolds  bool // some member (this one included) holds the floating IP
	ProbeOK       Tri  // the member's own health check, when known
	KeepalivedBin bool // keepalived binary found
}

// NodeState is computed server side so the page (and the smoke fixtures) only
// render it. First match wins.
func NodeState(f NodeFacts) string {
	switch {
	case !f.Reachable:
		return NodeUnknown
	case f.OldVersion:
		return NodeOldVersion
	case !f.KeepalivedBin || !f.Installed:
		return NodeWaiting
	case f.CurrentFP != "" && f.InstalledFP != f.CurrentFP:
		return NodeOutdated
	case f.KeepalivedUp == No:
		return NodeStopped
	case f.Held:
		return NodeHolding
	case f.SomeoneHolds:
		return NodeStandby
	case f.KeepalivedUp == Yes:
		return NodeFault
	}
	return NodeUnknown
}
