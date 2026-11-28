package vip

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

// HealthPath is the probe path; it must equal cluster.HealthPath (a test in
// mod/cluster keeps the two in step).
const HealthPath = "/.dunree/health"

// BlockedError is returned when no config may be generated. The UI lists
// Blockers.
type BlockedError struct{ Blockers []string }

func (e *BlockedError) Error() string {
	return "cannot generate the configuration: " + strings.Join(e.Blockers, "; ")
}

// Output is what Generate returns. Dunree never runs any of it.
type Output struct {
	KeepalivedConf  string   `json:"keepalivedConf"`
	InstallCommands string   `json:"installCommands"`
	VerifyCommands  string   `json:"verifyCommands"`
	Sysctl          string   `json:"sysctl,omitempty"`
	FirewallNote    string   `json:"firewallNote,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Fingerprint     string   `json:"fingerprint"`
	Member          string   `json:"member"`
	HealthURL       string   `json:"healthUrl"`
}

// fingerprintSalt keys the password part of the fingerprint.
const fingerprintSalt = "dunree-vip-fp"

// Fingerprint is a short hash of the canonical shared settings plus a slow,
// keyed digest of the effective authentication password, so two nodes can be
// compared at a glance. It never contains the password itself and it is not
// written to the audit log: the password only enters through PBKDF2, so the
// 32 bit value is no cheap check for a guessed password.
func Fingerprint(s *Shared, effectivePassword string) string {
	c := *s
	c.Password, c.ClusterPass = "", ""
	b, _ := json.Marshal(c)
	h := sha256.New()
	h.Write(b)
	h.Write([]byte{0})
	if effectivePassword != "" {
		if k, err := pbkdf2.Key(sha256.New, effectivePassword, []byte(fingerprintSalt), 20000, 16); err == nil {
			h.Write(k)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// EffectivePassword returns the VRRP password for the settings ("" for none).
func EffectivePassword(s *Shared, env *Env) (string, error) {
	switch s.Auth {
	case AuthPassword:
		return s.Password, nil
	case AuthCluster:
		if s.ClusterPass == "" {
			return "", errors.New("authentication is set to the cluster password, but none has been generated yet; save the Floating IP settings on the primary")
		}
		return s.ClusterPass, nil
	}
	return "", nil
}

// Every substituted token has to match this (section 2.2). keepalived reads
// '#' and '!' as comments, braces as blocks and quotes as strings.
var reToken = regexp.MustCompile(`^[A-Za-z0-9._:/\[\]+~-]+$`)

// reComment is what the header comment may contain.
var reComment = regexp.MustCompile(`^[A-Za-z0-9 ._:()/+~-]+$`)

type probe struct {
	Base string // scheme://host:port
	TLS  bool
}

func isWildcardHost(h string) bool {
	return h == "" || h == "0.0.0.0" || h == "::" || h == "[::]"
}

// hostPort splits "[host]:port" forms of -health_port.
func hostPort(s string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, false
	}
	return h, n, true
}

func urlHost(h string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// ProbeTarget selects the health probe (section 3.1). It returns blockers
// separately from warnings.
func ProbeTarget(s *Shared, l *Local, env *Env) (p probe, blockers []string, err error) {
	vip := netip.MustParseAddr(s.VIP)
	// The probe only asks the local Dunree, which listens on all addresses, so
	// the address family of the VIP does not matter. Always IPv4 loopback: a
	// host with IPv6 disabled on lo would otherwise never pass.
	loop := "127.0.0.1"
	f := env.Listener
	if f.HealthDisabled {
		blockers = append(blockers, "the health endpoint is switched off, so a probe would reach normal routing and mean nothing; switch it on")
	}
	// bound non-loopback, non-VIP address replaces the loopback host
	host := loop
	if b := f.BoundAddr; b != "" && !isWildcardHost(b) {
		if a, e := netip.ParseAddr(b); e == nil && a != vip && !a.IsLoopback() {
			host = a.String()
		}
	}
	custom := ""
	if l != nil {
		var e error
		custom, _, e = ParseHealthTarget(l.HealthTarget)
		if e != nil {
			return p, blockers, e
		}
	}
	switch {
	case custom != "":
		p.Base = custom
		p.TLS = strings.HasPrefix(custom, "https://")
	case f.HealthPort != "":
		h, port, ok := hostPort(f.HealthPort)
		if !ok {
			blockers = append(blockers, "the -health_port value is not usable: "+f.HealthPort)
			break
		}
		if !isWildcardHost(h) {
			a, e := netip.ParseAddr(h)
			if e != nil {
				blockers = append(blockers, "the -health_port host is not an IP address: use a port only (:8081) or an IP address")
				break
			}
			if a == vip {
				blockers = append(blockers, "the health listener is bound to the floating IP, so the probe fails on the standby node; bind it to all addresses or to the node's own address")
				break
			}
			host = a.String()
		} else {
			host = loop
		}
		p.Base = "http://" + urlHost(host) + ":" + strconv.Itoa(port)
	case f.Port80 && f.TLS:
		// The plain HTTP listener only runs next to a TLS proxy listener.
		hp := f.HTTPPort
		if hp == 0 {
			hp = 80
		}
		p.Base = "http://" + urlHost(host) + ":" + strconv.Itoa(hp)
	case f.TLS && f.InboundPort > 0:
		if f.RejectUnknownSNI {
			blockers = append(blockers, "the proxy rejects unknown server names and the probe to 127.0.0.1 sends none; start Dunree with -health_port (for example :8081) or set a node-local health target")
			break
		}
		p.Base = "https://" + urlHost(host) + ":" + strconv.Itoa(f.InboundPort)
		p.TLS = true
	case f.InboundPort > 0:
		p.Base = "http://" + urlHost(host) + ":" + strconv.Itoa(f.InboundPort)
	default:
		blockers = append(blockers, "cannot tell which port the proxy listens on; set a node-local health target")
	}
	if p.Base != "" {
		// The probe's source address has to be admitted by the health allow-list.
		src := loop
		if u := strings.TrimPrefix(strings.TrimPrefix(p.Base, "http://"), "https://"); u != "" {
			if h, _, ok := hostPort(u); ok {
				src = strings.Trim(h, "[]")
			}
		}
		if len(f.HealthAllow) > 0 && !allowListAdmits(f.HealthAllow, src) {
			blockers = append(blockers, "the health allow-list does not admit the probe source "+src+" (add it to the health allow-list)")
		}
	}
	return p, blockers, nil
}

func allowListAdmits(list []string, src string) bool {
	a, err := netip.ParseAddr(src)
	if err != nil {
		return false
	}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if p, err := netip.ParsePrefix(e); err == nil && p.Contains(a) {
				return true
			}
			continue
		}
		if x, err := netip.ParseAddr(e); err == nil && x == a {
			return true
		}
	}
	return false
}

type tmplData struct {
	Version, Fingerprint string
	Label, Source        string
	V6                   bool
	State, Iface         string
	VRID, Priority       int
	Advert               int
	PreemptDelay         int
	NoPreempt            bool
	Multicast            bool
	Peers                []string
	AuthType, AuthPass   string
	VIPCIDR              string
	Script               string
	Interval, Timeout    int
	Fall, Rise           int
	NotifyLog            bool
	Garp                 int
	InstanceName         string
}

const confTemplate = `# Generated by Dunree {{.Version}} for member "{{.Label}}" ({{.Source}}). Settings fingerprint: {{.Fingerprint}}
# Do not edit by hand: change the Floating IP settings in Dunree and generate again.
global_defs {
    enable_script_security
    script_user keepalived_script
{{- if .V6}}
    vrrp_version 3
{{- end}}
    vrrp_garp_master_refresh {{.Garp}}
}

vrrp_script chk_dunree {
    script "{{.Script}}"
    interval {{.Interval}}
    timeout {{.Timeout}}
    fall {{.Fall}}
    rise {{.Rise}}
    init_fail
}

vrrp_instance {{.InstanceName}} {
    state {{.State}}
{{- if .NoPreempt}}
    nopreempt
{{- end}}
    interface {{.Iface}}
{{- if .V6}}
    native_ipv6
{{- end}}
    virtual_router_id {{.VRID}}
    priority {{.Priority}}
    advert_int {{.Advert}}
{{- if gt .PreemptDelay 0}}
    preempt_delay {{.PreemptDelay}}
{{- end}}
{{- if not .Multicast}}
    unicast_src_ip {{.Source}}
    unicast_peer {
{{- range .Peers}}
        {{.}}
{{- end}}
    }
{{- end}}
{{- if .AuthType}}
    authentication {
        auth_type {{.AuthType}}
        auth_pass {{.AuthPass}}
    }
{{- end}}
    virtual_ipaddress {
        {{.VIPCIDR}} dev {{.Iface}}
    }
{{- if .NotifyLog}}
    notify_master "/usr/bin/logger -t dunree-vip MASTER"
    notify_backup "/usr/bin/logger -t dunree-vip BACKUP"
    notify_fault  "/usr/bin/logger -t dunree-vip FAULT"
{{- end}}
    track_script {
        chk_dunree
    }
}
`

var tmpl = template.Must(template.New("keepalived").Option("missingkey=error").Parse(confTemplate))

// checkRendered applies the render guard: the keywords this generator emits
// are constants, so any line outside the known shapes is an internal error.
func checkRendered(d *tmplData) error {
	toks := map[string]string{
		"interface": d.Iface, "source": d.Source, "vip": d.VIPCIDR, "authpass": d.AuthPass,
		"version": d.Version, "fingerprint": d.Fingerprint, "authtype": d.AuthType,
	}
	for _, p := range d.Peers {
		toks["peer"] = p
		if !reToken.MatchString(p) {
			return fmt.Errorf("render guard: peer token %q", p)
		}
	}
	for k, v := range toks {
		if v == "" && (k == "authpass" || k == "authtype") {
			continue
		}
		if !reToken.MatchString(v) {
			return fmt.Errorf("render guard: %s token %q", k, v)
		}
	}
	if !reComment.MatchString(d.Label) {
		return fmt.Errorf("render guard: label %q", d.Label)
	}
	return checkScript(d.Script)
}

// checkScript requires the exact argv shape this generator emits:
//
//	/usr/bin/curl -fsS --max-time N [-k] -o /dev/null URL
//
// with N a number and URL one http(s) URL without whitespace, user info,
// query or fragment. Anything else is an internal error.
func checkScript(script string) error {
	f := strings.Split(script, " ")
	n := len(f)
	if n != 7 && n != 8 {
		return errors.New("render guard: script shape")
	}
	fixed := []string{"/usr/bin/curl", "-fsS", "--max-time"}
	for i, w := range fixed {
		if f[i] != w {
			return errors.New("render guard: script")
		}
	}
	if v, err := strconv.Atoi(f[3]); err != nil || v < 1 || v > 60 || strconv.Itoa(v) != f[3] {
		return errors.New("render guard: script time limit")
	}
	rest := f[4:]
	if len(rest) == 4 {
		if rest[0] != "-k" {
			return errors.New("render guard: script flag")
		}
		rest = rest[1:]
	}
	if len(rest) != 3 || rest[0] != "-o" || rest[1] != "/dev/null" {
		return errors.New("render guard: script output")
	}
	u := rest[2]
	if !reToken.MatchString(u) || strings.ContainsAny(u, "?#@") {
		return fmt.Errorf("render guard: script url %q", u)
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || pu.Path != HealthPath || pu.Port() == "" {
		return fmt.Errorf("render guard: script url %q", u)
	}
	// The probe only ever asks a Dunree by its IP address: a host name would let
	// whoever controls the name steer the failover.
	if _, err := netip.ParseAddr(strings.Trim(pu.Hostname(), "[]")); err != nil {
		return fmt.Errorf("render guard: script host %q", u)
	}
	return nil
}

// ValidProbeBase says whether a health check base URL ("scheme://host:port")
// that another member reported may go into that member's script: the host has
// to be that member's own loopback or its own address, and the port a plain
// number. Anything else would let whoever answers at that address point the
// failover check at a host of their choice.
func ValidProbeBase(base, member string) bool {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	port := u.Port()
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	host := u.Hostname()
	if host == "127.0.0.1" || host == "::1" {
		return true
	}
	h, herr := netip.ParseAddr(host)
	m, merr := netip.ParseAddr(member)
	return herr == nil && merr == nil && h.Zone() == "" && h.Unmap() == m.Unmap()
}

// Generate renders keepalived.conf for one member (section 3). member < 0
// means this node. It is a pure function of its inputs.
func Generate(s *Shared, l *Local, env *Env, member int) (*Output, error) {
	out, _, err := generate(s, l, env, member, nil)
	return out, err
}

// PeerFacts are what the peer's own Dunree reported about itself (its
// interface name and health check base URL). Empty fields are guessed from
// this node and listed in ScriptOutput.Guessed.
type PeerFacts struct {
	Iface     string // interface carrying the member address
	ProbeBase string // scheme://host:port of the health listener, "" = guess
	// Priority is the priority this member itself uses when it has its own
	// override (0 = none), so a script made for it elsewhere carries the same number.
	Priority int
}

func generate(s *Shared, l *Local, env *Env, member int, pf *PeerFacts) (*Output, *tmplData, error) {
	if l == nil {
		l = &Local{}
	}
	if err := ValidateShared(s); err != nil {
		return nil, nil, &BlockedError{Blockers: []string{err.Error()}}
	}
	if err := ValidateLocal(l, s); err != nil {
		return nil, nil, &BlockedError{Blockers: []string{err.Error()}}
	}
	if s.VIP == "" || len(s.Members) < 2 {
		return nil, nil, &BlockedError{Blockers: []string{"enter the floating IP and at least two members"}}
	}
	var blockers, warnings []string
	pass, err := EffectivePassword(s, env)
	if err != nil {
		blockers = append(blockers, err.Error())
	}
	self, serr := Resolve(s, l, env.Interfaces)
	d := &tmplData{Version: sanitizeVersion(env.Version), NotifyLog: s.NotifyLog, Garp: s.GarpRefresh,
		VRID: s.VRID, Advert: s.AdvertInt, Multicast: s.Transport == TransportMulticast,
		Interval: s.Health.Interval, Timeout: s.Health.Timeout, Fall: s.Health.Fall, Rise: s.Health.Rise}
	vipAddr := netip.MustParseAddr(s.VIP)
	d.V6 = vipAddr.Is6()
	d.InstanceName = "VI_DUNREE"
	if d.V6 {
		d.InstanceName = "VI_DUNREE6"
	}
	var idx int
	var ifaceName string
	prio := 0
	if member < 0 {
		if serr != nil {
			blockers = append(blockers, serr.Error())
		} else {
			idx, ifaceName, prio = self.Index, self.Interface, self.Priority
			if l.Interface != "" {
				ifaceName = l.Interface
			}
		}
	} else {
		if member >= len(s.Members) {
			return nil, nil, &BlockedError{Blockers: []string{"no such member"}}
		}
		idx = member
		prio = s.Members[idx].Priority
		ifaceName = s.Members[idx].InterfaceHint
		if pf != nil && pf.Iface != "" {
			ifaceName = pf.Iface
		}
		if ifaceName == "" && serr == nil {
			ifaceName = self.Interface
			warnings = append(warnings, "the interface name was taken from this node ("+ifaceName+"); check the interface name on "+s.Members[idx].Label)
		}
		if ifaceName == "" {
			blockers = append(blockers, "set an interface hint for "+s.Members[idx].Label+" or open the page on that node")
		}
		if pf != nil && pf.ProbeBase != "" && !ValidProbeBase(pf.ProbeBase, s.Members[idx].Address) {
			return nil, nil, &BlockedError{Blockers: []string{"the health check address reported by " + s.Members[idx].Label + " is not that server's own address"}}
		}
		if pf == nil || pf.ProbeBase == "" {
			warnings = append(warnings, "the health check target was chosen from this node's listener settings; check it on "+s.Members[idx].Label)
		}
		if pf != nil && pf.Priority >= 1 && pf.Priority <= 254 {
			prio = pf.Priority
			if s.Main != "" {
				warnings = append(warnings, s.Members[idx].Label+" has its own priority ("+strconv.Itoa(prio)+") under Expert values, which overrides your choice of the main server")
			}
		}
	}
	if member < 0 && l.PriorityOverride != 0 && s.Main != "" {
		warnings = append(warnings, "this server has its own priority ("+strconv.Itoa(l.PriorityOverride)+") under Expert values, which overrides your choice of the main server")
	}
	pr, pb, perr := ProbeTarget(s, l, env)
	if member >= 0 && pf != nil && pf.ProbeBase != "" {
		// the peer told us how it reaches its own health check
		pr, pb, perr = probe{Base: pf.ProbeBase, TLS: strings.HasPrefix(pf.ProbeBase, "https://")}, nil, nil
	}
	blockers = append(blockers, pb...)
	if perr != nil {
		blockers = append(blockers, perr.Error())
	}
	if len(blockers) > 0 {
		return nil, nil, &BlockedError{Blockers: blockers}
	}
	m := s.Members[idx]
	d.Label, d.Source, d.Iface, d.Priority = m.Label, m.Address, ifaceName, prio
	for i, o := range s.Members {
		if i != idx {
			d.Peers = append(d.Peers, o.Address)
		}
	}
	// state: MASTER for the highest effective priority
	d.State = "MASTER"
	for i, o := range s.Members {
		if i != idx && o.Priority > prio {
			d.State = "BACKUP"
		}
	}
	if !s.Preempt {
		d.State, d.NoPreempt = "BACKUP", true
	} else {
		d.PreemptDelay = s.PreemptDelay
		// keepalived only honours preempt_delay when the instance starts in
		// BACKUP ("preempt delay will not work with initial state MASTER" and
		// the config test exits 5). The priority still makes the highest
		// member the normal owner.
		if d.PreemptDelay > 0 {
			d.State = "BACKUP"
		}
	}
	if !d.V6 && s.Auth != AuthNone {
		d.AuthType, d.AuthPass = "PASS", pass
	}
	if d.V6 && s.Auth != AuthNone {
		warnings = append(warnings, "IPv6 uses VRRP version 3, which has no authentication: the password is not used")
	}
	d.VIPCIDR = fmt.Sprintf("%s/%d", vipAddr.String(), s.Prefix)
	script := "/usr/bin/curl -fsS --max-time " + strconv.Itoa(CurlMaxTime(s.Health.Timeout))
	if pr.TLS {
		script += " -k"
	}
	healthURL := pr.Base + HealthPath
	script += " -o /dev/null " + healthURL
	d.Script = script
	d.Fingerprint = Fingerprint(s, pass)
	if err := checkRendered(d); err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return nil, nil, err
	}
	conf := buf.String()
	for _, line := range strings.Split(conf, "\n") {
		if strings.TrimSpace(line) == heredocDelim {
			return nil, nil, errors.New("render guard: heredoc delimiter in output")
		}
	}
	out := &Output{KeepalivedConf: conf, Fingerprint: d.Fingerprint, Member: m.Label, HealthURL: healthURL, Warnings: warnings}
	out.InstallCommands = installCommands(conf)
	out.VerifyCommands = verifyCommands(d.Iface)
	// sysctl: only when a Dunree listener binds the VIP itself
	if bindsVIP(env.Listener, vipAddr) {
		key := "net.ipv4.ip_nonlocal_bind"
		if d.V6 {
			key = "net.ipv6.ip_nonlocal_bind"
		}
		out.Sysctl = "echo '" + key + " = 1' | sudo tee /etc/sysctl.d/60-dunree-vip.conf\nsudo sysctl --system\n"
	}
	if env.UFWEnabled {
		out.FirewallNote = ufwNote(s, d)
	}
	return out, d, nil
}

func bindsVIP(f ListenerFacts, vip netip.Addr) bool {
	if a, err := netip.ParseAddr(f.BoundAddr); err == nil && a == vip {
		return true
	}
	return false
}

func sanitizeVersion(v string) string {
	var b strings.Builder
	for _, c := range v {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '+' || c == '_' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "dev"
	}
	return b.String()
}

const heredocDelim = "DUNREE_EOF"

func installCommands(conf string) string {
	var b strings.Builder
	b.WriteString("sudo apt update\n")
	b.WriteString("sudo apt install -y keepalived curl\n")
	b.WriteString("id keepalived_script >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin -M keepalived_script\n")
	b.WriteString("sudo tee /etc/keepalived/keepalived.conf >/dev/null <<'" + heredocDelim + "'\n")
	b.WriteString(conf)
	b.WriteString(heredocDelim + "\n")
	b.WriteString("sudo chmod 600 /etc/keepalived/keepalived.conf\n")
	// one chained command: a failed config test must not start keepalived
	b.WriteString("sudo keepalived -t -f /etc/keepalived/keepalived.conf && sudo systemctl enable keepalived && sudo systemctl restart keepalived\n")
	return b.String()
}

func verifyCommands(iface string) string {
	return "ip -br addr show dev " + iface + "\n" +
		"systemctl status keepalived --no-pager\n" +
		"journalctl -u keepalived -n 50 --no-pager\n"
}

func ufwNote(s *Shared, d *tmplData) string {
	file, chain, group := "/etc/ufw/before.rules", "ufw-before-input", "224.0.0.18"
	if d.V6 {
		file, chain, group = "/etc/ufw/before6.rules", "ufw6-before-input", "ff02::12"
	}
	var b strings.Builder
	b.WriteString("ufw is enabled on this host. ufw has no \"proto vrrp\" rule, so add the following to " + file + " (before the final COMMIT), then run: sudo ufw reload\n")
	if d.Multicast {
		b.WriteString("-A " + chain + " -p vrrp -d " + group + " -j ACCEPT\n")
	} else {
		for _, p := range d.Peers {
			b.WriteString("-A " + chain + " -p vrrp -s " + p + " -j ACCEPT\n")
		}
	}
	return b.String()
}
