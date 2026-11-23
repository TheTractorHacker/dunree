//go:build unix

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

/*
	Starting, watching and ending the plugin process, the way Zoraxy does it:
	working directory = the folder of the plugin, a process group of its own,
	the configure payload on the command line or on standard input, output read
	from pipes, SIGTERM and SIGKILL to the group.
*/

// logCounter counts what the plugin writes without keeping it
type logCounter struct {
	mu      sync.Mutex
	bytes   int64
	lines   int64
	longest int64
	cur     int64
	partial []byte
	tail    []string
}

const (
	tailLines   = 12
	tailLineLen = 300
)

func (l *logCounter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bytes += int64(len(p))
	rest := p
	for len(rest) > 0 {
		i := bytes.IndexByte(rest, '\n')
		chunk := rest
		if i >= 0 {
			chunk = rest[:i]
		}
		l.cur += int64(len(chunk))
		if room := tailLineLen - len(l.partial); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			l.partial = append(l.partial, chunk...)
		}
		if i < 0 {
			break
		}
		l.endLine()
		rest = rest[i+1:]
	}
	if l.cur > l.longest {
		l.longest = l.cur
	}
	return len(p), nil
}

func (l *logCounter) endLine() {
	l.lines++
	if l.cur > l.longest {
		l.longest = l.cur
	}
	l.tail = append(l.tail, strings.ToValidUTF8(string(l.partial), "?"))
	if len(l.tail) > tailLines {
		l.tail = l.tail[len(l.tail)-tailLines:]
	}
	l.cur, l.partial = 0, l.partial[:0]
}

func (l *logCounter) snapshot() (lines, size, longest int64, tail []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines, tail = l.lines, append([]string{}, l.tail...)
	if l.cur > 0 {
		lines++ //a last line without a newline
		tail = append(tail, strings.ToValidUTF8(string(l.partial), "?"))
	}
	return lines, l.bytes, l.longest, tail
}

type proc struct {
	cmd       *exec.Cmd
	pid       int
	port      int
	token     string
	apiKey    string
	started   time.Time
	done      chan struct{}
	waitErr   error
	peakRSS   atomic.Int64
	memKilled atomic.Bool
	seenMu    sync.Mutex
	seen      map[procID]bool //every process seen below the plugin (Linux)
}

// track remembers the processes that are below the plugin right now. A child that
// leaves the process group (setsid, setpgid) is still a child, so it is seen here.
func (p *proc) track() {
	if p.exited() {
		return
	}
	list := descendants(p.pid)
	p.seenMu.Lock()
	defer p.seenMu.Unlock()
	for _, id := range list {
		if len(p.seen) >= 4096 {
			return
		}
		if p.seen == nil {
			p.seen = map[procID]bool{}
		}
		p.seen[id] = true
	}
}

// strays lists the processes seen below the plugin that are still running
func (p *proc) strays() []procID {
	p.seenMu.Lock()
	defer p.seenMu.Unlock()
	var out []procID
	for id := range p.seen {
		if id.alive() {
			out = append(out, id)
		}
	}
	return out
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// exitText describes how the process ended
func (p *proc) exitText() string {
	if !p.exited() {
		return "still running"
	}
	if p.waitErr == nil {
		return "exit code 0"
	}
	var ee *exec.ExitError
	if errors.As(p.waitErr, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return "ended by signal " + ws.Signal().String()
		}
		return "exit code " + strconv.Itoa(ee.ExitCode())
	}
	return p.waitErr.Error()
}

func (p *proc) waitExit(d time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(d):
		return false
	}
}

func (p *proc) signalGroup(sig syscall.Signal) { syscall.Kill(-p.pid, sig) }

// groupAlive reports whether any process of the group of the plugin is left
func (p *proc) groupAlive() bool { return syscall.Kill(-p.pid, 0) == nil }

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func portFree(port int) bool {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// pickPort returns a free loopback port, inside the range of the options when one is set
func (k *kit) pickPort() (int, error) {
	if k.o.PortMin > 0 && k.o.PortMax >= k.o.PortMin {
		span := k.o.PortMax - k.o.PortMin + 1
		off, _ := rand.Int(rand.Reader, big.NewInt(int64(span)))
		for i := 0; i < span; i++ {
			port := k.o.PortMin + (int(off.Int64())+i)%span
			if !k.usedPorts[port] && portFree(port) {
				k.usedPorts[port] = true
				return port, nil
			}
		}
		return 0, fmt.Errorf("no free port between %d and %d", k.o.PortMin, k.o.PortMax)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// start starts the plugin with a configure payload as Zoraxy builds it
func (k *kit) start() (*proc, error) {
	port, err := k.pickPort()
	if err != nil {
		return nil, err
	}
	p := &proc{port: port, token: randomHex(24), done: make(chan struct{})}
	payload := map[string]any{
		"port":          port,
		"runtime_const": map[string]any{"zoraxy_version": "plugin-check " + toolVersion, "zoraxy_uuid": k.uuid, "development_build": false},
		"invoke_token":  p.token,
	}
	if len(k.m.PermittedAPIEndpoints) > 0 && k.stub != nil {
		p.apiKey = randomHex(24)
		payload["api_key"], payload["zoraxy_port"] = p.apiKey, k.stub.port
		k.stub.setKey(p.apiKey)
	}
	if k.m.APIVersion >= 1 {
		payload["api_version_max"] = contractMax //the lower end is 0 and is left out, as Zoraxy does
	}
	js, _ := json.Marshal(payload)
	var cmd *exec.Cmd
	if k.m.ConfigureVia == "stdin" {
		cmd = exec.Command(k.runBin, "-configure-stdin")
		cmd.Stdin = strings.NewReader(string(js) + "\n")
	} else {
		cmd = exec.Command(k.runBin, "-configure="+string(js))
	}
	cmd.Dir = filepath.Dir(k.runBin)
	cmd.Env = k.env
	cmd.SysProcAttr = childAttr()
	cmd.Stdout, cmd.Stderr = k.logs, k.logs
	cmd.WaitDelay = 2 * time.Second
	//Under the lock of the kit: an interrupted kit either sees this process in its
	//list and ends it, or the process is not started at all
	k.mu.Lock()
	if k.aborted {
		k.mu.Unlock()
		return nil, errors.New("the kit was interrupted")
	}
	if err := cmd.Start(); err != nil {
		k.mu.Unlock()
		return nil, err
	}
	p.cmd, p.pid, p.started = cmd, cmd.Process.Pid, time.Now()
	k.procs = append(k.procs, p)
	k.mu.Unlock()
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	go k.watchMemory(p)
	return p, nil
}

// waitReady waits until the port of the plugin accepts a connection
func (p *proc) waitReady(timeout time.Duration) (time.Duration, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) && !p.exited() {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p.port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return time.Since(p.started), true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return time.Since(p.started), false
}

// watchMemory samples the memory of the plugin and its children, and ends the
// plugin when it passes the cap: a plugin that eats memory must not take the
// machine the kit runs on with it.
func (k *kit) watchMemory(p *proc) {
	limit := int64(k.o.MemCapMB) << 20
	for n := 0; !p.exited(); n++ {
		if n%5 == 0 {
			p.track()
		}
		rss, ok := groupRSS(p.pid)
		if !ok {
			return
		}
		if rss > p.peakRSS.Load() {
			p.peakRSS.Store(rss)
		}
		if limit > 0 && rss > limit {
			p.memKilled.Store(true)
			p.signalGroup(syscall.SIGKILL)
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
}

// groupRSS is the resident memory of a process and its descendants (Linux only)
func groupRSS(pid int) (int64, bool) {
	total, found := int64(0), false
	seen := map[int]bool{}
	var walk func(pid, depth int)
	walk = func(pid, depth int) {
		if seen[pid] || depth > 8 || len(seen) > 512 {
			return
		}
		seen[pid] = true
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
		if err != nil {
			return
		}
		if f := strings.Fields(string(raw)); len(f) > 1 {
			if pages, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				total += pages * int64(os.Getpagesize())
				found = true
			}
		}
		//children are listed per thread, and a Go program starts them from any thread
		tasks, _ := filepath.Glob("/proc/" + strconv.Itoa(pid) + "/task/*/children")
		for _, task := range tasks {
			kids, _ := os.ReadFile(task)
			for _, c := range strings.Fields(string(kids)) {
				if n, err := strconv.Atoi(c); err == nil {
					walk(n, depth+1)
				}
			}
		}
	}
	walk(pid, 0)
	return total, found
}

/*
A stand-in for the plugin API of Zoraxy. A plugin that asks for API endpoints
gets the port of this listener as zoraxy_port and a key. Nothing here is a real
Zoraxy: every call is recorded and answered with an empty result.
*/
type apiCall struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	KeyOK    bool   `json:"key_ok"`
	Declared bool   `json:"declared"`
}

type stubAPI struct {
	port     int
	srv      *http.Server
	mu       sync.Mutex
	keys     map[string]bool
	declared map[string]bool
	calls    []apiCall
	total    int
}

func (k *kit) startStub() error {
	port, err := k.pickPort()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	s := &stubAPI{port: port, keys: map[string]bool{}, declared: map[string]bool{}}
	for _, ep := range k.m.PermittedAPIEndpoints {
		s.declared[ep.Method+" "+ep.Endpoint] = true
	}
	s.srv = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		call := apiCall{Method: r.Method, Path: r.URL.Path, KeyOK: s.keys[key], Declared: s.declared[r.Method+" "+r.URL.Path]}
		s.total++
		if len(s.calls) < 200 {
			s.calls = append(s.calls, call)
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case !call.KeyOK:
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		case !call.Declared:
			http.Error(w, `{"error":"endpoint not permitted"}`, http.StatusForbidden)
		case strings.HasSuffix(r.URL.Path, "/list"):
			io.WriteString(w, "[]")
		default:
			io.WriteString(w, `"OK"`)
		}
	})}
	go s.srv.Serve(ln)
	k.stub = s
	return nil
}

func (s *stubAPI) setKey(key string) {
	s.mu.Lock()
	s.keys[key] = true
	s.mu.Unlock()
}

func (s *stubAPI) snapshot() ([]apiCall, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]apiCall{}, s.calls...), s.total
}

// copyTree copies a plugin folder (regular files and folders only)
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case info.IsDir():
			return os.MkdirAll(target, 0o755)
		case info.Mode().IsRegular():
			return copyFile(path, target, info.Mode().Perm())
		}
		return nil //links, sockets and devices are not copied
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
