// Package secaudit is the security audit log: a dedicated, size-bounded,
// append-only JSON-lines file (conf/security_audit.log, mode 0600) that records
// who changed a security relevant setting, from which address, and what.
//
// Properties:
//   - Bounded: the current file is rotated at MaxBytes and MaxFiles files are
//     kept in total (current + MaxFiles-1 rotated). The oldest file is the one
//     that is dropped, never the entry being written: when the file cannot be
//     written the entry waits in a bounded in-memory queue and is retried with
//     the next entry (Stats reports the failures and the rare overflow).
//   - Tamper evident, not tamper proof: every entry carries the SHA-256 of the
//     previous entry and its own hash, so an edited, removed or reordered line
//     in the middle is found by Verify. Someone who can rewrite the whole file
//     can also rewrite the chain; ship the file off-box for that threat.
//   - Redacted: the detail of an entry is built from request parameters by key
//     name (see redact.go). Secrets are never written, and a listing runs the
//     redaction again over what it reads back.
package secaudit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults for the log size: 5 files of 5 MiB.
const (
	DefaultMaxBytes = 5 << 20
	DefaultMaxFiles = 5
	maxPending      = 1000
	maxLineBytes    = 16 << 10
)

// Event is what a caller records. Detail values are redacted by Record.
type Event struct {
	Actor   string
	IP      string
	Event   string
	Target  string
	Outcome string // ok, error, denied (empty means ok)
	Detail  map[string]string
}

// Entry is one stored line.
type Entry struct {
	Seq     uint64            `json:"seq"`
	Time    string            `json:"time"`
	Unix    int64             `json:"ts"`
	Actor   string            `json:"actor"`
	IP      string            `json:"ip,omitempty"`
	Event   string            `json:"event"`
	Target  string            `json:"target,omitempty"`
	Outcome string            `json:"outcome"`
	Detail  map[string]string `json:"detail,omitempty"`
	Prev    string            `json:"prev,omitempty"`
	Hash    string            `json:"hash,omitempty"`
}

// Options configures a Logger.
type Options struct {
	Path     string
	MaxBytes int64
	MaxFiles int
	Logf     func(format string, a ...any)
	Now      func() time.Time
}

// Logger is safe for concurrent use. A nil *Logger ignores Record.
type Logger struct {
	mu      sync.Mutex
	opt     Options
	seq     uint64
	last    string
	pending [][]byte
	stats   Stats
}

// Stats are counters for the viewer and for tests.
type Stats struct {
	Written       uint64 `json:"written"`
	WriteFailures uint64 `json:"writeFailures"`
	Queued        int    `json:"queued"`
	Dropped       uint64 `json:"dropped"`
	Rotations     uint64 `json:"rotations"`
}

// New opens (and creates) the log and resumes the hash chain from the last entry on disk.
func New(opt Options) (*Logger, error) {
	if opt.Path == "" {
		return nil, errors.New("secaudit: no path")
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = DefaultMaxBytes
	}
	if opt.MaxBytes < 1024 {
		opt.MaxBytes = 1024
	}
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = DefaultMaxFiles
	}
	if opt.MaxFiles < 2 {
		opt.MaxFiles = 2
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(opt.Path), 0o775); err != nil {
		return nil, err
	}
	l := &Logger{opt: opt, last: strings.Repeat("0", 64)}
	l.resume()
	for _, p := range l.files() { //tighten files from an older, laxer umask
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			os.Chmod(p, 0o600)
		}
	}
	return l, nil
}

func (l *Logger) logf(format string, a ...any) {
	if l.opt.Logf != nil {
		l.opt.Logf(format, a...)
	}
}

// files lists the log files newest first (current, .1, .2, ...) that exist.
func (l *Logger) files() []string {
	out := []string{}
	for i := 0; i < l.opt.MaxFiles; i++ {
		p := l.opt.Path
		if i > 0 {
			p += "." + strconv.Itoa(i)
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func readEntries(path string) []Entry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Hash != "" {
			out = append(out, e)
		}
	}
	return out
}

// resume continues the chain after the newest valid entry on disk.
func (l *Logger) resume() {
	for _, p := range l.files() {
		es := readEntries(p)
		if len(es) > 0 {
			e := es[len(es)-1]
			l.seq, l.last = e.Seq, e.Hash
			return
		}
	}
}

func entryHash(e Entry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Record redacts and appends one event. It never blocks on anything but the file write.
func (l *Logger) Record(ev Event) {
	if l == nil {
		return
	}
	now := l.opt.Now()
	outcome := ev.Outcome
	if outcome == "" {
		outcome = "ok"
	}
	e := Entry{
		Time: now.UTC().Format(time.RFC3339), Unix: now.Unix(),
		Actor: clip(cleanText(ev.Actor), 120), IP: clip(cleanText(ev.IP), 64),
		Event: clip(cleanText(ev.Event), 80), Target: RedactValue("target", ev.Target),
		Outcome: clip(cleanText(outcome), 16), Detail: RedactMap(ev.Detail),
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.seq + 1
	e.Prev = l.last
	e.Hash = entryHash(e)
	line, _ := json.Marshal(e)
	if len(line) > maxLineBytes { //a line this big can only come from a bug; keep the event, shrink the detail
		e.Detail = map[string]string{"note": "detail dropped, too large"}
		e.Hash = entryHash(e)
		line, _ = json.Marshal(e)
	}
	l.seq, l.last = e.Seq, e.Hash //the chain advances even while the file is not writable
	l.pending = append(l.pending, append(line, '\n'))
	l.flushLocked()
}

func (l *Logger) flushLocked() {
	for len(l.pending) > 0 {
		if err := l.appendLocked(l.pending[0]); err != nil {
			l.stats.WriteFailures++
			l.logf("security audit log: write failed, %d entries queued: %v", len(l.pending), err)
			break
		}
		l.stats.Written++
		l.pending = l.pending[1:]
	}
	if len(l.pending) > maxPending { //only reachable while the disk stays unwritable
		over := len(l.pending) - maxPending
		l.pending = l.pending[over:]
		l.stats.Dropped += uint64(over)
		l.logf("security audit log: %d oldest queued entries lost, the log file is not writable", over)
	}
	l.stats.Queued = len(l.pending)
}

func (l *Logger) appendLocked(line []byte) error {
	if fi, err := os.Stat(l.opt.Path); err == nil && fi.Size() > 0 && fi.Size()+int64(len(line)) > l.opt.MaxBytes {
		l.rotateLocked()
	}
	f, err := os.OpenFile(l.opt.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	f.Sync()
	return f.Close()
}

// rotateLocked shifts path -> path.1 -> ... and removes the oldest file. A failed
// rename is logged and the entry is still appended to the current file (the bound is
// soft in that case, an entry is never discarded for it).
func (l *Logger) rotateLocked() {
	last := l.opt.Path + "." + strconv.Itoa(l.opt.MaxFiles-1)
	os.Remove(last)
	for i := l.opt.MaxFiles - 2; i >= 1; i-- {
		from := l.opt.Path + "." + strconv.Itoa(i)
		if _, err := os.Stat(from); err != nil {
			continue
		}
		if err := os.Rename(from, l.opt.Path+"."+strconv.Itoa(i+1)); err != nil {
			l.logf("security audit log: rotate %s failed: %v", from, err)
			return
		}
	}
	if err := os.Rename(l.opt.Path, l.opt.Path+".1"); err != nil {
		l.logf("security audit log: rotate failed: %v", err)
		return
	}
	l.stats.Rotations++
}

// Stats returns the counters.
func (l *Logger) Stats() Stats {
	if l == nil {
		return Stats{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Queued = len(l.pending)
	return s
}

// Query selects entries for List.
type Query struct {
	Event  string // exact event name, or a prefix ending in "*" ("trustedproxy.*")
	Actor  string
	Before uint64 // only entries with a smaller sequence number (the Next value of the previous page)
	Limit  int    // default 50, at most 200
}

// Page is a listing result, newest first.
type Page struct {
	Entries []Entry `json:"entries"`
	Next    uint64  `json:"next"` // pass as Before for the following page, 0 when there is none
	Stats   Stats   `json:"stats"`
}

func matchEvent(filter, ev string) bool {
	if filter == "" {
		return true
	}
	if strings.HasSuffix(filter, "*") {
		return strings.HasPrefix(ev, strings.TrimSuffix(filter, "*"))
	}
	return filter == ev
}

// List returns a page of entries, newest first. Detail values are redacted again on
// the way out, so a line that was edited on disk or written by an older build cannot
// leak a secret through the API.
func (l *Logger) List(q Query) (Page, error) {
	if l == nil {
		return Page{Entries: []Entry{}}, nil
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	l.mu.Lock()
	files := l.files()
	l.mu.Unlock()
	page := Page{Entries: []Entry{}}
	for _, p := range files {
		es := readEntries(p)
		for i := len(es) - 1; i >= 0; i-- {
			e := es[i]
			if q.Before != 0 && e.Seq >= q.Before {
				continue
			}
			if !matchEvent(q.Event, e.Event) || (q.Actor != "" && e.Actor != q.Actor) {
				continue
			}
			if len(page.Entries) == limit {
				page.Next = page.Entries[len(page.Entries)-1].Seq
				page.Stats = l.Stats()
				return page, nil
			}
			e.Target = RedactValue("target", e.Target)
			e.Detail = RedactMap(e.Detail)
			e.Prev, e.Hash = "", "" //chain values are for Verify, not for the viewer
			page.Entries = append(page.Entries, e)
		}
	}
	page.Stats = l.Stats()
	return page, nil
}

// VerifyResult describes the state of the hash chain.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Entries  int    `json:"entries"`
	FirstSeq uint64 `json:"firstSeq"`
	BadSeq   uint64 `json:"badSeq,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

// Verify walks every kept file oldest first and checks the chain. The chain legitimately
// starts mid-way once the oldest files have been rotated out, so the first kept entry is
// trusted as the anchor.
func (l *Logger) Verify() VerifyResult {
	res := VerifyResult{OK: true}
	if l == nil {
		return res
	}
	l.mu.Lock()
	files := l.files()
	l.mu.Unlock()
	var prev string
	var prevSeq uint64
	for i := len(files) - 1; i >= 0; i-- {
		for _, e := range readEntries(files[i]) {
			if res.Entries == 0 {
				res.FirstSeq = e.Seq
			} else {
				if e.Seq != prevSeq+1 {
					return VerifyResult{Entries: res.Entries, FirstSeq: res.FirstSeq, BadSeq: e.Seq, Problem: fmt.Sprintf("sequence jumps from %d to %d (entries removed or reordered)", prevSeq, e.Seq)}
				}
				if e.Prev != prev {
					return VerifyResult{Entries: res.Entries, FirstSeq: res.FirstSeq, BadSeq: e.Seq, Problem: "link to the previous entry does not match"}
				}
			}
			if entryHash(e) != e.Hash {
				return VerifyResult{Entries: res.Entries, FirstSeq: res.FirstSeq, BadSeq: e.Seq, Problem: "entry content does not match its hash (edited)"}
			}
			prev, prevSeq = e.Hash, e.Seq
			res.Entries++
		}
	}
	return res
}

// Flush is a no-op kept for symmetry with other stores: Record writes synchronously.
func (l *Logger) Flush() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.flushLocked()
	l.mu.Unlock()
}
