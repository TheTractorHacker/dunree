package plugins

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
	Plugin output (phase 1 of docs/plugins/reliability-plan.md)

	Every output line of a plugin is counted and kept in a small ring in memory
	(shown in the Plugin Manager). Where it goes after that is a per plugin policy:

	- LogTarget = main (default): into the main Zoraxy log, as always;
	- LogTarget = file: into <plugin log dir>/<plugin id>.log, rotated at LogMaxKB
	  with one old file kept, so a plugin can use at most about twice that on disk.

	LogRateLimit (lines per second, default 0 = off) drops what is over the limit.
	Dropped lines are counted, and one line per 10 s says how many were dropped.
*/

const logDropReportEvery = 10 * time.Second

// logRateLimiter is a token bucket for the output of one plugin process: a burst
// of one second of lines, refilled at perSecond.
type logRateLimiter struct {
	mu        sync.Mutex
	perSecond int //0 = no limit
	tokens    float64
	last      time.Time
	dropped   int64 //since the last report
	reportAt  time.Time
}

// allow reports whether the line may pass. report > 0 asks the caller to write
// one line saying that this many lines were dropped.
func (l *logRateLimiter) allow(now time.Time) (ok bool, report int64) {
	if l.perSecond <= 0 {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.IsZero() {
		l.tokens = float64(l.perSecond)
		l.reportAt = now
	} else {
		l.tokens += now.Sub(l.last).Seconds() * float64(l.perSecond)
		if l.tokens > float64(l.perSecond) {
			l.tokens = float64(l.perSecond)
		}
	}
	l.last = now
	if l.dropped > 0 && now.Sub(l.reportAt) >= logDropReportEvery {
		report = l.dropped
		l.dropped = 0
		l.reportAt = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return true, report
	}
	if l.dropped == 0 && report == 0 {
		l.reportAt = now
	}
	l.dropped++
	return false, report
}

// pluginLogFile is the size limited log file of one plugin
type pluginLogFile struct {
	mu      sync.Mutex
	path    string //empty = not in use
	maxSize int64
	f       *os.File
	size    int64
	failed  bool //opening or writing failed: fall back to the main log
}

// pluginLogDir is the folder of the per plugin log files
func (m *Manager) pluginLogDir() string {
	if m.Options != nil && m.Options.PluginLogDir != "" {
		return m.Options.PluginLogDir
	}
	if m.Options != nil && m.Options.Logger != nil && m.Options.Logger.LogFolder != "" {
		return filepath.Join(m.Options.Logger.LogFolder, "plugins")
	}
	return filepath.Join("log", "plugins")
}

// pluginLogPath is the log file of a plugin. The name is the plugin ID reduced to
// harmless characters: an ID comes from the manifest of the plugin.
func (m *Manager) pluginLogPath(p *Plugin) string {
	var b strings.Builder
	for _, r := range p.Spec.ID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.TrimLeft(b.String(), ".")
	if name == "" {
		name = "plugin"
	}
	if len(name) > 120 {
		name = name[:120]
	}
	return filepath.Join(m.pluginLogDir(), name+".log")
}

// openPluginLog prepares the log file of a plugin for a new process (lifeMu held)
func (m *Manager) openPluginLog(p *Plugin, pol PluginPolicy) {
	lf := &p.logw
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.f != nil {
		lf.f.Close()
		lf.f = nil
	}
	lf.path, lf.failed, lf.size = "", false, 0
	if pol.LogTarget != LogTargetFile {
		return
	}
	path := m.pluginLogPath(p)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		lf.failed = true
		m.Log("plugin "+p.Spec.ID+": cannot create the plugin log folder, its output goes to the main log", err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		lf.failed = true
		m.Log("plugin "+p.Spec.ID+": cannot open its log file, its output goes to the main log", err)
		return
	}
	if fi, err := f.Stat(); err == nil {
		lf.size = fi.Size()
	}
	lf.f = f
	lf.path = path
	lf.maxSize = int64(pol.LogMaxKB) * 1024
}

// write appends one line. It returns false when the file is not in use (the caller
// then writes to the main log).
func (lf *pluginLogFile) write(line string) bool {
	lf.mu.Lock()
	defer lf.mu.Unlock()
	if lf.f == nil || lf.failed {
		return false
	}
	n := int64(len(line) + 1)
	if lf.size+n > lf.maxSize && lf.size > 0 {
		//Rotate: keep exactly one old file
		lf.f.Close()
		os.Remove(lf.path + ".1")
		os.Rename(lf.path, lf.path+".1")
		f, err := os.OpenFile(lf.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			lf.f, lf.failed = nil, true
			return false
		}
		lf.f, lf.size = f, 0
	}
	if n > lf.maxSize {
		//One line larger than the whole file: keep the head of it
		line = line[:lf.maxSize-1]
		n = lf.maxSize
	}
	if _, err := lf.f.WriteString(line + "\n"); err != nil {
		lf.failed = true
		return false
	}
	lf.size += n
	return true
}

func (lf *pluginLogFile) close() {
	lf.mu.Lock()
	if lf.f != nil {
		lf.f.Close()
		lf.f = nil
	}
	lf.mu.Unlock()
}

// routePluginOutput counts one output line of a plugin, keeps it in the ring and
// writes it to the log target of the plugin. proc is nil when the caller does not
// know the process (old entry points): then there is no rate limit.
func (m *Manager) routePluginOutput(p *Plugin, proc *pluginProc, pid int, stream string, line string) {
	p.obs.logLines.Add(1)
	p.noteAlive()
	now := time.Now()
	if proc != nil {
		ok, report := proc.logLimit.allow(now)
		if report > 0 {
			m.writePluginLine(p, pid, now, "log", "[zoraxy] "+strconv.FormatInt(report, 10)+" output lines of this plugin were dropped by its rate limit of "+strconv.Itoa(proc.logLimit.perSecond)+" lines per second")
		}
		if !ok {
			p.obs.logDropped.Add(1)
			return
		}
	}
	p.noteOutput(stream, line)
	m.writePluginLine(p, pid, now, stream, line)
}

func (m *Manager) writePluginLine(p *Plugin, pid int, now time.Time, stream string, line string) {
	if p.logw.write(now.Format("2006-01-02 15:04:05.000") + " [" + strconv.Itoa(pid) + "] " + stream + " " + line) {
		return
	}
	p.obs.mainLogLines.Add(1)
	m.Log("["+p.Spec.Name+":"+strconv.Itoa(pid)+"] "+line, nil)
}
