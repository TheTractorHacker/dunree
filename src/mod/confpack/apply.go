package confpack

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxListed bounds the file lists of a report; the counts stay exact.
const maxListed = 300

// Report says what an import would do (dry run) or did.
type Report struct {
	Mode            string   `json:"mode"`
	Verified        bool     `json:"verified"`
	DunreeVersion   string   `json:"zoraxyVersion,omitempty"`
	Created         string   `json:"created,omitempty"`
	SchemaVersion   int      `json:"schemaVersion"`
	HasDB           bool     `json:"hasDB"`
	Added           []string `json:"added"`
	Replaced        []string `json:"replaced"`
	Removed         []string `json:"removed"`
	Kept            []string `json:"kept"` // live files that stay as they are (secrets a shareable archive cannot carry, the audit log)
	Unchanged       int      `json:"unchanged"`
	NAdded          int      `json:"nAdded"`
	NReplaced       int      `json:"nReplaced"`
	NRemoved        int      `json:"nRemoved"`
	NKept           int      `json:"nKept"`
	Truncated       bool     `json:"truncated,omitempty"`
	SecretsKept     int      `json:"secretsKept"`    // redacted fields that keep their current value
	SecretsDropped  int      `json:"secretsDropped"` // redacted fields with no current value (left out)
	SecretsIgnored  int      `json:"secretsIgnored"` // shareable archive only: credential fields that held a real value in the archive; the live value was kept instead
	DBReplaced      bool     `json:"dbReplaced"`
	RestartRequired bool     `json:"restartRequired"`
	Warnings        []string `json:"warnings"`
}

type action struct {
	rel     string
	entry   *Entry
	content []byte      // non nil: merged JSON to write instead of the entry bytes
	carry   string      // live file to copy over (kept files)
	mode    os.FileMode // permission bits of the staged file
}

type planned struct {
	rep     Report
	actions []action
	hasConf bool
}

// PlanOptions are the inputs shared by Plan and Apply.
type PlanOptions struct {
	ConfDir  string
	DBPath   string
	Preserve func(rel string) bool // live files an import never replaces or removes (the audit log)
}

func sha256File(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// liveFiles lists the regular files of the config folder. skipped lists what an import cannot carry over because it
// is not a regular file (a symlink such as certs/ pointing at another folder); those stay only in the backup folder.
func liveFiles(confDir string) (map[string]string, []string, error) {
	out := map[string]string{}
	var skipped []string
	err := filepath.WalkDir(confDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == confDir {
				return filepath.SkipDir
			}
			return err
		}
		rel, _ := filepath.Rel(confDir, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".history" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			out[rel] = p
		} else if d.Type()&fs.ModeSymlink != 0 {
			skipped = append(skipped, rel)
		}
		return nil
	})
	return out, skipped, err
}

// stagedMode decides the permission bits of a file written into the staging folder: the file it replaces keeps its
// mode (an import must not loosen what the operator tightened); a new file is private when it can hold credentials
// (proxy rules carry basic auth hashes, acme_conf.json, keys, the system database) and 0644 otherwise.
func stagedMode(rel, livePath string) os.FileMode {
	if livePath != "" {
		if st, err := os.Stat(livePath); err == nil {
			return st.Mode().Perm()
		}
	}
	if sensitivePath(rel) || rel == "sys.db" || rel == "acme_conf.json" || strings.HasPrefix(rel, "proxy/") || strings.HasPrefix(rel, "certs/") {
		return 0o600
	}
	return 0o644
}

func addCapped(list *[]string, n *int, trunc *bool, s string) {
	*n++
	if len(*list) < maxListed {
		*list = append(*list, s)
	} else {
		*trunc = true
	}
}

func hasPrivateKey(p string) bool {
	b, err := os.ReadFile(p)
	return err == nil && strings.Contains(string(b), "PRIVATE KEY-----")
}

func plan(a *Archive, o PlanOptions) (*planned, error) {
	pl := &planned{}
	r := &pl.rep
	r.Mode, r.Verified, r.HasDB = a.Mode, a.Verified, a.HasDB
	r.Warnings = append([]string{}, a.Warnings...)
	r.Added, r.Replaced, r.Removed, r.Kept = []string{}, []string{}, []string{}, []string{}
	if m := a.Manifest; m != nil {
		r.DunreeVersion, r.Created, r.SchemaVersion = m.DunreeVersion, m.Created, m.SchemaVersion
	}
	live, symlinks, err := liveFiles(o.ConfDir)
	if err != nil {
		return nil, err
	}
	if len(symlinks) > 0 {
		show := symlinks
		if len(show) > 5 {
			show = show[:5]
		}
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d symbolic link(s) in the current config folder (%s) are not carried over; they stay only in the backup folder of this import", len(symlinks), strings.Join(show, ", ")))
	}
	shareable := a.Mode == ModeShareable
	inArchive := map[string]bool{}
	for i := range a.Entries {
		e := &a.Entries[i]
		if e.DB {
			continue
		}
		pl.hasConf = true
		inArchive[e.Rel] = true
		if o.Preserve != nil && o.Preserve(e.Rel) {
			continue //a backup never replaces the audit log of this install
		}
		livePath, exists := live[e.Rel]
		if shareable && KeepLiveAlways(e.Rel) {
			continue //the version and schema stamp describe this install; an archive must never rewind or advance them
		}
		if shareable && exists && strings.HasPrefix(e.Rel, "certs/") {
			continue //a certificate file that exists here is never replaced by a key-less one; reported as kept below
		}
		act := action{rel: e.Rel, entry: e, mode: stagedMode(e.Rel, livePath)}
		newSHA := e.SHA
		if shareable && isJSONName(e.Rel) {
			raw, err := readEntry(e)
			if err != nil {
				return nil, err
			}
			var existing []byte
			if exists {
				existing, _ = os.ReadFile(livePath)
			}
			//a shareable archive is not trusted to carry credentials: real looking values in credential fields are
			//refused and the live ones kept, whatever the (self consistent) manifest says
			merged, kept, dropped, ignored, err := MergeShareable(raw, existing)
			if err != nil {
				return nil, fmt.Errorf("%q: %v", e.Rel, err)
			}
			r.SecretsKept += kept
			r.SecretsDropped += dropped
			r.SecretsIgnored += ignored
			act.content = merged
			h := sha256.Sum256(merged)
			newSHA = hex.EncodeToString(h[:])
		}
		pl.actions = append(pl.actions, act)
		switch {
		case !exists:
			addCapped(&r.Added, &r.NAdded, &r.Truncated, e.Rel)
		case sha256File(livePath) == newSHA:
			r.Unchanged++
		default:
			addCapped(&r.Replaced, &r.NReplaced, &r.Truncated, e.Rel)
		}
	}
	if pl.hasConf {
		rels := make([]string, 0, len(live))
		for rel := range live {
			rels = append(rels, rel)
		}
		sort.Strings(rels)
		for _, rel := range rels {
			p := live[rel]
			switch {
			case o.Preserve != nil && o.Preserve(rel):
				pl.actions = append(pl.actions, action{rel: rel, carry: p})
				addCapped(&r.Kept, &r.NKept, &r.Truncated, rel)
			case shareable && (KeepLiveAlways(rel) || KeptOnShareableImport(rel) || strings.HasPrefix(rel, "certs/") || hasPrivateKeyIfRaw(rel, p)):
				if !inArchive[rel] || strings.HasPrefix(rel, "certs/") || KeepLiveAlways(rel) {
					pl.actions = append(pl.actions, action{rel: rel, carry: p})
					addCapped(&r.Kept, &r.NKept, &r.Truncated, rel)
				}
			case !inArchive[rel]:
				addCapped(&r.Removed, &r.NRemoved, &r.Truncated, rel)
			}
		}
	}
	r.DBReplaced = a.HasDB
	//the running modules keep their in memory state and can write it over a restored folder: any import needs a restart
	r.RestartRequired = a.HasDB || pl.hasConf
	if r.SecretsIgnored > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d credential field(s) in this shareable archive held a real value; they were ignored and the current values kept (a shareable archive cannot set credentials)", r.SecretsIgnored))
	}
	if shareable {
		r.Warnings = append(r.Warnings, "shareable archive: existing secrets, keys and credentials are kept; redacted fields keep their current value")
	} else if a.Manifest != nil {
		r.Warnings = append(r.Warnings, "full backup: the current configuration is replaced as a whole, including TLS keys, the cluster secret and credentials")
	}
	return pl, nil
}

func hasPrivateKeyIfRaw(rel, p string) bool {
	if k, _ := ShareableKind(rel); k == "raw" {
		return hasPrivateKey(p)
	}
	return false
}

func readEntry(e *Entry) ([]byte, error) {
	rc, err := e.f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, DefaultLimits.MaxJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > DefaultLimits.MaxJSONBytes {
		return nil, fmt.Errorf("%q is too large", e.Rel)
	}
	return b, nil
}

// Plan is the dry run: it reports what Apply would replace, add and remove and changes nothing.
func Plan(a *Archive, o PlanOptions) (*Report, error) {
	pl, err := plan(a, o)
	if err != nil {
		return nil, err
	}
	return &pl.rep, nil
}

// ApplyOptions extends PlanOptions.
type ApplyOptions struct {
	PlanOptions
	Now      func() time.Time
	BeforeDB func()                   // called right before the system database file is replaced (close it)
	Fault    func(stage string) error // test seam: "stage", "swap-conf", "swap-db"
}

// Result is what Apply did.
type Result struct {
	Report
	BackupDir string `json:"backupDir,omitempty"`
	DBBackup  string `json:"dbBackup,omitempty"`
	DBClosed  bool   `json:"-"` // BeforeDB ran and the replacement then failed: the caller must restart
}

func sensitivePath(rel string) bool {
	if bad, _ := NeverExported(rel); bad {
		return true
	}
	return strings.HasPrefix(rel, "certs/") && strings.HasSuffix(strings.ToLower(rel), ".pem")
}

func writeStaged(dst string, rel string, e *Entry, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o775); err != nil {
		return err
	}
	if mode == 0 {
		mode = 0o600
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if content != nil {
		if _, err := out.Write(content); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	rc, err := e.f.Open()
	if err != nil {
		out.Close()
		return err
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, DefaultLimits.MaxFileBytes+1))
	if err != nil {
		out.Close()
		return err
	}
	if n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA {
		out.Close()
		return fmt.Errorf("%q changed while it was being restored", rel)
	}
	return out.Close()
}

// Apply installs the archive atomically. Everything is first written into a staging folder next to
// the config folder; the live folder is only touched by two renames at the end (live -> <conf>.old_<unix>
// as the automatic backup, staging -> live), and any failure after the first rename puts the old folder
// back. The system database, when part of the archive, is staged the same way and swapped last
// (the old file is kept as <db>.pre-import_<unix>); a failure there rolls the config swap back too.
func Apply(a *Archive, o ApplyOptions) (*Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	fault := func(s string) error {
		if o.Fault != nil {
			return o.Fault(s)
		}
		return nil
	}
	pl, err := plan(a, o.PlanOptions)
	if err != nil {
		return nil, err
	}
	res := &Result{Report: pl.rep}
	ts := fmt.Sprint(o.Now().Unix())
	confDir := filepath.Clean(o.ConfDir)
	parent := filepath.Dir(confDir)
	if err := os.MkdirAll(parent, 0o775); err != nil {
		return nil, err
	}

	var stage, dbStage string
	cleanup := func() {
		if stage != "" {
			os.RemoveAll(stage)
		}
		if dbStage != "" {
			os.Remove(dbStage)
		}
	}
	if pl.hasConf {
		stage, err = os.MkdirTemp(parent, filepath.Base(confDir)+".staging_")
		if err != nil {
			return nil, fmt.Errorf("cannot create a staging folder next to the config folder: %w", err)
		}
		if err := os.Chmod(stage, 0o775); err != nil {
			cleanup()
			return nil, err
		}
		for _, act := range pl.actions {
			dst := filepath.Join(stage, filepath.FromSlash(act.rel))
			if act.carry != "" {
				if err := os.MkdirAll(filepath.Dir(dst), 0o775); err == nil {
					err = copyFile(act.carry, dst)
				}
				if err != nil {
					cleanup()
					return nil, fmt.Errorf("could not carry over %q: %w", act.rel, err)
				}
				continue
			}
			if err := writeStaged(dst, act.rel, act.entry, act.content, act.mode); err != nil {
				cleanup()
				return nil, fmt.Errorf("could not stage %q: %w", act.rel, err)
			}
		}
	}
	if a.HasDB {
		for i := range a.Entries {
			if !a.Entries[i].DB {
				continue
			}
			dbStage = o.DBPath + ".staging_" + ts
			if err := writeStaged(dbStage, "sys.db", &a.Entries[i], nil, stagedMode("sys.db", o.DBPath)); err != nil {
				cleanup()
				return nil, fmt.Errorf("could not stage the system database: %w", err)
			}
		}
	}
	if err := fault("stage"); err != nil {
		cleanup()
		return nil, err
	}

	// --- point of no return starts here: from now on every failure restores ---
	oldDir := ""
	swapped := false
	histMoved := false
	// rollbackConf puts the old folder back. It never fails silently: when it cannot, the error names the folder
	// that still holds the previous configuration.
	rollbackConf := func() error {
		if histMoved { //the change history goes back with the old folder
			os.Rename(filepath.Join(confDir, ".history"), filepath.Join(oldDir, ".history"))
			histMoved = false
		}
		if _, err := os.Lstat(confDir); err == nil { //the new folder, or one a module recreated in between
			failed := confDir + ".failed_" + ts
			if _, err := os.Lstat(failed); err == nil {
				failed = fmt.Sprintf("%s_%d", failed, os.Getpid())
			}
			if err := os.Rename(confDir, failed); err != nil {
				return fmt.Errorf("could not move the new config folder aside, the previous configuration is in %q: %w", oldDir, err)
			}
			if swapped {
				os.RemoveAll(failed)
			}
		}
		if oldDir != "" {
			if err := os.Rename(oldDir, confDir); err != nil {
				return fmt.Errorf("could not restore the previous config folder, it is still in %q: %w", oldDir, err)
			}
		}
		return nil
	}
	wrapRollback := func(err error) error {
		if rerr := rollbackConf(); rerr != nil {
			return fmt.Errorf("%w; %v", err, rerr)
		}
		return err
	}
	if pl.hasConf {
		if _, err := os.Stat(confDir); err == nil {
			oldDir = confDir + ".old_" + ts
			if _, err := os.Stat(oldDir); err == nil {
				oldDir = fmt.Sprintf("%s.old_%s_%d", confDir, ts, os.Getpid())
			}
			if err := os.Rename(confDir, oldDir); err != nil {
				oldDir = ""
				cleanup()
				return nil, fmt.Errorf("unable to back up the current config folder: %w", err)
			}
		}
		if err := fault("swap-conf"); err != nil {
			err = wrapRollback(err)
			cleanup()
			return nil, err
		}
		if err := os.Rename(stage, confDir); err != nil {
			err = wrapRollback(fmt.Errorf("could not install the new configuration: %w", err))
			cleanup()
			return nil, err
		}
		swapped, stage = true, ""
		res.BackupDir = oldDir
	}
	if a.HasDB {
		if o.BeforeDB != nil {
			o.BeforeDB()
			res.DBClosed = true
		}
		bak := ""
		if _, err := os.Stat(o.DBPath); err == nil {
			bak = o.DBPath + ".pre-import_" + ts
			if err := os.Rename(o.DBPath, bak); err != nil {
				err = wrapRollback(fmt.Errorf("unable to back up the system database: %w", err))
				cleanup()
				return res, err
			}
		}
		err := fault("swap-db")
		if err == nil {
			err = os.Rename(dbStage, o.DBPath)
		}
		if err != nil {
			if bak != "" {
				os.Rename(bak, o.DBPath)
			}
			err = wrapRollback(fmt.Errorf("could not install the system database: %w", err))
			cleanup()
			res.BackupDir = ""
			return res, err
		}
		dbStage = ""
		res.DBBackup = bak
	}
	if swapped && oldDir != "" {
		//the sealed change history belongs to this install, not to the archive: carry it into the new folder
		//(a rename inside one parent folder), the restore points stay usable
		if st, err := os.Lstat(filepath.Join(oldDir, ".history")); err == nil && st.IsDir() {
			if _, err := os.Lstat(filepath.Join(confDir, ".history")); err != nil {
				if err := os.Rename(filepath.Join(oldDir, ".history"), filepath.Join(confDir, ".history")); err == nil {
					histMoved = true
				} else {
					res.Warnings = append(res.Warnings, "the change history could not be carried over and stays in "+oldDir)
				}
			}
		}
	}
	cleanup()
	return res, nil
}
