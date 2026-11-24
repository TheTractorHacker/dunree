package legacycompat

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/foleyit/dunree/mod/apitoken"
	db "github.com/foleyit/dunree/mod/database"
)

type quietLog struct{}

func (quietLog) PrintAndLog(string, string, error) {}

// legacyInstall is a working folder the way the base program leaves it: conf/, sys.db, sys.uuid, plugins/.
type legacyInstall struct {
	root, conf, db, uuid, plugins string
	token                         string // an API token created before the upgrade
}

func write(t *testing.T, p string, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func newLegacyInstall(t *testing.T) *legacyInstall {
	t.Helper()
	root := t.TempDir()
	in := &legacyInstall{root: root, conf: filepath.Join(root, "conf"), db: filepath.Join(root, "sys.db"),
		uuid: filepath.Join(root, "sys.uuid"), plugins: filepath.Join(root, "plugins")}
	write(t, filepath.Join(in.conf, "version"), "336", 0o775)
	write(t, filepath.Join(in.conf, "config_schema.json"), `{"schema":1,"updated":"2026-10-01T00:00:00Z","by":"Zoraxy 3.3.6"}`, 0o644) // legacy-compat
	write(t, filepath.Join(in.conf, "proxy", "app.example.com.config"), `{"ProxyType":1,"RootOrMatchingDomain":"app.example.com","ActiveOrigins":[{"OriginIpOrDomain":"10.0.0.5:8080"}]}`, 0o775)
	write(t, filepath.Join(in.conf, "proxy", "root.config"), `{"ProxyType":0,"RootOrMatchingDomain":"/"}`, 0o775)
	write(t, filepath.Join(in.conf, "certs", "app.example.com.pem"), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", 0o644)
	write(t, filepath.Join(in.conf, "certs", "app.example.com.key"), "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n", 0o600)
	write(t, filepath.Join(in.conf, "access", "default.json"), `{"ID":"default"}`, 0o775)
	write(t, filepath.Join(in.conf, "redirect", "old.example.com.json"), `{"RedirectURL":"old.example.com"}`, 0o775)
	write(t, filepath.Join(in.conf, "acme_conf.json"), `{"Email":"admin@example.com"}`, 0o775)
	write(t, filepath.Join(in.conf, "webui", "webui.key"), "KEY", 0o600)
	write(t, filepath.Join(in.conf, ".history", "000001.json"), `{"n":1}`, 0o644)
	write(t, filepath.Join(in.conf, "geodb", "geoip.mmdb"), strings.Repeat("G", 4096), 0o644)
	if runtime.GOOS != "windows" {
		if err := os.Symlink("app.example.com.pem", filepath.Join(in.conf, "certs", "default.pem")); err != nil {
			t.Fatal(err)
		}
	}
	write(t, in.uuid, "0b0c9a1e-2222-4333-8444-555566667777", 0o775)
	write(t, filepath.Join(in.plugins, "helloworld", "helloworld"), "#!/bin/sh\n", 0o755)
	write(t, filepath.Join(in.plugins, "helloworld", "store", "data.json"), `{"k":"v"}`, 0o644)

	d, err := db.NewDatabase(in.db, db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	d.NewTable("auth")
	d.Write("auth", "passhash/admin", "argon2id$stored-hash")
	d.NewTable("settings")
	d.Write("settings", "sessionkey", "0123456789abcdef0123456789abcdef")
	tm, err := apitoken.NewManager(d, quietLog{})
	if err != nil {
		t.Fatal(err)
	}
	if in.token, _, err = tm.Create("monitoring", apitoken.ScopeRead, 0, nil); err != nil {
		t.Fatal(err)
	}
	d.Close()
	return in
}

// snapshot maps every path below root to "<mode> <sha256>" (or "dir <mode>", "link <target>").
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			out[rel] = "dir"
		case d.Type()&fs.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			out[rel] = "link " + l
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s := sha256.Sum256(b)
			out[rel] = fmt.Sprintf("%o %s", info.Mode().Perm(), hex.EncodeToString(s[:]))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func without(m map[string]string, prefixes ...string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		skip := false
		for _, p := range prefixes {
			if k == p || strings.HasPrefix(k, p+string(filepath.Separator)) {
				skip = true
			}
		}
		if !skip {
			out[k] = v
		}
	}
	return out
}

func diff(a, b map[string]string) string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, fmt.Sprintf("%s: %q != %q", k, v, b[k]))
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, "extra: "+k)
		}
	}
	sort.Strings(d)
	return strings.Join(d, "\n")
}

func backupsOf(t *testing.T, p string) []string {
	t.Helper()
	m, _ := filepath.Glob(p + BackupInfix + "*")
	return m
}

var firstStartTime = time.Date(2026, 11, 24, 10, 15, 0, 0, time.UTC)

func (in *legacyInstall) opts() FirstStartOptions {
	return FirstStartOptions{ConfDir: in.conf, DBPath: in.db, Version: "1.0.0-beta.1", BasedOn: "3.3.6", Now: firstStartTime}
}

// The first Dunree start on an existing install: nothing in the install changes except one added marker
// file, a full copy is taken once, and the database still holds the accounts and API tokens.
func TestFirstStartOnExistingInstall(t *testing.T) {
	in := newLegacyInstall(t)
	before := snapshot(t, in.root)

	res, err := FirstStart(in.opts())
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionMigrated || res.Marker.Origin != OriginLegacy {
		t.Fatalf("action %q origin %q", res.Action, res.Marker.Origin)
	}
	wantConfBackup := in.conf + BackupInfix + "20261124-101500"
	wantDBBackup := in.db + BackupInfix + "20261124-101500"
	if res.Marker.ConfBackup != wantConfBackup || res.Marker.DBBackup != wantDBBackup {
		t.Fatalf("backups: %q %q", res.Marker.ConfBackup, res.Marker.DBBackup)
	}

	//1. no data loss: every file that existed is byte and mode identical; the only additions are the marker and the copies
	after := snapshot(t, in.root)
	added := without(after, "conf"+BackupInfix+"20261124-101500", "sys.db"+BackupInfix+"20261124-101500", filepath.Join("conf", MarkerFile))
	if d := diff(before, added); d != "" {
		t.Fatalf("the install was changed by the first start:\n%s", d)
	}

	//2. the copy is the configuration folder as it was (without the downloaded geodb)
	wantCopy := without(snapshot(t, in.conf), MarkerFile, "geodb")
	if d := diff(wantCopy, snapshot(t, wantConfBackup)); d != "" {
		t.Fatalf("the copy differs from the original:\n%s", d)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(wantConfBackup)
		if st.Mode().Perm() != 0o700 {
			t.Fatalf("the copy holds keys and must be private, mode %o", st.Mode().Perm())
		}
		if st, _ := os.Stat(filepath.Join(wantConfBackup, "certs", "app.example.com.key")); st.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode in the copy: %o", st.Mode().Perm())
		}
	}
	a, _ := os.ReadFile(in.db)
	b, _ := os.ReadFile(wantDBBackup)
	if len(a) == 0 || string(a) != string(b) {
		t.Fatal("database copy differs from the database")
	}
	if res.Files < 9 || res.Bytes == 0 {
		t.Fatalf("copy statistics: %d files %d bytes", res.Files, res.Bytes)
	}

	//3. the marker
	m, ok := ReadMarker(in.conf)
	if !ok || !reflect.DeepEqual(m, res.Marker) || m.Product != "dunree" || m.FirstVersion != "1.0.0-beta.1" || m.BasedOn != "3.3.6" || m.FirstStart != "2026-11-24T10:15:00Z" {
		t.Fatalf("marker: %+v", m)
	}

	//4. the database still works: account record, session key and the API token of before the upgrade
	d, err := db.NewDatabase(in.db, db.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var hash, key string
	if d.Read("auth", "passhash/admin", &hash) != nil || hash != "argon2id$stored-hash" {
		t.Fatalf("admin account lost: %q", hash)
	}
	if d.Read("settings", "sessionkey", &key) != nil || key != "0123456789abcdef0123456789abcdef" {
		t.Fatal("session key lost: sessions would not survive")
	}
	tm, err := apitoken.NewManager(d, quietLog{})
	if err != nil {
		t.Fatal(err)
	}
	if l := tm.List(); len(l) != 1 || l[0].Name != "monitoring" || l[0].Revoked {
		t.Fatalf("API tokens after the upgrade: %+v", l)
	}
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Header.Set("Authorization", "Bearer "+in.token)
	r.RemoteAddr = "127.0.0.1:5555"
	w := httptest.NewRecorder()
	tm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("the API token of before the upgrade is refused: %d %s", w.Code, w.Body.String())
	}
}

// Every later start does nothing: no second copy, marker untouched, even much later.
func TestFirstStartIsIdempotent(t *testing.T) {
	in := newLegacyInstall(t)
	if _, err := FirstStart(in.opts()); err != nil {
		t.Fatal(err)
	}
	after1 := snapshot(t, in.root)
	for i := 1; i <= 3; i++ {
		o := in.opts()
		o.Now = firstStartTime.Add(time.Duration(i) * 24 * time.Hour)
		res, err := FirstStart(o)
		if err != nil || res.Action != ActionNone {
			t.Fatalf("run %d: action %q err %v", i+1, res.Action, err)
		}
		if res.Marker.Origin != OriginLegacy || res.Marker.ConfBackup == "" {
			t.Fatalf("run %d must report the stored marker: %+v", i+1, res.Marker)
		}
	}
	if d := diff(after1, snapshot(t, in.root)); d != "" {
		t.Fatalf("a later start changed something:\n%s", d)
	}
	if n := len(backupsOf(t, in.conf)); n != 1 {
		t.Fatalf("want exactly one copy of conf, got %d", n)
	}
	if n := len(backupsOf(t, in.db)); n != 1 {
		t.Fatalf("want exactly one copy of the database, got %d", n)
	}
}

// A new install gets a marker and nothing else, so its second start is not taken for an upgrade.
func TestFirstStartFreshInstall(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	o := FirstStartOptions{ConfDir: conf, DBPath: filepath.Join(root, "sys.db"), Fresh: true, Version: "1.0.0-beta.1", Now: firstStartTime}
	res, err := FirstStart(o)
	if err != nil || res.Action != ActionFresh {
		t.Fatalf("action %q err %v", res.Action, err)
	}
	m, ok := ReadMarker(conf)
	if !ok || m.Origin != OriginDunree || m.ConfBackup != "" || m.DBBackup != "" {
		t.Fatalf("marker: %+v ok=%v", m, ok)
	}
	//second start: files exist now (Fresh is false), still nothing is copied
	write(t, filepath.Join(conf, "proxy", "a.config"), "{}", 0o644)
	o.Fresh = false
	res, err = FirstStart(o)
	if err != nil || res.Action != ActionNone {
		t.Fatalf("second start: action %q err %v", res.Action, err)
	}
	if len(backupsOf(t, conf)) != 0 {
		t.Fatal("a Dunree install must never get a pre-dunree copy")
	}
}

// When the marker is lost (a full configuration import replaces the folder) the existing copy is kept and
// no second one is taken.
func TestFirstStartMarkerLostKeepsSingleCopy(t *testing.T) {
	in := newLegacyInstall(t)
	if _, err := FirstStart(in.opts()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(in.conf, MarkerFile)); err != nil {
		t.Fatal(err)
	}
	o := in.opts()
	o.Now = firstStartTime.Add(time.Hour)
	res, err := FirstStart(o)
	if err != nil || res.Action != ActionAdopted {
		t.Fatalf("action %q err %v", res.Action, err)
	}
	if len(backupsOf(t, in.conf)) != 1 || len(backupsOf(t, in.db)) != 1 {
		t.Fatalf("copies: %v %v", backupsOf(t, in.conf), backupsOf(t, in.db))
	}
	if m, ok := ReadMarker(in.conf); !ok || m.ConfBackup != in.conf+BackupInfix+"20261124-101500" {
		t.Fatalf("marker must point at the first copy: %+v", m)
	}
}

// A copy that cannot be completed leaves no half copy and no marker, changes nothing, and is retried.
func TestFirstStartCopyFailureIsRetried(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file the test cannot read")
	}
	in := newLegacyInstall(t)
	locked := filepath.Join(in.conf, "certs", "app.example.com.key")
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o600) })
	before := snapshot2(t, in.conf, locked)

	res, err := FirstStart(in.opts())
	if err == nil {
		t.Fatal("want an error when a file cannot be copied")
	}
	if !strings.Contains(err.Error(), in.conf) {
		t.Fatalf("the error must name the folder: %v", err)
	}
	if _, ok := ReadMarker(in.conf); ok {
		t.Fatal("no marker may be written when the copy failed")
	}
	if all, _ := filepath.Glob(in.conf + ".pre-dunree-*"); len(all) != 0 {
		t.Fatalf("a failed copy must leave nothing behind: %v", all)
	}
	if d := diff(before, snapshot2(t, in.conf, locked)); d != "" {
		t.Fatalf("the configuration changed:\n%s", d)
	}
	_ = res

	os.Chmod(locked, 0o600)
	res, err = FirstStart(in.opts())
	if err != nil || res.Action != ActionMigrated {
		t.Fatalf("retry: action %q err %v", res.Action, err)
	}
}

// snapshot2 is snapshot that tolerates one unreadable file.
func snapshot2(t *testing.T, root string, unreadable string) map[string]string {
	t.Helper()
	st, _ := os.Stat(unreadable)
	mode := st.Mode().Perm()
	os.Chmod(unreadable, 0o600)
	defer os.Chmod(unreadable, mode)
	s := snapshot(t, root)
	rel, _ := filepath.Rel(root, unreadable)
	s[rel] = "x " + strings.SplitN(s[rel], " ", 2)[1]
	return s
}

// A database over the limit is not copied; the marker says so and the start is not held up.
func TestFirstStartLargeDatabaseNotCopied(t *testing.T) {
	in := newLegacyInstall(t)
	o := in.opts()
	o.MaxDBCopy = 16
	res, err := FirstStart(o)
	if err != nil || res.Action != ActionMigrated {
		t.Fatalf("action %q err %v", res.Action, err)
	}
	if res.Marker.DBBackup != "" || len(backupsOf(t, in.db)) != 0 {
		t.Fatal("database over the limit was copied")
	}
	if res.Marker.ConfBackup == "" {
		t.Fatal("the configuration copy does not depend on the database")
	}
	if !strings.Contains(strings.Join(res.Marker.Notes, "\n"), "database not copied") {
		t.Fatalf("the marker must say why: %v", res.Marker.Notes)
	}
}

// A folder database (LevelDB) is copied as a folder; a configuration folder that is a symbolic link is followed.
func TestFirstStartFolderDatabaseAndLinkedConf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	in := newLegacyInstall(t)
	os.Remove(in.db)
	write(t, filepath.Join(in.db, "000001.log"), "leveldb-log", 0o644)
	write(t, filepath.Join(in.db, "CURRENT"), "MANIFEST-000000\n", 0o644)
	real := filepath.Join(in.root, "data", "conf")
	os.MkdirAll(filepath.Dir(real), 0o775)
	if err := os.Rename(in.conf, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, in.conf); err != nil {
		t.Fatal(err)
	}
	res, err := FirstStart(in.opts())
	if err != nil || res.Action != ActionMigrated {
		t.Fatalf("action %q err %v", res.Action, err)
	}
	if b, _ := os.ReadFile(filepath.Join(res.Marker.DBBackup, "CURRENT")); string(b) != "MANIFEST-000000\n" {
		t.Fatalf("folder database not copied: %q", res.Marker.DBBackup)
	}
	if b, _ := os.ReadFile(filepath.Join(res.Marker.ConfBackup, "proxy", "app.example.com.config")); len(b) == 0 {
		t.Fatal("a linked configuration folder was not copied")
	}
	if st, err := os.Lstat(in.conf); err != nil || st.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("the link itself must stay a link")
	}
}

// Review regression: with "-conf ." the copy used to be "..pre-dunree-..." inside the working folder, so the
// walk copied the copy into itself until the path was too long, failed, and did the same at every start.
func TestFirstStartConfDotDoesNotCopyItself(t *testing.T) {
	parent := t.TempDir()
	conf := filepath.Join(parent, "work")
	write(t, filepath.Join(conf, "proxy", "a.config"), `{"x":1}`, 0o644)
	write(t, filepath.Join(conf, "acme_conf.json"), `{}`, 0o644)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(conf); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	res, err := FirstStart(FirstStartOptions{ConfDir: ".", Now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("first start with -conf .: %v", err)
	}
	want := filepath.Join(parent, "work"+BackupInfix+"20261124-100000")
	if res.Action != ActionMigrated || res.Marker.ConfBackup != want || res.Files != 2 {
		t.Fatalf("action %s backup %q files %d, want migrated %q 2", res.Action, res.Marker.ConfBackup, res.Files, want)
	}
	ents, _ := os.ReadDir(conf)
	for _, e := range ents {
		if strings.Contains(e.Name(), BackupInfix) {
			t.Errorf("copy left inside the configuration folder: %s", e.Name())
		}
	}
	if b, err := os.ReadFile(filepath.Join(want, "proxy", "a.config")); err != nil || string(b) != `{"x":1}` {
		t.Errorf("copy incomplete: %q %v", b, err)
	}
}

// Review regression: the copy must never be walked into when it lies inside the tree being copied.
func TestCopyTreeSkipsItsOwnDestination(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a.json"), "a", 0o644)
	dst := filepath.Join(root, "inner"+BackupInfix+"x")
	n, _, err := copyTreeAtomic(root, dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("copied %d files, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(dst, filepath.Base(dst)+partialSuffix)); err == nil {
		t.Error("the copy contains itself")
	}
}

// Review regression: finding the earlier copy must not depend on glob syntax (a [ in the path, and on
// Windows no escaping at all): a lost marker must never lead to a second copy.
func TestFirstStartMarkerLostWithSpecialCharsInPath(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "site [1] *x?", "conf")
	if runtime.GOOS == "windows" {
		conf = filepath.Join(t.TempDir(), "site [1]", "conf")
	}
	write(t, filepath.Join(conf, "a.json"), "a", 0o644)
	r1, err := FirstStart(FirstStartOptions{ConfDir: conf, Now: time.Unix(100, 0)})
	if err != nil || r1.Action != ActionMigrated {
		t.Fatalf("first: %v %v", r1.Action, err)
	}
	os.Remove(filepath.Join(conf, MarkerFile))
	r2, err := FirstStart(FirstStartOptions{ConfDir: conf, Now: time.Unix(200, 0)})
	if err != nil || r2.Action != ActionAdopted || r2.Marker.ConfBackup != r1.Marker.ConfBackup {
		t.Fatalf("second: %v %q %v, want adopted %q", r2.Action, r2.Marker.ConfBackup, err, r1.Marker.ConfBackup)
	}
	if got := existingBackups(conf); len(got) != 1 {
		t.Errorf("copies: %v", got)
	}
}
