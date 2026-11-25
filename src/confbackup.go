package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/foleyit/dunree/mod/aiassist"
	"github.com/foleyit/dunree/mod/confpack"
	"github.com/foleyit/dunree/mod/crowdsec"
	"github.com/foleyit/dunree/mod/secaudit"
	"github.com/foleyit/dunree/mod/utils"
)

/*
	Configuration backup (zip export) and restore (zip import)

	Archive layout: every file of the config folder is stored as "conf/<relative path>" no matter where
	the folder lives (-conf flag), the optional system database as "sys.db", and since fork.21 a
	"manifest.json" (opt in for the full backup, always for shareable: schema version, Dunree version, mode, created time, size and SHA-256 of every entry).
	The logic lives in mod/confpack; this file is the HTTP side:

	  GET  /api/conf/export?mode=full|shareable&includeDB=true&manifest=true   full is the historic backup and CONTAINS SECRETS (manifest=true adds
                                                             manifest.json; without it the archive restores on older Dunree versions too);
	                                                             shareable is redacted and never carries keys or credentials
	  POST /api/conf/importcheck   (file)  dry run: validates the archive and reports what an import would add, replace and
	                                       remove. Changes nothing.
	  POST /api/conf/import        (file, format=json optional)  validates, backs up (<conf>.old_<unix>), stages and swaps
	                                       atomically; any failure restores the previous state.
*/

// importMu allows one import at a time
var importMu sync.Mutex

const maxImportUpload = 2<<30 + 1<<20

// skipFullExport are the per install files that even the full backup leaves out
func skipFullExport(rel string) bool {
	return aiassist.IsSecretFile(rel) || // the AI assistant key and its install key
		crowdsec.IsSecretFile(rel) || // the CrowdSec bouncer API key and its install key
		isAuditFile(rel) // per install: an export would copy addresses and user names out and an import must not replace it
}

// writeConfigZip writes the config folder (and optionally the system database) as a full backup archive
func writeConfigZip(out io.Writer, confDir string, dbPath string) error {
	_, err := confpack.WriteExport(out, confpack.ExportOptions{ConfDir: confDir, DBPath: dbPath, Mode: confpack.ModeFull,
		DunreeVersion: COMPAT_VERSION, SkipFull: skipFullExport, OmitManifest: true})
	return err
}

func ExportConfigAsZip(w http.ResponseWriter, r *http.Request) {
	includeSysDB, _ := utils.GetBool(r, "includeDB")
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if mode == "" {
		mode = confpack.ModeFull //today's behaviour stays the default
	}
	if mode != confpack.ModeFull && mode != confpack.ModeShareable {
		http.Error(w, "mode must be full or shareable", http.StatusBadRequest)
		return
	}

	if !utils.FileExists(CONF_FOLDER) {
		SystemWideLogger.PrintAndLog("Backup", "Configuration folder not found", nil)
		http.Error(w, "Configuration folder not found", http.StatusInternalServerError)
		return
	}

	dbPath := ""
	if includeSysDB && mode == confpack.ModeFull {
		dbPath = *path_database
	}

	name := "dunree-config-"
	if mode == confpack.ModeShareable {
		name = "dunree-config-shareable-"
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+time.Now().Format("2006-01-02-15-04-05")+".zip\"")
	//the full backup keeps the historic layout (no manifest.json: an older Dunree refuses an archive that has one);
	//manifest=true adds it for integrity checking. The shareable export always has one.
	withManifest, _ := utils.GetBool(r, "manifest")
	_, err := confpack.WriteExport(w, confpack.ExportOptions{ConfDir: CONF_FOLDER, DBPath: dbPath, Mode: mode,
		DunreeVersion: COMPAT_VERSION, SkipFull: skipFullExport, OmitManifest: mode == confpack.ModeFull && !withManifest})
	if err != nil {
		SystemWideLogger.PrintAndLog("Backup", "Unable to write the backup archive", err)
	}
}

// openUploadedArchive reads and validates the uploaded zip. status is the HTTP status to answer on error.
func openUploadedArchive(w http.ResponseWriter, r *http.Request) (a *confpack.Archive, cleanup func(), status int, err error) {
	cleanup = func() {}
	if r.Method != http.MethodPost {
		return nil, cleanup, http.StatusMethodNotAllowed, errors.New("Invalid request method")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImportUpload)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		return nil, cleanup, http.StatusBadRequest, errors.New("Failed to read the upload (too large or malformed)")
	}
	cleanup = func() {
		if r.MultipartForm != nil {
			r.MultipartForm.RemoveAll()
		}
	}
	file, handler, err := r.FormFile("file")
	if err != nil {
		return nil, cleanup, http.StatusBadRequest, errors.New("Failed to retrieve uploaded file")
	}
	prev := cleanup
	cleanup = func() { file.Close(); prev() }
	if filepath.Ext(handler.Filename) != ".zip" {
		return nil, cleanup, http.StatusBadRequest, errors.New("Upload file is not a zip file")
	}
	zipReader, err := zip.NewReader(file, handler.Size)
	if err != nil {
		return nil, cleanup, http.StatusBadRequest, fmt.Errorf("Failed to open zip file: %v", err)
	}
	a, err = confpack.Inspect(zipReader, confpack.DefaultLimits)
	if err != nil {
		return nil, cleanup, http.StatusBadRequest, err
	}
	return a, cleanup, 0, nil
}

func importPlanOptions() confpack.PlanOptions {
	return confpack.PlanOptions{ConfDir: CONF_FOLDER, DBPath: *path_database, Preserve: isAuditFile}
}

// ImportCheckConfigZip is the dry run: nothing is changed, the answer says what an import would do
func ImportCheckConfigZip(w http.ResponseWriter, r *http.Request) {
	a, cleanup, status, err := openUploadedArchive(w, r)
	defer cleanup()
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	rep, err := confpack.Plan(a, importPlanOptions())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(rep)
}

func recordImportAudit(r *http.Request, outcome string, detail map[string]string) {
	actor, _ := historyActor(r)
	if actor == "" {
		actor = "admin"
	}
	ip := r.RemoteAddr
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	secAudit.Record(secaudit.Event{Actor: actor, IP: ip, Event: "config.import.result", Outcome: outcome, Detail: detail})
}

func ImportConfigFromZip(w http.ResponseWriter, r *http.Request) {
	if !importMu.TryLock() {
		http.Error(w, "another import is running", http.StatusConflict)
		return
	}
	defer importMu.Unlock()
	a, cleanup, status, err := openUploadedArchive(w, r)
	defer cleanup()
	if err != nil {
		if r.Method == http.MethodPost {
			SystemWideLogger.PrintAndLog("Backup", "Configuration import refused", err)
			recordImportAudit(r, "denied", map[string]string{"reason": err.Error()})
		}
		http.Error(w, err.Error(), status)
		return
	}

	opts := confpack.ApplyOptions{PlanOptions: importPlanOptions(), BeforeDB: func() {
		//Sysdb replacement. Close the database before the file is overwritten
		sysdb.Close()
	}}
	res, err := confpack.Apply(a, opts)
	if err != nil {
		SystemWideLogger.PrintAndLog("Backup", "Configuration restore failed", err)
		recordImportAudit(r, "error", map[string]string{"mode": a.Mode, "verified": strconv.FormatBool(a.Verified), "error": err.Error()})
		http.Error(w, err.Error(), http.StatusInternalServerError)
		if res != nil && res.DBClosed {
			go restartAfterImport("the system database was closed during a failed import")
		}
		return
	}
	recordImportAudit(r, "ok", map[string]string{
		"mode": res.Mode, "verified": strconv.FormatBool(res.Verified), "added": strconv.Itoa(res.NAdded), "replaced": strconv.Itoa(res.NReplaced),
		"removed": strconv.Itoa(res.NRemoved), "kept": strconv.Itoa(res.NKept), "database": strconv.FormatBool(res.DBReplaced), "backup": res.BackupDir,
		"credentialsIgnored": strconv.Itoa(res.SecretsIgnored),
	})

	SystemWideLogger.Println("Configuration restored")
	if r.FormValue("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Configuration restored")
	}

	if res.DBReplaced {
		go restartAfterImport("Database altered")
	}
}

func restartAfterImport(why string) {
	SystemWideLogger.Println(why + ". Restarting in 3 seconds...")
	time.Sleep(3 * time.Second)
	os.Exit(0)
}

// isAuditFile matches the per install audit logs: the security audit and the login and session audit, rotated copies included
func isAuditFile(rel string) bool {
	return isSecurityAuditFile(rel) || rel == authAuditFile || strings.HasPrefix(rel, authAuditFile+".")
}

// authAuditFile is the login and session audit log (start.go points mod/auth at CONF_FOLDER + "/" + authAuditFile)
const authAuditFile = "auth_audit.log"

// isSecurityAuditFile matches conf/security_audit.log and its rotated copies
func isSecurityAuditFile(rel string) bool {
	return rel == securityAuditFile || strings.HasPrefix(rel, securityAuditFile+".")
}
