package baseline

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/TheTractorHacker/dunree/mod/confpack"
)

// Probe is what is looked at, before this start touches anything, to decide whether this is a new install.
type Probe struct {
	DBExisted   bool  //sys.db (file or folder) already existed
	DBErr       error //it could not be examined
	SchemaStamp int   //config schema stamp found in the config folder (0 = none)
	StampErr    error //the stamp exists but cannot be read
	ConfFiles   int   //regular files already in the config folder (proxy rules, certificates, access rules, anything)
	ConfErr     error //the folder could not be examined
}

// CaptureProbe reads the three facts. It never writes. Call it before the config schema migration and
// before the database is opened, because both create files.
func CaptureProbe(dbPath, confDir string) Probe {
	var p Probe
	if _, err := os.Stat(dbPath); err == nil {
		p.DBExisted = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		p.DBErr = err
	}
	p.SchemaStamp, p.StampErr = confpack.ReadSchema(confDir)
	err := filepath.WalkDir(confDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == confDir {
				return filepath.SkipAll //a folder that does not exist yet has nothing in it
			}
			return err
		}
		if d.Type().IsRegular() || d.Type()&fs.ModeSymlink != 0 {
			p.ConfFiles++
			return filepath.SkipAll //one is enough to know this is not a new folder
		}
		return nil
	})
	p.ConfErr = err
	return p
}

// IsFresh is deliberately conservative: only a start that finds no database, no schema stamp and
// no file at all in the config folder is a new install. Anything unreadable or unexpected is an
// existing install. The reason is for the log.
func IsFresh(p Probe) (bool, string) {
	switch {
	case p.DBErr != nil:
		return false, "the database path could not be examined"
	case p.DBExisted:
		return false, "a database already exists"
	case p.StampErr != nil:
		return false, "the config schema stamp is unreadable"
	case p.SchemaStamp != 0:
		return false, "the config folder carries a schema stamp from an earlier start"
	case p.ConfErr != nil:
		return false, "the config folder could not be examined"
	case p.ConfFiles != 0:
		return false, "the config folder already holds files (proxy rules, certificates or settings)"
	}
	return true, "no database, no schema stamp and an empty config folder"
}
