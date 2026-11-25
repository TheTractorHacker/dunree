package statistic

import (
	"os"
	"testing"
	"time"

	"github.com/TheTractorHacker/dunree/mod/database"
	"github.com/TheTractorHacker/dunree/mod/database/dbinc"
)

func newRetentionCollector(t *testing.T) (*Collector, *database.Database) {
	t.Helper()
	dbPath := t.TempDir() + "/retention_db"
	db, err := database.NewDatabase(dbPath, dbinc.BackendLevelDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); os.RemoveAll(dbPath) })
	c, err := NewStatisticCollector(CollectorOption{Database: db})
	if err != nil {
		t.Fatal(err)
	}
	return c, db
}

func seedDays(db *database.Database, ages ...int) {
	for _, a := range ages {
		db.Write("stats", summaryKeyOf(time.Now().AddDate(0, 0, -a)), map[string]int{"TotalRequest": a})
	}
}

func TestRetentionOffKeepsEverything(t *testing.T) {
	c, db := newRetentionCollector(t)
	seedDays(db, 0, 1, 40, 400, 2000)
	if n := c.PruneOldDays(); n != 0 {
		t.Fatalf("retention 0 deleted %d records", n)
	}
	if err := c.SetSettings(DefaultSettings()); err != nil {
		t.Fatal(err)
	}
	for _, a := range []int{0, 1, 40, 400, 2000} {
		if !db.KeyExists("stats", summaryKeyOf(time.Now().AddDate(0, 0, -a))) {
			t.Fatalf("day -%d was deleted with retention off", a)
		}
	}
}

func TestRetentionDeletesOnlyOlderDays(t *testing.T) {
	c, db := newRetentionCollector(t)
	seedDays(db, 0, 1, 29, 30, 31, 90, 400, 2000)
	s := DefaultSettings()
	s.RetentionDays = 30
	if err := c.SetSettings(s); err != nil { // applying the setting prunes at once
		t.Fatal(err)
	}
	keep := map[int]bool{0: true, 1: true, 29: true, 30: true, 31: false, 90: false, 400: false, 2000: false}
	for a, want := range keep {
		if got := db.KeyExists("stats", summaryKeyOf(time.Now().AddDate(0, 0, -a))); got != want {
			t.Errorf("day -%d kept=%v, want %v (retention 30 days)", a, got, want)
		}
	}
	if n := c.PruneOldDays(); n != 0 {
		t.Errorf("a second prune deleted %d records", n)
	}
}

func TestRetentionValidation(t *testing.T) {
	c, _ := newRetentionCollector(t)
	for _, bad := range []int{-1, 1, 6, 3651, 100000} {
		s := DefaultSettings()
		s.RetentionDays = bad
		if err := c.SetSettings(s); err == nil {
			t.Errorf("retention %d must be refused", bad)
		}
	}
	for _, ok := range []int{0, 7, 90, 3650} {
		s := DefaultSettings()
		s.RetentionDays = ok
		if err := c.SetSettings(s); err != nil {
			t.Errorf("retention %d must be accepted: %v", ok, err)
		}
	}
}

func TestRetentionRunsAtDayRollover(t *testing.T) {
	c, db := newRetentionCollector(t)
	s := DefaultSettings()
	s.RetentionDays = 7
	c.SetSettings(s)
	seedDays(db, 8, 20)
	c.summaryKey = summaryKeyOf(time.Now().AddDate(0, 0, -1))
	c.SaveSummaryOfDay() // rolls the day over
	if db.KeyExists("stats", summaryKeyOf(time.Now().AddDate(0, 0, -8))) || db.KeyExists("stats", summaryKeyOf(time.Now().AddDate(0, 0, -20))) {
		t.Fatal("the day rollover must prune the records older than the retention")
	}
	if !db.KeyExists("stats", summaryKeyOf(time.Now().AddDate(0, 0, -1))) {
		t.Fatal("yesterday's record must survive")
	}
}
