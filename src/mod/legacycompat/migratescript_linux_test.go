//go:build linux

package legacycompat

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Review regression: a move between two file systems is a copy and a delete that cannot be undone half way:
// the script refuses it before it stops anything.
func TestMigrateServiceScriptRefusesCrossFilesystemMove(t *testing.T) {
	h := newFakeHost(t, true, true)
	other, err := os.MkdirTemp("/dev/shm", "dunree-migrate-")
	if err != nil {
		t.Skip("no /dev/shm")
	}
	defer os.RemoveAll(other)
	var a, b syscall.Stat_t
	if syscall.Stat(other, &a) != nil || syscall.Stat(h.root, &b) != nil || a.Dev == b.Dev {
		t.Skip("/dev/shm is on the same file system as the temp folder")
	}
	if err := os.Symlink(other, filepath.Join(h.root, "mnt")); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, filepath.Join(h.root, "opt"))
	out, code := h.run(nil, "--new-dir", "/mnt/dunree")
	if code != 2 || !strings.Contains(out, "different file systems") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if d := diff(before, snapshot(t, filepath.Join(h.root, "opt"))); d != "" || !h.active(oldUnitName) {
		t.Fatalf("a refused run changed something:\n%s", d)
	}
}
