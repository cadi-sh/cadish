package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReapOrphanedTempBlobs (R01e): a stray wip-* temp file (residue of a crashed
// mid-write) must be removed at startup and never counted toward the budget.
func TestReapOrphanedTempBlobs(t *testing.T) {
	dir := t.TempDir()
	blobDir := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(blobDir, "wip-deadbeef")
	if err := os.WriteFile(orphan, []byte("partial-body-from-a-crashed-write"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A committed (sha256-named) blob alongside it must be untouched: drop a plausible
	// non-wip file to prove the reaper only targets the wip- prefix.
	keep := filepath.Join(blobDir, "0123456789abcdef")
	if err := os.WriteFile(keep, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	d, err := NewDiskTier(dir, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("orphaned wip-* temp blob still present after startup (err=%v); it must be reaped", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("non-wip file was wrongly removed: %v", err)
	}
	// The orphan never counted toward the budget.
	if got := d.Bytes(); got != 0 {
		t.Errorf("Bytes()=%d after reaping; a wip-* orphan must never count toward the budget", got)
	}
	// Sanity: the writer's temp prefix really is wip- (guards the reaper's match string).
	w, _ := d.Writer(ObjectMeta{Key: "/x", Size: 1})
	if dw, ok := w.(*diskWriter); ok {
		if base := filepath.Base(dw.tmp.Name()); !strings.HasPrefix(base, "wip-") {
			t.Errorf("diskWriter temp name %q lost the wip- prefix the reaper matches", base)
		}
	}
	_ = w.Abort()
}
