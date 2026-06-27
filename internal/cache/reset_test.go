package cache

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStoreResetEmptiesReloadedDiskTier proves Store.Reset drops blobs that a freshly
// reopened store loaded from a persisted on-disk index — the reload flush primitive
// used when a site's cache-key scheme changed. After Reset a Get misses, the blob
// files are gone, and a SUBSEQUENT reopen of the same dir loads nothing (the index was
// emptied), so a colliding old-recipe key can never serve a stale object.
func TestStoreResetEmptiesReloadedDiskTier(t *testing.T) {
	dir := t.TempDir()
	body := []byte("served:/p?x=1")

	// Seed a store and persist its index (Close flushes), simulating the previous run.
	s0, err := NewStore(RouterConfig{DiskDir: dir, DiskMaxBytes: 100 << 20, RAMMaxBytes: 0})
	if err != nil {
		t.Fatalf("NewStore s0: %v", err)
	}
	w, err := s0.disk.Writer(ObjectMeta{Key: "host\x1f/p", Size: int64(len(body))})
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s0.Close(); err != nil {
		t.Fatalf("Close s0: %v", err)
	}

	// Reopen (the reload cold store): it loads the persisted blob.
	s1, err := NewStore(RouterConfig{DiskDir: dir, DiskMaxBytes: 100 << 20, RAMMaxBytes: 0})
	if err != nil {
		t.Fatalf("NewStore s1: %v", err)
	}
	if _, _, ok := s1.GetTier("host\x1f/p"); !ok {
		t.Fatal("precondition: reopened store should have loaded the persisted blob")
	}

	// Flush.
	s1.Reset()
	if _, _, ok := s1.GetTier("host\x1f/p"); ok {
		t.Fatal("after Reset: blob still present in reopened store")
	}
	// Blob files removed.
	ents, _ := os.ReadDir(filepath.Join(dir, "blobs"))
	for _, e := range ents {
		if e.Name() != "" && e.Name()[0] != '.' {
			t.Fatalf("after Reset: stray blob file %q remains", e.Name())
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close s1: %v", err)
	}

	// A further reopen must load nothing (index was emptied + persisted).
	s2, err := NewStore(RouterConfig{DiskDir: dir, DiskMaxBytes: 100 << 20, RAMMaxBytes: 0})
	if err != nil {
		t.Fatalf("NewStore s2: %v", err)
	}
	defer s2.Close()
	if _, _, ok := s2.GetTier("host\x1f/p"); ok {
		t.Fatal("after Reset+reopen: stale blob reloaded from a non-emptied index")
	}
}
