package cache

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDiskCachePerms verifies the local-hardening fixes (security review #10/#11):
// the blob directory is 0700 (no cache-presence oracle) and index.json is 0600 (no
// leak of cached URLs/paths).
func TestDiskCachePerms(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	putTier(t, d, "private/token-abc.m3u8", "data", "application/vnd.apple.mpegurl")
	if err := d.Close(); err != nil { // final synchronous index flush
		t.Fatal(err)
	}

	blobDir := filepath.Join(dir, "blobs")
	fi, err := os.Stat(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("blob dir perm = %o, want 0700", perm)
	}

	idx := filepath.Join(dir, "index.json")
	fi2, err := os.Stat(idx)
	if err != nil {
		t.Fatalf("index.json not written: %v", err)
	}
	if perm := fi2.Mode().Perm(); perm != 0o600 {
		t.Errorf("index.json perm = %o, want 0600", perm)
	}
}
