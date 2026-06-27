package cache

import (
	"io"
	"testing"
)

// writeObj streams body into the store under key with an explicit tier override and
// commits it.
func writeObj(t *testing.T, st *Store, key, body, tier string) {
	t.Helper()
	w, err := st.Writer(ObjectMeta{Key: key, Size: int64(len(body)), Tier: tier})
	if err != nil {
		t.Fatalf("Writer(%s,%s): %v", key, tier, err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatalf("Write(%s): %v", key, err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit(%s): %v", key, err)
	}
}

func readObj(t *testing.T, st *Store, key string) (string, string, bool) {
	t.Helper()
	r, tier, ok := st.GetTier(key)
	if !ok {
		return "", "", false
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll(%s): %v", key, err)
	}
	return string(b), tier, true
}

// TestCrossTierDedupNewerWins (R14): a key first stored in RAM then re-committed (newer
// content) to disk must serve the NEWER disk copy, not the stale RAM shadow. GetTier
// returns RAM before disk, so without cross-tier eviction the stale RAM copy would
// shadow the fresh disk copy forever — serving superseded content as a fresh HIT.
func TestCrossTierDedupNewerWins(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          64 << 20,
		DiskMaxBytes:         64 << 20,
		SmallObjectThreshold: 1 << 20,
		DiskDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const key = "/clip"
	writeObj(t, st, key, "OLD-ram-copy", TierRAM)
	if body, tier, ok := readObj(t, st, key); !ok || tier != TierRAM || body != "OLD-ram-copy" {
		t.Fatalf("after RAM store: body=%q tier=%q ok=%v, want OLD-ram-copy/ram/true", body, tier, ok)
	}

	// Re-store a newer copy that routes to DISK (tier flip).
	writeObj(t, st, key, "NEW-disk-copy", TierDisk)

	body, tier, ok := readObj(t, st, key)
	if !ok {
		t.Fatal("key missing after disk re-store")
	}
	if body != "NEW-disk-copy" {
		t.Errorf("served body=%q, want NEW-disk-copy (the stale RAM shadow must be evicted)", body)
	}
	if tier != TierDisk {
		t.Errorf("served tier=%q, want disk", tier)
	}
	// The RAM tier must no longer hold the key (cross-tier dedup deleted it).
	if r, ok := st.ram.Get(key); ok {
		r.Close()
		t.Errorf("stale RAM copy still resident after disk re-store; cross-tier dedup did not evict it")
	}
}

// TestCrossTierDedupReverse (R14): the symmetric direction — disk first, then RAM —
// must also evict the disk sibling (and drop its blob).
func TestCrossTierDedupReverse(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          64 << 20,
		DiskMaxBytes:         64 << 20,
		SmallObjectThreshold: 1 << 20,
		DiskDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const key = "/seg"
	writeObj(t, st, key, "OLD-disk-copy", TierDisk)
	writeObj(t, st, key, "NEW-ram-copy", TierRAM)

	body, tier, ok := readObj(t, st, key)
	if !ok || body != "NEW-ram-copy" || tier != TierRAM {
		t.Fatalf("served body=%q tier=%q ok=%v, want NEW-ram-copy/ram/true", body, tier, ok)
	}
	if r, ok := st.disk.Get(key); ok {
		r.Close()
		t.Errorf("stale disk copy still resident after RAM re-store; cross-tier dedup did not evict it")
	}
}

// TestSameTierRestoreUnaffected: a same-tier re-store still replaces in place and the
// (absent) sibling delete is a harmless no-op.
func TestSameTierRestoreUnaffected(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          64 << 20,
		DiskMaxBytes:         64 << 20,
		SmallObjectThreshold: 1 << 20,
		DiskDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const key = "/p"
	writeObj(t, st, key, "v1", TierRAM)
	writeObj(t, st, key, "v2", TierRAM)
	if body, tier, ok := readObj(t, st, key); !ok || body != "v2" || tier != TierRAM {
		t.Fatalf("body=%q tier=%q ok=%v, want v2/ram/true", body, tier, ok)
	}
}
