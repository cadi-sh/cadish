package cache

import (
	"io"
	"strings"
	"testing"
)

// TestCrossTierDedupKeepsSiblingOnRAMOverflow is the BUG-2 regression (R14): a re-store
// that routes to RAM and OVERFLOWS the per-object cap stores NOTHING, yet ramWriter.Commit
// returns nil. dedupWriter must NOT treat that nil as "stored" and delete the existing disk
// sibling — doing so leaves the key resident in NEITHER tier, silently destroying the only
// cached copy (and its grace / max_stale-on-error fallback) at the worst possible time.
func TestCrossTierDedupKeepsSiblingOnRAMOverflow(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          64 << 20,
		DiskMaxBytes:         64 << 20,
		SmallObjectThreshold: 1 << 20,
		RAMMaxObjectBytes:    8, // tiny per-object RAM cap to force overflow
		DiskDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const key = "/clip"
	// 1. Store the real copy on DISK.
	writeObj(t, st, key, "the-disk-copy", TierDisk)
	if body, tier, ok := readObj(t, st, key); !ok || tier != TierDisk || body != "the-disk-copy" {
		t.Fatalf("after disk store: body=%q tier=%q ok=%v, want the-disk-copy/disk/true", body, tier, ok)
	}

	// 2. Re-store the SAME key routed to RAM with UNKNOWN size (so routing keeps it in RAM)
	//    but a body that exceeds the per-object cap, so the bounded ramWriter OVERFLOWS and
	//    installs nothing. The destination tier stored nothing, so the disk sibling MUST
	//    survive.
	big := strings.Repeat("x", 4096) // >> 8-byte per-object cap
	w, err := st.Writer(ObjectMeta{Key: key, Size: -1, Tier: TierRAM})
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := io.WriteString(w, big); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// RAM must hold nothing (it overflowed).
	if r, ok := st.ram.Get(key); ok {
		r.Close()
		t.Fatal("RAM unexpectedly holds the overflowed object")
	}
	// The disk sibling MUST still be retrievable — the overflow re-store must not destroy it.
	body, tier, ok := readObj(t, st, key)
	if !ok {
		t.Fatal("key resident in NEITHER tier after an overflow re-store: the disk sibling was destroyed (BUG-2)")
	}
	if tier != TierDisk || body != "the-disk-copy" {
		t.Fatalf("served body=%q tier=%q, want the-disk-copy/disk (original disk copy preserved)", body, tier)
	}
}

// TestCrossTierDedupKeepsSiblingOnDiskOversize is the symmetric BUG-2 case: a re-store that
// routes to DISK and is discarded as oversize (per-shard cap) stores nothing, yet
// DiskTier.commit returns nil — the RAM sibling must survive.
func TestCrossTierDedupKeepsSiblingOnDiskOversize(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          64 << 20,
		DiskMaxBytes:         64, // minuscule disk tier: per-shard cap forces an oversize discard
		SmallObjectThreshold: 1 << 20,
		DiskDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const key = "/seg"
	// 1. Store the real copy in RAM.
	writeObj(t, st, key, "the-ram-copy", TierRAM)
	if _, tier, ok := readObj(t, st, key); !ok || tier != TierRAM {
		t.Fatalf("after ram store: tier=%q ok=%v, want ram/true", tier, ok)
	}

	// 2. Re-store the SAME key routed to DISK with a body that exceeds the per-shard cap,
	//    so DiskTier.commit discards it (oversize) without storing. The RAM sibling must
	//    survive.
	big := strings.Repeat("y", 4096) // >> 64-byte disk tier
	w, err := st.Writer(ObjectMeta{Key: key, Size: -1, Tier: TierDisk})
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := io.WriteString(w, big); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The RAM sibling MUST still be retrievable.
	body, tier, ok := readObj(t, st, key)
	if !ok {
		t.Fatal("key resident in NEITHER tier after a disk-oversize re-store: the RAM sibling was destroyed (BUG-2)")
	}
	if tier != TierRAM || body != "the-ram-copy" {
		t.Fatalf("served body=%q tier=%q, want the-ram-copy/ram (original RAM copy preserved)", body, tier)
	}
}
