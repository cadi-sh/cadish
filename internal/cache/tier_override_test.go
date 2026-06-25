package cache

import (
	"io"
	"testing"
)

// newOverrideStore builds a small store with a known per-object RAM cap so the
// tier-override safety fallback is exercisable.
func newOverrideStore(t *testing.T) *Store {
	t.Helper()
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          1 << 20,
		RAMMaxObjectBytes:    1000,
		DiskMaxBytes:         1 << 20,
		DiskDir:              t.TempDir(),
		SmallObjectThreshold: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestTierFor covers the placement resolution: explicit override wins over the
// size policy, with the forced-RAM-too-big safety fallback to disk.
func TestTierFor(t *testing.T) {
	st := newOverrideStore(t)
	tests := []struct {
		name string
		meta ObjectMeta
		want Tier
	}{
		{"disk override beats m3u8-always-RAM", ObjectMeta{Key: "p.m3u8", Size: 10, Tier: TierDisk}, st.disk},
		{"ram override beats disk-routed-ext", ObjectMeta{Key: "big.bin", Size: 500, Tier: TierRAM}, st.ram},
		{"ram override honored for unknown size", ObjectMeta{Key: "x.bin", Size: -1, Tier: TierRAM}, st.ram},
		{"ram override too big -> disk safety", ObjectMeta{Key: "huge.bin", Size: 2000, Tier: TierRAM}, st.disk},
		{"no override -> automatic (small image to RAM)", ObjectMeta{Key: "t.jpg", Size: 50}, st.ram},
		{"no override -> automatic (big.bin to disk)", ObjectMeta{Key: "big.bin", Size: 5000}, st.disk},
	}
	for _, c := range tests {
		if got := st.tierFor(c.meta); got != c.want {
			ramWant := c.want == st.ram
			t.Errorf("%s: tierFor → RAM=%v, want RAM=%v", c.name, got == st.ram, ramWant)
		}
	}
}

// TestTierExtensions: `cache { tier .ext -> … }` per-extension defaults route by
// extension, and a per-request meta.Tier override still wins over the config default.
func TestTierExtensions(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          1 << 20,
		DiskMaxBytes:         1 << 20,
		DiskDir:              t.TempDir(),
		SmallObjectThreshold: 100,
		TierExtensions:       map[string]string{".mp4": TierDisk, ".html": TierRAM},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// A SMALL .mp4 (would be RAM by size) goes to disk per the extension default.
	if got := st.tierFor(ObjectMeta{Key: "clip.mp4", Size: 10}); got != st.disk {
		t.Errorf(".mp4 extension → not disk; want disk")
	}
	// A LARGE .html (would be disk by size) goes to RAM per the extension default.
	if got := st.tierFor(ObjectMeta{Key: "page.html", Size: 5000}); got != st.ram {
		t.Errorf(".html extension → not RAM; want RAM")
	}
	// A per-request `storage` override beats the extension default.
	if got := st.tierFor(ObjectMeta{Key: "clip.mp4", Size: 10, Tier: TierRAM}); got != st.ram {
		t.Errorf("meta.Tier override did not beat the tier-extension default")
	}
	// An unconfigured extension still uses the size policy.
	if got := st.tierFor(ObjectMeta{Key: "data.bin", Size: 5000}); got != st.disk {
		t.Errorf("unconfigured ext → not size-policy disk")
	}
}

// TestTierOverridePersistsAcrossReload: an object forced to disk by a tier rule is
// still on the disk tier after the store is closed and reopened.
func TestTierOverridePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	cfg := RouterConfig{RAMMaxBytes: 1 << 20, DiskMaxBytes: 1 << 20, DiskDir: dir}

	st1, err := NewStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// A small jpg normally routes to RAM; force it to disk.
	w, err := st1.Writer(ObjectMeta{Key: "forced.jpg", Size: 4, ContentType: "image/jpeg", Tier: TierDisk})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "data")
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = st1.Close() // flush the disk index

	st2, err := NewStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if _, tier, ok := st2.GetTier("forced.jpg"); !ok || tier != TierDisk {
		t.Errorf("after reload: forced.jpg tier = %q (ok=%v), want disk", tier, ok)
	}
}

// TestTierForDiskFallbackRAMOnly: a `-> disk` override on a RAM-only store (no
// disk budget) falls back to RAM so the object is cached somewhere, not nowhere.
func TestTierForDiskFallbackRAMOnly(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:  1 << 20,
		DiskMaxBytes: 0, // RAM-only deployment
		DiskDir:      t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if got := st.tierFor(ObjectMeta{Key: "x.jpg", Size: 100, Tier: TierDisk}); got != st.ram {
		t.Errorf("force-disk with no disk budget → not RAM; want RAM fallback")
	}
}

// TestWriterHonorsTierOverride proves the full write path: a `storage -> disk`
// override lands a normally-RAM object on disk (and vice-versa), confirmed by
// GetTier.
func TestWriterHonorsTierOverride(t *testing.T) {
	st := newOverrideStore(t)

	// An image normally routes to RAM; force it to disk.
	wd, err := st.Writer(ObjectMeta{Key: "forced.jpg", Size: 4, ContentType: "image/jpeg", Tier: TierDisk})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(wd, "data")
	if err := wd.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, tier, ok := st.GetTier("forced.jpg"); !ok || tier != TierDisk {
		t.Errorf("forced.jpg tier = %q (ok=%v), want disk", tier, ok)
	}

	// A large unknown-ext object normally routes to disk; force it to RAM.
	wr, err := st.Writer(ObjectMeta{Key: "forced.bin", Size: 500, Tier: TierRAM})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = wr.Write(make([]byte, 500))
	if err := wr.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, tier, ok := st.GetTier("forced.bin"); !ok || tier != TierRAM {
		t.Errorf("forced.bin tier = %q (ok=%v), want ram", tier, ok)
	}

	// No override → automatic policy still applies.
	wa, _ := st.Writer(ObjectMeta{Key: "auto.bin", Size: 5000})
	_, _ = wa.Write(make([]byte, 5000))
	_ = wa.Commit()
	if _, tier, _ := st.GetTier("auto.bin"); tier != TierDisk {
		t.Errorf("auto.bin tier = %q, want disk (automatic)", tier)
	}
}
