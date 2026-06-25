package cache

import "testing"

// TestObjectMetaEffectiveStatus pins the zero-value → 200 mapping (legacy/positive
// entries) and the explicit negative status.
func TestObjectMetaEffectiveStatus(t *testing.T) {
	if got := (ObjectMeta{}).EffectiveStatus(); got != 200 {
		t.Errorf("zero status EffectiveStatus=%d, want 200", got)
	}
	if got := (ObjectMeta{Status: 404}).EffectiveStatus(); got != 404 {
		t.Errorf("EffectiveStatus=%d, want 404", got)
	}
}

// TestRAMNegativeEntry stores a bodyless negative (410) entry in the RAM tier and
// confirms it reads back with the right status and zero size.
func TestRAMNegativeEntry(t *testing.T) {
	r := NewRAMTier(1<<20, 0, 0)
	w, err := r.Writer(ObjectMeta{Key: "k", Status: 410})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil { // no body: a bodyless negative entry
		t.Fatal(err)
	}
	rd, ok := r.Get("k")
	if !ok {
		t.Fatal("negative entry missing")
	}
	defer rd.Close()
	if rd.Meta.EffectiveStatus() != 410 {
		t.Fatalf("EffectiveStatus=%d, want 410", rd.Meta.EffectiveStatus())
	}
	if rd.Meta.Size != 0 {
		t.Fatalf("size=%d, want 0", rd.Meta.Size)
	}
}

// TestDiskNegativeEntryRoundTrip writes a bodyless negative (404) entry, persists
// the index, reopens the tier, and verifies the Status survives — so a
// negatively-cached object is still served with its status after a restart.
func TestDiskNegativeEntryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	const key = "GET\x1fhost\x1f/gone"
	w, err := d.Writer(ObjectMeta{Key: key, Status: 404})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil { // final synchronous index flush
		t.Fatal(err)
	}

	d2, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	rd, ok := d2.Get(key)
	if !ok {
		t.Fatal("negative entry missing after restart")
	}
	defer rd.Close()
	if rd.Meta.Status != 404 || rd.Meta.EffectiveStatus() != 404 {
		t.Fatalf("after restart status=%d effective=%d, want 404", rd.Meta.Status, rd.Meta.EffectiveStatus())
	}
	if rd.Meta.Size != 0 {
		t.Fatalf("after restart size=%d, want 0 (bodyless)", rd.Meta.Size)
	}
}
