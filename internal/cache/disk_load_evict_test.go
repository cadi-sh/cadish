package cache

import "testing"

func diskWrite(t *testing.T, d *DiskTier, key string, body []byte) {
	t.Helper()
	w, err := d.Writer(ObjectMeta{Key: key, Size: int64(len(body))})
	if err != nil {
		t.Fatalf("Writer(%s): %v", key, err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("Write(%s): %v", key, err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit(%s): %v", key, err)
	}
}

// TestLoadEvictsOverBudgetShard (R03e): reopening a tier with a SMALLER budget than the
// persisted on-disk content must evict the shard back to budget during load(), not leave
// it over budget until the next write (which also makes Bytes()/Stats() over-report).
func TestLoadEvictsOverBudgetShard(t *testing.T) {
	dir := t.TempDir()
	body := make([]byte, 500)
	for i := range body {
		body[i] = 'x'
	}

	// First open with a 4000-byte budget (<=1MiB -> a single shard with the whole budget).
	d1, err := NewDiskTier(dir, 4000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		diskWrite(t, d1, "/seg"+string(rune('a'+i)), body)
	}
	resident := d1.Bytes()
	if resident <= 2000 {
		t.Fatalf("precondition: want >2000 bytes resident before shrink, got %d", resident)
	}
	if err := d1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with a 2000-byte budget. Each 500-byte object individually fits, but their
	// sum (resident) exceeds 2000, so load() must evict to <= 2000.
	d2, err := NewDiskTier(dir, 2000)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if got := d2.Bytes(); got > 2000 {
		t.Errorf("after reopen at smaller budget: Bytes()=%d, want <= 2000 (load must evict to budget)", got)
	}
	// Bytes() (the atomic mirror) must equal the real resident size — i.e. the eviction
	// updated curBytes and atomicBytes together, so Stats() does not over-report.
	var realBytes int64
	for _, s := range d2.shards {
		realBytes += s.curBytes
	}
	if realBytes != d2.Bytes() {
		t.Errorf("atomicBytes mirror %d != summed curBytes %d after load eviction", d2.Bytes(), realBytes)
	}
}
