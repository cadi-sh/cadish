package cache

import (
	"strconv"
	"strings"
	"testing"
)

// TestDiskTier_ShardedRoundTripAcrossRestart writes many keys (which spread across many
// shards), closes the tier, reopens it, and verifies every still-present object survives
// — proving the single merged index.json round-trips correctly when entries are
// re-homed to shards by hash on load.
func TestDiskTier_ShardedRoundTripAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	maxBytes := int64(64 << 20) // big enough for the full shard split, fits all writes below
	d, err := NewDiskTier(dir, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.shards) < 2 {
		t.Fatalf("expected a multi-shard disk tier, got %d shards", len(d.shards))
	}
	const N = 200
	body := strings.Repeat("m", 1024)
	for i := 0; i < N; i++ {
		putTier(t, d, "seg-"+strconv.Itoa(i)+".ts", body, "video/mp2t")
	}
	wantLen := d.Len()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d2, err := NewDiskTier(dir, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if got := d2.Len(); got != wantLen {
		t.Fatalf("after restart Len = %d, want %d", got, wantLen)
	}
	for i := 0; i < N; i++ {
		k := "seg-" + strconv.Itoa(i) + ".ts"
		got, _, ok := getTier(t, d2, k)
		if !ok || got != body {
			t.Fatalf("%s missing/corrupt after restart: ok=%v", k, ok)
		}
	}
}

// TestDiskTier_PerShardEvictionStaysBounded churns far more data than the tier holds and
// asserts the aggregate stays within maxBytes across the sharded eviction.
func TestDiskTier_PerShardEvictionStaysBounded(t *testing.T) {
	dir := t.TempDir()
	maxBytes := int64(64 << 20)
	d, err := NewDiskTier(dir, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// Objects are a meaningful fraction of a shard's cap so eviction churns within
	// shards while the aggregate stays bounded.
	body := strings.Repeat("d", 64<<10)
	for i := 0; i < 4000; i++ {
		putTier(t, d, "blob-"+strconv.Itoa(i)+".mp4", body, "video/mp4")
		if b := d.Bytes(); b > maxBytes {
			t.Fatalf("disk bytes %d exceeded maxBytes %d at i=%d", b, maxBytes, i)
		}
	}
}
