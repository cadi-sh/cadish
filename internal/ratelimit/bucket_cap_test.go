package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

// TestBucketCapBoundsHighCardinality: a flood of distinct keys must not grow the bucket
// store without bound. The total live buckets stay at or below the per-shard ceiling.
func TestBucketCapBoundsHighCardinality(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewWithClock(func() time.Time { return now })
	defer l.Stop()
	r := Rule{RatePerSec: 1, Burst: 1}
	// Far more distinct keys than the total ceiling, each advancing the clock so lastSeen
	// differs (the eviction cutoff is well-defined).
	for i := 0; i < maxBucketsPerShard*numShards*3; i++ {
		now = now.Add(time.Millisecond)
		l.Allow("k"+strconv.Itoa(i), r)
	}
	total := 0
	for s := range l.shards {
		l.shards[s].mu.Lock()
		total += len(l.shards[s].buckets)
		l.shards[s].mu.Unlock()
	}
	ceiling := maxBucketsPerShard * numShards
	if total > ceiling {
		t.Errorf("live buckets = %d, want <= %d (per-shard cap not enforced)", total, ceiling)
	}
	t.Logf("live buckets after %d distinct keys: %d (ceiling %d)", maxBucketsPerShard*numShards*3, total, ceiling)
}

// TestBucketCapKeepsActiveBucket: an active (frequently-seen) key's throttling state is
// preserved across a flood of one-shot keys — it is not the eviction victim.
func TestBucketCapKeepsActiveBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewWithClock(func() time.Time { return now })
	defer l.Stop()
	r := Rule{RatePerSec: 0.001, Burst: 1} // ~1 token / 1000s: easy to exhaust and observe
	// Exhaust the active key's bucket.
	if d := l.Allow("active", r); !d.OK {
		t.Fatal("first active request should be admitted")
	}
	if d := l.Allow("active", r); d.OK {
		t.Fatal("second active request should be throttled (bucket exhausted)")
	}
	// Flood distinct keys, touching "active" often so it stays recently-seen.
	for i := 0; i < maxBucketsPerShard*numShards*2; i++ {
		now = now.Add(time.Millisecond)
		l.Allow("flood"+strconv.Itoa(i), r)
		if i%500 == 0 {
			l.Allow("active", r) // keep it warm
		}
	}
	// The active bucket must still be throttled (not evicted+reset to full).
	if d := l.Allow("active", r); d.OK {
		t.Error("active bucket was evicted/reset by the flood — throttle state lost")
	}
}
