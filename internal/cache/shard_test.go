package cache

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestShardCaps_SumsToBudget verifies the per-shard budget split never exceeds (and in
// the positive case exactly equals) the tier budget, including when the budget does not
// divide evenly across the shards — the remainder is spread one byte at a time so the
// SUM stays == maxBytes (never over).
func TestShardCaps_SumsToBudget(t *testing.T) {
	for _, maxBytes := range []int64{0, 1, 63, 64, 65, 100, 1 << 20, (44 << 30) + 7} {
		n := shardCount(maxBytes)
		caps := shardCaps(maxBytes, n)
		if len(caps) != n {
			t.Fatalf("maxBytes=%d: got %d caps want %d", maxBytes, len(caps), n)
		}
		var sum int64
		for _, c := range caps {
			sum += c
		}
		if maxBytes > 0 && sum != maxBytes {
			t.Errorf("maxBytes=%d: sum of caps = %d, want exactly %d", maxBytes, sum, maxBytes)
		}
		if maxBytes > 0 && sum > maxBytes {
			t.Errorf("maxBytes=%d: sum of caps = %d EXCEEDS budget", maxBytes, sum)
		}
	}
}

// TestShardCount_ScalesWithBudget verifies a small/test-sized tier collapses toward a
// single shard (preserving the original global-LRU semantics on tiny budgets) while a
// production-sized tier gets the full defaultShards split.
func TestShardCount_ScalesWithBudget(t *testing.T) {
	if got := shardCount(0); got != 1 {
		t.Errorf("shardCount(0) = %d, want 1", got)
	}
	if got := shardCount(20); got != 1 {
		t.Errorf("shardCount(20) = %d, want 1 (tiny budget => single shard)", got)
	}
	if got := shardCount(44 << 30); got != defaultShards {
		t.Errorf("shardCount(44GiB) = %d, want %d", got, defaultShards)
	}
}

// TestRAMTier_KeysDistributeAcrossShards asserts that many distinct keys actually land
// in different shards (so the locks they take are different) — i.e. the sharding really
// spreads load rather than funnelling everything to one mutex.
func TestRAMTier_KeysDistributeAcrossShards(t *testing.T) {
	r := NewRAMTier(64<<20, 0, 0) // large enough for the full defaultShards split
	if len(r.shards) != defaultShards {
		t.Fatalf("expected %d shards, got %d", defaultShards, len(r.shards))
	}
	used := make(map[int]bool)
	for i := 0; i < 1000; i++ {
		used[shardIndex("key-"+strconv.Itoa(i), len(r.shards))] = true
	}
	// 1000 keys over 64 shards: essentially every shard should be hit. Require a strong
	// majority so the test is robust but still proves real distribution.
	if len(used) < defaultShards*3/4 {
		t.Fatalf("keys only reached %d/%d shards; distribution too skewed", len(used), defaultShards)
	}
}

// TestRAMTier_PerShardEviction proves eviction happens per-shard: two keys that hash to
// the SAME shard, written into a tier whose per-shard cap only holds one of them, evict
// each other; while a key in a DIFFERENT shard is untouched by that churn.
func TestRAMTier_PerShardEviction(t *testing.T) {
	// Build a tier with exactly 2 shards by choosing a budget of 2*minShardBytes.
	maxBytes := 2 * minShardBytes
	r := NewRAMTier(maxBytes, 0, 0)
	if len(r.shards) != 2 {
		t.Skipf("expected 2 shards for this budget, got %d (minShardBytes changed)", len(r.shards))
	}

	// Find two keys in shard 0 and one key in shard 1.
	var inShard0 []string
	var inShard1 string
	for i := 0; len(inShard0) < 2 || inShard1 == ""; i++ {
		k := "k" + strconv.Itoa(i)
		switch shardIndex(k, 2) {
		case 0:
			if len(inShard0) < 2 {
				inShard0 = append(inShard0, k)
			}
		case 1:
			if inShard1 == "" {
				inShard1 = k
			}
		}
	}

	// Each object is just over half a shard's cap, so a shard holds only ONE at a time.
	body := strings.Repeat("x", int(r.shards[0].maxBytes/2)+1)
	putTier(t, r, inShard0[0], body, "")
	putTier(t, r, inShard1, body, "")    // different shard, must survive everything below
	putTier(t, r, inShard0[1], body, "") // evicts inShard0[0] from shard 0

	if _, ok := r.Get(inShard0[0]); ok {
		t.Error("first object in shard 0 should have been evicted by the second")
	}
	if _, ok := r.Get(inShard0[1]); !ok {
		t.Error("second object in shard 0 should be present")
	}
	if _, ok := r.Get(inShard1); !ok {
		t.Error("object in shard 1 must be untouched by shard 0's eviction")
	}
}

// TestRAMTier_StaysWithinBudgetUnderChurn hammers the tier with far more distinct keys
// than fit and asserts the aggregate byte count never exceeds maxBytes (the sum of the
// per-shard caps), proving the sharded budget split keeps the whole tier bounded.
func TestRAMTier_StaysWithinBudgetUnderChurn(t *testing.T) {
	maxBytes := int64(2 << 20) // 2 MiB -> full multi-shard split
	r := NewRAMTier(maxBytes, 0, 0)
	body := strings.Repeat("y", 4096)
	for i := 0; i < 5000; i++ {
		putTier(t, r, "churn-"+strconv.Itoa(i), body, "")
		if b := r.Bytes(); b > maxBytes {
			t.Fatalf("tier bytes %d exceeded maxBytes %d at i=%d", b, maxBytes, i)
		}
	}
	if b := r.Bytes(); b > maxBytes {
		t.Fatalf("final tier bytes %d exceed maxBytes %d", b, maxBytes)
	}
}

// TestRAMTier_ConcurrentAcrossShards runs many goroutines hitting disjoint key spaces
// (so they mostly land in different shards) doing mixed get/put. With -race this proves
// the per-shard locks are correct and that cross-shard work proceeds without data races.
func TestRAMTier_ConcurrentAcrossShards(t *testing.T) {
	r := NewRAMTier(8<<20, 0, 0)
	body := strings.Repeat("z", 256)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				k := "g" + strconv.Itoa(g) + "-" + strconv.Itoa(i%50)
				putTier(t, r, k, body, "")
				if rd, ok := r.Get(k); ok {
					_, _ = io.Copy(io.Discard, rd)
					rd.Close()
				}
			}
		}(g)
	}
	wg.Wait()
	if r.Bytes() > 8<<20 {
		t.Fatalf("bytes %d exceed cap after concurrent churn", r.Bytes())
	}
}
