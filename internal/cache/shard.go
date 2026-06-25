package cache

import "hash/fnv"

// defaultShards is how many independent lock domains each tier is split into when its
// budget is large enough to give every shard a meaningful slice. The performance
// problem this addresses is that BOTH tiers serialized every read on one global mutex
// — and a cache hit is a WRITE (LRU MoveToFront), so even an all-hits workload (the
// hottest, most common case) fully serializes. Sharding by hash(key)%N spreads
// reads/writes across N independent mutexes so unrelated keys almost never contend.
//
// 64 is a deliberate default: large enough that hundreds of concurrent streams rarely
// collide on the same shard (birthday-bound collisions stay low), small enough that
// the per-shard fixed overhead (a map + a list + a mutex + a counter) is negligible
// and Len()/Bytes() aggregation over the shards stays cheap. It is a const rather than
// configurable because the tier's external interface (Tier in cache.go) must not
// change; if it ever needs tuning, change it here.
const defaultShards = 64

// minShardBytes is the smallest per-shard byte budget we will create. It serves two
// purposes:
//
//  1. A shard's cap is the largest object that shard can hold (commit refuses anything
//     bigger — see shardCaps). The disk tier caches large media (multi-hundred-KiB to
//     multi-MiB .ts/.mp4 segments), so a per-shard cap MUST stay comfortably above a
//     realistic object size; otherwise an object that fit the unsharded tier would be
//     refused by every shard and silently stop being cacheable. 1 MiB keeps a single
//     shard able to hold the objects these tiers actually cache (RAM's per-object cap
//     defaults to 64 MiB but a production RAM shard is ~hundreds of MiB; disk segments
//     are well under a shard's cap at production sizes).
//  2. Splitting a tiny tier 64 ways would give most shards a 0-byte cap and scatter a
//     handful of keys so the LRU semantics degrade to noise. shardCount(maxBytes)
//     instead reduces the shard count until each shard gets at least this many bytes.
//
// Effect: a production-sized tier (tens to hundreds of GiB) gets the full 64-way split,
// while a small/test-sized tier (<= 1 MiB) collapses to a single shard and thus keeps
// the original global-LRU semantics — so existing small-budget tests (a 20-byte
// LRU-eviction tier, a 1 MiB tier caching a 768 KiB object) behave exactly as before.
const minShardBytes int64 = 1 << 20

// shardCount picks how many shards a tier with the given byte budget should use:
// defaultShards when the budget is large, fewer (down to 1) when it is small, so every
// shard always gets at least minShardBytes (except the degenerate single-shard case,
// which simply gets the whole budget). A non-positive budget collapses to 1 shard.
func shardCount(maxBytes int64) int {
	if maxBytes <= 0 {
		return 1
	}
	n := int(maxBytes / minShardBytes)
	if n < 1 {
		n = 1
	}
	if n > defaultShards {
		n = defaultShards
	}
	return n
}

// shardIndex maps a key to one of n shards via a fast non-cryptographic hash (FNV-1a).
// It MUST be deterministic and stable for the lifetime of a tier so a key is always
// stored in and looked up from the SAME shard — the disk tier also relies on this to
// re-home persisted entries on load(). (Blob filenames still use sha256(key); this hash
// only selects the shard, so the two never need to agree.) n is the tier's own shard
// count (from shardCount), so the same key can map to different shards in tiers of
// different sizes — fine, because a shard is only ever consulted within its own tier.
func shardIndex(key string, n int) int {
	h := fnv.New32a()
	// Hash.Write on the standard fnv hasher never returns an error.
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % uint32(n))
}

// shardCaps splits a tier-global byte budget into n per-shard caps whose SUM is exactly
// maxBytes (never over). With sharding, eviction is necessarily per-shard (each shard
// runs its own LRU under its own lock), so the budget must be partitioned too: each
// shard gets floor(maxBytes/n), and the first (maxBytes mod n) shards get one extra
// byte to absorb the remainder. This guarantees the tier as a whole stays within
// maxBytes.
//
// Consequence (documented, accepted): with n > 1, eviction is per-shard
// approximate-LRU, not a single global LRU. A hot object can be evicted from its (full)
// shard while a colder object survives in a different, emptier shard. For a hot-object
// cache this is fine — hot keys are re-fetched cheaply and the aggregate hit rate is
// dominated by working-set fit, not by perfect global recency ordering. An object
// larger than its shard's cap is handled exactly as an over-tier object was before: the
// shard's commit refuses it (RAM: skip; disk: discard temp), so it streams through
// uncached and never wedges the tier.
func shardCaps(maxBytes int64, n int) []int64 {
	caps := make([]int64, n)
	if maxBytes <= 0 {
		// Non-positive budget: every shard cap is the (non-positive) budget itself. The
		// per-shard commit's "size > cap" guard then refuses everything, matching the
		// unsharded behavior where a non-positive tier cap caches nothing.
		for i := range caps {
			caps[i] = maxBytes
		}
		return caps
	}
	base := maxBytes / int64(n)
	rem := maxBytes % int64(n)
	for i := range caps {
		caps[i] = base
		if int64(i) < rem {
			caps[i]++
		}
	}
	return caps
}
