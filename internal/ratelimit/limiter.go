// Package ratelimit is cadish's in-memory, per-node token-bucket rate limiter —
// the stateful server-side half of the native `rate_limit` security primitive.
//
// Architecture (WAF v1b / D51):
//
//   - The PURE pipeline gate (internal/pipeline.EvalSecurity) identifies the
//     applicable rate_limit rule for a request and computes the bucket KEY (the
//     resolved real client IP, a header value, or a whole-site constant). It does
//     NO counting — it stays a side-effect-free function safe for concurrent use.
//   - This package owns the MUTABLE state: one token bucket per (rule, key). The
//     server consults Allow(key, rule) in the gate seam after `deny`; on a throttle
//     it returns 429 + Retry-After, touching neither cache nor origin.
//
// State is PER-NODE only (spec §2.7 / D51): no distributed counters, no Redis, no
// gossip. With N nodes behind an LB each counts independently, so the effective
// limit is ≈ N× the configured rate — mitigate by setting limit = target/N.
//
// The store is SHARDED by key hash so concurrent requests on different keys do not
// contend on a single global lock, and idle buckets are swept on a background timer
// so memory stays bounded under a high-cardinality key space (e.g. per-IP buckets
// during a botnet flood). The clock is injectable so the token math is testable
// without sleeping.
package ratelimit

import (
	"hash/maphash"
	"math"
	"sort"
	"sync"
	"time"
)

// numShards is the fixed shard count. A power of two so the shard index is a cheap
// mask of the key hash. 64 keeps per-shard lock contention low even under a flood
// of distinct keys while staying small enough that a full sweep is cheap.
const numShards = 64

// idleTTL is how long a bucket may sit untouched before the sweeper reclaims it. A
// bucket idle this long is at (or near) full capacity, so evicting it loses no
// throttling state — a returning client simply gets a fresh full bucket. Kept short
// enough to bound memory under high-cardinality keys, long enough that an active
// client's bucket is never evicted between requests.
const idleTTL = 10 * time.Minute

// sweepInterval is how often the background sweeper scans for idle buckets.
const sweepInterval = time.Minute

// maxBucketsPerShard hard-caps the live bucket count per shard so a flood of requests on
// a HIGH-CARDINALITY key (e.g. `rate_limit` keyed on an attacker-controlled header value)
// cannot grow memory without bound between sweeps — the idle sweeper only reclaims buckets
// untouched for idleTTL (10m), so without this cap an attacker could allocate ~rate×10m
// distinct buckets. When a shard hits the cap, the OLDEST (least-recently-seen) buckets are
// evicted down to a low-water mark; those are exactly the one-shot flood keys (an active
// client's bucket has a recent lastSeen and survives). 4096×64 shards ≈ 262k buckets ceiling.
const maxBucketsPerShard = 4096

// evictOldestLocked drops the least-recently-seen buckets until at most `target` remain.
// Caller holds s.mu. An evicted bucket simply resets to full on the key's next request
// (no throttling state lost for a near-idle bucket), so evicting the oldest is safe; the
// batch (down to a low-water mark) amortizes the O(n) scan over many insertions.
func (s *shard) evictOldestLocked(target int) {
	if len(s.buckets) <= target {
		return
	}
	times := make([]time.Time, 0, len(s.buckets))
	for _, b := range s.buckets {
		times = append(times, b.lastSeen)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	cutoff := times[len(times)-target] // keep the `target` most-recently-seen
	for k, b := range s.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(s.buckets, k)
		}
	}
}

// Rule is the immutable rate spec the pure gate hands to the limiter. RatePerSec is
// the steady refill rate (tokens/second); Burst is the extra capacity above one
// token (a burst of N lets N requests through in an instant when full). Capacity =
// max(1, Burst): a request costs one token.
type Rule struct {
	RatePerSec float64
	Burst      int
}

// capacity is the bucket's maximum token count: at least 1, plus the configured
// burst. (burst 0 => capacity 1 => strict one-at-a-time at the steady rate.)
func (r Rule) capacity() float64 {
	c := float64(r.Burst)
	if c < 1 {
		c = 1
	}
	return c
}

// Decision is the outcome of an Allow call. OK is false when the request is
// throttled; RetryAfter is then the time until the next token is available (a hint
// for the 429 Retry-After header; the server rounds it up to whole seconds).
type Decision struct {
	OK         bool
	RetryAfter time.Duration
}

// bucket is a single token bucket: tokens available, the last time it was refilled,
// and the last time it was touched (for idle eviction). Guarded by its shard's mutex.
type bucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// shard is one striped partition of the bucket map with its own mutex.
type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// Limiter is a sharded, in-memory, per-node token-bucket rate limiter. Construct
// with New (real clock) or NewWithClock (injectable clock, for tests). Safe for
// concurrent use. Call Stop to halt the background sweeper.
type Limiter struct {
	shards [numShards]shard
	now    func() time.Time
	seed   maphash.Seed

	stop     chan struct{}
	stopOnce sync.Once
}

// New builds a Limiter using the wall clock and starts its background sweeper.
func New() *Limiter { return NewWithClock(time.Now) }

// NewWithClock builds a Limiter with an injectable time source (tests pass a fake
// clock so token refill is deterministic without sleeping) and starts the sweeper.
func NewWithClock(now func() time.Time) *Limiter {
	l := &Limiter{now: now, seed: maphash.MakeSeed(), stop: make(chan struct{})}
	for i := range l.shards {
		l.shards[i].buckets = make(map[string]*bucket)
	}
	go l.sweepLoop()
	return l
}

// Stop halts the background sweeper. Idempotent; safe to call on a nil Limiter
// (the nil case is a no-op so a non-rate-limited server can hold a nil one).
func (l *Limiter) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() { close(l.stop) })
}

// Allow consumes one token for key under rule and reports whether the request is
// admitted. A nil Limiter always admits (defensive: a server with no rate_limit
// rules holds a nil limiter and never calls this).
func (l *Limiter) Allow(key string, r Rule) Decision {
	if l == nil {
		return Decision{OK: true}
	}
	now := l.now()
	sh := &l.shards[l.shardIndex(key)]
	cap := r.capacity()

	sh.mu.Lock()
	defer sh.mu.Unlock()
	b := sh.buckets[key]
	if b == nil {
		// Bound memory under a high-cardinality key flood: at the per-shard cap, evict the
		// oldest (least-recently-seen) buckets — the one-shot flood keys — down to a low-water
		// mark before admitting a new one. An active client's bucket has a recent lastSeen and
		// is never the victim.
		if len(sh.buckets) >= maxBucketsPerShard {
			sh.evictOldestLocked(maxBucketsPerShard * 7 / 8)
		}
		// A fresh bucket starts FULL: a first-seen client gets its full burst.
		b = &bucket{tokens: cap, lastFill: now, lastSeen: now}
		sh.buckets[key] = b
	} else {
		// Refill: add rate × elapsed, capped at capacity.
		if elapsed := now.Sub(b.lastFill); elapsed > 0 {
			b.tokens += r.RatePerSec * elapsed.Seconds()
			if b.tokens > cap {
				b.tokens = cap
			}
			b.lastFill = now
		}
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return Decision{OK: true}
	}
	// Throttled: time until the bucket reaches one token at the steady rate.
	retry := time.Duration(0)
	if r.RatePerSec > 0 {
		need := 1 - b.tokens
		secs := need / r.RatePerSec
		retry = time.Duration(secs * float64(time.Second))
		if retry <= 0 {
			retry = time.Nanosecond
		}
	} else {
		// A rate of 0 never refills: once the initial capacity is spent the key stays
		// blocked (until the idle sweep eventually evicts the bucket). There is no
		// steady-rate retry time, so report a long back-off (idleTTL) rather than a
		// misleading 0 (RL-P1). A genuine permanent block is better expressed with
		// `deny` — see the rate_limit docs.
		retry = idleTTL
	}
	return Decision{OK: false, RetryAfter: retry}
}

// shardIndex maps a key to its shard via a seeded hash masked to numShards.
func (l *Limiter) shardIndex(key string) int {
	var h maphash.Hash
	h.SetSeed(l.seed)
	_, _ = h.WriteString(key)
	return int(h.Sum64() & (numShards - 1))
}

// Len reports the total live bucket count across all shards (for tests / metrics).
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	n := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		n += len(sh.buckets)
		sh.mu.Unlock()
	}
	return n
}

// sweepLoop runs the idle-bucket eviction on a ticker until Stop.
func (l *Limiter) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.sweep()
		}
	}
}

// sweep evicts every bucket untouched for longer than idleTTL. Such a bucket has
// refilled to (near) full, so dropping it loses no throttling state — a returning
// client gets a fresh full bucket. This bounds memory under a high-cardinality key
// space (per-IP buckets during a flood) without a global lock: each shard is swept
// independently.
func (l *Limiter) sweep() {
	if l == nil {
		return
	}
	cutoff := l.now().Add(-idleTTL)
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		for k, b := range sh.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(sh.buckets, k)
			}
		}
		sh.mu.Unlock()
	}
}

// RetryAfterSeconds rounds a Retry-After hint up to whole seconds (minimum 1), the
// form the HTTP Retry-After header takes for a delta value.
func RetryAfterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}
