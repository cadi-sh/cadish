package ratelimit

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeClock is an injectable, deterministic time source so the token-bucket math
// is tested without sleeping. advance() moves it forward by a fixed delta.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// rule builds a Rule with rate r/s and the given burst (capacity above steady).
func rule(perSec float64, burst int) Rule {
	return Rule{RatePerSec: perSec, Burst: burst}
}

// TestSteadyRateAndBurst verifies the bucket admits an initial burst then throttles
// to the steady rate, all without real time passing.
func TestSteadyRateAndBurst(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	// 10 r/s, burst 5 => capacity = 10 (steady) ... actually capacity = rate + burst?
	// We define capacity = max(1, burst) tokens available immediately, refilled at
	// RatePerSec. With burst 5 the first 5 requests in the same instant pass, the 6th
	// is throttled (no time has elapsed to refill).
	r := rule(10, 5)
	key := "1.2.3.4"
	for i := 0; i < 5; i++ {
		if !l.Allow(key, r).OK {
			t.Fatalf("request %d within burst must pass", i+1)
		}
	}
	if l.Allow(key, r).OK {
		t.Fatal("request beyond burst (no time elapsed) must be throttled")
	}
}

// TestRefillOverTime verifies tokens refill at the steady rate as the clock advances.
func TestRefillOverTime(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	r := rule(10, 1) // 10 r/s, capacity 1
	key := "ip"
	if !l.Allow(key, r).OK {
		t.Fatal("first request must pass")
	}
	if l.Allow(key, r).OK {
		t.Fatal("second immediate request must be throttled (capacity 1)")
	}
	// 10 r/s => one token every 100ms. Advance 100ms and one more should pass.
	clk.advance(100 * time.Millisecond)
	if !l.Allow(key, r).OK {
		t.Fatal("after 100ms a token should have refilled")
	}
	if l.Allow(key, r).OK {
		t.Fatal("the refilled token is spent; next is throttled")
	}
}

// TestCapacityCeiling verifies tokens never accumulate beyond capacity even after a
// long idle gap (no infinite burst after a quiet period).
func TestCapacityCeiling(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	r := rule(10, 3) // capacity 3
	key := "ip"
	// Idle for an hour: tokens cap at capacity, not 36000.
	clk.advance(time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow(key, r).OK {
			t.Fatalf("request %d after idle must pass (capped at capacity)", i+1)
		}
	}
	if l.Allow(key, r).OK {
		t.Fatal("4th request must be throttled: capacity is 3, not unbounded")
	}
}

// TestRetryAfter verifies a throttled decision reports a positive Retry-After hint.
func TestRetryAfter(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	r := rule(2, 1) // 2 r/s => 500ms per token
	key := "ip"
	if !l.Allow(key, r).OK {
		t.Fatal("first request passes")
	}
	d := l.Allow(key, r)
	if d.OK {
		t.Fatal("second request throttled")
	}
	if d.RetryAfter <= 0 {
		t.Fatalf("throttled decision must carry a positive Retry-After, got %v", d.RetryAfter)
	}
	// Retry-After should be at most one token interval (500ms), rounded up to >=1s
	// at the header layer; here we just assert the raw hint is within a token period.
	if d.RetryAfter > 500*time.Millisecond+time.Millisecond {
		t.Fatalf("Retry-After %v exceeds one token interval", d.RetryAfter)
	}
}

// TestPerKeyIsolation verifies one key's flood does not throttle another key.
func TestPerKeyIsolation(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	r := rule(5, 2)
	flooder := "10.0.0.1"
	// Exhaust the flooder.
	for l.Allow(flooder, r).OK {
	}
	// A different key is unaffected.
	victim := "10.0.0.2"
	if !l.Allow(victim, r).OK {
		t.Fatal("a different key must have its own independent bucket")
	}
}

// TestIdleEviction verifies idle buckets are reclaimed so memory stays bounded.
func TestIdleEviction(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	r := rule(10, 2)
	for i := 0; i < 1000; i++ {
		l.Allow("key-"+strconv.Itoa(i), r)
	}
	if got := l.Len(); got < 1000 {
		t.Fatalf("expected ~1000 live buckets before eviction, got %d", got)
	}
	// Advance well past the idle TTL and sweep: a bucket untouched for longer than
	// idleTTL is evicted.
	clk.advance(2 * idleTTL)
	l.sweep()
	if got := l.Len(); got != 0 {
		t.Fatalf("idle buckets must be evicted; %d remain", got)
	}
}

// TestEvictedBucketRefillsFull verifies a bucket re-created after eviction starts at
// full capacity (it has no memory of its drained predecessor), so eviction never
// throttles a returning client.
func TestEvictedBucketRefillsFull(t *testing.T) {
	clk := newFakeClock()
	l := NewWithClock(clk.now)
	defer l.Stop()

	r := rule(1, 3)
	key := "returning"
	for l.Allow(key, r).OK { // drain
	}
	clk.advance(2 * idleTTL)
	l.sweep()
	// The drained bucket was evicted; a fresh one starts full.
	if !l.Allow(key, r).OK {
		t.Fatal("a re-created bucket must start at full capacity")
	}
}

// TestSharding verifies keys distribute across shards (no single global lock). This
// is a structural check: distinct keys land in more than one shard.
func TestSharding(t *testing.T) {
	l := New()
	defer l.Stop()
	seen := map[int]bool{}
	for i := 0; i < 256; i++ {
		seen[l.shardIndex("key-"+strconv.Itoa(i))] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected keys to spread across shards, got %d distinct shards", len(seen))
	}
}

// TestConcurrentAllow is a race-detector smoke test: many goroutines hammer the
// limiter on shared and distinct keys with no data races.
func TestConcurrentAllow(t *testing.T) {
	l := New()
	defer l.Stop()
	r := rule(1000, 100)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				l.Allow("shared", r)
				l.Allow("g-"+strconv.Itoa(g), r)
			}
		}(g)
	}
	wg.Wait()
}
