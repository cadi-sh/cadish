package server

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestFreshnessSweep_ReclaimsExpired inserts a batch of distinct-key entries,
// advances the (injected) clock past their grace/max-stale windows, runs a sweep,
// and asserts every entry is reclaimed and the map shrank to zero — the
// distinct-key (?cachebust=N) accumulation guard.
func TestFreshnessSweep_ReclaimsExpired(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	t.Cleanup(f.Close)

	const n = 500
	for i := 0; i < n; i++ {
		f.store(fmt.Sprintf("/k%d", i), 10*time.Second, 5*time.Second, 0)
	}
	// A few with a max_stale window so we cover that retention path too.
	for i := 0; i < 10; i++ {
		f.store(fmt.Sprintf("/ms%d", i), 10*time.Second, 5*time.Second, 30*time.Second)
	}
	if got := f.len(); got != n+10 {
		t.Fatalf("after store: len = %d, want %d", got, n+10)
	}

	// Advance past grace (15s) but NOT past the max_stale entries (45s): the plain
	// entries reclaim; the max_stale ones must survive (they can still serve on an
	// origin error).
	clk.advance(20 * time.Second)
	f.sweep()
	if got := f.len(); got != 10 {
		t.Fatalf("after first sweep: len = %d, want 10 (max_stale entries survive)", got)
	}

	// Advance past max_stale: now everything reclaims.
	clk.advance(40 * time.Second)
	f.sweep()
	if got := f.len(); got != 0 {
		t.Fatalf("after second sweep: len = %d, want 0", got)
	}
}

// TestFreshnessSweep_KeepsLiveEntries verifies the sweeper does not evict entries
// that can still produce a hit (fresh, stale-in-grace, or an active hit-for-miss).
func TestFreshnessSweep_KeepsLiveEntries(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	t.Cleanup(f.Close)

	f.store("/fresh", 60*time.Second, 10*time.Second, 0)
	f.store("/stale", 5*time.Second, 60*time.Second, 0)
	f.setHitForMiss("/hfm", 60*time.Second)

	clk.advance(10 * time.Second) // /stale now past TTL but within grace; others live
	f.sweep()
	if got := f.len(); got != 3 {
		t.Fatalf("sweep evicted live entries: len = %d, want 3", got)
	}
}

// TestFreshnessSweep_StopsOnClose asserts the background sweeper goroutine exits on
// Close (no goroutine leak).
func TestFreshnessSweep_StopsOnClose(t *testing.T) {
	before := runtime.NumGoroutine()
	f := newFreshness(time.Now)
	// Give the goroutine a moment to start.
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	f.Close()
	f.Close() // idempotent

	// The sweeper goroutine should return; goroutine count drops back to baseline.
	for i := 0; i < 200; i++ {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("sweeper goroutine did not exit on Close: goroutines = %d, baseline = %d",
		runtime.NumGoroutine(), before)
}
