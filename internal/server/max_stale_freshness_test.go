package server

import (
	"regexp"
	"testing"
	"time"
)

// TestMaxStaleClassifyUnchangedHotPath: a within-max_stale entry classifies as
// stateMiss to a HEALTHY request — max_stale never affects classify (the hot path).
func TestMaxStaleClassifyUnchangedHotPath(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	const key = "k"
	f.store(key, time.Minute, time.Minute, time.Hour) // ttl 1m, grace 1m, max_stale 1h

	// fresh
	if st, _ := f.classify(key); st != stateFresh {
		t.Fatalf("fresh: state=%v, want stateFresh", st)
	}
	// in grace
	clk.advance(90 * time.Second)
	if st, _ := f.classify(key); st != stateStale {
		t.Fatalf("grace: state=%v, want stateStale", st)
	}
	// past grace, within max_stale -> stateMiss to a healthy request (NOT stale)
	clk.advance(time.Minute) // now t+150s: past graceUntil (120s), within max_stale (1h+)
	if st, _ := f.classify(key); st != stateMiss {
		t.Fatalf("within max_stale healthy: state=%v, want stateMiss", st)
	}
}

// TestMaxStaleMarkerSurvivesPruning: classify within the max_stale window must NOT
// delete the entry (the marker must survive so the error path can serve it).
func TestMaxStaleMarkerSurvivesPruning(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	const key = "k"
	f.store(key, time.Minute, time.Minute, time.Hour)

	clk.advance(150 * time.Second) // past grace, within max_stale
	_, _ = f.classify(key)         // a healthy MISS — must NOT prune the marker
	if !f.staleWithin(key) {
		t.Fatal("marker was pruned within the max_stale window; staleWithin should still see it")
	}

	// Past the full max_stale window, classify prunes and staleWithin is false.
	clk.advance(2 * time.Hour)
	if st, _ := f.classify(key); st != stateMiss {
		t.Fatalf("beyond max_stale: state=%v, want stateMiss", st)
	}
	if f.staleWithin(key) {
		t.Fatal("staleWithin true beyond maxStaleUntil; the entry must have expired")
	}
}

// TestStaleWithinWindow exercises staleWithin's exact boundaries.
func TestStaleWithinWindow(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	const key = "k"
	f.store(key, time.Minute, time.Minute, time.Hour) // expires t+60s, grace t+120s, maxStale t+1h2m

	// fresh: not a max_stale fallback
	if f.staleWithin(key) {
		t.Fatal("staleWithin true while fresh; want false")
	}
	// in grace: still not (grace is the live path; error path never reached)
	clk.advance(90 * time.Second)
	if f.staleWithin(key) {
		t.Fatal("staleWithin true while in grace; want false (now < graceUntil)")
	}
	// just past grace: within max_stale -> true
	clk.advance(40 * time.Second) // now t+130s, past graceUntil(120s)
	if !f.staleWithin(key) {
		t.Fatal("staleWithin false just past grace; want true (within max_stale)")
	}
	// past maxStaleUntil: false
	clk.advance(2 * time.Hour)
	if f.staleWithin(key) {
		t.Fatal("staleWithin true past maxStaleUntil; want false")
	}
}

// TestStaleWithinZeroCostWhenUnset: an entry with no max_stale (zero maxStaleUntil)
// is never a max_stale fallback, and prunes at graceUntil exactly as before.
func TestStaleWithinZeroCostWhenUnset(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	const key = "k"
	f.store(key, time.Minute, time.Minute, 0) // no max_stale

	clk.advance(150 * time.Second) // past grace
	if f.staleWithin(key) {
		t.Fatal("staleWithin true for an entry with no max_stale; want false")
	}
	// classify prunes at graceUntil (today's rule) — the entry is gone.
	if st, _ := f.classify(key); st != stateMiss {
		t.Fatalf("state=%v, want stateMiss", st)
	}
	if f.staleWithin(key) {
		t.Fatal("staleWithin true after prune; want false")
	}
}

// TestStaleWithinRestartSafety: a missing freshness entry (simulating a restart) is
// NEVER a max_stale hit — staleWithin returns false so the request revalidates.
func TestStaleWithinRestartSafety(t *testing.T) {
	f := newFreshness(newFakeClock().now)
	if f.staleWithin("never-stored") {
		t.Fatal("staleWithin true for a missing entry; a restart must revalidate, never a max_stale hit")
	}
}

// TestStaleWithinHonorsBans: a banned within-max_stale entry is not a fallback.
func TestStaleWithinHonorsBans(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	const key = "k"
	f.store(key, time.Minute, time.Minute, time.Hour)
	clk.advance(150 * time.Second) // within max_stale
	if !f.staleWithin(key) {
		t.Fatal("precondition: want within max_stale")
	}
	// Ban issued now (after storedAt) invalidates the entry.
	f.ban(regexp.MustCompile("^k$"))
	if f.staleWithin(key) {
		t.Fatal("staleWithin true for a banned entry; a ban must invalidate the max_stale fallback")
	}
}

// TestStaleWithinIgnoresHitForMiss: a hit-for-miss marker is not a servable object.
func TestStaleWithinIgnoresHitForMiss(t *testing.T) {
	f := newFreshness(newFakeClock().now)
	f.setHitForMiss("k", time.Hour)
	if f.staleWithin("k") {
		t.Fatal("staleWithin true for a hit-for-miss marker; want false")
	}
}
