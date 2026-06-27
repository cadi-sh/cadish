package server

import (
	"testing"
	"time"
)

// TestMustRevalidateHonoredByDefaultGrace (R36 / ADR D97): cadish's serve-stale behavior
// is operator-authoritative. With NO grace configured (the default, grace 0) a stale
// object is NEVER served — it classifies stateMiss the instant it expires and revalidates
// on its next request. This is precisely why an origin `Cache-Control: must-revalidate`
// is honored as a matter of course in the default configuration (no stale serve exists to
// violate RFC 9111 §5.2.2.1). Only an EXPLICIT operator `grace` opt-in serves stale, and
// that decision is authoritative over the origin directive. This test locks both halves of
// that argument.
func TestMustRevalidateHonoredByDefaultGrace(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)
	defer f.Close()

	// Default configuration: grace 0. After the TTL the object must NOT be servable stale.
	const noGrace = "no-grace"
	f.store(noGrace, time.Minute, 0, 0)
	if st, _ := f.classify(noGrace); st != stateFresh {
		t.Fatalf("fresh: state=%v, want stateFresh", st)
	}
	clk.advance(61 * time.Second) // past expiry
	if st, _ := f.classify(noGrace); st != stateMiss {
		t.Fatalf("expired with grace 0: state=%v, want stateMiss (no stale serve -> revalidates, "+
			"so must-revalidate is honored by default)", st)
	}

	// Explicit operator grace opt-in: a stale-in-grace object IS served stale (this is the
	// deliberate, authoritative relaxation — it would apply even to a must-revalidate
	// response, by design).
	const withGrace = "with-grace"
	f.store(withGrace, time.Minute, time.Minute, 0)
	clk.advance(90 * time.Second) // past TTL (60s), within grace (120s)
	if st, _ := f.classify(withGrace); st != stateStale {
		t.Fatalf("within explicit grace: state=%v, want stateStale (operator grace is "+
			"authoritative over origin must-revalidate)", st)
	}
}
