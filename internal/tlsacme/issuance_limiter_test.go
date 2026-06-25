package tlsacme

import (
	"testing"
	"time"
)

// TestIssuanceLimiter verifies the new-name ACME order rate limit: an immediate burst is
// admitted, further new orders are refused, and the bucket refills at the steady rate. This
// is the bound that stops a random-SNI flood on a wildcard/on-demand ACME site from exhausting
// the ACME account's new-order limit.
func TestIssuanceLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIssuanceLimiter(func() time.Time { return now })

	// The full burst is admitted.
	for i := 0; i < newCertBurst; i++ {
		if !l.allow() {
			t.Fatalf("burst token %d/%d should be admitted", i+1, newCertBurst)
		}
	}
	// The next new order (burst exhausted, no time elapsed) is refused.
	if l.allow() {
		t.Fatal("new order past the burst should be refused (random-SNI flood guard)")
	}

	// After enough time for one refill token (3600/refillPerHour seconds), one more is admitted.
	now = now.Add(time.Duration(3600/newCertRefillPerHour) * time.Second)
	if !l.allow() {
		t.Fatal("one token should have refilled after the steady-rate interval")
	}
	if l.allow() {
		t.Fatal("only one token should have refilled; the second is refused")
	}

	// Over a full hour the refill is bounded to ~newCertRefillPerHour (well under LE's 300/3h).
	now = now.Add(time.Hour)
	admitted := 0
	for l.allow() {
		admitted++
		if admitted > newCertBurst+1 { // capacity is the burst; never exceed it in one drain
			t.Fatalf("refill exceeded the burst cap: admitted %d", admitted)
		}
	}
	if admitted > newCertRefillPerHour+1 {
		t.Errorf("one hour refilled %d tokens, want <= ~%d (steady rate)", admitted, newCertRefillPerHour)
	}
}
