package server

import (
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

const cfgRateLimit = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 10.0.0.0/8
	@api path /api/*
	rate_limit @api 10r/s burst 2 key ip
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestRateLimitThrottlesWith429NoOriginNoCache is the load-bearing guarantee: once
// the bucket is empty a request gets 429 + Retry-After and touches NEITHER origin
// NOR cache (same guarantee as deny).
func TestRateLimitThrottlesWith429NoOriginNoCache(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "api-body")
	})
	h, _ := buildHandler(t, clk, cfgRateLimit, origin.srv.URL)

	// burst 2 => first two requests from one IP pass and reach origin.
	for i := 0; i < 2; i++ {
		rec := doFrom(h, "GET", "http://test.local/api/x", "203.0.113.5:5000", nil)
		if rec.Code != 200 {
			t.Fatalf("request %d within burst: got %d, want 200", i+1, rec.Code)
		}
	}
	hitsAfterBurst := origin.hits.Load()
	if hitsAfterBurst == 0 {
		t.Fatal("burst requests must reach origin")
	}

	// Third request (no time elapsed) is throttled: 429 + Retry-After, no origin hit.
	rec := doFrom(h, "GET", "http://test.local/api/x", "203.0.113.5:5000", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request: got %d, want 429", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 must carry a Retry-After header")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer (seconds)", ra)
	}
	if rec.Body.String() == "api-body" {
		t.Fatal("throttled request leaked the origin body (origin was reached)")
	}
	if origin.hits.Load() != hitsAfterBurst {
		t.Fatalf("throttled request reached origin (hits %d -> %d)", hitsAfterBurst, origin.hits.Load())
	}
	// A throttled request must not have stored anything: X-Cache (deliver-phase) absent.
	if got := rec.Header().Get("X-Cache"); got != "" {
		t.Fatalf("throttled request set X-Cache=%q, want empty (never reached cache)", got)
	}

	// Advance the clock so a token refills (10 r/s => 100ms/token); next passes.
	clk.advance(150 * time.Millisecond)
	rec = doFrom(h, "GET", "http://test.local/api/x", "203.0.113.5:5000", nil)
	if rec.Code != 200 {
		t.Fatalf("after refill: got %d, want 200", rec.Code)
	}
}

// TestRateLimitScopeOnlyMatching verifies a scoped rate_limit only throttles
// matching requests; an unscoped path is never limited.
func TestRateLimitScopeOnlyMatching(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, clk, cfgRateLimit, origin.srv.URL)

	// Hammer a NON-/api path far past the limit: never throttled.
	for i := 0; i < 50; i++ {
		rec := doFrom(h, "GET", "http://test.local/static/x", "203.0.113.5:5000", nil)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("non-matching path was rate-limited at request %d", i+1)
		}
	}
}

// TestRateLimitPerKeyIsolation verifies one IP's flood does not throttle another IP.
func TestRateLimitPerKeyIsolation(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, clk, cfgRateLimit, origin.srv.URL)

	// Exhaust IP A (burst 2 + the throttled one).
	for i := 0; i < 5; i++ {
		doFrom(h, "GET", "http://test.local/api/x", "203.0.113.5:5000", nil)
	}
	throttled := doFrom(h, "GET", "http://test.local/api/x", "203.0.113.5:5000", nil)
	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf("flooding IP must be throttled, got %d", throttled.Code)
	}
	// A DIFFERENT IP has its own full bucket.
	other := doFrom(h, "GET", "http://test.local/api/x", "203.0.113.99:5000", nil)
	if other.Code != 200 {
		t.Fatalf("a different IP must not be throttled by another IP's flood, got %d", other.Code)
	}
}

// TestRateLimitResolvesRealClientBehindProxy verifies key ip uses the trusted-proxy
// resolved REAL client IP (decision #16): two requests from the same real client
// behind a proxy share a bucket; a different real client behind the same proxy has
// its own.
func TestRateLimitResolvesRealClientBehindProxy(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, clk, cfgRateLimit, origin.srv.URL)

	clientA := http.Header{"X-Forwarded-For": {"198.51.100.7"}}
	clientB := http.Header{"X-Forwarded-For": {"198.51.100.8"}}

	// Exhaust client A (peer is the trusted proxy 10.x; real client is the XFF IP).
	for i := 0; i < 5; i++ {
		doFrom(h, "GET", "http://test.local/api/x", "10.0.0.1:443", clientA)
	}
	a := doFrom(h, "GET", "http://test.local/api/x", "10.0.0.1:443", clientA)
	if a.Code != http.StatusTooManyRequests {
		t.Fatalf("real client A behind proxy must be throttled by its OWN IP, got %d", a.Code)
	}
	// Client B behind the SAME proxy is independent (bucket keyed on real client, not
	// the shared proxy peer — otherwise B would already be throttled).
	b := doFrom(h, "GET", "http://test.local/api/x", "10.0.0.1:443", clientB)
	if b.Code != 200 {
		t.Fatalf("real client B behind the same proxy must have its own bucket, got %d", b.Code)
	}
}

const cfgRateLimitMonitor = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 10.0.0.0/8
	rate_limit 1r/s burst 1 key ip monitor
	cache_ttl default ttl 60s
}
`

// TestRateLimitMonitorPasses verifies monitor mode records a would-429 but lets the
// request through to origin (decision #19).
func TestRateLimitMonitorPasses(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, clk, cfgRateLimitMonitor, origin.srv.URL)

	// burst 1 => the first request consumes the only token; subsequent requests in
	// monitor mode would-429 but PASS (200) — they are NOT throttled (the cache may
	// serve them, which is fine; the point is no 429 and no Retry-After).
	for i := 0; i < 4; i++ {
		rec := doFrom(h, "GET", "http://test.local/x", "203.0.113.5:5000", nil)
		if rec.Code != 200 {
			t.Fatalf("monitor mode request %d: got %d, want 200 (passes)", i+1, rec.Code)
		}
		if rec.Header().Get("Retry-After") != "" {
			t.Fatalf("monitor mode must not set Retry-After (request %d)", i+1)
		}
	}
}

const cfgNoRateLimit = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
}
`

// TestNoRateLimitNoLimiterConstructed verifies a site with no rate_limit rule
// constructs NO limiter (zero cost — no sweeper goroutine).
func TestNoRateLimitNoLimiterConstructed(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, nil, cfgNoRateLimit, origin.srv.URL)
	if h.limiter != nil {
		t.Fatal("a site with no rate_limit rule must not construct a limiter")
	}
}

// TestRateLimitConstructsLimiter verifies the limiter IS constructed when a site
// uses rate_limit.
func TestRateLimitConstructsLimiter(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, nil, cfgRateLimit, origin.srv.URL)
	if h.limiter == nil {
		t.Fatal("a site with a rate_limit rule must construct a limiter")
	}
}
