package server

import (
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// cfgMaxStale: 1m TTL, 2m grace, 1h max_stale; only 200 is cacheable so a 5xx /
// transport error is uncacheable and reaches the error path. on_error is configured
// so the precedence (max_stale > on_error) is observable.
const cfgMaxStale = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 1m grace 2m max_stale 1h
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`

// prime stores a fresh object and asserts the MISS.
func primeMaxStale(t *testing.T, h *Handler, path string) {
	t.Helper()
	if rec := do(h, "GET", "http://test.local"+path, nil); rec.Code != 200 {
		t.Fatalf("prime %s: code=%d, want 200", path, rec.Code)
	}
}

// Test 1 (spec): within-max_stale + origin OK -> normal fetch (expired-like), NOT a
// stale serve. Proves max_stale never affects the healthy path.
func TestMaxStaleOriginOKFetchesNormally(t *testing.T) {
	clk := newFakeClock()
	var body atomic.Value
	body.Store("v1")
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body.Load().(string))
	})
	h, _ := buildHandler(t, clk, cfgMaxStale, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	// Move past grace, still within max_stale; origin healthy and now serves v2.
	clk.advance(4 * time.Minute) // past 1m TTL + 2m grace
	body.Store("v2")

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "v2" {
		t.Fatalf("got %d %q, want 200 v2 (normal fetch, not a stale serve)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("X-Cache=%q, want MISS (healthy request fetched origin)", got)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits=%d, want 2 (prime + refetch)", origin.hits.Load())
	}
}

// Test 2 (spec): within-max_stale + origin DOWN -> serve stale (HIT-STALE-ERROR);
// the marker is NOT refreshed (a second failing request still serves
// HIT-STALE-ERROR, never HIT).
func TestMaxStaleOriginDownServesStale(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "last-good")
	})
	h, _ := buildHandler(t, clk, cfgMaxStale, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	clk.advance(4 * time.Minute) // past grace, within max_stale
	fail.Store(true)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "last-good" {
		t.Fatalf("got %d %q, want 200 last-good (HIT-STALE-ERROR), not on_error", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT-STALE-ERROR" {
		t.Fatalf("X-Cache=%q, want HIT-STALE-ERROR", got)
	}

	// No marker refresh: advance a little (still within original max_stale) and fail
	// again — must still be HIT-STALE-ERROR, never HIT.
	clk.advance(10 * time.Minute)
	rec2 := do(h, "GET", "http://test.local/p", nil)
	if got := rec2.Header().Get("X-Cache"); got != "HIT-STALE-ERROR" {
		t.Fatalf("second failing request X-Cache=%q, want HIT-STALE-ERROR (marker not refreshed)", got)
	}
}

// Test 3 (spec): within-max_stale + origin 404 (ErrNotFound) -> last-good served
// (max_stale outranks the D57 404 path).
func TestMaxStaleOrigin404ServesLastGood(t *testing.T) {
	clk := newFakeClock()
	var gone atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if gone.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "last-good")
	})
	h, _ := buildHandler(t, clk, cfgMaxStale, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	clk.advance(4 * time.Minute) // within max_stale
	gone.Store(true)             // origin now 404s

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "last-good" {
		t.Fatalf("got %d %q, want 200 last-good (max_stale beats the 404)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT-STALE-ERROR" {
		t.Fatalf("X-Cache=%q, want HIT-STALE-ERROR", got)
	}
}

// Test 4 (spec): beyond max_stale + origin down -> falls through to on_error (the
// ceiling is enforced).
func TestMaxStaleBeyondWindowFallsToOnError(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "last-good")
	})
	h, _ := buildHandler(t, clk, cfgMaxStale, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	clk.advance(2 * time.Hour) // well past 1m+2m+1h max_stale ceiling
	fail.Store(true)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 503 || rec.Body.String() != "down for maintenance" {
		t.Fatalf("got %d %q, want 503 on_error (beyond max_stale)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got == "HIT-STALE-ERROR" {
		t.Fatal("served HIT-STALE-ERROR beyond the max_stale ceiling")
	}
}

// Test 5 (spec): precedence vs grace — within grace + origin down -> HIT-STALE
// (live grace), NOT HIT-STALE-ERROR. Grace is decided before the fetch and never
// reaches the error path.
func TestMaxStaleGraceWinsBeforeFetch(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, clk, cfgMaxStale, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	clk.advance(90 * time.Second) // past 1m TTL, within 2m grace
	fail.Store(true)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "body" {
		t.Fatalf("got %d %q, want 200 body (live grace)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("X-Cache=%q, want HIT-STALE (grace), not HIT-STALE-ERROR", got)
	}
}

// Test 6 (spec): precedence vs D57 / negative cache. With max_stale AND on_error AND
// a cacheable negative rule all configured: within max_stale -> HIT-STALE-ERROR;
// beyond max_stale -> the negative cache / on_error in that order.
func TestMaxStalePrecedenceOverNegativeAndOnError(t *testing.T) {
	clk := newFakeClock()
	var mode atomic.Int32 // 0 ok, 1 fail-503
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "real")
	})
	// 200 cacheable with max_stale; 503 is also a cacheable negative status (D15).
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 1m grace 2m max_stale 1h
	cache_ttl status 503 ttl 30s
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, body, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	clk.advance(4 * time.Minute) // within max_stale
	mode.Store(1)                // origin 503s

	// max_stale wins over both negative cache and on_error.
	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "real" || rec.Header().Get("X-Cache") != "HIT-STALE-ERROR" {
		t.Fatalf("within max_stale: got %d %q X-Cache=%q, want 200 real HIT-STALE-ERROR", rec.Code, rec.Body.String(), rec.Header().Get("X-Cache"))
	}

	// Beyond max_stale: the 503 is negative-cacheable, so it is stored+served (503),
	// NOT the on_error synthetic (negative cache > on_error).
	clk.advance(2 * time.Hour)
	rec2 := do(h, "GET", "http://test.local/p", nil)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("beyond max_stale: code=%d, want 503", rec2.Code)
	}
	if rec2.Body.String() == "down for maintenance" {
		t.Fatal("beyond max_stale served the on_error page; the cacheable negative entry must win")
	}
}

// Test 7 (spec): restart-safety. Drop the freshness entry (simulating a restart)
// with the blob still in the store; a failing-origin request must MISS/revalidate,
// never serve HIT-STALE-ERROR.
func TestMaxStaleRestartSafety(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "last-good")
	})
	h, _ := buildHandler(t, clk, cfgMaxStale, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	// Simulate a restart: the in-memory freshness index is empty, but the blob may
	// linger in the store. forget drops the marker. The default cache key is
	// method \x1f host \x1f path.
	h.fresh.forget("GET\x1ftest.local\x1f/p")

	clk.advance(4 * time.Minute) // would be within max_stale had the marker survived
	fail.Store(true)

	rec := do(h, "GET", "http://test.local/p", nil)
	// No marker => not a max_stale hit. The origin fails and there is no servable
	// object, so it falls to on_error (503), never HIT-STALE-ERROR.
	if got := rec.Header().Get("X-Cache"); got == "HIT-STALE-ERROR" {
		t.Fatal("served HIT-STALE-ERROR after a simulated restart; a missing marker must never be a max_stale hit")
	}
	if rec.Code != 503 {
		t.Fatalf("code=%d, want 503 on_error (revalidate failed, no servable object)", rec.Code)
	}
}

// Test 8 (spec): zero-cost / opt-out. A site with NO max_stale: a past-grace object
// + failing origin reaches on_error exactly as today (regression guard).
func TestMaxStaleOptOutUnchanged(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "body")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 1m grace 2m
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, body, origin.srv.URL)

	primeMaxStale(t, h, "/p")
	clk.advance(4 * time.Minute) // past grace; no max_stale window exists
	fail.Store(true)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 503 || rec.Body.String() != "down for maintenance" {
		t.Fatalf("got %d %q, want 503 on_error (no max_stale configured)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got == "HIT-STALE-ERROR" {
		t.Fatal("served HIT-STALE-ERROR without a max_stale window")
	}
}
