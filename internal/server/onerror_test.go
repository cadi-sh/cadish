package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// flipOrigin is an httptest origin whose handler can be swapped atomically, so a
// test can make the SAME upstream go from healthy to hard-failing mid-test.
type flipOrigin struct {
	srv *httptest.Server
	h   atomic.Pointer[http.HandlerFunc]
}

func newFlipOrigin(t *testing.T, initial http.HandlerFunc) *flipOrigin {
	t.Helper()
	fo := &flipOrigin{}
	fo.h.Store(&initial)
	fo.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*fo.h.Load())(w, r)
	}))
	t.Cleanup(fo.srv.Close)
	return fo
}

func (fo *flipOrigin) set(h http.HandlerFunc) { fo.h.Store(&h) }

// cfgOnError caches only a 200 (cache_ttl status 200), so a 5xx / transport error
// is UNCACHEABLE and reaches the on_error fallback. A `cache_ttl default` would
// instead negative-cache the 5xx (negative-cache > on_error), which the dedicated
// precedence test exercises separately.
const cfgOnError = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 60s
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`

// TestOnErrorTransportError: a transport error (unreachable origin) with on_error
// configured and a cold cache serves the configured status + body (spec test 1).
func TestOnErrorTransportError(t *testing.T) {
	// Stand up an origin, then close it so every dial is a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	url := srv.URL
	srv.Close() // now unreachable

	h, _ := buildHandler(t, nil, cfgOnError, url)
	rec := do(h, "GET", "http://test.local/anything", nil)
	if rec.Code != 503 {
		t.Fatalf("code = %d, want 503 (on_error synthetic)", rec.Code)
	}
	if rec.Body.String() != "down for maintenance" {
		t.Fatalf("body = %q, want the maintenance page", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8 (default)", got)
	}
}

// TestOnErrorNonCacheable5xx: a non-cacheable 5xx (no `cache_ttl status` for it)
// with no stale copy fires on_error (spec test 2).
func TestOnErrorNonCacheable5xx(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream 502")
	})
	h, _ := buildHandler(t, nil, cfgOnError, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/x", nil)
	if rec.Code != 503 {
		t.Fatalf("code = %d, want 503 (on_error, the 502 is uncacheable)", rec.Code)
	}
	if rec.Body.String() != "down for maintenance" {
		t.Fatalf("body = %q, want the maintenance page", rec.Body.String())
	}
}

// TestOnErrorReturned4xxFiresOnError PINS the real Go behavior for a returned 4xx
// that is NOT 404/410 (e.g. 403, 429, 405): httporigin maps it to a *StatusError
// (negativeStatus is ONLY 404||410), which flows into handleOriginError, whose
// hard-failure chain DOES fire `respond on_error`. This is the divergence the edge
// worker must mirror (a returned 403/429 is NOT a Negative response and is NOT
// normal MISS delivery — it is the on_error/max_stale path). The status is
// uncacheable here (cache_ttl status 200 only), so on_error wins.
func TestOnErrorReturned4xxFiresOnError(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusMethodNotAllowed, http.StatusUnauthorized} {
		origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, "upstream error page")
		})
		h, _ := buildHandler(t, nil, cfgOnError, origin.srv.URL)
		rec := do(h, "GET", "http://test.local/x", nil)
		if rec.Code != 503 {
			t.Fatalf("returned %d: code = %d, want 503 (on_error fires for a non-404/410 4xx StatusError)", code, rec.Code)
		}
		if rec.Body.String() != "down for maintenance" {
			t.Fatalf("returned %d: body = %q, want the maintenance page", code, rec.Body.String())
		}
	}
}

// TestReturned4xxBareStatusNoOnError PINS that with NO on_error, a returned
// non-404/410 4xx surfaces the BARE upstream status (writeStatus(code)), not 502 and
// not a Negative-cache 404. Confirms the edge's bare-status fallthrough target.
func TestReturned4xxBareStatusNoOnError(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "forbidden page")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/x", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 (bare returned status, no on_error)", rec.Code)
	}
}

// TestReturned4xxMaxStaleSalvageWins PINS that a returned non-404/410 4xx, like any
// hard failure, is salvaged by a last-good copy still within its max_stale window —
// max_stale outranks on_error and the bare status (the FIRST fallback in
// handleOriginError).
func TestReturned4xxMaxStaleSalvageWins(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "forbidden")
			return
		}
		_, _ = io.WriteString(w, "good body")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s max_stale 1h
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, body, origin.srv.URL)
	if rec := do(h, "GET", "http://test.local/p", nil); rec.Code != 200 {
		t.Fatalf("prime code = %d, want 200", rec.Code)
	}
	clk.advance(2 * time.Minute) // past TTL, inside max_stale window
	fail.Store(true)
	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "good body" {
		t.Fatalf("got %d %q, want 200 good-body (max_stale salvage beats on_error on a returned 403)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT-STALE-ERROR" {
		t.Fatalf("X-Cache = %q, want HIT-STALE-ERROR", got)
	}
}

// TestOnErrorNegativeCacheWins: a cacheable negative status (D15) is served from
// the negative cache; on_error is NOT invoked (precedence: negative-cache >
// on_error) (spec test 3).
func TestOnErrorNegativeCacheWins(t *testing.T) {
	const errBody = "<html>real 404 page</html>"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, errBody)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 404 ttl 60s
	cache_ttl default ttl 60s
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/missing", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 (cacheable negative wins over on_error)", rec.Code)
	}
	if rec.Body.String() == "down for maintenance" {
		t.Fatal("served the on_error page; the cacheable negative entry must win")
	}
}

// TestOnErrorStaleInGraceWins: a stale-but-in-grace object is served on origin
// failure; on_error is NOT invoked (precedence: stale > on_error) (spec test 4).
func TestOnErrorStaleInGraceWins(t *testing.T) {
	clk := newFakeClock()
	var fail atomic.Bool
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "fresh body")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s grace 1h
	respond on_error 503 "down for maintenance"
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, body, origin.srv.URL)

	// Prime the cache with a fresh object.
	if rec := do(h, "GET", "http://test.local/p", nil); rec.Code != 200 {
		t.Fatalf("prime code = %d, want 200", rec.Code)
	}
	// Move into the grace window and make the origin hard-fail.
	clk.advance(2 * time.Minute) // past 60s TTL, inside 1h grace
	fail.Store(true)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 {
		t.Fatalf("code = %d, want 200 (stale-in-grace served, not on_error)", rec.Code)
	}
	if rec.Body.String() != "fresh body" {
		t.Fatalf("body = %q, want the stale cached body, not the on_error page", rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("X-Cache = %q, want HIT-STALE", got)
	}
}

// TestOnErrorScope: an `@scope`d on_error fires only for matching paths; a
// non-matching path falls through to the bare fallback (spec test 5).
func TestOnErrorScope(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 60s
	@api path /api/*
	respond on_error @api 503 "api down"
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/api/users", nil)
	if rec.Code != 503 || rec.Body.String() != "api down" {
		t.Fatalf("matching path: got %d %q, want 503 api-down", rec.Code, rec.Body.String())
	}

	rec2 := do(h, "GET", "http://test.local/home", nil)
	if rec2.Code != http.StatusBadGateway {
		t.Fatalf("non-matching path code = %d, want 502 (bare fallback)", rec2.Code)
	}
	if rec2.Body.String() == "api down" {
		t.Fatal("non-matching path served the api page; @scope must gate it")
	}
}

// TestOnErrorHeadNoBody: a HEAD request gets the on_error status + headers with no
// body (spec test 7).
func TestOnErrorHeadNoBody(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	h, _ := buildHandler(t, nil, cfgOnError, origin.srv.URL)
	rec := do(h, "HEAD", "http://test.local/x", nil)
	if rec.Code != 503 {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD body len = %d, want 0", rec.Body.Len())
	}
	if got := rec.Header().Get("Content-Length"); got != "20" { // len("down for maintenance")
		t.Fatalf("Content-Length = %q, want 20 (the full body length, even on HEAD)", got)
	}
}

// TestOnErrorRangeFullBody: a Range request that hits origin error gets the FULL
// synthetic, never a 206 slice of an error page (spec test 7).
func TestOnErrorRangeFullBody(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	h, _ := buildHandler(t, nil, cfgOnError, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/x", http.Header{"Range": {"bytes=0-3"}})
	if rec.Code != 503 {
		t.Fatalf("code = %d, want 503 (full synthetic), not 206", rec.Code)
	}
	if rec.Body.String() != "down for maintenance" {
		t.Fatalf("body = %q, want the full synthetic body", rec.Body.String())
	}
}

// TestOnErrorNotCached: the on_error synthetic is NOT cached — a subsequent request
// after the origin recovers is a fresh MISS that serves the real body (spec test 8).
func TestOnErrorNotCached(t *testing.T) {
	fo := newFlipOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	h, _ := buildHandler(t, nil, cfgOnError, fo.srv.URL)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 503 || rec.Body.String() != "down for maintenance" {
		t.Fatalf("first: got %d %q, want 503 on_error", rec.Code, rec.Body.String())
	}

	// Origin recovers; the synthetic must not have poisoned the cache.
	fo.set(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "real body")
	})
	rec2 := do(h, "GET", "http://test.local/p", nil)
	if rec2.Code != 200 || rec2.Body.String() != "real body" {
		t.Fatalf("after recovery: got %d %q, want 200 real-body (synthetic was not cached)", rec2.Code, rec2.Body.String())
	}
	if got := rec2.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("after recovery X-Cache = %q, want MISS (re-evaluated, not served from cache)", got)
	}
}

// TestNoOnErrorUpstream5xxBodyDelivered: with NO `respond on_error`, a real upstream
// 5xx now delivers the origin's REAL status + body + headers verbatim (the bare
// `origin error` synthetic is reserved for a transport failure, where there is no
// upstream body — see TestTransportErrorBareFallback). PRESERVE-ORIGIN-ERROR-BODY.
func TestNoOnErrorUpstream5xxBodyDelivered(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"upstream boom"}`)
	})
	// Cache only a 200, so the uncacheable 502 reaches the terminal (not the
	// negative cache), and there is no `respond on_error` to intercept it.
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/x", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502 (real upstream status delivered verbatim)", rec.Code)
	}
	if rec.Body.String() != `{"error":"upstream boom"}` {
		t.Fatalf("body = %q, want the upstream JSON body verbatim (not \"origin error\")", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json (origin error headers delivered)", got)
	}
}
