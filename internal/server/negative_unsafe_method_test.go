package server

import (
	"io"
	"net/http"
	"testing"
)

// cfgNegUnsafe uses a METHOD-LESS cache key (cache_key path) so a POST and a GET to
// the same path share one key. Negative caching is enabled for 404, 410 and 500.
// Without the safe-method store guard, a cacheable error response to a POST would be
// negatively cached under that shared key and then served to a subsequent GET —
// poisoning the GET with a cached failure that never reaches origin.
const cfgNegUnsafe = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key path
	cache_ttl status 404 410 500 ttl 60s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestNegativeCacheNotStoredForUnsafeMethod_FullBody404 covers the serveOrigin
// negative path (a 404 carrying a body comes back as a full-body Negative response):
// a POST yielding a 404 must NOT populate the (method-less) negative cache, so a
// later GET still reaches origin (MISS).
func TestNegativeCacheNotStoredForUnsafeMethod_FullBody404(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "not here")
	})
	h, _ := buildHandler(t, nil, cfgNegUnsafe, origin.srv.URL)

	// POST that 404s: served to the client, but must NOT be negatively cached.
	rp := doBody(h, "POST", "http://test.local/p", "payload", nil)
	if rp.Code != http.StatusNotFound {
		t.Fatalf("POST code = %d, want 404", rp.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("after POST: origin hits = %d, want 1", origin.hits.Load())
	}

	// Subsequent GET to the same (method-less) key must reach origin — a MISS, not a
	// HIT served from the poisoned negative entry.
	rg := do(h, "GET", "http://test.local/p", nil)
	if rg.Code != http.StatusNotFound {
		t.Fatalf("GET code = %d, want 404", rg.Code)
	}
	if got := rg.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("GET X-Cache = %q, want MISS (POST must not poison the negative cache)", got)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("after GET: origin hits = %d, want 2 (GET must reach origin)", origin.hits.Load())
	}
}

// TestNegativeCacheNotStoredForUnsafeMethod_StatusError500 covers the
// handleOriginError negative path (a 500 comes back as a bodyless *StatusError):
// a POST yielding a cacheable 500 must NOT populate the method-less negative cache.
func TestNegativeCacheNotStoredForUnsafeMethod_StatusError500(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	})
	h, _ := buildHandler(t, nil, cfgNegUnsafe, origin.srv.URL)

	rp := doBody(h, "POST", "http://test.local/q", "payload", nil)
	if rp.Code != http.StatusInternalServerError {
		t.Fatalf("POST code = %d, want 500", rp.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("after POST: origin hits = %d, want 1", origin.hits.Load())
	}

	rg := do(h, "GET", "http://test.local/q", nil)
	if rg.Code != http.StatusInternalServerError {
		t.Fatalf("GET code = %d, want 500", rg.Code)
	}
	if got := rg.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("GET X-Cache = %q, want MISS (POST 500 must not poison the negative cache)", got)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("after GET: origin hits = %d, want 2 (GET must reach origin)", origin.hits.Load())
	}
}

// TestNegativeCacheStillStoredForGet is the control: a GET that yields a cacheable
// 404 IS negatively cached, so the SECOND GET is served the 404 from cache (HIT)
// without re-hitting origin. This confirms the safe-method guard does not break
// normal negative caching.
func TestNegativeCacheStillStoredForGet(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "gone")
	})
	h, _ := buildHandler(t, nil, cfgNegUnsafe, origin.srv.URL)

	r1 := do(h, "GET", "http://test.local/g", nil)
	if r1.Code != http.StatusNotFound || r1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET: code=%d X-Cache=%q, want 404 MISS", r1.Code, r1.Header().Get("X-Cache"))
	}
	r2 := do(h, "GET", "http://test.local/g", nil)
	if r2.Code != http.StatusNotFound {
		t.Fatalf("second GET code = %d, want 404", r2.Code)
	}
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second GET X-Cache = %q, want HIT (GET 404 is negatively cached)", got)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (second GET served from negative cache)", origin.hits.Load())
	}
}
