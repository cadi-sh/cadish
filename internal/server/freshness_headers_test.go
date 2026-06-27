package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestHitMissFreshnessConsistent (R13): a cadish-cached object must advertise the SAME
// operator-authoritative freshness on a MISS and a later HIT. Previously the origin's
// Cache-Control/Expires were forwarded on a MISS but DROPPED on a HIT, leaving a bare
// Last-Modified that triggers downstream RFC 9111 §4.2.2 heuristic freshness (possibly
// beyond the operator's TTL). cadish now emits `Cache-Control: public, max-age=<ttl>`
// (reflecting its OWN cache_ttl, which overrides the origin's max-age) on both paths and
// drops the absolute Expires.
func TestHitMissFreshnessConsistent(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		// Origin advertises a SHORT heuristic-friendly response: a long max-age and an
		// old Last-Modified + Expires. cadish's cache_ttl (60s) is authoritative and must
		// override these downstream.
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "max-age=999999")
		w.Header().Set("Expires", "Thu, 01 Jan 2099 00:00:00 GMT")
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	miss := get()
	if got := miss.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache=%q, want MISS", got)
	}
	if got := miss.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("MISS Cache-Control=%q, want operator-authoritative public, max-age=60", got)
	}
	if got := miss.Header().Get("Expires"); got != "" {
		t.Errorf("MISS Expires=%q, want it dropped (max-age is authoritative)", got)
	}

	hit := get()
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache=%q, want HIT", got)
	}
	if got := hit.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("HIT Cache-Control=%q, want public, max-age=60 (same as MISS, no heuristic over-cache)", got)
	}
	if got := hit.Header().Get("Expires"); got != "" {
		t.Errorf("HIT Expires=%q, want it dropped", got)
	}
	// The Last-Modified is still replayed (a validator), but it is no longer the ONLY
	// freshness signal — the synthesized Cache-Control prevents heuristic freshness.
	if got := hit.Header().Get("Last-Modified"); got == "" {
		t.Errorf("HIT dropped Last-Modified; the validator should still be replayed")
	}
	// HIT must carry an Age and it must be consistent with max-age (Age <= max-age while fresh).
	if age := hit.Header().Get("Age"); age != "" {
		if a, err := strconv.Atoi(age); err == nil && a > 60 {
			t.Errorf("HIT Age=%d exceeds max-age=60 while fresh", a)
		}
	}
}

// TestExplicitCacheControlOverridesSynthesized (R13): an explicit `header Cache-Control`
// directive must still win over the synthesized operator-authoritative value (the
// synthesized value is written BEFORE the deliver phase).
func TestExplicitCacheControlOverridesSynthesized(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header Cache-Control "public, max-age=31536000, immutable"
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	_ = get() // MISS
	hit := get()
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache=%q, want HIT", got)
	}
	if got := hit.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("HIT Cache-Control=%q, want the explicit operator directive to win", got)
	}
}

// TestUncacheableKeepsOriginCacheControl (R13): a response cadish does NOT store (here a
// `private` response) keeps the origin's Cache-Control verbatim — the synthesis is scoped
// to STORED responses only.
func TestUncacheableKeepsOriginCacheControl(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "private, max-age=30")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	req := httptest.NewRequest("GET", "http://test.local/p", nil)
	req.Host = "test.local"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Cache-Control"); got != "private, max-age=30" {
		t.Errorf("uncacheable Cache-Control=%q, want origin value verbatim (not synthesized)", got)
	}
}

// TestCacheUnsafePrivateNotPromotedToPublic (R13/D96): under `cache_unsafe`, a response the
// origin marked `private` (or no-store/no-cache) IS stored at cadish's own tier (the
// operator's explicit opt-in), but cadish must NOT advertise `public` downstream — that
// would instruct every DOWNSTREAM shared cache (CDN, browser, the Cadish Edge tier) to
// cache a response the origin marked confidential, a broader exposure than the opt-in. The
// HIT (and MISS) must NOT carry `public`; they carry `private` so shared caches refuse it,
// with cadish's authoritative max-age bounding the (private) browser cache.
func TestCacheUnsafePrivateNotPromotedToPublic(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "private")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "secret")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_unsafe
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	miss := get()
	if got := miss.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache=%q, want MISS", got)
	}
	if cc := miss.Header().Get("Cache-Control"); strings.Contains(cc, "public") {
		t.Errorf("MISS Cache-Control=%q must NOT advertise public for a cache_unsafe-forced private store", cc)
	} else if !strings.Contains(cc, "private") {
		t.Errorf("MISS Cache-Control=%q, want a private marker so downstream shared caches refuse it", cc)
	}

	hit := get()
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache=%q, want HIT (cache_unsafe stored it)", got)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits=%d, want 1 (cache_unsafe must still cache at cadish's tier)", origin.hits.Load())
	}
	cc := hit.Header().Get("Cache-Control")
	if strings.Contains(cc, "public") {
		t.Errorf("HIT Cache-Control=%q promotes a private origin response to public downstream (confidentiality leak)", cc)
	}
	if !strings.Contains(cc, "private") {
		t.Errorf("HIT Cache-Control=%q, want a private marker (and a bounded max-age)", cc)
	}
}

// TestCacheUnsafePublicStillSynthesizesPublic guards that the FIX is scoped: a normal
// cacheable PUBLIC response under cache_unsafe (origin sent nothing restrictive) still gets
// the operator-authoritative `public, max-age=N` on HIT==MISS — only the forced-private
// store is downgraded.
func TestCacheUnsafePublicStillSynthesizesPublic(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_unsafe
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := get().Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("MISS Cache-Control=%q, want public, max-age=60 (normal public store unaffected)", got)
	}
	hit := get()
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache=%q, want HIT", got)
	}
	if got := hit.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Errorf("HIT Cache-Control=%q, want public, max-age=60", got)
	}
}
