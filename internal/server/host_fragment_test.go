package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHostPortDoesNotFragmentCache is the "host normalizer split" regression: site selection
// (normalizeAddr) and the cache key (normalizeHost) must canonicalize a Host IDENTICALLY, or a
// Host that selects the same site forks the cache key — a cache-bust / fragmentation DoS. An
// attacker sending `test.local:<random>` (a non-numeric "port") once forked a distinct entry
// per value while still routing to the site. The normalizers are now one function, so any
// single-colon host:port (numeric or not) collapses onto the bare host.
func TestHostPortDoesNotFragmentCache(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)
	xcache := func(host string) string {
		req := httptest.NewRequest("GET", "http://x/p", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header().Get("X-Cache")
	}
	if got := xcache("test.local"); got != "MISS" {
		t.Fatalf("first request X-Cache=%q, want MISS", got)
	}
	// A numeric port already collapsed; a NON-numeric "port" must too (no fork).
	if got := xcache("test.local:9999"); got != "HIT" {
		t.Errorf("numeric-port host X-Cache=%q, want HIT (same entry)", got)
	}
	if got := xcache("test.local:zzz"); got != "HIT" {
		t.Errorf("non-numeric-port host X-Cache=%q, want HIT (must not fork the cache)", got)
	}
	if got := xcache("TEST.LOCAL."); got != "HIT" {
		t.Errorf("upper-case + trailing-dot host X-Cache=%q, want HIT (canonicalizes the same)", got)
	}
	if n := origin.hits.Load(); n != 1 {
		t.Errorf("origin hits = %d, want 1 (all host variants collapse onto one cache entry)", n)
	}
}
