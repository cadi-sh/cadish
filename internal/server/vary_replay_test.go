package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestVaryReplayedOnHit: the origin's Vary header must be re-emitted on a HIT so a downstream
// shared cache (or the edge tier in front) keeps the variance signal. cadish partitions its
// OWN cache by the key (here cache_key covers Accept-Language), but a HIT previously dropped
// Vary because ObjectMeta did not store it.
func TestVaryReplayedOnHit(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Vary", "Accept-Language")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path header:Accept-Language
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		req.Header.Set("Accept-Language", "en")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if got := get().Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache=%q, want MISS", got)
	}
	hit := get()
	if got := hit.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache=%q, want HIT", got)
	}
	if got := hit.Header().Get("Vary"); got != "Accept-Language" {
		t.Errorf("HIT Vary=%q, want Accept-Language (replayed for downstream variant safety)", got)
	}
}
