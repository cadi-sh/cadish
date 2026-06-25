package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestQuerySemicolonDoesNotPoison is a cache-poisoning regression: a ';'-cloaked query
// (`/p?cb=PWNED;x=1`) must key DISTINCTLY from the plain resource (`/p`), not collapse onto
// it. Go's url.Query() drops a ';'-containing segment, which made the cache key omit query
// content the origin still receives — so a `cache_key url` entry created by the cloaked query
// would be served to a victim requesting plain `/p` (parameter cloaking). parseQueryLossless
// ('&'-only, matching the edge + the origin's raw view) closes it.
func TestQuerySemicolonDoesNotPoison(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "BODY-FOR["+r.URL.RawQuery+"]")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key url
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	doRaw := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local"+target, nil)
		req.Host = "test.local"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Attacker primes a ;-cloaked query.
	a := doRaw("/p?cb=PWNED;x=1")
	if got := a.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("attacker request X-Cache=%q, want MISS", got)
	}
	// Victim's PLAIN /p must NOT be served the attacker's entry.
	b := doRaw("/p")
	if got := b.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("CACHE POISON: plain /p served the ;-cloaked entry (body=%q)", b.Body.String())
	}
	if b.Body.String() != "BODY-FOR[]" {
		t.Errorf("victim /p body=%q, want its own empty-query body", b.Body.String())
	}
	// The cloaked query IS keyed: a second identical cloaked request HITs its own entry.
	if got := doRaw("/p?cb=PWNED;x=1").Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second cloaked request X-Cache=%q, want HIT (it has its own entry)", got)
	}
}
