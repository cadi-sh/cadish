package server

import (
	"net/http"
	"testing"
)

// cfgGraceStrip: the origin drives TTL+grace+max_stale via private control headers;
// cadish must STRIP those consumed control headers from the delivered response (they
// are an internal origin↔cache contract, not for the client — Varnish unsets them).
const cfgGraceStrip = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default from_header X-Cache-Ttl grace_from_header X-Cache-Grace max_stale_from_header X-Cache-Max-Stale grace 1m max_stale 2h
}
`

// The consumed from_header-family control headers are stripped from the MISS delivery.
func TestGraceFromHeaderStripsControlHeaders(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Set("X-Cache-Grace", "5m")
		w.Header().Set("X-Cache-Max-Stale", "30m")
		w.Header().Set("X-Keep-Me", "yes")
		_, _ = w.Write([]byte("body"))
	})
	h, _ := buildHandler(t, nil, cfgGraceStrip, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "body" {
		t.Fatalf("got %d %q, want 200 body", rec.Code, rec.Body.String())
	}
	for _, n := range []string{"X-Cache-Ttl", "X-Cache-Grace", "X-Cache-Max-Stale"} {
		if got := rec.Header().Get(n); got != "" {
			t.Errorf("control header %q leaked to client: %q", n, got)
		}
	}
	// A non-control origin header is untouched.
	if got := rec.Header().Get("X-Keep-Me"); got != "yes" {
		t.Errorf("X-Keep-Me=%q, want yes (non-control header must survive)", got)
	}
}

// A plain `ttl` site does NOT strip an origin's X-Cache-Ttl-looking header (no
// from_header rule consumes it) — proves the strip is scoped to consumed headers.
func TestNoStripWithoutFromHeaderRule(t *testing.T) {
	const cfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 30s
}
`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache-Ttl", "60")
		_, _ = w.Write([]byte("body"))
	})
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", nil)
	if got := rec.Header().Get("X-Cache-Ttl"); got != "60" {
		t.Errorf("X-Cache-Ttl=%q, want 60 (no from_header rule -> not stripped)", got)
	}
}
