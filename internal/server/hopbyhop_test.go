package server

import (
	"io"
	"net/http"
	"sync"
	"testing"
)

const cfgPassthrough = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 0s
}
`

// TestConnectionTokensStrippedToOrigin verifies RFC 7230 §6.1: a proxy must strip
// every header NAMED in the request's Connection token list before forwarding to
// the origin. A client must not be able to smuggle a Connection-listed header
// (e.g. `Connection: X-Secret` + `X-Secret: v`) past the proxy to the origin.
func TestConnectionTokensStrippedToOrigin(t *testing.T) {
	var mu sync.Mutex
	var gotSecret, gotConn string
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotSecret = r.Header.Get("X-Secret")
		gotConn = r.Header.Get("Connection")
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgPassthrough, origin.srv.URL)

	hdr := http.Header{
		"Connection": {"X-Secret"},
		"X-Secret":   {"v"},
	}
	rec := do(h, "GET", "http://test.local/a", hdr)
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotSecret != "" {
		t.Fatalf("Connection-listed header forwarded to origin: X-Secret=%q, want stripped", gotSecret)
	}
	if gotConn != "" {
		t.Fatalf("Connection header forwarded to origin: %q, want stripped", gotConn)
	}
}

// TestConnectionTokensStrippedFromOrigin verifies the response direction: a header
// named in the origin response's Connection token list must not reach the client.
func TestConnectionTokensStrippedFromOrigin(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Leak")
		w.Header().Set("X-Leak", "v")
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgPassthrough, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/b", nil)
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Leak"); got != "" {
		t.Fatalf("Connection-listed response header reached client: X-Leak=%q, want stripped", got)
	}
}
