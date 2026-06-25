package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHostNormalizationDoesNotPoison is the Host dimension of the "key reads differently than
// the origin gets" class: the cache key normalizes the Host (strips :port, lower-cases), but
// the origin (host_header preserve) previously received the RAW Host. So `test.local:1337` and
// `test.local` collided on one cache entry while the origin saw different Hosts — a
// Host-reflecting origin's response for the port variant was then served to the bare host
// (cache poisoning). The forwarded Host is now the same canonical host the key uses.
func TestHostNormalizationDoesNotPoison(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "host["+r.Host+"]") // a Host-reflecting origin
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)
	do := func(host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://x/p", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Attacker primes the entry with a :port Host variant.
	a := do("test.local:1337")
	if got := a.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("attacker X-Cache=%q, want MISS", got)
	}
	// The origin must have received the CANONICAL host (no :1337), matching the key.
	if a.Body.String() != "host[test.local]" {
		t.Fatalf("origin Host=%q, want the canonical host[test.local] (forwarded host must match the key)", a.Body.String())
	}
	// The bare-host victim shares the (now identical) canonical entry — and it carries the
	// canonical host, never a poisoned :1337 reflection.
	b := do("test.local")
	if strings.Contains(b.Body.String(), "1337") {
		t.Fatalf("HOST POISON: bare host served a response carrying the attacker's :1337 Host: %q", b.Body.String())
	}
}
