package server

import (
	"io"
	"net/http"
	"testing"
)

// TestDynamicHeaderValuesEndToEnd drives the real handler (config.Load ->
// NewHandler) and asserts that a `header` value interpolating request-derived
// placeholders (#17) is resolved against the live request on delivery:
//   - response-side `Access-Control-Allow-Origin {http.Origin}` reflects the
//     request's Origin (and a different Origin reflects differently — per-request,
//     not baked);
//   - an absent Origin resolves to an empty header value (fail-closed);
//   - a static header value is unchanged.
func TestDynamicHeaderValuesEndToEnd(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header Access-Control-Allow-Origin {http.Origin}
	header +Vary Origin
	header X-Static plain
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/a", http.Header{"Origin": {"https://app.example.com"}})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO = %q, want the reflected Origin", got)
	}
	if got := rec.Header().Get("X-Static"); got != "plain" {
		t.Errorf("X-Static = %q, want plain (static value unchanged)", got)
	}

	// A different Origin reflects differently (resolved per-request). Use a fresh
	// path so a cached delivery cannot mask the behavior.
	rec2 := do(h, "GET", "http://test.local/b", http.Header{"Origin": {"https://other.example.org"}})
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "https://other.example.org" {
		t.Errorf("ACAO = %q, want the second request's reflected Origin", got)
	}

	// Absent Origin -> empty ACAO (fail-closed: browsers grant no permission).
	rec3 := do(h, "GET", "http://test.local/c", nil)
	if _, ok := rec3.Header()["Access-Control-Allow-Origin"]; ok {
		if got := rec3.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("ACAO = %q with no Origin, want empty", got)
		}
	}
}

// TestDynamicRequestHeaderClientIP asserts a request-phase `header X-Real-IP
// {client_ip}` (before cache_key) sets the header forwarded to the origin to the
// resolved client IP.
func TestDynamicRequestHeaderClientIP(t *testing.T) {
	var gotXRealIP string
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		gotXRealIP = r.Header.Get("X-Real-IP")
		_, _ = io.WriteString(w, "ok")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	header X-Real-IP {client_ip}
	cache_key path
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	_ = do(h, "GET", "http://test.local/a", nil)
	// httptest.NewRequest uses RemoteAddr 192.0.2.1:1234; the resolved client IP is
	// the host part.
	if gotXRealIP != "192.0.2.1" {
		t.Errorf("origin saw X-Real-IP = %q, want 192.0.2.1 (resolved client IP)", gotXRealIP)
	}
}
