package server

import (
	"io"
	"net/http"
	"testing"
)

// TestClientIPWalksTrustProxy is the D4 guard: with a trust_proxy set, the
// `{client_ip}` token (here stamped into X-Real-IP forwarded to the origin) resolves
// to the REAL client from X-Forwarded-For, not the immediate socket peer — the same
// trust_proxy/XFF resolution as {geo} and the `ip` ACL.
func TestClientIPWalksTrustProxy(t *testing.T) {
	var gotXRealIP string
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		gotXRealIP = r.Header.Get("X-Real-IP")
		_, _ = io.WriteString(w, "ok")
	})
	// httptest.NewRequest uses RemoteAddr 192.0.2.1:1234, so 192.0.2.0/24 trusts it.
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 192.0.2.0/24
	header X-Real-IP {client_ip}
	cache_key path
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	_ = do(h, "GET", "http://test.local/a", http.Header{"X-Forwarded-For": {"203.0.113.5"}})
	if gotXRealIP != "203.0.113.5" {
		t.Errorf("origin saw X-Real-IP = %q, want 203.0.113.5 (the trust_proxy-walked client)", gotXRealIP)
	}
}

// TestClientIPIgnoresUntrustedXFF is the D4 control: with NO trust_proxy, an
// X-Forwarded-For from an untrusted peer is ignored and {client_ip} stays the socket
// peer (no spoofing the stamped client IP).
func TestClientIPIgnoresUntrustedXFF(t *testing.T) {
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
	_ = do(h, "GET", "http://test.local/a", http.Header{"X-Forwarded-For": {"203.0.113.5"}})
	if gotXRealIP != "192.0.2.1" {
		t.Errorf("origin saw X-Real-IP = %q, want 192.0.2.1 (socket peer; untrusted XFF ignored)", gotXRealIP)
	}
}

// TestNoHealthyBackendReturns503 is the LB-D1 guard: when an lb pool has no eligible
// (healthy) backend, the client gets 503 Service Unavailable (retriable "no upstream
// available"), not 502 Bad Gateway. A single-backend pool with a health spec starts
// DOWN; pointing it at a closed origin keeps it DOWN, so the fetch never finds an
// eligible backend (ErrNoBackend).
func TestNoHealthyBackendReturns503(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	deadURL := origin.srv.URL
	origin.srv.Close() // unreachable: the backend starts DOWN and never probes back UP

	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend {
		to %s
		health GET /healthz expect 200 interval 1s window 1 threshold 1
	}
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, deadURL)
	rec := do(h, "GET", "http://test.local/a", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("all backends down: code = %d, want 503 Service Unavailable (LB-D1)", rec.Code)
	}
}
