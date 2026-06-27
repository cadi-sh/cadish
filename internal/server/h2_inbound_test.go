package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestInboundHTTP2RoutesByAuthority drives the cadish handler over a REAL TLS + HTTP/2
// connection (ALPN h2) and proves three h2-boundary properties at once:
//
//  1. Go's net/http serves the cadish handler over HTTP/2 — the request arrives with
//     ProtoMajor == 2 (the rapid-reset-fixed, stream-bounded server is actually in play).
//  2. The h2 `:authority` pseudo-header is what cadish routes on: it surfaces as r.Host,
//     selects the site, and (host_header preserve, the default) is the Host forwarded to
//     origin — there is no separate Host header that could disagree with :authority.
//  3. A plain end-to-end header rides through to origin unmodified (no over-strip).
//
// h2 forbids connection-specific request headers at the protocol layer (RFC 9113
// §8.2.2), so the Go h2 CLIENT refuses to send Transfer-Encoding / Connection / Upgrade
// and the Go h2 SERVER rejects a stream that carries them as malformed — the smuggling
// header set is therefore unrepresentable over h2 and is covered against the h1 origin in
// smuggle_origin_test.go. This test pins the h2 transport + authority routing.
func TestInboundHTTP2RoutesByAuthority(t *testing.T) {
	var mu sync.Mutex
	var gotHost, gotProbe string
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost = r.Host
		gotProbe = r.Header.Get("X-Probe")
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgPassthrough, origin.srv.URL)

	// Serve the cadish handler over a real TLS server with HTTP/2 enabled. httptest's
	// EnableHTTP2 wires both the server's ALPN and the returned Client to negotiate h2.
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)

	req, err := http.NewRequest("GET", ts.URL+"/auth-probe", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// Set the h2 :authority. The TLS SNI stays the dialed 127.0.0.1 (cert covers it); the
	// :authority is independent and is what cadish must route + forward on.
	req.Host = "test.local"
	req.Header.Set("X-Probe", "p1")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("h2 request: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.ProtoMajor != 2 {
		t.Fatalf("response Proto = %s, want HTTP/2 (automatic h2 not in effect)", resp.Proto)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHost != "test.local" {
		t.Errorf("origin Host = %q, want \"test.local\" (:authority must drive the forwarded Host)", gotHost)
	}
	if gotProbe != "p1" {
		t.Errorf("origin X-Probe = %q, want \"p1\"", gotProbe)
	}
}
