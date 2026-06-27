package server

import (
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// TestBuildOriginHeaderStripsHopByHop proves the request-rebuild step that turns an
// inbound request into the origin-bound request drops EVERY hop-by-hop / connection-
// scoped header (RFC 9110 §7.6.1) plus Host, so a client cannot smuggle framing- or
// connection-control headers (Transfer-Encoding, Connection, Upgrade, TE, …) across the
// proxy→origin boundary to desync the pooled origin connection. This is the h2→h1 (and
// h1→h1) downgrade-smuggling defense at the cadish layer; net/http additionally refuses
// to WRITE Content-Length / Transfer-Encoding from the header map (it frames from
// req.ContentLength), so even a copied Content-Length never reaches the origin wire.
func TestBuildOriginHeaderStripsHopByHop(t *testing.T) {
	in := http.Header{
		// Static hop-by-hop set (handler.go hopByHop).
		"Connection":          {"keep-alive, X-Smuggle"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authenticate":  {"Basic"},
		"Proxy-Authorization": {"Basic Zm9v"},
		"Te":                  {"trailers"},
		"Trailer":             {"X-Foo"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		// A header NAMED in the Connection token list must also be stripped.
		"X-Smuggle": {"evil"},
		// Host is authoritative via req.Host upstream, never copied as a header.
		"Host": {"attacker.example"},
		// A legitimate end-to-end header must survive.
		"X-Keep":       {"yes"},
		"Content-Type": {"text/plain"},
	}

	out := buildOriginHeader(in, nil, nil)

	for _, banned := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-Smuggle", "Host",
	} {
		if v := out.Get(banned); v != "" {
			t.Errorf("origin-bound header retained %q=%q, want stripped", banned, v)
		}
	}
	if got := out.Get("X-Keep"); got != "yes" {
		t.Errorf("legitimate header X-Keep = %q, want \"yes\" (over-stripped)", got)
	}
	if got := out.Get("Content-Type"); got != "text/plain" {
		t.Errorf("Content-Type = %q, want \"text/plain\"", got)
	}
}

// TestHopByHopAndForgedFramingNotForwardedToOrigin is the integration twin: an inbound
// GET carrying the full hop-by-hop set, a Connection-smuggled header, and a FORGED
// Content-Length reaches a real origin as a clean, bodyless GET — no smuggled header, no
// stray body. Proves the strip holds end-to-end through httporigin + net/http framing.
func TestHopByHopAndForgedFramingNotForwardedToOrigin(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	var bodyLen int64
	var readLen int
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = r.Header.Clone()
		bodyLen = r.ContentLength
		readLen = len(b)
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgPassthrough, origin.srv.URL)

	hdr := http.Header{
		"Connection":          {"keep-alive, X-Smuggle"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authorization": {"Basic Zm9v"},
		"Te":                  {"trailers"},
		"Trailer":             {"X-Foo"},
		"Upgrade":             {"websocket"},
		"X-Smuggle":           {"evil"},
		"Content-Length":      {"100"}, // forged: a GET has no body
	}
	rec := do(h, "GET", "http://test.local/smuggle", hdr)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, banned := range []string{
		"Connection", "Keep-Alive", "Proxy-Authorization", "Te", "Trailer", "Upgrade", "X-Smuggle",
	} {
		if v := got.Get(banned); v != "" {
			t.Errorf("origin saw smuggled header %q=%q, want stripped", banned, v)
		}
	}
	// The forged Content-Length must NOT have produced a phantom body on the origin
	// connection (which would desync the next pooled request). net/http frames a GET as
	// bodyless regardless of a Content-Length entry in the header map.
	if bodyLen > 0 {
		t.Errorf("origin ContentLength = %d, want <= 0 (forged CL must not frame a body)", bodyLen)
	}
	if readLen != 0 {
		t.Errorf("origin read %d body bytes, want 0", readLen)
	}
}

// TestReqHeaderOpsAfterStrip confirms an explicit request-phase header op still applies
// on top of the strip (the operator can re-set a controlled value), so the strip does
// not silently defeat configured forwarding.
func TestReqHeaderOpsAfterStrip(t *testing.T) {
	ops := []pipeline.HeaderOp{{Op: pipeline.OpSet, Name: "X-Trace", Value: "abc"}}
	out := buildOriginHeader(http.Header{"Connection": {"keep-alive"}}, ops, nil)
	if got := out.Get("X-Trace"); got != "abc" {
		t.Fatalf("X-Trace = %q, want \"abc\"", got)
	}
	if out.Get("Connection") != "" {
		t.Fatal("Connection survived the strip")
	}
}
