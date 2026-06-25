package httporigin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// hostRecorder captures the Host header the upstream actually received.
type hostRecorder struct {
	mu       sync.Mutex
	lastHost string
}

func (h *hostRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.lastHost = r.Host
	h.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

func (h *hostRecorder) host() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastHost
}

// newHostOrigin spins up a server that records its received Host and builds an
// origin pointed at it with the supplied options.
func newHostOrigin(t *testing.T, opts ...Option) (*Origin, *hostRecorder) {
	t.Helper()
	rec := &hostRecorder{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	o, err := New(srv.URL, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, rec
}

// upstreamHostOf is the host:port of the test server (the Go default Host).
func upstreamHostOf(t *testing.T, o *Origin) string {
	t.Helper()
	return o.base.Host
}

// TestHostHeader_DefaultPreserve verifies the DEFAULT policy forwards the
// client's Host to the origin (the staging-POC fix: WordPress vhost no longer
// canonical-301s because it sees its own public Host, not the internal upstream).
func TestHostHeader_DefaultPreserve(t *testing.T) {
	o, rec := newHostOrigin(t)

	_, err := o.Fetch(context.Background(), &origin.Request{Key: "x", ClientHost: "www.example.com"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := rec.host(); got != "www.example.com" {
		t.Fatalf("upstream Host = %q, want client host %q (default = preserve)", got, "www.example.com")
	}
}

// TestHostHeader_PreserveExplicit is the explicit `host_header preserve` mode.
func TestHostHeader_PreserveExplicit(t *testing.T) {
	o, rec := newHostOrigin(t, WithHostPolicy(HostPreserve, ""))

	_, err := o.Fetch(context.Background(), &origin.Request{Key: "x", ClientHost: "shop.example.com:8443"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := rec.host(); got != "shop.example.com:8443" {
		t.Fatalf("upstream Host = %q, want %q", got, "shop.example.com:8443")
	}
}

// TestHostHeader_Origin keeps the legacy behavior: the request carries the
// upstream base URL's host (what Go sends when req.Host is left empty).
func TestHostHeader_Origin(t *testing.T) {
	o, rec := newHostOrigin(t, WithHostPolicy(HostOrigin, ""))
	want := upstreamHostOf(t, o)

	_, err := o.Fetch(context.Background(), &origin.Request{Key: "x", ClientHost: "www.example.com"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := rec.host(); got != want {
		t.Fatalf("upstream Host = %q, want upstream host %q (host_header origin)", got, want)
	}
}

// TestHostHeader_Fixed sets a fixed Host value regardless of the client's Host.
func TestHostHeader_Fixed(t *testing.T) {
	o, rec := newHostOrigin(t, WithHostPolicy(HostFixed, "origin.internal"))

	_, err := o.Fetch(context.Background(), &origin.Request{Key: "x", ClientHost: "www.example.com"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := rec.host(); got != "origin.internal" {
		t.Fatalf("upstream Host = %q, want fixed %q", got, "origin.internal")
	}
}

// TestHostHeader_PreserveEmptyClientFallsBackToOrigin verifies that when the
// policy is preserve but the request carries no client Host (e.g. a background
// revalidation where the client headers are gone), we fall back to the upstream
// host rather than sending an empty/garbage Host.
func TestHostHeader_PreserveEmptyClientFallsBackToOrigin(t *testing.T) {
	o, rec := newHostOrigin(t) // default preserve
	want := upstreamHostOf(t, o)

	_, err := o.Fetch(context.Background(), &origin.Request{Key: "x"}) // no ClientHost
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := rec.host(); got != want {
		t.Fatalf("upstream Host = %q, want fallback to upstream host %q", got, want)
	}
}
