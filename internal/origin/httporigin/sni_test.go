package httporigin

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// sniRecorder is an httptest TLS server that captures the ServerName from the
// ClientHello of each handshake, so a test can assert exactly what SNI the origin
// advertised on the wire.
type sniRecorder struct {
	mu   sync.Mutex
	last string
}

func (s *sniRecorder) record(name string) {
	s.mu.Lock()
	s.last = name
	s.mu.Unlock()
}

func (s *sniRecorder) serverName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// newSNIServer stands up a TLS server whose GetConfigForClient hook captures the
// ClientHelloInfo.ServerName. It returns the recorder, the server's host:port, and
// a *tls.Config (InsecureSkipVerify) the origin's transport must use to dial it.
func newSNIServer(t *testing.T, rec *sniRecorder) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			rec.record(hi.ServerName)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// The server certificate is for 127.0.0.1/example.com; dial it by IP so the
	// DIALED host (an IP) cannot itself supply a name-shaped SNI — the only way a
	// hostname SNI reaches the wire is the explicit WithSNI override.
	host := srv.Listener.Addr().String()
	return srv, host
}

// insecureTLSClient builds a client whose transport trusts the httptest cert (so
// the handshake completes) — the test asserts the SNI, not cert verification.
func insecureTLSClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
		},
	}
}

// TestSNI_OnTheWire asserts that WithSNI puts the configured server name in the
// TLS ClientHello even when the origin is dialed by IP (so the dialed host can't
// supply the name). This is the placercams-blog `sni www.placercams.com` case.
func TestSNI_OnTheWire(t *testing.T) {
	rec := &sniRecorder{}
	srv, host := newSNIServer(t, rec)
	_ = srv

	const want = "expected.example"
	// Build the origin with WithSNI; supply an insecure client so the handshake
	// completes (cert is for a different name) — WithSNI must still set ServerName
	// because applyTransportKnobs clones/overrides the supplied TLS config.
	o, err := New("https://"+host, WithSNI(want), WithHTTPClient(insecureTLSClient()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := o.Fetch(context.Background(), &origin.Request{Key: "x"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := rec.serverName(); got != want {
		t.Fatalf("ClientHello ServerName = %q, want %q", got, want)
	}
}

// TestSNI_DefaultIsDialedHost is the companion: with NO WithSNI, Go derives the SNI
// from the dialed host. Dialed by an IP, the ServerName is empty (Go does not put a
// literal IP in SNI), proving the unset default is unchanged (no injection).
func TestSNI_DefaultIsDialedHost(t *testing.T) {
	rec := &sniRecorder{}
	srv, host := newSNIServer(t, rec)
	_ = srv

	o, err := New("https://"+host, WithHTTPClient(insecureTLSClient()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := o.Fetch(context.Background(), &origin.Request{Key: "x"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Dialed by IP ⇒ Go sends an empty SNI (it does not put a literal IP in the
	// ClientHello). The key assertion: no hostname was injected for the unset default.
	if got := rec.serverName(); got != "" {
		t.Fatalf("ClientHello ServerName = %q, want empty (IP-dialed Go default, no injection)", got)
	}
}

// connCountServer counts how many distinct backend connections were accepted, so a
// test can prove keep-alive reuse (one conn) vs no-reuse (one per request).
type connCountServer struct {
	mu    sync.Mutex
	conns map[string]struct{}
}

func newConnCountServer(t *testing.T) (*httptest.Server, *connCountServer) {
	t.Helper()
	cc := &connCountServer{conns: map[string]struct{}{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cc.mu.Lock()
		cc.conns[r.RemoteAddr] = struct{}{}
		cc.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, cc
}

func (cc *connCountServer) count() int {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return len(cc.conns)
}

// fetchTwice makes two sequential Fetches, fully consuming+closing each body so a
// reusable connection returns to the pool between them.
func fetchTwice(t *testing.T, o *Origin) {
	t.Helper()
	for i := 0; i < 2; i++ {
		resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x"})
		if err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// TestDisableKeepAlives_NoReuse asserts that WithDisableKeepAlives forces a fresh
// connection per request (two distinct backend conns) — `http_reuse never`.
func TestDisableKeepAlives_NoReuse(t *testing.T) {
	srv, cc := newConnCountServer(t)
	o, err := New(srv.URL, WithDisableKeepAlives(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fetchTwice(t, o)
	if got := cc.count(); got != 2 {
		t.Fatalf("distinct backend connections = %d, want 2 (no reuse)", got)
	}
}

// TestDefaultKeepAlive_Reuses is the companion: without the knob, the second
// request reuses the first connection (one distinct conn), proving the default
// path keeps pooling.
func TestDefaultKeepAlive_Reuses(t *testing.T) {
	srv, cc := newConnCountServer(t)
	o, err := New(srv.URL) // default: shared pooled client, keep-alive on
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fetchTwice(t, o)
	if got := cc.count(); got != 1 {
		t.Fatalf("distinct backend connections = %d, want 1 (keep-alive reuse)", got)
	}
}

// TestTransportIsolation_Default guards the zero-datapath-change invariant: an
// origin that sets NEITHER knob has a transport with a nil TLSClientConfig and
// DisableKeepAlives == false (the legacy default, untouched).
func TestTransportIsolation_Default(t *testing.T) {
	o, err := New("https://origin.example.com")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr := o.hc.Transport.(*http.Transport)
	if tr.TLSClientConfig != nil {
		t.Errorf("default transport TLSClientConfig = %v, want nil", tr.TLSClientConfig)
	}
	if tr.DisableKeepAlives {
		t.Error("default transport DisableKeepAlives = true, want false")
	}
}

// TestTransportIsolation_KnobsAreScoped verifies the two knobs affect ONLY the
// origin that sets them: a knobbed origin has the knobs on its transport, while a
// sibling default origin built right after is pristine (clients are per-origin, so
// no global mutation leaks).
func TestTransportIsolation_KnobsAreScoped(t *testing.T) {
	o, err := New("https://origin.example.com", WithSNI("a.example"), WithDisableKeepAlives(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr := o.hc.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.ServerName != "a.example" {
		t.Errorf("knobbed transport ServerName = %v, want a.example", tr.TLSClientConfig)
	}
	if !tr.DisableKeepAlives {
		t.Error("knobbed transport DisableKeepAlives = false, want true")
	}
	// A sibling default origin is unaffected.
	sib, err := New("https://origin.example.com")
	if err != nil {
		t.Fatalf("New sibling: %v", err)
	}
	str := sib.hc.Transport.(*http.Transport)
	if str.TLSClientConfig != nil || str.DisableKeepAlives {
		t.Error("a knobbed origin leaked into a sibling default origin's transport")
	}
	if o.hc == sib.hc {
		t.Error("two origins share the same *http.Client (knobs would cross-contaminate)")
	}
}
