package httporigin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// newTLSServer stands up a self-signed TLS httptest server. enableH2 toggles
// HTTP/2 negotiation. The handler records the negotiated request ProtoMajor so a
// test can assert h2 (2) vs HTTP/1.1 (1). It returns the server and its host:port.
func newTLSServer(t *testing.T, enableH2 bool, proto *protoRecorder) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proto != nil {
			proto.record(r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = enableH2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// protoRecorder captures the last negotiated HTTP major version seen server-side.
type protoRecorder struct {
	mu   sync.Mutex
	last int
}

func (p *protoRecorder) record(major int) {
	p.mu.Lock()
	p.last = major
	p.mu.Unlock()
}

func (p *protoRecorder) major() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.last
}

func mustFetch(t *testing.T, o *Origin) {
	t.Helper()
	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// TestDefaultTLS_VerifiesAndFails proves the secure default: with NO knob, an
// origin pointed at a self-signed server FAILS the handshake (the cert is not
// trusted by the system roots).
func TestDefaultTLS_VerifiesAndFails(t *testing.T) {
	srv := newTLSServer(t, false, nil)
	o, err := New(srv.URL) // default: full verification, system roots
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := o.Fetch(context.Background(), &origin.Request{Key: "x"}); err == nil {
		t.Fatal("Fetch succeeded against a self-signed origin with no knob; want a verification failure")
	}
}

// TestInsecureTLS_Succeeds proves `tls_insecure` lets the same self-signed origin
// handshake (verification skipped).
func TestInsecureTLS_Succeeds(t *testing.T) {
	srv := newTLSServer(t, false, nil)
	o, err := New(srv.URL, WithInsecureTLS(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mustFetch(t, o)
}

// TestRootCAs_VerifiesAgainstPool proves `ca_file` builds a RootCAs pool the origin
// verifies against: with the server's own cert added to the pool the handshake
// succeeds (SAN includes 127.0.0.1, the dialed host), while a pristine pool fails.
func TestRootCAs_VerifiesAgainstPool(t *testing.T) {
	srv := newTLSServer(t, false, nil)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	o, err := New(srv.URL, WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mustFetch(t, o)

	// An empty pool (no trusted roots) must still fail — proving RootCAs is the
	// thing being verified against, not a silent skip.
	empty, err := New(srv.URL, WithRootCAs(x509.NewCertPool()))
	if err != nil {
		t.Fatalf("New empty: %v", err)
	}
	if _, err := empty.Fetch(context.Background(), &origin.Request{Key: "x"}); err == nil {
		t.Fatal("Fetch succeeded with an empty RootCAs pool; want a verification failure")
	}
}

// TestInsecureTLS_PreservesHTTP2 is the h2 gotcha: setting ONLY tls_insecure (no
// alpn) must leave HTTP/2 reachable — the origin still negotiates h2 with an
// h2-capable server via ForceAttemptHTTP2.
func TestInsecureTLS_PreservesHTTP2(t *testing.T) {
	proto := &protoRecorder{}
	srv := newTLSServer(t, true, proto)
	o, err := New(srv.URL, WithInsecureTLS(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mustFetch(t, o)
	if got := proto.major(); got != 2 {
		t.Fatalf("negotiated HTTP major = %d, want 2 (h2 preserved on tls_insecure)", got)
	}
}

// TestALPN_PinsHTTP1DisablesHTTP2 is the companion: pinning `alpn http/1.1`
// deliberately sets NextProtos and so drops the h2 auto-upgrade — the same
// h2-capable server falls back to HTTP/1.1.
func TestALPN_PinsHTTP1DisablesHTTP2(t *testing.T) {
	proto := &protoRecorder{}
	srv := newTLSServer(t, true, proto)
	o, err := New(srv.URL, WithInsecureTLS(true), WithALPN([]string{"http/1.1"}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mustFetch(t, o)
	if got := proto.major(); got != 1 {
		t.Fatalf("negotiated HTTP major = %d, want 1 (alpn http/1.1 disables h2)", got)
	}
}

// TestInsecureTLS_Isolation proves the knob affects ONLY its own transport: an
// insecure origin and a sibling default origin do not share a client, and the
// sibling's transport keeps full verification (InsecureSkipVerify false).
func TestInsecureTLS_Isolation(t *testing.T) {
	insecure, err := New("https://origin.example.com", WithInsecureTLS(true))
	if err != nil {
		t.Fatalf("New insecure: %v", err)
	}
	itr := insecure.hc.Transport.(*http.Transport)
	if itr.TLSClientConfig == nil || !itr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure origin transport did not set InsecureSkipVerify")
	}

	sib, err := New("https://origin.example.com")
	if err != nil {
		t.Fatalf("New sibling: %v", err)
	}
	str := sib.hc.Transport.(*http.Transport)
	if str.TLSClientConfig != nil {
		t.Errorf("sibling default transport TLSClientConfig = %v, want nil (verification not relaxed)", str.TLSClientConfig)
	}
	if insecure.hc == sib.hc {
		t.Error("insecure and default origins share the same *http.Client (knob would cross-contaminate)")
	}
}

// TestALPN_AndSNI_OnTheWire asserts both the pinned ALPN list and the SNI reach the
// ClientHello, reusing the SNI recorder harness (the placercams blog case).
func TestALPN_AndSNI_OnTheWire(t *testing.T) {
	var (
		mu       sync.Mutex
		gotName  string
		gotProto []string
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			gotName = hi.ServerName
			gotProto = append([]string(nil), hi.SupportedProtos...)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()

	o, err := New("https://"+host,
		WithSNI("www.placercams.com"),
		WithALPN([]string{"http/1.1"}),
		WithInsecureTLS(true),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mustFetch(t, o)

	mu.Lock()
	defer mu.Unlock()
	if gotName != "www.placercams.com" {
		t.Errorf("ClientHello ServerName = %q, want www.placercams.com", gotName)
	}
	if len(gotProto) != 1 || gotProto[0] != "http/1.1" {
		t.Errorf("ClientHello ALPN = %v, want [http/1.1]", gotProto)
	}
}
