package tlsacme

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeACMESource is an injectable acmeSource that records calls and returns a
// canned certificate, so Manager SNI dispatch can be tested without a live ACME
// issuer.
type fakeACMESource struct {
	cert        *tls.Certificate
	getCalls    int
	httpHandler http.Handler
	issued      map[string]bool // hosts for which a cert has been "issued" (HasIssuedCert)
}

func (f *fakeACMESource) HasIssuedCert(host string) bool { return f.issued[host] }

func (f *fakeACMESource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.getCalls++
	return f.cert, nil
}

func (f *fakeACMESource) HTTPHandler(fallback http.Handler) http.Handler {
	if f.httpHandler != nil {
		return f.httpHandler
	}
	return fallback
}

// TestManager_DispatchToFakeACME builds a Manager (white-box) with a static
// keypair and a fake ACME source, then asserts SNI dispatch: a static host uses
// its keypair (never the ACME source), an ACME-only host falls through to the
// fake source.
func TestManager_DispatchToFakeACME(t *testing.T) {
	cert, key := genSelfSigned(t, "static.example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"static.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	// Inject a fake ACME source covering acme.example.com.
	fake := &fakeACMESource{cert: &tls.Certificate{}}
	m.acme = fake
	m.state.Load().acmeHosts.add("acme.example.com")

	// Static host -> served by the static keypair, NOT the ACME source.
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "static.example.com"}); err != nil {
		t.Fatalf("static host getCertificate: %v", err)
	}
	if fake.getCalls != 0 {
		t.Errorf("static host should not consult the ACME source; calls=%d", fake.getCalls)
	}

	// ACME host -> dispatched to the fake source.
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "acme.example.com"}); err != nil {
		t.Fatalf("acme host getCertificate: %v", err)
	}
	if fake.getCalls != 1 {
		t.Errorf("acme host should consult the ACME source once; calls=%d", fake.getCalls)
	}
}

// TestManager_ALPNChallengeToACME verifies a TLS-ALPN-01 handshake (acme-tls/1)
// is always routed to the ACME source, even for a host that also has a static
// keypair.
func TestManager_ALPNChallengeToACME(t *testing.T) {
	cert, key := genSelfSigned(t, "dual.example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"dual.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeACMESource{cert: &tls.Certificate{}}
	m.acme = fake
	m.state.Load().acmeHosts.add("dual.example.com")

	hello := &tls.ClientHelloInfo{ServerName: "dual.example.com", SupportedProtos: []string{"acme-tls/1"}}
	if _, err := m.getCertificate(hello); err != nil {
		t.Fatalf("alpn challenge getCertificate: %v", err)
	}
	if fake.getCalls != 1 {
		t.Errorf("TLS-ALPN-01 challenge must go to the ACME source; calls=%d", fake.getCalls)
	}
}

// TestManager_HTTPHandlerUsesACMESource verifies the :80 handler delegates to the
// ACME source's HTTPHandler when ACME is active.
func TestManager_HTTPHandlerUsesACMESource(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	marker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "fake-acme")
	})
	m.acme = &fakeACMESource{httpHandler: marker}

	rec := httptest.NewRecorder()
	m.HTTPHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if rec.Header().Get("X-Served-By") != "fake-acme" {
		t.Error("HTTPHandler did not delegate to the ACME source")
	}
}
