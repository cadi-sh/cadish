package tlsacme

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestNewManager_Empty(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if m.NeedsTLS() {
		t.Error("empty manager should not need TLS")
	}
}

func TestNewManager_ACMEHostPolicy(t *testing.T) {
	sites := []SiteConfig{
		{Hosts: []string{"example.com", "*.example.com"}, TLS: SiteTLS{Mode: ModeACME, Email: "me@x.io"}},
		{Hosts: []string{"plain.com"}, TLS: SiteTLS{Mode: ModeOff}},
	}
	m, err := NewManager(sites, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !m.NeedsTLS() {
		t.Error("NeedsTLS = false, want true")
	}
	if !m.HostAllowed("api.example.com") {
		t.Error("api.example.com should be ACME-allowed")
	}
	if m.HostAllowed("plain.com") {
		t.Error("plain.com (tls off) must not be ACME-allowed (no open issuer)")
	}
	if m.HostAllowed("evil.com") {
		t.Error("evil.com must not be ACME-allowed")
	}
	// hostPolicy mirrors HostAllowed.
	if err := m.hostPolicy(context.Background(), "example.com"); err != nil {
		t.Errorf("hostPolicy(example.com) = %v, want nil", err)
	}
	if err := m.hostPolicy(context.Background(), "evil.com"); err == nil {
		t.Error("hostPolicy(evil.com) = nil, want error")
	}
}

func TestTLSConfig_Hardening(t *testing.T) {
	cert, key := genSelfSigned(t, "example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.TLSConfig()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
	}
	if !containsStr(cfg.NextProtos, "h2") || !containsStr(cfg.NextProtos, "http/1.1") {
		t.Errorf("NextProtos = %v, want h2 + http/1.1", cfg.NextProtos)
	}
	// No ACME site → no acme-tls/1 advertised.
	if containsStr(cfg.NextProtos, acme.ALPNProto) {
		t.Errorf("static-only NextProtos should not advertise %q", acme.ALPNProto)
	}
}

func TestTLSConfig_ACMEAdvertisesALPN(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeACME}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(m.TLSConfig().NextProtos, acme.ALPNProto) {
		t.Errorf("ACME manager must advertise %q for TLS-ALPN-01", acme.ALPNProto)
	}
}

func TestStaticKeypair_BadPath(t *testing.T) {
	_, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: "/nope/c.pem", KeyFile: "/nope/k.pem"}},
	}, Options{CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error loading missing keypair")
	}
}

func TestStaticKeypair_MissingKey(t *testing.T) {
	cert, _ := genSelfSigned(t, "example.com")
	_, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: ""}},
	}, Options{CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected error when key file missing")
	}
}

// TestHandshake_StaticCert exercises a real TLS handshake end-to-end through the
// hardened TLSConfig, asserting the right cert is served by SNI and the
// negotiated version honors the floor.
func TestHandshake_StaticCert(t *testing.T) {
	cert, key := genSelfSigned(t, "example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})}
	tlsLn := tls.NewListener(ln, m.TLSConfig())
	go srv.Serve(tlsLn)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "example.com"},
	}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("handshake/GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version too low: %+v", resp.TLS)
	}
	if len(resp.TLS.PeerCertificates) == 0 ||
		resp.TLS.PeerCertificates[0].Subject.CommonName != "example.com" {
		t.Errorf("served wrong certificate: %+v", resp.TLS.PeerCertificates)
	}
}

// TestHandshake_RejectsOldTLS confirms a TLS 1.1 client cannot negotiate.
func TestHandshake_RejectsOldTLS(t *testing.T) {
	cert, key := genSelfSigned(t, "example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.NewServeMux()}
	go srv.Serve(tls.NewListener(ln, m.TLSConfig()))
	defer srv.Close()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		MaxVersion:         tls.VersionTLS11,
	})
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.1 client should have been rejected")
	}
}

func TestHTTPHandler_Redirects(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeOff}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?q=1", nil)
	rec := httptest.NewRecorder()
	m.HTTPHandler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/path?q=1" {
		t.Errorf("Location = %q, want https://example.com/path?q=1", loc)
	}
}

// TestHTTPHandler_ACMEChallengeSplit verifies the :80 handler routes ACME
// HTTP-01 challenge paths to autocert (not a redirect) while still redirecting
// ordinary traffic — the challenge/redirect split the design requires.
func TestHTTPHandler_ACMEChallengeSplit(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeACME}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := m.HTTPHandler(nil)

	// An unknown challenge token is handled by autocert (404), NOT redirected.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/tok", nil))
	if rec.Code == http.StatusMovedPermanently {
		t.Errorf("challenge path was redirected (%d); want it handled by ACME", rec.Code)
	}

	// Ordinary traffic still redirects to HTTPS.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "http://example.com/page", nil))
	if rec2.Code != http.StatusMovedPermanently {
		t.Errorf("ordinary path status = %d, want 301", rec2.Code)
	}
}

func TestHSTSMiddleware(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeACME, HSTS: HSTS{MaxAge: 100, IncludeSubdomains: true}}},
		{Hosts: []string{"nohsts.com"}, TLS: SiteTLS{Mode: ModeACME}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := m.HSTSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=100; includeSubDomains" {
		t.Errorf("HSTS header = %q", got)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "https://nohsts.com/", nil))
	if got := rec2.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("unexpected HSTS for nohsts.com: %q", got)
	}
}

func TestBuildServers_Defaults(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeACME}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	s := m.BuildServers(http.NewServeMux(), "", "")
	if s.HTTP.Addr != DefaultHTTPAddr || s.HTTPS.Addr != DefaultHTTPSAddr {
		t.Errorf("addrs = %q/%q", s.HTTP.Addr, s.HTTPS.Addr)
	}
	if s.HTTPS.TLSConfig == nil {
		t.Error("HTTPS server missing TLSConfig")
	}
	if s.HTTP.ReadHeaderTimeout == 0 {
		t.Error("missing ReadHeaderTimeout hardening")
	}
	if s.HTTP.MaxHeaderBytes != MaxHeaderBytes || s.HTTPS.MaxHeaderBytes != MaxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d/%d, want %d on both listeners",
			s.HTTP.MaxHeaderBytes, s.HTTPS.MaxHeaderBytes, MaxHeaderBytes)
	}
}

// TestServers_ListenAndServe_ShutdownOnCtx checks the run loop returns promptly
// when its context is cancelled.
func TestServers_ListenAndServe_ShutdownOnCtx(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"example.com"}, TLS: SiteTLS{Mode: ModeOff}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	// Bind ephemeral ports so the test never needs :80/:443.
	s := m.BuildServers(http.NewServeMux(), "127.0.0.1:0", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return after context cancel")
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
