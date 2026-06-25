package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// --- Load balancing: sticky routing through the server ---

func TestStickyRoutingThroughServer(t *testing.T) {
	b1 := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "b1") })
	b2 := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "b2") })

	// A sticky-by-cookie pool over two backends. `pass` keeps every request going to
	// origin (no cache, no coalescing) so we observe per-request backend selection.
	body := fmt.Sprintf(`test.local {
	cache { ram 16MiB }
	upstream pool {
		to %s
		to %s
		sticky by cookie SID else client_ip
	}
	pass method GET
}
`, b1.srv.URL, "%s")
	h, _ := buildHandler(t, nil, body, b2.srv.URL)

	// Each distinct cookie value must pin to ONE backend across repeated requests.
	backendFor := func(sid string) string {
		hdr := http.Header{"Cookie": {"SID=" + sid}}
		first := do(h, "GET", "http://test.local/x", hdr).Body.String()
		for i := 0; i < 8; i++ {
			if got := do(h, "GET", "http://test.local/x", hdr).Body.String(); got != first {
				t.Fatalf("sticky key %q not pinned: saw %q then %q", sid, first, got)
			}
		}
		return first
	}

	seen := map[string]bool{}
	for _, sid := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		seen[backendFor(sid)] = true
	}
	// With a balanced consistent-hash ring over 2 backends and 12 keys, both
	// backends should be exercised — proving routing isn't "always the first".
	if !seen["b1"] || !seen["b2"] {
		t.Fatalf("expected both backends used across keys, saw %v", seen)
	}
}

// TestLBFailoverThroughServer: a pool with one dead backend and one live backend
// still serves (lb fails over).
func TestLBFailoverThroughServer(t *testing.T) {
	live := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "live") })

	// Grab a port and immediately release it → a backend that refuses connections.
	dead := freeAddr(t)

	body := fmt.Sprintf(`test.local {
	cache { ram 16MiB }
	upstream pool {
		to http://%s
		to %s
	}
	cache_ttl default ttl 60s
}
`, dead, "%s")
	h, _ := buildHandler(t, nil, body, live.srv.URL)

	// Several requests; every one should be served by the live backend despite the
	// dead one in the pool.
	for i := 0; i < 5; i++ {
		rec := do(h, "GET", fmt.Sprintf("http://test.local/obj%d", i), nil)
		if rec.Code != 200 || rec.Body.String() != "live" {
			t.Fatalf("failover req %d: got %d %q", i, rec.Code, rec.Body.String())
		}
	}
}

// --- TLS termination ---

func TestNeedsTLS(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "x") })

	// No tls directive → plain HTTP.
	plainCfg := loadCfg(t, fmt.Sprintf(`plain.local {
	cache { ram 8MiB }
	upstream b { to %s }
	cache_ttl default ttl 60s
}
`, origin.srv.URL))
	plain, err := NewServer(plainCfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Shutdown(testCtx(t)) })
	if plain.NeedsTLS() {
		t.Error("plain config should not need TLS")
	}

	// tls off → still plain.
	offCfg := loadCfg(t, fmt.Sprintf(`off.local {
	tls off
	cache { ram 8MiB }
	upstream b { to %s }
	cache_ttl default ttl 60s
}
`, origin.srv.URL))
	off, err := NewServer(offCfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = off.Shutdown(testCtx(t)) })
	if off.NeedsTLS() {
		t.Error("`tls off` should not need TLS")
	}
}

// TestTLSStaticKeypairEndToEnd serves a static-keypair site over real HTTPS and
// verifies the proxy fetches + caches behind TLS.
func TestTLSStaticKeypairEndToEnd(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "secure-body")
	})

	certFile, keyFile := writeSelfSignedCert(t, "tls.local")

	cfgText := fmt.Sprintf(`tls.local {
	tls {
		cert %s
		key %s
	}
	cache { ram 16MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`, certFile, keyFile, origin.srv.URL)
	cfg := loadCfg(t, cfgText)

	httpAddr := freeAddr(t)
	httpsAddr := freeAddr(t)
	srv, err := NewServer(cfg, httpAddr, Options{Logger: discardLogger(), HTTPSAddr: httpsAddr})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if !srv.NeedsTLS() {
		t.Fatal("static-keypair site should need TLS")
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown(testCtx(t))
		<-serveErr
	})

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "tls.local", InsecureSkipVerify: true}, //nolint:gosec // test client
	}}

	url := "https://" + httpsAddr + "/secret.txt"
	// Retry until the listener is up (port was released just before binding).
	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest("GET", url, nil)
		req.Host = "tls.local"
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("HTTPS request never succeeded: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "secure-body" {
		t.Fatalf("HTTPS miss: got %d %q", resp.StatusCode, b)
	}
	if resp.TLS == nil {
		t.Fatal("response was not served over TLS")
	}
	if got := resp.Header.Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}

	// Second request is a cache HIT, still over TLS.
	req2, _ := http.NewRequest("GET", url, nil)
	req2.Host = "tls.local"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second HTTPS request: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(b2) != "secure-body" || resp2.Header.Get("X-Cache") != "HIT" {
		t.Fatalf("second: %q X-Cache=%q", b2, resp2.Header.Get("X-Cache"))
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (cached behind TLS)", origin.hits.Load())
	}
}

// --- test helpers ---

// loadCfg writes cfgText to a temp Cadishfile and loads it.
func loadCfg(t *testing.T, cfgText string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, cfgText)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	return cfg
}

// freeAddr returns a 127.0.0.1 address whose port was free at call time (released
// immediately, so the caller binds it shortly after — racy but fine for tests).
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// writeSelfSignedCert generates an ECDSA self-signed cert for host and writes the
// cert+key PEM files, returning their paths.
func writeSelfSignedCert(t *testing.T, host string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatal(err)
	}
	keyOut.Close()
	return certFile, keyFile
}
