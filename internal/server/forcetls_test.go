package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// TestForceTLS_BindsWithoutTLSConfig proves the Ingress-controller startup mode: a
// base config with NO `tls` directive still binds a TLS-capable :443 (ForceTLS), and
// a BYO Secret cert injected via SetDynamicCerts is served over real HTTPS and
// proxied — all with no restart and no `tls` block anywhere in the Cadishfile.
func TestForceTLS_BindsWithoutTLSConfig(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "byo-body")
	})

	// HTTP-only base: the site declares no tls. ForceTLS is what makes :443 bind.
	cfg := loadCfg(t, fmt.Sprintf(`byo.local {
	cache { ram 8MiB }
	upstream b { to %s }
	cache_ttl default ttl 60s
}
`, origin.srv.URL))

	httpAddr := freeAddr(t)
	httpsAddr := freeAddr(t)
	srv, err := NewServer(cfg, httpAddr, Options{Logger: discardLogger(), HTTPSAddr: httpsAddr, ForceTLS: true})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if !srv.NeedsTLS() {
		t.Fatal("ForceTLS must make an HTTP-only base TLS-capable so :443 binds")
	}

	// Inject the BYO Secret keypair (in-memory PEM) for the host, as the controller does.
	certFile, keyFile := writeSelfSignedCert(t, "byo.local")
	certPEM, _ := os.ReadFile(certFile)
	keyPEM, _ := os.ReadFile(keyFile)
	if err := srv.SetDynamicCerts([]tlsacme.DynamicCert{{Hosts: []string{"byo.local"}, CertPEM: certPEM, KeyPEM: keyPEM}}); err != nil {
		t.Fatalf("SetDynamicCerts: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown(testCtx(t))
		<-serveErr
	})

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "byo.local", InsecureSkipVerify: true}, //nolint:gosec // test client
	}}
	url := "https://" + httpsAddr + "/x.txt"

	var resp *http.Response
	deadline := time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest("GET", url, nil)
		req.Host = "byo.local"
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
	if resp.StatusCode != 200 || string(b) != "byo-body" {
		t.Fatalf("HTTPS via BYO cert: got %d %q", resp.StatusCode, b)
	}
	if resp.TLS == nil {
		t.Fatal("response was not served over TLS")
	}
	// The served leaf must be the BYO cert we injected (CN byo.local).
	if len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].Subject.CommonName != "byo.local" {
		t.Fatalf("served the wrong certificate: %+v", resp.TLS.PeerCertificates)
	}
}
