package tlsacme

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestManagerReload_ACMEHostSet proves Manager.Reload makes a TLS-hostname change a
// hot reload: a newly-added ACME host becomes issuable (HostPolicy passes) without a
// restart, removing it makes it fail again, and an existing host keeps serving
// throughout. The autocert source is never recreated.
func TestManagerReload_ACMEHostSet(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"a.example.com"}, TLS: SiteTLS{Mode: ModeACME, Email: "me@x.io"}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	acmeBefore := m.acme // capture the source identity
	if !m.HostAllowed("a.example.com") {
		t.Fatal("a.example.com should be allowed at startup")
	}
	if m.HostAllowed("b.example.com") {
		t.Fatal("b.example.com must not be allowed before reload")
	}

	// Reload ADDING b.example.com (and keeping a.example.com).
	if err := m.Reload([]SiteConfig{
		{Hosts: []string{"a.example.com"}, TLS: SiteTLS{Mode: ModeACME, Email: "me@x.io"}},
		{Hosts: []string{"b.example.com"}, TLS: SiteTLS{Mode: ModeACME, Email: "me@x.io"}},
	}); err != nil {
		t.Fatalf("reload add: %v", err)
	}
	if m.acme != acmeBefore {
		t.Fatal("autocert source must NOT be recreated by Reload")
	}
	if !m.HostAllowed("b.example.com") {
		t.Fatal("b.example.com should be issuable immediately after reload")
	}
	if err := m.hostPolicy(context.Background(), "b.example.com"); err != nil {
		t.Fatalf("hostPolicy(b) after add = %v, want nil", err)
	}
	if !m.HostAllowed("a.example.com") {
		t.Fatal("a.example.com must keep serving across the reload")
	}

	// Reload REMOVING b.example.com.
	if err := m.Reload([]SiteConfig{
		{Hosts: []string{"a.example.com"}, TLS: SiteTLS{Mode: ModeACME, Email: "me@x.io"}},
	}); err != nil {
		t.Fatalf("reload remove: %v", err)
	}
	if m.HostAllowed("b.example.com") {
		t.Fatal("b.example.com must stop being issuable after removal")
	}
	if err := m.hostPolicy(context.Background(), "b.example.com"); err == nil {
		t.Fatal("hostPolicy(b) after removal = nil, want error")
	}
	if !m.HostAllowed("a.example.com") {
		t.Fatal("a.example.com must still be allowed after the removal reload")
	}
}

// TestManagerReload_StaticKeypair proves a static keypair can be added and removed via
// reload (served / refused by SNI accordingly) and that a bad cert path is a fail-safe
// reload error that keeps the previous host set intact.
func TestManagerReload_StaticKeypair(t *testing.T) {
	certA, keyA := genSelfSigned(t, "a.local")
	certB, keyB := genSelfSigned(t, "b.local")

	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"a.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certA, KeyFile: keyA}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	// a.local served; b.local refused (not configured).
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "a.local"}); err != nil {
		t.Fatalf("a.local before reload: %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "b.local"}); err == nil {
		t.Fatal("b.local should be refused before reload")
	}

	// Reload ADDING b.local.
	if err := m.Reload([]SiteConfig{
		{Hosts: []string{"a.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certA, KeyFile: keyA}},
		{Hosts: []string{"b.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certB, KeyFile: keyB}},
	}); err != nil {
		t.Fatalf("reload add b: %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "b.local"}); err != nil {
		t.Fatalf("b.local after add: %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "a.local"}); err != nil {
		t.Fatalf("a.local must keep serving after add: %v", err)
	}

	// Reload with a BAD cert path → error, and the old set (a.local + b.local) is kept.
	err = m.Reload([]SiteConfig{
		{Hosts: []string{"a.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: "/nope/c.pem", KeyFile: "/nope/k.pem"}},
	})
	if err == nil {
		t.Fatal("reload with bad cert path must return an error")
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "a.local"}); err != nil {
		t.Fatalf("a.local must still serve after a failed reload (fail-safe): %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "b.local"}); err != nil {
		t.Fatalf("b.local must still serve after a failed reload (fail-safe): %v", err)
	}

	// A clean reload REMOVING b.local.
	if err := m.Reload([]SiteConfig{
		{Hosts: []string{"a.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certA, KeyFile: keyA}},
	}); err != nil {
		t.Fatalf("reload remove b: %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "b.local"}); err == nil {
		t.Fatal("b.local should be refused after removal")
	}
}

// TestManagerReload_RaceHandshakesAndReload drives real TLS handshakes concurrently
// with Manager.Reload to prove the atomic state swap is race-clean (run with -race).
// The static keypair set flips between two hosts while clients keep handshaking
// against a stable host; the listener and *tls.Config are never rebuilt.
func TestManagerReload_RaceHandshakesAndReload(t *testing.T) {
	certStable, keyStable := genSelfSigned(t, "stable.local")
	certX, keyX := genSelfSigned(t, "x.local")
	certY, keyY := genSelfSigned(t, "y.local")

	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"stable.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certStable, KeyFile: keyStable}},
		{Hosts: []string{"x.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certX, KeyFile: keyX}},
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
	go srv.Serve(tls.NewListener(ln, m.TLSConfig()))
	defer srv.Close()
	addr := ln.Addr().String()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reloader: flip the second host between x.local and y.local repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			second := SiteConfig{Hosts: []string{"x.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certX, KeyFile: keyX}}
			if toggle {
				second = SiteConfig{Hosts: []string{"y.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certY, KeyFile: keyY}}
			}
			toggle = !toggle
			if err := m.Reload([]SiteConfig{
				{Hosts: []string{"stable.local"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: certStable, KeyFile: keyStable}},
				second,
			}); err != nil {
				t.Errorf("reload: %v", err)
				return
			}
		}
	}()

	// Handshakers: keep dialing stable.local; it must always serve.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				select {
				case <-stop:
					return
				default:
				}
				conn, derr := tls.Dial("tcp", addr, &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "stable.local",
				})
				if derr != nil {
					t.Errorf("handshake stable.local: %v", derr)
					return
				}
				_ = conn.Close()
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	// After the churn, stable.local still serves its cert.
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "stable.local"}); err != nil {
		t.Fatalf("stable.local after churn: %v", err)
	}
}
