package tlsacme

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestPebbleEndToEnd drives the FULL ACME issuance flow against Let's Encrypt's
// pebble test server. It is OPT-IN: skipped unless CADISH_ACME_PEBBLE is set, so
// CI stays green without Docker.
//
// Quick start (see test/acme/docker-compose.yml and docs/tls.md):
//
//	docker compose -f test/acme/docker-compose.yml up -d
//	CADISH_ACME_PEBBLE=1 \
//	CADISH_ACME_CHALLTESTSRV=http://localhost:8055 \
//	CADISH_ACME_HOST_IP=<ip pebble can reach this host on> \
//	go test ./internal/tlsacme -run TestPebbleEndToEnd -v
//
// Environment:
//
//	CADISH_ACME_PEBBLE       required; "1"/"true" => https://localhost:14000/dir,
//	                         otherwise the ACME directory URL to use.
//	CADISH_ACME_HOST         domain to issue for (default "cadish.test").
//	CADISH_ACME_HTTP_PORT    HTTP-01 challenge listener port (default "5002";
//	                         matches pebble-config.json's httpPort — non-privileged
//	                         so no sudo needed).
//	CADISH_ACME_TLS_PORT     TLS-ALPN-01 challenge listener port (default "5001").
//	CADISH_ACME_CHALLTESTSRV pebble-challtestsrv management URL; when set, the test
//	                         seeds an A/AAAA record so pebble resolves the host to…
//	CADISH_ACME_HOST_IP      …this IP (the address pebble's container reaches this
//	                         test process on: 127.0.0.1 with host networking on
//	                         Linux, or the Docker-Desktop host-gateway IP).
func TestPebbleEndToEnd(t *testing.T) {
	v := os.Getenv("CADISH_ACME_PEBBLE")
	if v == "" {
		t.Skip("set CADISH_ACME_PEBBLE=1 (with the pebble compose up) to run the live ACME e2e test")
	}
	dirURL := "https://localhost:14000/dir"
	if v != "1" && v != "true" {
		dirURL = v
	}
	host := getenvOr("CADISH_ACME_HOST", "cadish.test")
	httpPort := getenvOr("CADISH_ACME_HTTP_PORT", "5002")
	tlsPort := getenvOr("CADISH_ACME_TLS_PORT", "5001")

	// Point pebble's DNS at this test process, if a challtestsrv is configured.
	if cts := os.Getenv("CADISH_ACME_CHALLTESTSRV"); cts != "" {
		hostIP := os.Getenv("CADISH_ACME_HOST_IP")
		if hostIP == "" {
			t.Fatal("CADISH_ACME_CHALLTESTSRV is set but CADISH_ACME_HOST_IP is missing (the IP pebble reaches this host on)")
		}
		if err := challtestsrvAdd(cts, host, hostIP); err != nil {
			t.Fatalf("seeding challtestsrv DNS: %v", err)
		}
		t.Logf("seeded %s -> %s via %s", host, hostIP, cts)
	}

	// pebble's ACME directory is served with a self-signed cert — trust anything
	// for the directory connection (this is a local test server).
	insecure := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local pebble test server
	}}

	m, err := NewManager([]SiteConfig{
		{Hosts: []string{host}, TLS: SiteTLS{Mode: ModeACME, Email: "e2e@cadish.test"}},
	}, Options{CacheDir: t.TempDir(), ACMEDirectoryURL: dirURL, ACMEHTTPClient: insecure})
	if err != nil {
		t.Fatal(err)
	}

	// HTTP-01 challenge + redirect on the (non-privileged) http port.
	httpLn, err := net.Listen("tcp", ":"+httpPort)
	if err != nil {
		t.Fatalf("listen :%s (HTTP-01): %v", httpPort, err)
	}
	defer httpLn.Close()
	httpSrv := &http.Server{Handler: m.HTTPHandler(nil)}
	go func() { _ = httpSrv.Serve(httpLn) }()
	defer httpSrv.Close()

	// TLS-ALPN-01 + the hardened TLS config on the tls port.
	tlsLn, err := net.Listen("tcp", ":"+tlsPort)
	if err != nil {
		t.Fatalf("listen :%s (TLS-ALPN-01): %v", tlsPort, err)
	}
	defer tlsLn.Close()
	httpsSrv := &http.Server{Handler: http.NewServeMux()}
	go func() { _ = httpsSrv.Serve(tls.NewListener(tlsLn, m.TLSConfig())) }()
	defer httpsSrv.Close()

	// Drive issuance: a handshake for the configured host triggers autocert to
	// obtain a certificate from pebble.
	hello := &tls.ClientHelloInfo{ServerName: host}
	deadline := time.Now().Add(90 * time.Second)
	for {
		cert, certErr := m.getCertificate(hello)
		if certErr == nil && cert != nil && len(cert.Certificate) > 0 {
			subject := ""
			if cert.Leaf != nil {
				subject = cert.Leaf.Subject.CommonName
			}
			t.Logf("ISSUED: %d-cert chain for %s (leaf CN=%q) from %s", len(cert.Certificate), host, subject, dirURL)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ACME issuance for %s did not complete within deadline: %v", host, certErr)
		}
		time.Sleep(2 * time.Second)
	}
}

// challtestsrvAdd registers a DNS record (host -> ip) with a pebble-challtestsrv
// management server so pebble resolves the challenge domain to this test process.
// An IPv6 address (containing ':') is registered as an AAAA record (the
// Docker-Desktop host-gateway is sometimes IPv6-only).
func challtestsrvAdd(mgmtURL, host, ip string) error {
	endpoint := "/add-a"
	if strings.Contains(ip, ":") {
		endpoint = "/add-aaaa"
	}
	body, _ := json.Marshal(map[string]any{
		"host":      dnsName(host),
		"addresses": []string{ip},
	})
	resp, err := http.Post(mgmtURL+endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &challtestsrvError{status: resp.StatusCode}
	}
	return nil
}

type challtestsrvError struct{ status int }

func (e *challtestsrvError) Error() string {
	return "challtestsrv returned HTTP " + http.StatusText(e.status)
}

// dnsName ensures a trailing dot (challtestsrv keys records by FQDN).
func dnsName(h string) string {
	if len(h) > 0 && h[len(h)-1] == '.' {
		return h
	}
	return h + "."
}

func getenvOr(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
