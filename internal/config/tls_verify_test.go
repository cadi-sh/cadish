package config

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
)

// writeCfg writes src to a temp Cadishfile and returns its path.
func writeCfg(t *testing.T, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Cadishfile")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newSelfSignedServer stands up a self-signed TLS httptest server and returns it
// plus its host:port. The default cert is for 127.0.0.1/example.com, so dialing it
// by IP with the cert in RootCAs verifies.
func newSelfSignedServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, srv.Listener.Addr().String()
}

// writeServerCAFile writes the test server's leaf cert as a PEM file (usable as a
// ca_file: the leaf is its own trust anchor for these tests) and returns the path.
func writeServerCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	der := srv.Certificate().Raw
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTLSVerify_DefaultFailsInsecureSucceeds wires the knobs through config.Load and
// proves the security contract end-to-end: a self-signed origin FAILS by default and
// SUCCEEDS with `tls_insecure`.
func TestTLSVerify_DefaultFailsInsecureSucceeds(t *testing.T) {
	_, host := newSelfSignedServer(t)

	// Default: full verification → handshake fails.
	cfgDef, err := Load(writeCfg(t, "example.com {\n upstream blog {\n  to https://"+host+"\n }\n}\n"))
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	t.Cleanup(func() { _ = cfgDef.Close() })
	if _, ferr := cfgDef.Sites[0].Origin.Fetch(context.Background(), &origin.Request{Key: "x"}); ferr == nil {
		t.Fatal("default (no knob) Fetch succeeded against a self-signed origin; want a verification failure")
	}

	// tls_insecure: verification skipped → success.
	cfgIns, err := Load(writeCfg(t, "example.com {\n upstream blog {\n  to https://"+host+"\n  tls_insecure\n }\n}\n"))
	if err != nil {
		t.Fatalf("Load tls_insecure: %v", err)
	}
	t.Cleanup(func() { _ = cfgIns.Close() })
	resp, ferr := cfgIns.Sites[0].Origin.Fetch(context.Background(), &origin.Request{Key: "x"})
	if ferr != nil {
		t.Fatalf("tls_insecure Fetch: %v", ferr)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// TestTLSVerify_CAFileVerifies proves `ca_file` builds the right RootCAs pool: the
// same self-signed origin verifies successfully when its cert is the configured CA.
func TestTLSVerify_CAFileVerifies(t *testing.T) {
	srv, host := newSelfSignedServer(t)
	caPath := writeServerCAFile(t, srv)

	cfg, err := Load(writeCfg(t, "example.com {\n upstream blog {\n  to https://"+host+"\n  ca_file "+caPath+"\n }\n}\n"))
	if err != nil {
		t.Fatalf("Load ca_file: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	resp, ferr := cfg.Sites[0].Origin.Fetch(context.Background(), &origin.Request{Key: "x"})
	if ferr != nil {
		t.Fatalf("ca_file Fetch (should verify against the configured CA): %v", ferr)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// TestTLSVerify_FastPathKnobs verifies a TRIVIAL single-`to` upstream that sets the
// TLSVERIFY knobs still takes the httporigin fast path (no lb pool). The knob's
// transport effect is asserted at the httporigin layer (tls_test.go); here we only
// guard that the knobs do not force a pool.
func TestTLSVerify_FastPathKnobs(t *testing.T) {
	cfg, err := Load(writeCfg(t, "example.com {\n upstream blog {\n  to https://1.2.3.4:443\n  tls_insecure\n  alpn http/1.1\n }\n}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	if _, ok := cfg.Sites[0].Origin.(*httporigin.Origin); !ok {
		t.Fatalf("default origin = %T, want *httporigin.Origin (TLSVERIFY knobs must NOT force an lb pool)", cfg.Sites[0].Origin)
	}
}

// TestTLSVerify_MutualExclusion: tls_insecure + ca_file is a compile error at check
// time (the two contradict).
func TestTLSVerify_MutualExclusion(t *testing.T) {
	srv, host := newSelfSignedServer(t)
	caPath := writeServerCAFile(t, srv)
	_, err := Load(writeCfg(t, "example.com {\n upstream blog {\n  to https://"+host+"\n  tls_insecure\n  ca_file "+caPath+"\n }\n}\n"))
	if err == nil {
		t.Fatal("Load accepted tls_insecure + ca_file together; want a mutual-exclusion error")
	}
}

// TestTLSVerify_BadCAFile: a missing or garbage ca_file fails loudly at load (check).
func TestTLSVerify_BadCAFile(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.pem")
		if _, err := Load(writeCfg(t, "example.com {\n upstream b { to https://o\n ca_file "+missing+" }\n}\n")); err == nil {
			t.Fatal("Load accepted a missing ca_file; want a read error")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		garbage := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(writeCfg(t, "example.com {\n upstream b { to https://o\n ca_file "+garbage+" }\n}\n")); err == nil {
			t.Fatal("Load accepted a non-PEM ca_file; want an empty-pool error")
		}
	})
}

// TestTLSVerify_BadArgs: malformed tls_insecure/alpn directives fail to load.
func TestTLSVerify_BadArgs(t *testing.T) {
	bad := []string{
		"example.com {\n upstream u { to https://o\n tls_insecure x }\n}\n", // tls_insecure takes no args
		"example.com {\n upstream u { to https://o\n alpn }\n}\n",           // alpn needs a proto
	}
	for _, src := range bad {
		if _, err := Load(writeCfg(t, src)); err == nil {
			t.Errorf("expected Load to fail for:\n%s", src)
		}
	}
}
