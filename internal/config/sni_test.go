package config

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
)

// TestSNIHTTPReuseConfig_FastPath verifies that a TRIVIAL single-`to` HTTPS
// upstream that sets `sni`/`http_reuse never` still takes the fast path (the built
// default origin is a plain *httporigin.Origin, NOT an *lb.Upstream) — gap H6: the
// knobs are transport tweaks, not lb features, so they don't force a pool.
func TestSNIHTTPReuseConfig_FastPath(t *testing.T) {
	src := "example.com {\n" +
		"  upstream blog {\n" +
		"    to https://1.2.3.4:443\n" +
		"    host_header www.placercams.com\n" +
		"    sni www.placercams.com\n" +
		"    http_reuse never\n" +
		"  }\n" +
		"}\n"
	p := filepath.Join(t.TempDir(), "Cadishfile")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	o := cfg.Sites[0].Origin
	if _, ok := o.(*httporigin.Origin); !ok {
		t.Fatalf("default origin = %T, want *httporigin.Origin (fast path; sni/http_reuse must NOT force an lb pool)", o)
	}
}

// sniCfgRecorder captures the ClientHello ServerName of a TLS server, so a config
// test can assert the wired `sni` reaches the wire end-to-end.
type sniCfgRecorder struct {
	mu   sync.Mutex
	last string
}

func (s *sniCfgRecorder) serverName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// TestSNIConfig_OnTheWire wires `sni` through config.Load and asserts the
// configured server name appears in the ClientHello. The upstream is dialed by IP
// (the test server's address) so only the explicit `sni` can supply the name.
func TestSNIConfig_OnTheWire(t *testing.T) {
	rec := &sniCfgRecorder{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			rec.mu.Lock()
			rec.last = hi.ServerName
			rec.mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()
	host := srv.Listener.Addr().String() // ip:port

	src := "example.com {\n" +
		"  upstream blog {\n" +
		"    to https://" + host + "\n" +
		"    sni www.placercams.com\n" +
		"  }\n" +
		"}\n"
	p := filepath.Join(t.TempDir(), "Cadishfile")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })

	o := cfg.Sites[0].Origin
	// The origin's transport verifies the httptest cert (unknown CA), so the
	// handshake will fail AFTER the ClientHello is sent — which is all we need: the
	// server records ServerName during the handshake regardless of the outcome.
	_, _ = o.Fetch(context.Background(), &origin.Request{Key: "x"})

	if got := rec.serverName(); got != "www.placercams.com" {
		t.Fatalf("ClientHello ServerName = %q, want www.placercams.com (wired from `sni`)", got)
	}
}

// TestSNIHTTPReuseConfigErrors verifies malformed `sni`/`http_reuse` directives
// fail to load with a positioned error (single-`to` fast-path upstream).
func TestSNIHTTPReuseConfigErrors(t *testing.T) {
	bad := []string{
		"example.com {\n upstream u { to https://o\n sni }\n}\n",               // sni no arg
		"example.com {\n upstream u { to https://o\n sni a b }\n}\n",           // sni two args
		"example.com {\n upstream u { to https://o\n http_reuse safe }\n}\n",   // unsupported keyword
		"example.com {\n upstream u { to https://o\n http_reuse always }\n}\n", // unsupported keyword
		"example.com {\n upstream u { to https://o\n http_reuse }\n}\n",        // no arg
	}
	for _, src := range bad {
		p := filepath.Join(t.TempDir(), "Cadishfile")
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("expected Load to fail for:\n%s", src)
		}
	}
}
