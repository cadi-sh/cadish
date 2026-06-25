package config

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// hostSink records the last Host header an upstream received.
type hostSink struct {
	mu   sync.Mutex
	host string
}

func (s *hostSink) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.host = r.Host
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}
}

func (s *hostSink) got() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host
}

// loadOriginFromUpstream loads a Cadishfile with a single `upstream u { … }` body
// and returns its built default origin.
func loadOriginFromUpstream(t *testing.T, upstreamBody string) origin.Origin {
	t.Helper()
	src := "example.com {\n  upstream u {\n" + upstreamBody + "\n  }\n}\n"
	p := filepath.Join(t.TempDir(), "Cadishfile")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v\n%s", err, src)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	o := cfg.Sites[0].Origin
	if o == nil {
		t.Fatal("no default origin built")
	}
	return o
}

// fetchHost fetches once through o, advertising clientHost, and returns the Host
// the upstream actually saw.
func fetchHost(t *testing.T, o origin.Origin, sink *hostSink, clientHost string) string {
	t.Helper()
	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x", ClientHost: clientHost})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	_ = resp.Body.Close()
	return sink.got()
}

// TestHostHeaderConfig wires the `host_header` directive end-to-end through
// config.Load for both the trivial single-origin path and the lb-pool path
// (backlog #11).
func TestHostHeaderConfig(t *testing.T) {
	sink := &hostSink{}
	srv := httptest.NewServer(sink.handler())
	defer srv.Close()
	upstreamHost := mustHost(t, srv.URL)

	cases := []struct {
		name       string
		body       string // upstream block body lines (besides the `to`)
		clientHost string
		want       string // expected Host at the upstream
	}{
		{
			name:       "default is preserve",
			body:       "    to " + srv.URL,
			clientHost: "www.example.com",
			want:       "www.example.com",
		},
		{
			name:       "explicit preserve",
			body:       "    to " + srv.URL + "\n    host_header preserve",
			clientHost: "shop.example.com:8443",
			want:       "shop.example.com:8443",
		},
		{
			name:       "origin keeps upstream host",
			body:       "    to " + srv.URL + "\n    host_header origin",
			clientHost: "www.example.com",
			want:       upstreamHost,
		},
		{
			name:       "fixed value",
			body:       "    to " + srv.URL + "\n    host_header origin.internal",
			clientHost: "www.example.com",
			want:       "origin.internal",
		},
		{
			// An lb pool (two `to` backends) must honor host_header too.
			name:       "lb pool preserves",
			body:       "    to " + srv.URL + " " + srv.URL + "\n    host_header preserve",
			clientHost: "pool.example.com",
			want:       "pool.example.com",
		},
		{
			name:       "lb pool fixed",
			body:       "    to " + srv.URL + " " + srv.URL + "\n    host_header fixed.internal",
			clientHost: "pool.example.com",
			want:       "fixed.internal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := loadOriginFromUpstream(t, tc.body)
			if got := fetchHost(t, o, sink, tc.clientHost); got != tc.want {
				t.Fatalf("upstream Host = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHostHeaderConfigErrors verifies malformed `host_header` directives fail to
// load with a positioned error.
func TestHostHeaderConfigErrors(t *testing.T) {
	bad := []string{
		"example.com {\n upstream u { to http://o\n host_header }\n}\n",      // no arg
		"example.com {\n upstream u { to http://o\n host_header a b }\n}\n",  // two args
		"example.com {\n upstream u { to http://o\n host_header @ref }\n}\n", // matcher ref
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

// mustHost extracts host:port from a server URL.
func mustHost(t *testing.T, raw string) string {
	t.Helper()
	// srv.URL is like "http://127.0.0.1:PORT" — strip the scheme.
	const p = "http://"
	if len(raw) > len(p) && raw[:len(p)] == p {
		return raw[len(p):]
	}
	t.Fatalf("unexpected server URL %q", raw)
	return ""
}
