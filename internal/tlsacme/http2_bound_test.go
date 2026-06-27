package tlsacme

import (
	"net/http"
	"testing"
)

// TestBuildServersHTTP2Bounded verifies the :443 listener (the only inbound HTTP/2
// surface) explicitly bounds the concurrent-stream ceiling and the request-header block,
// so a stream-flood / rapid-reset (CVE-2023-44487 class) and an HPACK header-list bomb
// cannot open unbounded streams or buffer unbounded header bytes. The :80 redirect/ACME
// server is HTTP/1.1 only but shares the header-byte cap.
func TestBuildServersHTTP2Bounded(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	srv := m.BuildServers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ":80", ":443")

	if srv.HTTPS.HTTP2 == nil {
		t.Fatal("HTTPS server has no explicit HTTP2 config; the stream-flood bound is left to the implicit default")
	}
	if got := srv.HTTPS.HTTP2.MaxConcurrentStreams; got != MaxConcurrentStreams {
		t.Fatalf("HTTPS MaxConcurrentStreams = %d, want %d", got, MaxConcurrentStreams)
	}
	if got := srv.HTTPS.MaxHeaderBytes; got != MaxHeaderBytes {
		t.Fatalf("HTTPS MaxHeaderBytes = %d, want %d (HPACK header-list size derives from this)", got, MaxHeaderBytes)
	}
	if got := srv.HTTP.MaxHeaderBytes; got != MaxHeaderBytes {
		t.Fatalf("HTTP (:80) MaxHeaderBytes = %d, want %d", got, MaxHeaderBytes)
	}

	// The advertised h2 ALPN proto must be present on the TLS config, else net/http would
	// never serve h2 and the bound above would be moot.
	cfg := m.TLSConfig()
	var hasH2 bool
	for _, p := range cfg.NextProtos {
		if p == "h2" {
			hasH2 = true
		}
	}
	if !hasH2 {
		t.Fatalf("TLSConfig.NextProtos = %v, missing \"h2\"", cfg.NextProtos)
	}
}
