package server

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// TestServerTimeouts verifies the streaming-safe connection timeouts (security
// review #7): ReadHeaderTimeout/ReadTimeout/IdleTimeout are set, while WriteTimeout
// stays 0 so large/slow media downloads are never truncated.
func TestServerTimeouts(t *testing.T) {
	cfg := loadCfg(t, `to.local {
	cache { ram 8MiB }
	upstream b { to http://127.0.0.1:1 }
	cache_ttl default ttl 60s
}
`)
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(testCtx(t)) })

	if srv.httpSrv.ReadHeaderTimeout != serverReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.httpSrv.ReadHeaderTimeout, serverReadHeaderTimeout)
	}
	if srv.httpSrv.ReadTimeout != serverReadTimeout {
		t.Errorf("ReadTimeout = %v, want %v", srv.httpSrv.ReadTimeout, serverReadTimeout)
	}
	if srv.httpSrv.IdleTimeout != serverIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.httpSrv.IdleTimeout, serverIdleTimeout)
	}
	if srv.httpSrv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want 0 (streaming-safe)", srv.httpSrv.WriteTimeout)
	}
	if srv.httpSrv.MaxHeaderBytes != serverMaxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.httpSrv.MaxHeaderBytes, serverMaxHeaderBytes)
	}
}

// TestServerMaxHeaderBytesConst pins the data-plane header cap to a sane explicit
// value (not net/http's 1 MiB default) and keeps the plain + TLS listeners in
// lockstep so neither path silently regresses to the default.
func TestServerMaxHeaderBytesConst(t *testing.T) {
	if serverMaxHeaderBytes != 64<<10 {
		t.Errorf("serverMaxHeaderBytes = %d, want 64 KiB", serverMaxHeaderBytes)
	}
	if serverMaxHeaderBytes != tlsacme.MaxHeaderBytes {
		t.Errorf("plain (%d) and TLS (%d) MaxHeaderBytes diverged", serverMaxHeaderBytes, tlsacme.MaxHeaderBytes)
	}
}
