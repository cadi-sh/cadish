package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServerInboundTimeoutOverrides: the global `server { read_timeout/idle_timeout }`
// knob overrides the hardcoded inbound http.Server timeouts; ReadHeaderTimeout (no
// knob) stays at its default constant.
func TestServerInboundTimeoutOverrides(t *testing.T) {
	cfg := loadCfg(t, `{
	server {
		read_timeout 7s
		idle_timeout 33s
	}
}
over.local {
	upstream b { to https://example.org }
	cache_ttl default ttl 60s
}
`)
	srv, err := NewServer(cfg, freeAddr(t), Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Shutdown(nil)
	if got := srv.httpSrv.ReadTimeout; got != 7*time.Second {
		t.Errorf("ReadTimeout = %v, want 7s (overridden)", got)
	}
	if got := srv.httpSrv.IdleTimeout; got != 33*time.Second {
		t.Errorf("IdleTimeout = %v, want 33s (overridden)", got)
	}
	if got := srv.httpSrv.ReadHeaderTimeout; got != serverReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want default %v (no knob)", got, serverReadHeaderTimeout)
	}
}

// TestServerInboundTimeoutDefaults: with no `server` block the inbound timeouts keep
// the shipped default constants (byte-for-byte unchanged behaviour).
func TestServerInboundTimeoutDefaults(t *testing.T) {
	cfg := loadCfg(t, `def.local {
	upstream b { to https://example.org }
	cache_ttl default ttl 60s
}
`)
	srv, err := NewServer(cfg, freeAddr(t), Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Shutdown(nil)
	if srv.httpSrv.ReadTimeout != serverReadTimeout {
		t.Errorf("ReadTimeout = %v, want default %v", srv.httpSrv.ReadTimeout, serverReadTimeout)
	}
	if srv.httpSrv.IdleTimeout != serverIdleTimeout {
		t.Errorf("IdleTimeout = %v, want default %v", srv.httpSrv.IdleTimeout, serverIdleTimeout)
	}
}

// TestServerMaxConnLimitsConcurrency: `server { maxconn N }` wraps the inbound
// listener with a LimitListener so no more than N connections are accepted (and thus
// served) at once. We drive the composed wrap over a real listener with a
// concurrency-counting handler and assert the observed peak never exceeds N.
func TestServerMaxConnLimitsConcurrency(t *testing.T) {
	const maxConn = 2
	cfg := loadCfg(t, fmt.Sprintf(`{
	server { maxconn %d }
}
lim.local {
	upstream b { to https://example.org }
	cache_ttl default ttl 60s
}
`, maxConn))
	srv, err := NewServer(cfg, freeAddr(t), Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Shutdown(nil)

	if srv.serverMaxConn() != maxConn {
		t.Fatalf("serverMaxConn() = %d, want %d", srv.serverMaxConn(), maxConn)
	}

	// Bare listener, then the data-plane wrap (LimitListener(maxConn), no proxy).
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrap := srv.dataPlaneListenerWrap()
	if wrap == nil {
		t.Fatal("dataPlaneListenerWrap() = nil, want a LimitListener wrap when maxconn is set")
	}
	ln, err := wrap(raw)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var active, peak int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&active, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond) // hold the slot so concurrent demand piles up
		atomic.AddInt64(&active, -1)
		_, _ = io.WriteString(w, "ok")
	})
	hs := &http.Server{Handler: h}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()

	addr := ln.Addr().String()
	// New connection per request (no keep-alive reuse) so each in-flight request
	// occupies its own accepted connection — the thing LimitListener caps.
	tr := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("http://" + addr + "/")
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&peak); got > maxConn {
		t.Errorf("peak concurrent served = %d, want <= maxconn %d (LimitListener not bounding accepts)", got, maxConn)
	}
	if atomic.LoadInt64(&peak) == 0 {
		t.Error("no requests were served — the wrapped listener did not accept any connection")
	}
}

// TestServerNoBlockNoListenerWrap: with neither proxy_protocol nor a maxconn knob the
// data-plane wrap is nil (the bare accept path, zero cost).
func TestServerNoBlockNoListenerWrap(t *testing.T) {
	cfg := loadCfg(t, `plain.local {
	upstream b { to https://example.org }
	cache_ttl default ttl 60s
}
`)
	srv, err := NewServer(cfg, freeAddr(t), Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Shutdown(nil)
	if w := srv.dataPlaneListenerWrap(); w != nil {
		t.Error("dataPlaneListenerWrap() should be nil with no proxy_protocol and no maxconn")
	}
}
