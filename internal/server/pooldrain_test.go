package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/lb"
)

// noKeepAliveClient is an HTTP client that never reuses a connection, so a stuck request
// cannot pin a keep-alive connection past a server shutdown.
func noKeepAliveClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
}

// TestRemovedPoolDrainGrace proves that when a reload removes a pool, an in-flight request
// started before the swap COMPLETES (the pool is not torn down underneath it), and the pool
// IS fully stopped EARLY once in-flight drains (well before the grace elapses). No leak.
func TestRemovedPoolDrainGrace(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	doRelease := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(doRelease)

	var served sync.Once
	gotRequest := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		served.Do(func() { close(gotRequest) })
		<-release // hold the request in flight
		_, _ = w.Write([]byte("drained-ok"))
	})

	drained := make(chan *lb.Upstream, 4)
	oldHook := drainPoolHook
	drainPoolHook = func(p *lb.Upstream) { drained <- p }
	t.Cleanup(func() { drainPoolHook = oldHook })

	// Generous pool grace so we assert the EARLY (in-flight==0) cancel, not the timeout.
	oldGrace := reloadPoolDrainGrace
	reloadPoolDrainGrace = 5 * time.Second
	oldStore := reloadDrainGrace
	reloadDrainGrace = 20 * time.Millisecond
	t.Cleanup(func() { reloadPoolDrainGrace = oldGrace; reloadDrainGrace = oldStore })

	srv, ln, loaded := startDrainServer(t, origin.srv.URL)
	path := loaded.ConfigPath
	base := "http://" + ln.Addr().String()
	client := noKeepAliveClient()

	var removedPool *lb.Upstream
	for _, p := range loaded.Pools() {
		if p.Name() == "backend" {
			removedPool = p
		}
	}
	if removedPool == nil {
		t.Fatal("backend pool not found")
	}

	respCh := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", base+"/x", nil)
		req.Host = "drop.local"
		resp, derr := client.Do(req)
		if derr != nil {
			respCh <- -1
			return
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		respCh <- resp.StatusCode
	}()
	<-gotRequest
	if got := removedPool.Inflight(); got != 1 {
		t.Fatalf("pre-reload pool Inflight = %d, want 1", got)
	}

	reloadDropPool(t, srv, path, origin.srv.URL)

	// Within grace, the pool must NOT be cancelled while the request is still in flight.
	select {
	case p := <-drained:
		t.Fatalf("removed pool %v torn down while a request was still in flight", p.Name())
	case <-time.After(150 * time.Millisecond):
	}
	if got := removedPool.Inflight(); got != 1 {
		t.Fatalf("during drain pool Inflight = %d, want 1 (request still served)", got)
	}

	// Release: the in-flight request finishes 200 against the removed pool, then the drain
	// observes zero in-flight and cancels the pool EARLY.
	doRelease()
	if code := <-respCh; code != 200 {
		t.Fatalf("in-flight request across reload: code = %d, want 200 (pool drained, not cut)", code)
	}
	select {
	case p := <-drained:
		if p != removedPool {
			t.Fatalf("drained the wrong pool: got %v want backend", p.Name())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("removed pool was never torn down after in-flight drained")
	}

	// Shutdown joins all drains; this returning proves no drain goroutine leaked.
	shutdown(t, srv)
}

// TestRemovedPoolDrainGraceTimeout proves the drain is BOUNDED: a request that never
// finishes does not keep the pool alive forever — after the grace the pool is cancelled.
func TestRemovedPoolDrainGraceTimeout(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	doRelease := func() { releaseOnce.Do(func() { close(release) }) }
	// Release BEFORE shutdown so the stuck handler can return and the server can close.
	t.Cleanup(doRelease)

	var served sync.Once
	gotRequest := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		served.Do(func() { close(gotRequest) })
		<-release
	})

	drained := make(chan *lb.Upstream, 4)
	oldHook := drainPoolHook
	drainPoolHook = func(p *lb.Upstream) { drained <- p }
	t.Cleanup(func() { drainPoolHook = oldHook })

	oldGrace := reloadPoolDrainGrace
	reloadPoolDrainGrace = 80 * time.Millisecond // short: assert the timeout path
	oldStore := reloadDrainGrace
	reloadDrainGrace = 20 * time.Millisecond
	t.Cleanup(func() { reloadPoolDrainGrace = oldGrace; reloadDrainGrace = oldStore })

	srv, ln, loaded := startDrainServer(t, origin.srv.URL)
	path := loaded.ConfigPath
	base := "http://" + ln.Addr().String()
	client := noKeepAliveClient()

	go func() {
		req, _ := http.NewRequest("GET", base+"/x", nil)
		req.Host = "drop.local"
		if resp, derr := client.Do(req); derr == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	}()
	<-gotRequest

	reloadDropPool(t, srv, path, origin.srv.URL)

	// The pool is still in flight, but the bounded grace must eventually cancel it.
	select {
	case <-drained:
		// good: bounded teardown fired despite the stuck request
	case <-time.After(3 * time.Second):
		t.Fatal("drain grace did not bound a stuck in-flight pool teardown")
	}

	doRelease() // let the stuck handler return before the deferred shutdown
	shutdown(t, srv)
}

// startDrainServer builds + serves a one-site config whose pool ("backend") the
// reloadDropPool helper later removes.
func startDrainServer(t *testing.T, originURL string) (*Server, net.Listener, *config.Config) {
	t.Helper()
	// A non-trivial upstream (an lb feature → a real lb.Upstream pool, not a plain
	// httporigin) so the pool-level in-flight drain applies. `policy round_robin` forces
	// the pool with a single backend, keeping the request deterministic.
	const cfg1 = `drop.local {
	upstream backend {
		to %s
		policy round_robin
	}
	route -> backend
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(cfg1, originURL)), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(loaded, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, ln, loaded
}

// reloadDropPool reloads srv to a config that REMOVES drop.local (and thus its pool),
// replacing it with a different site so the config still has a site.
func reloadDropPool(t *testing.T, srv *Server, path, originURL string) {
	t.Helper()
	const cfg2 = `keep.local {
	upstream other { to %s }
	route -> other
}
`
	if err := os.WriteFile(path, []byte(fmt.Sprintf(cfg2, originURL)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
}

func shutdown(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
