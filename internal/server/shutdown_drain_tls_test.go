package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// TestShutdownDrainsInFlightTLSRequest proves that a graceful Shutdown in TLS mode
// WAITS for an in-flight HTTPS request (served by the :443 tlsacme server, NOT the
// plain httpSrv) to drain before it returns and tears down the cache/handler.
//
// The bug it guards against: Server.Shutdown only cancelled servingCtx (which lets the
// tlsacme servers drain themselves on a SEPARATE goroutine) and then immediately closed
// the cache stores + handler machinery and returned. The cli's run loop returns and the
// process exits as soon as Shutdown returns — so the in-flight HTTPS request was dropped
// mid-flight (and the cache/handler it was still using were torn down underneath it).
// A correct Shutdown blocks until the :443 request has actually drained.
func TestShutdownDrainsInFlightTLSRequest(t *testing.T) {
	const originDelay = 500 * time.Millisecond
	started := make(chan struct{})
	var startedOnce sync.Once

	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			startedOnce.Do(func() { close(started) })
			time.Sleep(originDelay) // hold the request in-flight
		}
		_, _ = io.WriteString(w, "drained-body")
	})

	cfg := loadCfg(t, fmt.Sprintf(`drain.local {
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
	certFile, keyFile := writeSelfSignedCert(t, "drain.local")
	certPEM, _ := os.ReadFile(certFile)
	keyPEM, _ := os.ReadFile(keyFile)
	if err := srv.SetDynamicCerts([]tlsacme.DynamicCert{{Hosts: []string{"drain.local"}, CertPEM: certPEM, KeyPEM: keyPEM}}); err != nil {
		t.Fatalf("SetDynamicCerts: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "drain.local", InsecureSkipVerify: true}, //nolint:gosec // test client
	}}

	// Warm up: wait until the :443 listener is accepting on a fast path.
	deadline := time.Now().Add(3 * time.Second)
	for {
		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/ready", nil)
		req.Host = "drain.local"
		resp, rerr := client.Do(req)
		if rerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS listener never came up: %v", rerr)
		}
		time.Sleep(20 * time.Millisecond)
	}

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest("GET", "https://"+httpsAddr+"/slow", nil)
		req.Host = "drain.local"
		resp, rerr := client.Do(req)
		if rerr != nil {
			resCh <- result{err: rerr}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	// The request is in-flight on :443 once the origin starts handling it.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("slow request never reached origin")
	}

	shutStart := time.Now()
	if err := srv.Shutdown(testCtx(t)); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	elapsed := time.Since(shutStart)
	<-serveErr

	res := <-resCh
	if res.err != nil {
		t.Fatalf("in-flight TLS request was dropped by shutdown: %v", res.err)
	}
	if res.status != 200 || res.body != "drained-body" {
		t.Fatalf("in-flight TLS request not served cleanly: %d %q", res.status, res.body)
	}
	// The discriminating assertion: a draining Shutdown must not return until the
	// in-flight request (held ~originDelay at the origin) has completed.
	if elapsed < originDelay/2 {
		t.Fatalf("Shutdown returned in %v without draining the in-flight TLS request (origin held it %v); "+
			"in TLS mode the :443 server's in-flight requests are not waited on", elapsed, originDelay)
	}
}
