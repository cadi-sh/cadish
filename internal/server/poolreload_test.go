package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/lb"
)

// probeOrigin is an httptest origin that counts CONTENT fetches and HEALTH probes
// separately (health probes hit /healthz), so a test can assert a steady backend is
// not re-probed across a reload independently of content traffic.
type probeOrigin struct {
	srv     *httptest.Server
	content atomic.Int64
	probes  atomic.Int64
}

func newProbeOrigin(t *testing.T) *probeOrigin {
	t.Helper()
	po := &probeOrigin{}
	po.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			po.probes.Add(1)
			w.WriteHeader(200)
			return
		}
		po.content.Add(1)
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	}))
	t.Cleanup(po.srv.Close)
	return po
}

// poolWithName returns the live pool of the given name from the server's current
// config, or nil.
func poolWithName(s *Server, name string) *lb.Upstream {
	for _, p := range s.cfg.Pools() {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// healthPoolSite is a site whose `backend` upstream is a single-backend pool with
// active health probing (interval 1h ⇒ exactly ONE immediate probe at pool start, so
// a re-probe is detectable as an increment). The trailing %s is an extra line so the
// test can make an UNRELATED change without touching the upstream block.
const healthPoolSite = `test.local {
	cache { ram 32MiB }
	upstream backend {
		to %s
		health GET /healthz expect 200 interval 1h window 1 threshold 1
	}
	cache_ttl default ttl 300s
	header +cache_status X-Cache
	%s
}
`

// waitProbed polls until the pool has been probed at least once (its single backend
// converged healthy), so the test starts from a known warm state.
func waitProbed(t *testing.T, po *probeOrigin) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if po.probes.Load() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("health probe never fired")
}

// TestReloadTransplantsSteadyPool proves an UNRELATED reload keeps the steady pool's
// *lb.Upstream INSTANCE IDENTITY (same pointer) and does NOT re-probe its backend
// (the warm health FSM survives) — item 2 of the spec test list, at Server level.
func TestReloadTransplantsSteadyPool(t *testing.T) {
	po := newProbeOrigin(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	write := func(extra string) {
		if err := os.WriteFile(path, []byte(fmt.Sprintf(healthPoolSite, po.srv.URL, extra)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(testCtx(t)) })

	waitProbed(t, po)
	steadyPool := poolWithName(srv, "backend")
	if steadyPool == nil {
		t.Fatal("backend pool not found")
	}
	probesBefore := po.probes.Load()

	// Reload with an UNRELATED change (a response header) — the upstream block is
	// byte-identical, so its fingerprint is unchanged and the pool must be transplanted.
	write("header +x-extra Hello")
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := poolWithName(srv, "backend"); got != steadyPool {
		t.Fatalf("steady pool not transplanted: got %p want %p (same instance)", got, steadyPool)
	}
	// Give any (erroneous) new health loop a moment to fire an immediate probe.
	time.Sleep(100 * time.Millisecond)
	if got := po.probes.Load(); got != probesBefore {
		t.Fatalf("steady backend was re-probed across reload: probes %d -> %d", probesBefore, got)
	}
}

// twoPoolReloadSite has two real (multi-backend) pools so a reload can change one and
// leave the other; %s is poolB's first backend (the knob the test turns).
const twoPoolReloadSite = `test.local {
	cache { ram 16MiB }
	upstream poolA {
		to http://a1.invalid:80
		to http://a2.invalid:80
	}
	upstream poolB {
		to %s
		to http://b2.invalid:80
	}
	origin chain poolA -> poolB
}
`

// TestReloadRebuildsOnlyChangedPool proves a reload that changes ONE pool's backend
// set rebuilds ONLY that pool (new instance) while its sibling survives by instance
// identity — item 3. The pools sit behind an `origin chain` to also exercise the
// chain-member repointing path.
func TestReloadRebuildsOnlyChangedPool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	write := func(poolBFirst string) {
		if err := os.WriteFile(path, []byte(fmt.Sprintf(twoPoolReloadSite, poolBFirst)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("http://b1.invalid:80")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(testCtx(t)) })

	a0 := poolWithName(srv, "poolA")
	b0 := poolWithName(srv, "poolB")
	if a0 == nil || b0 == nil {
		t.Fatal("expected poolA and poolB")
	}

	// Change poolB's first backend; poolA untouched.
	write("http://b1-changed.invalid:80")
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if got := poolWithName(srv, "poolA"); got != a0 {
		t.Errorf("poolA must survive unchanged: got %p want %p", got, a0)
	}
	if got := poolWithName(srv, "poolB"); got == b0 {
		t.Error("poolB changed its backend set; it must be rebuilt (new instance)")
	}
	if got := poolWithName(srv, "poolB"); got == nil {
		t.Error("poolB missing after reload")
	}
}

// TestReloadLiveTLSAddHostKeepsCacheAndPool is the end-to-end item 8: over a real TLS
// listener, a reload that ADDS a new TLS host (an unrelated change) keeps a pre-reload
// cached object a HIT, does NOT re-probe the steady backend, and makes the NEW TLS host
// reachable live — with no restart and no listener churn.
func TestReloadLiveTLSAddHostKeepsCacheAndPool(t *testing.T) {
	po := newProbeOrigin(t)
	certA, keyA := writeSelfSignedCert(t, "one.local")
	certB, keyB := writeSelfSignedCert(t, "two.local")

	site1 := func() string {
		return fmt.Sprintf(`one.local {
	tls { cert %s
		key %s }
	cache { ram 32MiB }
	upstream backend {
		to %s
		health GET /healthz expect 200 interval 1h window 1 threshold 1
	}
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`, certA, keyA, po.srv.URL)
	}
	site2 := fmt.Sprintf(`two.local {
	tls { cert %s
		key %s }
	cache { ram 16MiB }
	upstream backend2 { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`, certB, keyB, po.srv.URL)

	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(site1()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	httpAddr := freeAddr(t)
	httpsAddr := freeAddr(t)
	srv, err := NewServer(cfg, httpAddr, Options{Logger: discardLogger(), HTTPSAddr: httpsAddr})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown(testCtx(t))
		<-serveErr
	})

	get := func(host, p string) (*http.Response, error) {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // test
		}}
		req, _ := http.NewRequest("GET", "https://"+httpsAddr+p, nil)
		req.Host = host
		return client.Do(req)
	}

	// Warm one.local: retry until the listener is up AND the health-gated backend is
	// serving (MISS), then a HIT.
	deadline := time.Now().Add(4 * time.Second)
	var warmed bool
	for time.Now().Before(deadline) {
		resp, gerr := get("one.local", "/a")
		if gerr != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 && string(b) == "body /a" && resp.Header.Get("X-Cache") == "MISS" {
			warmed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !warmed {
		t.Fatal("one.local never warmed to a MISS")
	}
	if resp, _ := get("one.local", "/a"); resp != nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Header.Get("X-Cache") != "HIT" || string(b) != "body /a" {
			t.Fatalf("warm HIT failed: xc=%q body=%q", resp.Header.Get("X-Cache"), b)
		}
	}
	waitProbed(t, po)

	steadyPool := poolWithName(srv, "backend")
	contentBefore := po.content.Load()
	probesBefore := po.probes.Load()

	// two.local is not reachable yet (no such TLS host / route).
	if resp, gerr := get("two.local", "/x"); gerr == nil {
		// A handshake may still succeed via SNI fallback to the single cert, but the
		// route must not exist yet → no 200 "body /x".
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 && string(b) == "body /x" {
			t.Fatal("two.local served before it was added")
		}
	}

	// Reload ADDING two.local (unrelated to one.local's upstream).
	if err := os.WriteFile(path, []byte(site1()+site2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// (a) one.local's cached object is STILL a HIT — no extra content fetch.
	if resp, gerr := get("one.local", "/a"); gerr != nil {
		t.Fatalf("one.local after reload: %v", gerr)
	} else {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Header.Get("X-Cache") != "HIT" || string(b) != "body /a" {
			t.Fatalf("post-reload one.local: xc=%q body=%q want HIT 'body /a'", resp.Header.Get("X-Cache"), b)
		}
	}
	if po.content.Load() != contentBefore {
		t.Fatalf("content fetched again after reload: %d -> %d (cache not preserved)", contentBefore, po.content.Load())
	}

	// (b) steady backend not re-probed; same pool instance.
	if got := poolWithName(srv, "backend"); got != steadyPool {
		t.Fatalf("steady pool not transplanted: got %p want %p", got, steadyPool)
	}
	time.Sleep(100 * time.Millisecond)
	if po.probes.Load() != probesBefore {
		t.Fatalf("steady backend re-probed across TLS reload: %d -> %d", probesBefore, po.probes.Load())
	}

	// (c) the NEW TLS host is reachable live — its cert is served and its route works.
	reached := false
	d2 := time.Now().Add(2 * time.Second)
	for time.Now().Before(d2) {
		resp, gerr := get("two.local", "/x")
		if gerr != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		cn := ""
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cn = resp.TLS.PeerCertificates[0].Subject.CommonName
		}
		resp.Body.Close()
		if resp.StatusCode == 200 && string(b) == "body /x" && cn == "two.local" {
			reached = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reached {
		t.Fatal("two.local not reachable with its own cert after reload (TLS hostname hot-reload failed)")
	}
}
