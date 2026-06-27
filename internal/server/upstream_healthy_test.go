package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// healthyBackend is an httptest origin whose /healthz reply is flipped at runtime, so a
// test can drive the active health FSM down and back up and watch the `upstream_healthy`
// probe follow it.
type healthyBackend struct {
	srv     *httptest.Server
	healthy atomic.Bool
}

func newHealthyBackend(t *testing.T) *healthyBackend {
	t.Helper()
	hb := &healthyBackend{}
	hb.healthy.Store(true)
	hb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if hb.healthy.Load() {
				w.WriteHeader(200)
			} else {
				w.WriteHeader(503)
			}
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(hb.srv.Close)
	return hb
}

const upstreamHealthyProbeSite = `test.local {
	cache { ram 16MiB }
	upstream cache_pool {
		to %s
		health GET /healthz expect 200 interval 30ms window 1 threshold 1
	}
	@probe path /aws-health-check
	@live  upstream_healthy cache_pool
	respond @probe @live 200 "OK"
	respond @probe 503
	cache_ttl default ttl 300s
}
`

// probeStatus issues the AWS health-probe request through the live server handler and
// returns the status code.
func probeStatus(h http.Handler) int {
	req := httptest.NewRequest("GET", "http://test.local/aws-health-check", nil)
	req.Host = "test.local"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// waitProbe polls the probe endpoint until it returns want (or fails the test).
func waitProbe(t *testing.T, h http.Handler, want string, code int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if probeStatus(h) == code {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("probe never reached %s (%d); last = %d", want, code, probeStatus(h))
}

// TestUpstreamHealthyProbeFlips is the end-to-end HEALTH integration: the
// `upstream_healthy cache_pool` matcher composed with scoped `respond` answers 200 while
// the pool has a live backend and 503 when the only backend goes down — and recovers —
// driven by the REAL active health FSM through the REAL server handler. (kill → 503 → 200)
func TestUpstreamHealthyProbeFlips(t *testing.T) {
	hb := newHealthyBackend(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(upstreamHealthyProbeSite, hb.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(testCtx(t)) })
	h := srv.Handler()

	// Backend converges healthy ⇒ probe answers 200.
	waitProbe(t, h, "live 200", 200)

	// Kill the backend's health ⇒ FSM flips down ⇒ probe answers 503 (no origin dial).
	hb.healthy.Store(false)
	waitProbe(t, h, "down 503", 503)

	// Recover ⇒ FSM flips up ⇒ probe answers 200 again.
	hb.healthy.Store(true)
	waitProbe(t, h, "recovered 200", 200)
}

// upstreamHealthySingleSite references `upstream_healthy single` where `single` is a
// TRIVIAL single-backend upstream (one `to`, no lb features) — built as a plain
// httporigin, not an lb pool. R03: poolHealthResolver used to type-assert *lb.Upstream
// and return FALSE for an httporigin, so this probe answered 503 forever even with the
// backend up (a self-inflicted outage when an L4 LB ejects the node). A known non-pool
// origin must now resolve HEALTHY.
const upstreamHealthySingleSite = `test.local {
	cache { ram 16MiB }
	upstream single {
		to %s
	}
	@probe path /aws-health-check
	@live  upstream_healthy single
	respond @probe @live 200 "OK"
	respond @probe 503
	cache_ttl default ttl 300s
}
`

// TestUpstreamHealthySingleBackendResolvesHealthy is the R03 regression: a single-`to`
// upstream (a plain httporigin, no health FSM) referenced by `upstream_healthy` resolves
// HEALTHY, so the scoped `respond @probe @live 200` answers 200 — not the stuck 503 the
// old fail-closed type assertion produced.
func TestUpstreamHealthySingleBackendResolvesHealthy(t *testing.T) {
	hb := newHealthyBackend(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(upstreamHealthySingleSite, hb.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(testCtx(t)) })
	h := srv.Handler()

	if code := probeStatus(h); code != 200 {
		t.Fatalf("single-backend upstream_healthy probe = %d, want 200 (a known non-pool origin must resolve healthy, not the R03 stuck 503)", code)
	}
}
