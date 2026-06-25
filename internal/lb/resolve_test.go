package lb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/origin"
)

// mustParse parses a target token or fails the test.
func mustParse(t *testing.T, tok string) Target {
	t.Helper()
	tgt, err := parseTarget(tok, cadishfile.Pos{})
	if err != nil {
		t.Fatalf("parseTarget %q: %v", tok, err)
	}
	return tgt
}

// stubOriginFactory builds a trivial in-memory origin for any base URL.
func stubOriginFactory(baseURL string, _ *Target, _ Timeouts) (origin.Origin, error) {
	return &recOrigin{base: baseURL, calls: new(int64)}, nil
}

// waitFor polls cond every 5ms until it holds or timeout elapses (then fails).
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("waitFor: condition not met within timeout")
}

type fakeEndpointResolver struct {
	mu        sync.Mutex
	eps       map[string][]Endpoint // "svc/ns" -> endpoints
	onChange  map[string]func()
	err       error
	watches   int // total Watch registrations made
	cancelled int // total cancel funcs invoked
}

func newFakeEndpointResolver() *fakeEndpointResolver {
	return &fakeEndpointResolver{eps: map[string][]Endpoint{}, onChange: map[string]func(){}}
}
func (f *fakeEndpointResolver) set(svc, ns string, eps []Endpoint) {
	f.mu.Lock()
	f.eps[svc+"/"+ns] = eps
	cb := f.onChange[svc+"/"+ns]
	f.mu.Unlock()
	if cb != nil {
		cb()
	}
}
func (f *fakeEndpointResolver) ResolveEndpoints(_ context.Context, svc, ns, _ string) ([]Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]Endpoint(nil), f.eps[svc+"/"+ns]...), nil
}
func (f *fakeEndpointResolver) Watch(svc, ns string, onChange func()) func() {
	f.mu.Lock()
	f.onChange[svc+"/"+ns] = onChange
	f.watches++
	f.mu.Unlock()
	return func() {
		f.mu.Lock()
		delete(f.onChange, svc+"/"+ns)
		f.cancelled++
		f.mu.Unlock()
	}
}

func TestK8sResolveTarget(t *testing.T) {
	res := newFakeEndpointResolver()
	res.set("web", "prod", []Endpoint{{IP: "10.0.0.1", Port: 8080}, {IP: "10.0.0.2", Port: 8080}})
	tgt, err := parseTarget("k8s://web.prod:8080", cadishfile.Pos{})
	if err != nil {
		t.Fatal(err)
	}
	eps, err := resolveTarget(context.Background(), nil, res, &tgt)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d", len(eps))
	}
	if eps[0].baseURL != "http://10.0.0.1:8080" {
		t.Fatalf("bad baseURL %q", eps[0].baseURL)
	}
}

func TestK8sResolveErrorRetainsBackends(t *testing.T) {
	res := newFakeEndpointResolver()
	res.set("web", "prod", []Endpoint{{IP: "10.0.0.1", Port: 80}})
	cfg := Config{Name: "web", Kind: "upstream", Policy: RoundRobin,
		Backends: []Target{mustParse(t, "k8s://web.prod:80")}}
	u, err := New(cfg, WithEndpointResolver(res), WithOriginFactory(stubOriginFactory))
	if err != nil {
		t.Fatal(err)
	}
	// One backend resolved at construction.
	if backends, _, _ := u.snapshot(); len(backends) != 1 {
		t.Fatalf("want 1 backend after initial resolve, got %d", len(backends))
	}
	// A resolution error must retain the prior backend set (transient API loss).
	res.mu.Lock()
	res.err = errors.New("api down")
	res.mu.Unlock()
	u.resolveOnce(context.Background())
	if backends, _, _ := u.snapshot(); len(backends) != 1 {
		t.Fatalf("want 1 backend retained after resolve error, got %d", len(backends))
	}
}

// TestK8sPoolDeregistersWatchOnCtxCancel is the FIX-4 leak guard: when a k8s:// pool's
// context is cancelled (as stopRemovedPools does on a fingerprint-change rebuild), the
// pool must deregister its resolver Watch so the dead *Upstream is not pinned forever.
func TestK8sPoolDeregistersWatchOnCtxCancel(t *testing.T) {
	res := newFakeEndpointResolver()
	res.set("web", "prod", []Endpoint{{IP: "10.0.0.1", Port: 80}})
	cfg := Config{Name: "web", Kind: "upstream", Policy: RoundRobin,
		Backends: []Target{mustParse(t, "k8s://web.prod:80")}}
	u, err := New(cfg, WithEndpointResolver(res), WithOriginFactory(stubOriginFactory))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.Start(ctx)

	// The Watch is registered synchronously inside Start.
	res.mu.Lock()
	w := res.watches
	res.mu.Unlock()
	if w != 1 {
		t.Fatalf("want 1 Watch registration after Start, got %d", w)
	}

	// Cancelling the pool ctx must deregister the Watch (asynchronously).
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		res.mu.Lock()
		c, n := res.cancelled, len(res.onChange)
		res.mu.Unlock()
		if c == 1 && n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Watch was not deregistered on ctx cancel: cancelled=%d remaining=%d", c, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// syncedResolver returns no endpoints until synced flips true, then a fixed set. It
// NEVER fires onChange — modelling the steady-cluster cold start where the informer's
// initial Add events fired (and were dropped) before the pool registered its Watch, so
// the pool must converge off resolveLoop's entry resolve, not a poke or the 30s tick.
type syncedResolver struct {
	mu     sync.Mutex
	synced bool
	eps    []Endpoint
}

func (r *syncedResolver) setSynced(v bool) {
	r.mu.Lock()
	r.synced = v
	r.mu.Unlock()
}

func (r *syncedResolver) ResolveEndpoints(_ context.Context, _, _, _ string) ([]Endpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.synced {
		return nil, nil
	}
	return append([]Endpoint(nil), r.eps...), nil
}

func (r *syncedResolver) Watch(_, _ string, _ func()) func() { return nil } // never pokes

func TestK8sPoolConvergesOnStartWithoutPoke(t *testing.T) {
	res := &syncedResolver{eps: []Endpoint{{IP: "10.0.0.1", Port: 80}, {IP: "10.0.0.2", Port: 80}}}
	cfg := Config{Name: "web", Kind: "upstream", Policy: RoundRobin,
		Backends: []Target{mustParse(t, "k8s://web.prod:80")}}
	// Use a long resolve interval so convergence cannot come from the periodic tick.
	u, err := New(cfg, WithEndpointResolver(res), WithOriginFactory(stubOriginFactory),
		WithResolveInterval(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Construction-time resolveOnce saw an unsynced (empty) cache.
	if backends, _, _ := u.snapshot(); len(backends) != 0 {
		t.Fatalf("want 0 backends before sync, got %d", len(backends))
	}

	// Cache is now warm (mirrors config.Start completing k8s cache sync before pool.Start).
	res.setSynced(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.Start(ctx)

	// The pool must converge to 2 backends off resolveLoop's entry resolve — with no
	// poke (Watch never fires) and no reliance on the 1h tick.
	waitFor(t, 2*time.Second, func() bool {
		backends, _, _ := u.snapshot()
		return len(backends) == 2
	})
}
