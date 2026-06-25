package config

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/lb"
)

// --- A k8s client fake that models informer freeze-on-close --------------------
//
// A config-owned k8s client's informer reflects live pod churn and fires Watch
// pokes ONLY while running; once Close()d (torn down after a reload swap) it serves
// a frozen snapshot and never pokes again. This is exactly the lifecycle a
// transplanted-onto-a-dying-client pool would get stuck on, so the harness lets a
// test prove the live pool keeps resolving through a LIVE client after a reload.

type k8sHarness struct {
	mu      sync.Mutex
	eps     map[string][]lb.Endpoint // live shared endpoints, "svc/ns"
	clients []*fakeChurnClient       // every client the factory built, in order
}

func newK8sHarness() *k8sHarness { return &k8sHarness{eps: map[string][]lb.Endpoint{}} }

func (h *k8sHarness) newClient() *fakeChurnClient {
	c := &fakeChurnClient{h: h, cbs: map[string]func(){}}
	h.mu.Lock()
	h.clients = append(h.clients, c)
	h.mu.Unlock()
	return c
}

// setEndpoints updates the live shared set and pokes every LIVE client's watchers.
func (h *k8sHarness) setEndpoints(svc, ns string, eps []lb.Endpoint) {
	h.mu.Lock()
	h.eps[svc+"/"+ns] = eps
	clients := append([]*fakeChurnClient(nil), h.clients...)
	h.mu.Unlock()
	for _, c := range clients {
		c.poke(svc, ns)
	}
}

func (h *k8sHarness) liveSet(svc, ns string) []lb.Endpoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]lb.Endpoint(nil), h.eps[svc+"/"+ns]...)
}

func (h *k8sHarness) snapshot() map[string][]lb.Endpoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string][]lb.Endpoint, len(h.eps))
	for k, v := range h.eps {
		out[k] = append([]lb.Endpoint(nil), v...)
	}
	return out
}

type fakeChurnClient struct {
	h       *k8sHarness
	mu      sync.Mutex
	closed  bool
	started bool
	frozen  map[string][]lb.Endpoint // snapshot captured at Close
	cbs     map[string]func()        // "svc/ns" -> pool poke
}

// fakeChurnClient is both the config.k8sClient and the lb.EndpointResolver.
func (c *fakeChurnClient) Resolver() lb.EndpointResolver { return c }
func (c *fakeChurnClient) Start(context.Context) error {
	c.mu.Lock()
	c.started = true
	c.mu.Unlock()
	return nil
}
func (c *fakeChurnClient) Close() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.frozen = c.h.snapshot() // informer stops: serve the last-seen set forever
	}
	c.mu.Unlock()
}

func (c *fakeChurnClient) ResolveEndpoints(_ context.Context, svc, ns, _ string) ([]lb.Endpoint, error) {
	key := svc + "/" + ns
	c.mu.Lock()
	closed, frozen := c.closed, c.frozen
	c.mu.Unlock()
	if closed {
		return append([]lb.Endpoint(nil), frozen[key]...), nil
	}
	return c.h.liveSet(svc, ns), nil
}

func (c *fakeChurnClient) Watch(svc, ns string, onChange func()) func() {
	c.mu.Lock()
	c.cbs[svc+"/"+ns] = onChange
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.cbs, svc+"/"+ns)
		c.mu.Unlock()
	}
}

func (c *fakeChurnClient) poke(svc, ns string) {
	c.mu.Lock()
	closed, cb := c.closed, c.cbs[svc+"/"+ns]
	c.mu.Unlock()
	if !closed && cb != nil {
		cb() // a stopped informer never pokes
	}
}

func (c *fakeChurnClient) isClosed() bool  { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
func (c *fakeChurnClient) isStarted() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.started }

func waitEndpoints(t *testing.T, u *lb.Upstream, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(u.Endpoints()) == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pool %q endpoints = %d, want %d", u.Name(), len(u.Endpoints()), n)
}

// TestTransplantPoolsFrom_ConfigOwnedK8sStaysLive proves the CRITICAL invariant: for
// the config-owned k8s client case (`cadish run` + SIGHUP, old.k8s != nil), a reload
// does NOT transplant a k8s:// pool onto the dying old client — the surviving k8s pool
// keeps resolving through a LIVE client and sees pod churn AFTER the reload, the old
// client is closed, and no client is left orphaned. A sibling NON-k8s pool still
// transplants (no over-rebuild). Fails before the scoped-rebuild fix, passes after.
func TestTransplantPoolsFrom_ConfigOwnedK8sStaysLive(t *testing.T) {
	h := newK8sHarness()
	h.setEndpoints("web", "prod", []lb.Endpoint{{IP: "10.0.0.1", Port: 8080}})
	restore := swapK8sFactory(func(k8s.Options) (k8sClient, error) { return h.newClient(), nil })
	defer restore()

	// A k8s:// pool plus an unrelated DNS/static multi-backend pool in the same site.
	const src = `site.local {
	upstream kpool { to k8s://web.prod:8080 }
	upstream dnspool {
		to http://a1:80
		to http://a2:80
	}
}
`
	old, err := LoadString("<old>", src)
	if err != nil {
		t.Fatalf("load old: %v", err)
	}
	if old.k8s == nil {
		t.Fatal("expected a config-owned k8s client (old.k8s != nil)")
	}
	ctxOld, cancelOld := context.WithCancel(context.Background())
	defer cancelOld()
	if err := old.Start(ctxOld); err != nil {
		t.Fatalf("start old: %v", err)
	}
	waitEndpoints(t, poolByName(old, "kpool"), 1)
	oldDNS := poolByName(old, "dnspool")

	// Reload with the SAME pools (kpool's fingerprint is unchanged — pre-fix this would
	// transplant it onto the dying old client).
	next, err := LoadString("<next>", src)
	if err != nil {
		t.Fatalf("load next: %v", err)
	}
	next.TransplantPoolsFrom(old)

	// The non-k8s pool transplants (same instance); the k8s pool is rebuilt (the new,
	// cold instance bound to next's fresh client).
	if poolByName(next, "dnspool") != oldDNS {
		t.Error("non-k8s dnspool must be transplanted (same instance)")
	}
	if poolByName(next, "kpool") == poolByName(old, "kpool") {
		t.Error("k8s kpool must be rebuilt, not transplanted onto the dying old client")
	}

	ctxNext, cancelNext := context.WithCancel(context.Background())
	defer cancelNext()
	if err := next.Start(ctxNext); err != nil {
		t.Fatalf("start next: %v", err)
	}
	kNext := poolByName(next, "kpool")
	waitEndpoints(t, kNext, 1)

	// Tear down the old config (closes old's k8s client) — exactly the post-swap teardown.
	if err := old.CloseExcept(nil); err != nil {
		t.Fatalf("close old: %v", err)
	}

	// Pod churn AFTER the reload+teardown: scale web.prod to 2 endpoints.
	h.setEndpoints("web", "prod", []lb.Endpoint{
		{IP: "10.0.0.1", Port: 8080},
		{IP: "10.0.0.2", Port: 8080},
	})

	// The live pool must re-resolve to 2 — proving it uses a LIVE client, not the closed
	// old one (this is the assertion that fails before the fix).
	waitEndpoints(t, kNext, 2)

	// Exactly two clients built; the old one closed, the live one open + started (no
	// orphaned/leaked client).
	if len(h.clients) != 2 {
		t.Fatalf("want exactly 2 k8s clients built, got %d", len(h.clients))
	}
	if !h.clients[0].isClosed() {
		t.Error("old k8s client must be closed after the reload")
	}
	if h.clients[1].isClosed() {
		t.Error("the live k8s client must NOT be closed (it backs the surviving pool)")
	}
	if !h.clients[1].isStarted() {
		t.Error("the live k8s client must be started")
	}
}
