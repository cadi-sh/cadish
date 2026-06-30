package peerorigin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/chain"
)

// hopHeader mirrors cluster.HopHeader without importing internal/cluster (which
// imports this package — an import cycle in test scope).
const hopHeader = "X-Cadish-Peer"

// peerPool builds a shard-by-key lb.Upstream over the given static peer URLs.
func peerPool(t *testing.T, urls ...string) *lb.Upstream {
	t.Helper()
	return peerPoolOpts(t, nil, urls...)
}

// peerPoolOpts is peerPool with extra lb options (e.g. tightened passive ejection).
func peerPoolOpts(t *testing.T, opts []lb.Option, urls ...string) *lb.Upstream {
	t.Helper()
	cfg := lb.Config{Name: "peers", Kind: "cluster", Policy: lb.Shard, Shard: lb.ShardKeyVal}
	for i, u := range urls {
		tg, err := lb.ParseTarget(u, cadishfile.Pos{File: "test", Line: i + 1})
		if err != nil {
			t.Fatalf("target %q: %v", u, err)
		}
		cfg.Backends = append(cfg.Backends, tg)
	}
	up, err := lb.New(cfg, opts...)
	if err != nil {
		t.Fatalf("lb.New: %v", err)
	}
	return up
}

func TestFetch_PeerHit(t *testing.T) {
	var gotHop string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHop = r.Header.Get(hopHeader)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "from-peer")
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	resp, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from-peer" {
		t.Errorf("body = %q", body)
	}
	if gotHop != "gra" {
		t.Errorf("hop header = %q, want gra (loop guard must be stamped)", gotHop)
	}
}

// TestFetch_WriteSkipsPeer is the F-B1 regression: a write method (or any request with a
// body) must NOT be read-through-routed to a peer — it surfaces ErrNotFound so the chain
// serves it from the real origin locally, avoiding the consumed-body / dead-peer-502 hazard.
func TestFetch_WriteSkipsPeer(t *testing.T) {
	var hit bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = io.WriteString(w, "peer")
	}))
	defer peer.Close()
	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")

	// POST method.
	if _, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj", Method: "POST"}); err != origin.ErrSkip {
		t.Errorf("POST Fetch = %v, want ErrSkip (no-op decline → chain falls through to real origin even with a body)", err)
	}
	// Body present (even with empty method, treated as a write).
	if _, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj", Body: io.NopCloser(strings.NewReader("x"))}); err != origin.ErrSkip {
		t.Errorf("body Fetch = %v, want ErrSkip", err)
	}
	if hit {
		t.Error("a write was dialed to the peer — writes must not be read-through-routed")
	}
}

// recordingOrigin records the last request body it received and returns 200.
type recordingOrigin struct {
	gotBody string
	hit     bool
}

func (o *recordingOrigin) Fetch(_ context.Context, req *origin.Request) (*origin.Response, error) {
	o.hit = true
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		o.gotBody = string(b)
	}
	return &origin.Response{StatusCode: 200, Header: http.Header{}, ContentLength: 2, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

// TestChain_WriteFallsThroughPeerToOrigin is the F-C regression: a write-with-body in a
// read-through chain [PeerOrigin, realOrigin] must reach the REAL origin with its body
// intact — PeerOrigin declines via ErrSkip (not ErrNotFound), so the chain falls through
// even though req.Body != nil, instead of 404ing the write (silent data loss).
func TestChain_WriteFallsThroughPeerToOrigin(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("peer must NOT be dialed for a write")
	}))
	defer peer.Close()
	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	def := &recordingOrigin{}
	ch, err := chain.New([]origin.Origin{po, def})
	if err != nil {
		t.Fatalf("chain.New: %v", err)
	}
	const payload = "the write body that must reach origin"
	resp, err := ch.Fetch(context.Background(), &origin.Request{
		Key: "/api/order", Method: "POST", Body: io.NopCloser(strings.NewReader(payload)),
	})
	if err != nil {
		t.Fatalf("chain.Fetch(POST) = %v, want success via the real origin", err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if !def.hit {
		t.Fatal("the real origin was never reached — the write was dropped (404), not served")
	}
	if def.gotBody != payload {
		t.Errorf("origin received body %q, want the full %q", def.gotBody, payload)
	}
}

func TestFetch_BypassSkipsPeer(t *testing.T) {
	// A `pass`/credential-bypass request (req.Bypass) must NEVER hit the peer: the
	// response is never stored, so a read-through is pure wasted latency. Fetch must
	// surface ErrNotFound (chain falls through to the real origin) without dialing the
	// peer at all.
	var peerHit bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerHit = true
		_, _ = io.WriteString(w, "from-peer")
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	_, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj", Bypass: true})
	if err != origin.ErrSkip {
		t.Fatalf("Bypass: got err %v, want ErrSkip (fall through to real origin)", err)
	}
	if peerHit {
		t.Fatal("Bypass: peer was dialed; a pass must go straight to origin, not hop to a peer")
	}
}

func TestFetch_PeerMissFallsThrough(t *testing.T) {
	// A peer that 404s any unknown key must surface ErrNotFound so a chain falls
	// through to the real origin (read-through is opportunistic, never terminal).
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A peer that already sees the hop header must NOT have it (this peer is the
		// one being asked); but it returns 404 for the miss.
		http.NotFound(w, r)
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	_, err := po.Fetch(context.Background(), &origin.Request{Key: "/missing"})
	if err == nil {
		t.Fatal("expected an error (peer miss), got nil")
	}
	if origin.StatusOf(err) != http.StatusNotFound {
		t.Errorf("StatusOf = %d, want 404", origin.StatusOf(err))
	}
}

func TestFetch_NoEligiblePeer(t *testing.T) {
	// With a peer pool that resolves to nothing usable, Fetch returns a
	// connection-class error (StatusOf == 0) so the chain falls through.
	po := New(peerPool(t, "http://127.0.0.1:1"), hopHeader, "gra", "")
	_, err := po.Fetch(context.Background(), &origin.Request{Key: "/x"})
	if err == nil {
		t.Fatal("expected an error")
	}
}

// The peer fetch must route by the cache key (shard), so the same key always
// targets the same peer — verified indirectly by the hop header presence and a
// 2-peer pool returning distinct bodies per owner.
func TestFetch_RoutesByKey(t *testing.T) {
	mk := func(tag string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, tag+":"+r.URL.Path)
		}))
	}
	a, b := mk("A"), mk("B")
	defer a.Close()
	defer b.Close()
	po := New(peerPool(t, a.URL, b.URL), hopHeader, "gra", "")

	seen := map[string]string{}
	for _, key := range []string{"/one", "/two", "/three", "/four"} {
		resp, err := po.Fetch(context.Background(), &origin.Request{Key: key})
		if err != nil {
			t.Fatalf("Fetch %s: %v", key, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		seen[key] = string(body)
		if !strings.HasSuffix(string(body), key) {
			t.Errorf("key %s body %q missing path", key, body)
		}
	}
	// A given key is deterministic: re-fetch lands on the same peer/body.
	resp, _ := po.Fetch(context.Background(), &origin.Request{Key: "/one"})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != seen["/one"] {
		t.Errorf("non-deterministic routing for /one: %q vs %q", body, seen["/one"])
	}
}

// TestFetch_UnhealthyOwnerSuccessorSelfServesLocally is the S2 regression: the
// read-through self-guard must resolve the owner HEALTH-AWARE, matching where
// Fetch actually routes. When the TOPOLOGICAL owner of a key is unhealthy/ejected
// and the next eligible node on the ring is self, the old guard (Owner(key,false))
// would pass, Fetch would dial self, and the self-dialed request would coalesce
// against the in-flight winner — a herd-stalling self-fetch. With Owner(key,true)
// the guard fires and we serve locally (ErrNotFound) instead of dialing ourselves.
func TestFetch_UnhealthyOwnerSuccessorSelfServesLocally(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	self := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		_, _ = io.WriteString(w, "from-self")
	}))
	defer self.Close()

	const dead = "http://127.0.0.1:1" // unreachable → conn-refused on dial
	// Threshold 1 + long eject window: a single failed dial ejects the dead peer
	// for the rest of the test, so it stays the topological owner but ineligible.
	pool := peerPoolOpts(t, []lb.Option{lb.WithPassiveEjection(1, time.Hour)}, self.URL, dead)
	po := New(pool, hopHeader, "gra", self.URL)

	// Find a key whose TOPOLOGICAL owner is the dead peer (so once dead is ejected,
	// the health-aware owner walks the ring to self).
	var key string
	for i := 0; i < 2000; i++ {
		k := "/k" + strconv.Itoa(i)
		if owner, ok := pool.Owner(k, false); ok && owner == dead {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatal("could not find a key topologically owned by the dead peer")
	}

	// Prime the ejection: route a (different) dead-owned key straight through the
	// pool so the conn-refused failure ejects the dead peer. Fail over lands on self.
	var prime string
	for i := 2000; i < 4000; i++ {
		k := "/p" + strconv.Itoa(i)
		if owner, ok := pool.Owner(k, false); ok && owner == dead && k != key {
			prime = k
			break
		}
	}
	if prime == "" {
		t.Fatal("could not find a prime key topologically owned by the dead peer")
	}
	primeCtx := lb.WithRoutingKey(context.Background(), prime)
	if resp, err := pool.Fetch(primeCtx, &origin.Request{Key: prime}); err == nil && resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// Sanity: dead is now ineligible, so the health-aware owner of `key` is self.
	if owner, ok := pool.Owner(key, true); !ok || owner != self.URL {
		t.Fatalf("after ejection, health-aware owner of %q = %q (ok=%v), want self %q", key, owner, ok, self.URL)
	}

	// The guarded read-through must serve locally (ErrSkip), NOT dial self.
	_, err := po.Fetch(context.Background(), &origin.Request{Key: key})
	if err != origin.ErrSkip {
		t.Fatalf("Fetch(%q) = %v, want ErrSkip (serve locally, no self-dial)", key, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits[key] > 0 {
		t.Fatalf("self was dialed for %q (%d hits) — self-fetch not prevented", key, hits[key])
	}
}
