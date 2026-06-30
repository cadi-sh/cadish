package lb

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/origin"
)

// recOrigin is an in-memory origin that records calls and returns a canned
// response or error. When err is set it is returned; otherwise a 200 "ok".
type recOrigin struct {
	base  string
	calls *int64
}

func (o *recOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	atomic.AddInt64(o.calls, 1)
	return &origin.Response{
		StatusCode:    200,
		Header:        http.Header{},
		ContentLength: 2,
		Body:          io.NopCloser(strings.NewReader("ok")),
	}, nil
}

// fakeFactory builds recOrigins and shares a per-base call counter map.
func fakeFactory() (OriginFactory, map[string]*int64) {
	counts := map[string]*int64{}
	var mu sync.Mutex
	f := func(baseURL string, _ *Target, _ Timeouts) (origin.Origin, error) {
		mu.Lock()
		c, ok := counts[baseURL]
		if !ok {
			c = new(int64)
			counts[baseURL] = c
		}
		mu.Unlock()
		return &recOrigin{base: baseURL, calls: c}, nil
	}
	return f, counts
}

func staticCfg(t *testing.T, policy Policy, urls ...string) Config {
	t.Helper()
	cfg := Config{Name: "u", Kind: "upstream", Policy: policy}
	for _, u := range urls {
		tgt, err := parseTarget(u, cadishfile.Pos{})
		if err != nil {
			t.Fatalf("parseTarget %q: %v", u, err)
		}
		cfg.Backends = append(cfg.Backends, tgt)
	}
	return cfg
}

func TestPickRoundRobin(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://a:80", "http://b:80", "http://c:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for i := 0; i < 30; i++ {
		b := u.pick(context.Background(), &origin.Request{}, map[string]bool{})
		if b == nil {
			t.Fatal("nil backend")
		}
		seen[b.baseURL]++
	}
	if len(seen) != 3 {
		t.Fatalf("round_robin used %d backends, want 3", len(seen))
	}
	for url, n := range seen {
		if n != 10 {
			t.Errorf("backend %s got %d, want even 10", url, n)
		}
	}
}

// TestPickExcludeBaseURL is the F-B2 backstop: WithExcludeBaseURL makes pick never
// select the excluded backend, even when the shard ring would land on it — so a
// peerorigin read-through can never be dialed back to self regardless of health-flap
// timing between the self-guard and pick.
func TestPickExcludeBaseURL(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, Shard, "http://a:80", "http://b:80")
	cfg.Shard = ShardKeyVal
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	// Find a key the ring assigns to a:80, then exclude it — pick must return b:80.
	var key string
	for i := 0; i < 500; i++ {
		k := "k" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
		if owner, ok := u.Owner(k, false); ok && owner == "http://a:80" {
			key = k
			break
		}
	}
	if key == "" {
		t.Skip("no key mapped to a:80 in the sample")
	}
	base := WithRoutingKey(context.Background(), key)
	if got := u.pick(base, &origin.Request{}, map[string]bool{}); got == nil || got.baseURL != "http://a:80" {
		t.Fatalf("sanity: key should route to a:80, got %v", got)
	}
	excl := WithExcludeBaseURL(base, "http://a:80")
	got := u.pick(excl, &origin.Request{}, map[string]bool{})
	if got == nil || got.baseURL == "http://a:80" {
		t.Fatalf("excluded backend was selected: %v (want b:80)", got)
	}
}

func TestPickLeastConn(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, LeastConn, "http://a:80", "http://b:80", "http://c:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	backends, _, byID := u.snapshot()
	_ = byID
	// Load them unevenly; least_conn must pick the 0-inflight one.
	byURL := map[string]*backend{}
	for _, b := range backends {
		byURL[b.baseURL] = b
	}
	byURL["http://a:80"].inflight.Store(5)
	byURL["http://b:80"].inflight.Store(0)
	byURL["http://c:80"].inflight.Store(3)
	got := u.pick(context.Background(), &origin.Request{}, map[string]bool{})
	if got.baseURL != "http://b:80" {
		t.Fatalf("least_conn picked %s, want b (0 inflight)", got.baseURL)
	}
}

func TestStickyPinAndRehash(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, Sticky, "http://a:80", "http://b:80", "http://c:80", "http://d:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRoutingKey(context.Background(), "user-42")
	first := u.pick(ctx, &origin.Request{}, map[string]bool{})
	if first == nil {
		t.Fatal("nil")
	}
	// Stable pin: same key -> same backend every time.
	for i := 0; i < 20; i++ {
		got := u.pick(ctx, &origin.Request{}, map[string]bool{})
		if got.baseURL != first.baseURL {
			t.Fatalf("sticky not stable: %s vs %s", got.baseURL, first.baseURL)
		}
	}
	// Kill the pinned backend -> rehash to a different, healthy one.
	first.mu.Lock()
	first.fsm.record(false) // window1/threshold1 -> down
	first.mu.Unlock()
	reh := u.pick(ctx, &origin.Request{}, map[string]bool{})
	if reh == nil || reh.baseURL == first.baseURL {
		t.Fatalf("expected rehash off dead backend, got %v", reh)
	}

	// No routing key -> falls back to round-robin (does not panic / nil).
	if b := u.pick(context.Background(), &origin.Request{}, map[string]bool{}); b == nil {
		t.Fatal("sticky w/o key should fall back to RR, got nil")
	}
}

// TestResolveUpgradeHonorsRoutingKey pins Finding 3: a connection-upgrade tunnel
// through a Sticky pool must pin to the SAME backend the Fetch path's pick would,
// reading the routing key from the ctx (lb.WithRoutingKey) instead of falling back to
// round-robin. Before the fix ResolveUpgrade hard-coded context.Background(), so a
// Sticky pool round-robined the tunnel — repeated calls with one key would NOT be
// stable. Uses the default origin factory so the backends are real httporigin
// Upgraders.
func TestResolveUpgradeHonorsRoutingKey(t *testing.T) {
	cfg := staticCfg(t, Sticky, "http://a:80", "http://b:80", "http://c:80", "http://d:80")
	u, err := New(cfg) // default factory -> httporigin origins (real Upgraders)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRoutingKey(context.Background(), "user-42")

	// The Fetch path's canonical pick for this key.
	want := u.pick(ctx, &origin.Request{}, map[string]bool{})
	if want == nil {
		t.Fatal("sticky pick returned nil")
	}
	wantHost := strings.TrimPrefix(want.baseURL, "http://")

	tgt, err := u.ResolveUpgrade(ctx, &origin.Request{})
	if err != nil {
		t.Fatalf("ResolveUpgrade: %v", err)
	}
	if tgt.URL == nil {
		t.Fatal("ResolveUpgrade returned nil URL")
	}
	if tgt.URL.Host != wantHost {
		t.Fatalf("upgrade tunnel pinned to %s, want %s (must match the Fetch pick for the sticky key)", tgt.URL.Host, wantHost)
	}

	// Stability: the same key always targets the same backend (would round-robin across
	// the 4 backends without the key being threaded through).
	for i := 0; i < 20; i++ {
		got, err := u.ResolveUpgrade(ctx, &origin.Request{})
		if err != nil {
			t.Fatalf("ResolveUpgrade iter %d: %v", i, err)
		}
		if got.URL.Host != wantHost {
			t.Fatalf("sticky upgrade not stable: iter %d got %s, want %s (routing key not honored)", i, got.URL.Host, wantHost)
		}
	}
}

func TestShardByURL(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, Shard, "http://a:80", "http://b:80", "http://c:80")
	cfg.Shard = ShardURL
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	// Same URL key -> same backend, regardless of (ignored) routing key.
	r := &origin.Request{Key: "videos/clip.mp4"}
	base := u.pick(context.Background(), r, map[string]bool{}).baseURL
	for i := 0; i < 10; i++ {
		ctx := WithRoutingKey(context.Background(), "ignored-different-each-time")
		if got := u.pick(ctx, r, map[string]bool{}).baseURL; got != base {
			t.Fatalf("shard_by url unstable: %s vs %s", got, base)
		}
	}
	// A different URL may land elsewhere (at least it must resolve).
	if u.pick(context.Background(), &origin.Request{Key: "other/object"}, map[string]bool{}) == nil {
		t.Fatal("nil for second url")
	}
}

// fakeResolver returns a controllable address set.
type fakeResolver struct {
	mu    sync.Mutex
	addrs []string
}

func (r *fakeResolver) set(a ...string) {
	r.mu.Lock()
	r.addrs = a
	r.mu.Unlock()
}

func (r *fakeResolver) Resolve(ctx context.Context, host string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.addrs))
	copy(out, r.addrs)
	return out, nil
}

func TestDynamicResolution(t *testing.T) {
	factory, _ := fakeFactory()
	res := &fakeResolver{}
	res.set("10.0.0.1", "10.0.0.2")
	cfg := staticCfg(t, RoundRobin, "dns://svc:8080")
	u, err := New(cfg, WithOriginFactory(factory), WithResolver(res))
	if err != nil {
		t.Fatal(err)
	}
	backends, _, _ := u.snapshot()
	if len(backends) != 2 {
		t.Fatalf("initial backends = %d, want 2", len(backends))
	}
	// Capture the .1 backend pointer to confirm it's preserved across
	// re-resolution (it survives the membership change).
	const keepID = "dns://svc:8080|10.0.0.1"
	keep := map[string]*backend{}
	for _, b := range backends {
		keep[b.id] = b
	}
	if keep[keepID] == nil {
		t.Fatalf("expected backend %s in initial set", keepID)
	}

	// New record set: drop .2, add .3.
	res.set("10.0.0.1", "10.0.0.3")
	u.resolveOnce(context.Background())
	backends, _, byID := u.snapshot()
	if len(backends) != 2 {
		t.Fatalf("after re-resolve backends = %d, want 2", len(backends))
	}
	// .1 endpoint must be the SAME pointer (state preserved).
	if byID[keepID] != keep[keepID] {
		t.Errorf("backend %s not preserved across re-resolution", keepID)
	}
	// .3 must now exist; .2 must be gone.
	if _, ok := byID["dns://svc:8080|10.0.0.3"]; !ok {
		t.Error("new address 10.0.0.3 not added")
	}
	if _, ok := byID["dns://svc:8080|10.0.0.2"]; ok {
		t.Error("removed address 10.0.0.2 still present")
	}
}

func TestDynamicResolutionFailureKeepsBackends(t *testing.T) {
	factory, _ := fakeFactory()
	res := &errResolver{addrs: []string{"10.0.0.1"}}
	cfg := staticCfg(t, RoundRobin, "dns://svc:8080")
	u, err := New(cfg, WithOriginFactory(factory), WithResolver(res))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(mustBackends(u)); n != 1 {
		t.Fatalf("initial = %d, want 1", n)
	}
	res.fail = true
	u.resolveOnce(context.Background())
	if n := len(mustBackends(u)); n != 1 {
		t.Fatalf("after failed resolve = %d, want 1 (retained)", n)
	}
}

type errResolver struct {
	addrs []string
	fail  bool
}

func (r *errResolver) Resolve(ctx context.Context, host string) ([]string, error) {
	if r.fail {
		return nil, errors.New("dns boom")
	}
	return r.addrs, nil
}

func mustBackends(u *Upstream) []*backend {
	b, _, _ := u.snapshot()
	return b
}

// --- End-to-end against httptest backends ---------------------------------

func TestFetchFailoverEndToEnd(t *testing.T) {
	var bad, good int64
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&bad, 1)
		w.WriteHeader(500)
	}))
	defer badSrv.Close()
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&good, 1)
		_, _ = io.WriteString(w, "hello")
	}))
	defer goodSrv.Close()

	cfg := staticCfg(t, RoundRobin, badSrv.URL, goodSrv.URL)
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Try several times; every request must end up at the good server (failover
	// past the 500).
	for i := 0; i < 6; i++ {
		resp, err := u.Fetch(context.Background(), &origin.Request{Key: "/x"})
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello" {
			t.Fatalf("body = %q, want hello", body)
		}
	}
	if atomic.LoadInt64(&good) < 6 {
		t.Errorf("good server hit %d times, want >=6", good)
	}
}

// countingBody is a recording ReadCloser standing in for a streamed client
// request body. It records whether it was read/closed (the way net/http drains
// a request body on the first send), so a test can assert the body is not
// replayed to a second backend.
type countingBody struct {
	reads  int64
	closes int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	atomic.AddInt64(&b.reads, 1)
	return 0, io.EOF
}

func (b *countingBody) Close() error {
	atomic.AddInt64(&b.closes, 1)
	return nil
}

// TestFetchNoFailoverForBodyRequest verifies that a request carrying a body
// (a non-idempotent write whose streamed body is consumed by the first attempt
// and is not replayable) does NOT fail over to a second backend: the first
// backend's 503 is surfaced and the second backend is never tried. The
// companion GET (no body) DOES fail over — failover for safe/idempotent reads
// is unchanged.
func TestFetchNoFailoverForBodyRequest(t *testing.T) {
	var bad, good int64
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&bad, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(503)
	}))
	defer badSrv.Close()
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&good, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "hello")
	}))
	defer goodSrv.Close()

	// Sticky policy with a fixed routing key so the FIRST pick is deterministic
	// (the bad server). RoundRobin would not guarantee bad is picked first.
	cfg := staticCfg(t, Sticky, badSrv.URL, goodSrv.URL)
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRoutingKey(context.Background(), "k")

	// Discover which server the routing key picks first by issuing one GET; the
	// no-body GET will fail over so both may be hit. Instead, assert behavior
	// directly: POST with a body must hit exactly one backend total.
	body := &countingBody{}
	resp, err := u.Fetch(ctx, &origin.Request{
		Method:        http.MethodPost,
		Key:           "/p",
		Body:          body,
		ContentLength: -1,
	})
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	totalFirst := atomic.LoadInt64(&bad) + atomic.LoadInt64(&good)
	if totalFirst != 1 {
		t.Fatalf("body request hit %d backends, want exactly 1 (no failover); bad=%d good=%d", totalFirst, bad, good)
	}
	// If the first pick was the bad backend, the 503 must surface as an error and
	// the good backend must NOT have been tried.
	if atomic.LoadInt64(&bad) == 1 {
		if err == nil {
			t.Fatalf("body request to 503 backend: want error, got nil")
		}
		if origin.StatusOf(err) != 503 {
			t.Fatalf("body request error StatusOf = %d, want 503", origin.StatusOf(err))
		}
		if atomic.LoadInt64(&good) != 0 {
			t.Fatalf("body request failed over to good backend (good=%d), want no failover", good)
		}
	}

	// Companion: a GET (no body) to a pool whose first pick is the bad backend
	// must fail over to good and succeed — unchanged behavior.
	atomic.StoreInt64(&bad, 0)
	atomic.StoreInt64(&good, 0)
	for i := 0; i < 6; i++ {
		gresp, gerr := u.Fetch(context.Background(), &origin.Request{Key: "/x"})
		if gerr != nil {
			t.Fatalf("GET Fetch: %v", gerr)
		}
		b, _ := io.ReadAll(gresp.Body)
		gresp.Body.Close()
		if string(b) != "hello" {
			t.Fatalf("GET body = %q, want hello (failover unchanged)", b)
		}
	}
	if atomic.LoadInt64(&good) < 6 {
		t.Errorf("GET failover broken: good hit %d times, want >=6", good)
	}
}

func TestFetchAllDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()
	cfg := staticCfg(t, RoundRobin, srv.URL)
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.Fetch(context.Background(), &origin.Request{Key: "/x"})
	if err == nil {
		t.Fatal("expected error when all backends 5xx")
	}
	if origin.StatusOf(err) != 503 {
		t.Errorf("StatusOf = %d, want 503", origin.StatusOf(err))
	}
}

func TestFetchStickyRoutesByKey(t *testing.T) {
	hits := make([]int64, 2)
	mk := func(i int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&hits[i], 1)
			_, _ = io.WriteString(w, "ok")
		}))
	}
	s0, s1 := mk(0), mk(1)
	defer s0.Close()
	defer s1.Close()

	cfg := staticCfg(t, Sticky, s0.URL, s1.URL)
	u, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithRoutingKey(context.Background(), "session-abc")
	for i := 0; i < 12; i++ {
		resp, err := u.Fetch(ctx, &origin.Request{Key: "/p"})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// All 12 requests for one key must hit exactly one backend.
	if (hits[0] == 12) == (hits[1] == 12) {
		t.Fatalf("sticky split traffic: hits=%v (want all on one)", hits)
	}
}

// --- Passive ejection & capacity ------------------------------------------

// failOrigin always returns a 5xx StatusError.
type failOrigin struct{}

func (failOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	return nil, &origin.StatusError{Status: 500, Origin: "fake"}
}

func TestPassiveEjection(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	factory := func(string, *Target, Timeouts) (origin.Origin, error) { return failOrigin{}, nil }

	cfg := staticCfg(t, RoundRobin, "http://a:80")
	u, err := New(cfg,
		WithOriginFactory(factory),
		WithClock(clock),
		WithPassiveEjection(3, 30*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	b := mustBackends(u)[0]
	if !b.eligible(now) {
		t.Fatal("should start eligible")
	}
	// Three failing Fetches -> ejected.
	for i := 0; i < 3; i++ {
		_, ferr := u.Fetch(context.Background(), &origin.Request{Key: "/x"})
		if ferr == nil {
			t.Fatal("expected failure")
		}
	}
	if b.eligible(now) {
		t.Fatal("backend should be ejected after 3 consecutive failures")
	}
	// After the ejection window passes, it's eligible again.
	now = now.Add(31 * time.Second)
	if !b.eligible(now) {
		t.Fatal("backend should recover after ejection window")
	}
}

// compile-time proof that an Upstream IS an origin.Origin.
var _ origin.Origin = (*Upstream)(nil)

func TestActiveHealthGatesTraffic(t *testing.T) {
	factory, _ := fakeFactory()
	doer := &fakeDoer{status: 200}
	cfg := staticCfg(t, RoundRobin, "http://a:80", "http://b:80")
	cfg.Health = &HealthSpec{Method: "GET", Path: "/", ExpectCode: 200, Interval: time.Hour, Window: 2, Threshold: 2}
	u, err := New(cfg, WithOriginFactory(factory), WithProbeDoer(doer))
	if err != nil {
		t.Fatal(err)
	}
	// With active health configured, backends start DOWN -> no traffic yet.
	if _, err := u.Fetch(context.Background(), &origin.Request{Key: "/x"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("expected ErrNoBackend before probing, got %v", err)
	}
	// Two successful probe rounds (threshold 2 in window 2) -> all backends up.
	u.probeAll(context.Background())
	u.probeAll(context.Background())
	for _, b := range mustBackends(u) {
		if !b.eligible(time.Now()) {
			t.Fatalf("backend %s still down after 2 good probes", b.baseURL)
		}
	}
	resp, err := u.Fetch(context.Background(), &origin.Request{Key: "/x"})
	if err != nil {
		t.Fatalf("Fetch after probes: %v", err)
	}
	resp.Body.Close()

	// Probes start failing -> backends go DOWN -> traffic gated again.
	doer.set(500, nil)
	u.probeAll(context.Background())
	u.probeAll(context.Background())
	if _, err := u.Fetch(context.Background(), &origin.Request{Key: "/x"}); !errors.Is(err, ErrNoBackend) {
		t.Fatalf("expected ErrNoBackend after backends fail health, got %v", err)
	}
}

func TestMaxConnsCapacity(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://a:80")
	cfg.MaxConns = 1
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	// First Fetch holds inflight by NOT closing its body.
	resp1, err := u.Fetch(context.Background(), &origin.Request{Key: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	// Second Fetch: only backend is at capacity -> ErrNoBackend.
	_, err = u.Fetch(context.Background(), &origin.Request{Key: "/y"})
	if !errors.Is(err, ErrNoBackend) && !errors.Is(err, errAtCapacity) {
		t.Fatalf("expected capacity error, got %v", err)
	}
	// Release capacity; next Fetch succeeds.
	resp1.Body.Close()
	resp3, err := u.Fetch(context.Background(), &origin.Request{Key: "/z"})
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	resp3.Body.Close()
}

func TestK8sPokeReresolves(t *testing.T) {
	res := newFakeEndpointResolver()
	res.set("web", "prod", []Endpoint{{IP: "10.0.0.1", Port: 80}})
	cfg := Config{Name: "web", Kind: "upstream", Policy: RoundRobin,
		Backends: []Target{mustParse(t, "k8s://web.prod:80")}}
	u, err := New(cfg, WithEndpointResolver(res), WithOriginFactory(stubOriginFactory))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.Start(ctx)

	// Scale up: add a second pod and fire the change callback.
	res.set("web", "prod", []Endpoint{{IP: "10.0.0.1", Port: 80}, {IP: "10.0.0.2", Port: 80}})

	// The poke should drive a re-resolve to 2 backends well under the 30s timer.
	waitFor(t, 2*time.Second, func() bool {
		backends, _, _ := u.snapshot()
		return len(backends) == 2
	})
}

// statusOrigin always returns a *StatusError with a fixed status, for asserting the
// passive-ejection FSM's status classification.
type statusOrigin struct{ code int }

func (s statusOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	return nil, &origin.StatusError{Status: s.code, Origin: "fake"}
}

// TestPassiveEjectionIgnores4xx pins the recordOutcome classification: a RETURNED 4xx
// (403/404/429 — the backend answered fine, the client/request is at fault) must NOT
// extend the passive-failure streak, so no number of 4xx answers ejects the backend.
// Only transport errors (StatusOf==0) and 5xx (the backend itself failing) do — the
// complement of TestPassiveEjection, which ejects on a returned 500.
func TestPassiveEjectionIgnores4xx(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests} {
		now := time.Unix(1000, 0)
		clock := func() time.Time { return now }
		factory := func(string, *Target, Timeouts) (origin.Origin, error) { return statusOrigin{code}, nil }
		cfg := staticCfg(t, RoundRobin, "http://a:80")
		u, err := New(cfg, WithOriginFactory(factory), WithClock(clock), WithPassiveEjection(3, 30*time.Second))
		if err != nil {
			t.Fatalf("%d: New: %v", code, err)
		}
		b := mustBackends(u)[0]
		// Far more than the threshold of consecutive 4xx answers.
		for i := 0; i < 10; i++ {
			if _, ferr := u.Fetch(context.Background(), &origin.Request{Key: "/x"}); ferr == nil {
				t.Fatalf("%d: expected the 4xx surfaced as an error", code)
			}
		}
		if !b.eligible(now) {
			t.Fatalf("%d: backend ejected after 4xx answers — a 4xx must not penalize backend health", code)
		}
	}
}
