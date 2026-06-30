package lb

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
)

// ErrNoBackend is returned by Fetch when no eligible backend could serve the
// request (all unhealthy, ejected, at capacity, or already tried). The origin
// chain above an Upstream treats it as a connection-class failure (StatusOf ⇒ 0)
// and may fall through to another origin.
var ErrNoBackend = errors.New("lb: no eligible backend")

// errAtCapacity is an internal, retriable signal that a chosen backend hit its
// max_conns ceiling in the window between selection and acquisition.
var errAtCapacity = errors.New("lb: backend at capacity")

// Default passive-ejection tuning: after this many consecutive
// connection/5xx failures a backend is ejected for ejectDuration. Kept simple
// per the M7 spec.
const (
	defaultPassiveThreshold = 5
	defaultEjectDuration    = 30 * time.Second
)

// OriginFactory builds the per-backend origin.Origin used to fetch from one
// resolved endpoint. The default builds an httporigin.Origin whose HTTP client
// honors the upstream's connect/first_byte timeouts. Tests inject a factory that
// returns an in-memory or httptest-backed origin.
type OriginFactory func(baseURL string, target *Target, timeouts Timeouts) (origin.Origin, error)

// backend is one resolved endpoint: an origin client plus its health, capacity,
// and passive-ejection state. All mutable health/ejection fields are guarded by
// mu; inflight is a lock-free counter.
type backend struct {
	id      string
	baseURL string
	target  *Target
	origin  origin.Origin

	inflight atomic.Int64
	sem      chan struct{} // capacity semaphore; nil when max_conns == 0

	mu         sync.Mutex
	fsm        *healthFSM
	consecFail int
	ejectUntil time.Time
}

func (b *backend) eligible(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.fsm.healthy() {
		return false
	}
	return !b.ejectUntil.After(now)
}

func (b *backend) underCap(max int) bool {
	return max == 0 || b.inflight.Load() < int64(max)
}

func (b *backend) passiveSuccess() {
	b.mu.Lock()
	b.consecFail = 0
	b.ejectUntil = time.Time{}
	b.mu.Unlock()
}

func (b *backend) passiveFailure(threshold int, now time.Time, dur time.Duration) {
	b.mu.Lock()
	b.consecFail++
	if b.consecFail >= threshold {
		b.ejectUntil = now.Add(dur)
	}
	b.mu.Unlock()
}

// Upstream is a named pool of backends that implements origin.Origin. It selects
// one healthy backend per request according to its policy, delegates the fetch,
// and records the outcome for passive ejection. Construct with New; call Start to
// run background health probing and dynamic re-resolution.
type Upstream struct {
	cfg Config

	// state is replaced wholesale (new slices/maps/ring) under stateMu on every
	// reconcile, so readers take a cheap snapshot and then run lock-free.
	stateMu  sync.RWMutex
	backends []*backend
	byID     map[string]*backend
	ring     *ring

	rr atomic.Uint64 // round-robin cursor

	// inflight is a lock-free POOL-level count of requests currently being served by
	// this upstream (incremented when a fetch acquires a backend, decremented when the
	// caller closes the response body). It is the sum of the per-backend counters but
	// kept separately so a removed pool's drain (server.stopRemovedPools) can wait for
	// the whole pool to quiesce without walking — and racing — the live backend set.
	inflight atomic.Int64

	resolver         Resolver
	endpointResolver EndpointResolver // non-nil only when a k8s:// target is present
	newOrigin        OriginFactory
	probeDoer        Doer
	now              func() time.Time
	resolveInterval  time.Duration

	passiveThreshold int
	ejectDuration    time.Duration

	poke chan struct{} // buffered(1); a k8s endpoint change signals a re-resolve

	startOnce sync.Once
}

// Option configures an Upstream.
type Option func(*Upstream)

// WithResolver overrides the DNS resolver for dns:// / k8s:// targets (tests
// inject a deterministic fake).
func WithResolver(r Resolver) Option { return func(u *Upstream) { u.resolver = r } }

// WithEndpointResolver injects the Kubernetes EndpointResolver used for k8s://
// targets (internal/k8s supplies the real one; tests inject a fake). Absent it, a
// k8s:// pool resolves to no endpoints.
func WithEndpointResolver(r EndpointResolver) Option {
	return func(u *Upstream) { u.endpointResolver = r }
}

// WithOriginFactory overrides how per-backend origins are built (tests return an
// in-memory or httptest-backed origin instead of a live httporigin).
func WithOriginFactory(f OriginFactory) Option { return func(u *Upstream) { u.newOrigin = f } }

// WithProbeDoer overrides the HTTP client used by active health probes (tests
// inject a fake Doer so probing never hits the network).
func WithProbeDoer(d Doer) Option { return func(u *Upstream) { u.probeDoer = d } }

// WithClock overrides the time source (tests use a fake clock to drive passive
// ejection windows deterministically).
func WithClock(now func() time.Time) Option { return func(u *Upstream) { u.now = now } }

// WithResolveInterval overrides the dynamic re-resolution interval (default 30s).
func WithResolveInterval(d time.Duration) Option {
	return func(u *Upstream) {
		if d > 0 {
			u.resolveInterval = d
		}
	}
}

// WithPassiveEjection overrides the passive-ejection tuning (consecutive-failure
// threshold and ejection duration).
func WithPassiveEjection(threshold int, dur time.Duration) Option {
	return func(u *Upstream) {
		if threshold > 0 {
			u.passiveThreshold = threshold
		}
		if dur > 0 {
			u.ejectDuration = dur
		}
	}
}

// New builds an Upstream from cfg. It validates the config, then performs an
// initial synchronous resolution so static pools are immediately usable (dynamic
// pools begin populating here too; transient resolution failures are tolerated
// and retried by Start). New itself does not start background goroutines — call
// Start(ctx) for active health checks and periodic re-resolution.
func New(cfg Config, opts ...Option) (*Upstream, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	u := &Upstream{
		cfg:  cfg,
		byID: map[string]*backend{},
		ring: newRing(cfg.Replicas, nil),
		// The DEFAULT system resolver is wrapped in guardedResolver too (Finding 3): a
		// dns:// hostname that resolves via the system resolv.conf onto a link-local /
		// cloud-metadata address (169.254.0.0/16, fe80::/10, fd00:ec2::254) must NOT
		// become a live backend, exactly as on the custom-nameserver path. The guard
		// drops only those ranges; every legitimate RFC1918/loopback/ULA backend passes
		// through untouched, so the default path is behaviorally unchanged for real hosts.
		resolver:         guardedResolver{inner: defaultResolver()},
		now:              time.Now,
		resolveInterval:  defaultResolveInterval,
		passiveThreshold: defaultPassiveThreshold,
		ejectDuration:    defaultEjectDuration,
	}
	// Config-driven RESOLVER knobs (inline `resolve [<interval>] [nameserver …]`),
	// applied BEFORE opts so a test's WithResolver/WithResolveInterval still wins.
	// When neither knob is set the default path is byte-for-byte unchanged: the
	// process-wide system resolver and the 30s re-resolution interval.
	if len(cfg.Nameservers) > 0 {
		u.resolver = nameserverResolver(cfg.Nameservers)
	}
	if cfg.ResolveInterval > 0 {
		u.resolveInterval = cfg.ResolveInterval
	}
	for _, opt := range opts {
		opt(u)
	}
	u.poke = make(chan struct{}, 1)
	if u.newOrigin == nil {
		u.newOrigin = hostAwareOriginFactory(cfg)
	}
	if u.probeDoer == nil {
		u.probeDoer = defaultProbeDoer(cfg.Timeouts, originTLSConfig(cfg))
	}
	// Initial resolution (best-effort): populate the backend set/ring now.
	u.resolveOnce(context.Background())
	return u, nil
}

// Name returns the upstream's configured name.
func (u *Upstream) Name() string { return u.cfg.Name }

// Policy returns the configured balancing policy.
func (u *Upstream) Policy() Policy { return u.cfg.Policy }

// Inflight returns the number of requests this pool is currently serving (a fetch that
// has acquired a backend and whose response body the caller has not yet closed). The
// server uses it to drain a REMOVED pool gracefully: stop sending new requests (the
// routing swap already did that) but wait for in-flight requests to finish before
// cancelling the pool's context. Safe for concurrent use.
func (u *Upstream) Inflight() int64 { return u.inflight.Load() }

// hasDynamic reports whether any backend target needs periodic re-resolution.
func (u *Upstream) hasDynamic() bool {
	for i := range u.cfg.Backends {
		if u.cfg.Backends[i].Scheme.dynamic() {
			return true
		}
	}
	return false
}

// Start launches background workers: active health probing (if a health spec is
// configured) and periodic re-resolution (if any dynamic target is present).
// Both exit when ctx is cancelled. Start is idempotent; only the first call has
// effect.
func (u *Upstream) Start(ctx context.Context) {
	u.startOnce.Do(func() {
		if u.cfg.Health != nil {
			go u.healthLoop(ctx)
		}
		if u.hasDynamic() {
			if u.endpointResolver != nil {
				var cancels []func()
				for i := range u.cfg.Backends {
					b := &u.cfg.Backends[i]
					if b.Scheme == SchemeK8s {
						if cancel := u.endpointResolver.Watch(b.Service, b.Namespace, u.signalPoke); cancel != nil {
							cancels = append(cancels, cancel)
						}
					}
				}
				// Deregister the Watch registrations when this pool's context is cancelled
				// (the per-pool ctx is cancelled by stopRemovedPools when a fingerprint change
				// rebuilds the pool). Without this the dead *Upstream stays pinned in the
				// resolver's listener list forever (FIX 4).
				if len(cancels) > 0 {
					go func() {
						<-ctx.Done()
						for _, cancel := range cancels {
							cancel()
						}
					}()
				}
			}
			go u.resolveLoop(ctx)
		}
	})
}

// signalPoke requests a re-resolve without blocking. A full buffer means a resolve
// is already pending, so the event coalesces — the next resolveOnce sees the latest
// cache state anyway.
func (u *Upstream) signalPoke() {
	select {
	case u.poke <- struct{}{}:
	default:
	}
}

func (u *Upstream) healthLoop(ctx context.Context) {
	t := time.NewTicker(u.cfg.Health.Interval)
	defer t.Stop()
	u.probeAll(ctx) // probe immediately so the pool converges without a full interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.probeAll(ctx)
		}
	}
}

func (u *Upstream) resolveLoop(ctx context.Context) {
	t := time.NewTicker(u.resolveInterval)
	defer t.Stop()
	// Resolve immediately at loop entry so the pool converges without waiting for the
	// first tick or a poke. This closes the cold-start 503 window for k8s:// pools: the
	// construction-time resolveOnce ran before the informer cache synced (→0 backends),
	// and the informer's initial Add events fired before the Watch was registered (→no
	// poke). config.Start guarantees k8s.Start (cache sync) completes before pool.Start,
	// so this resolve sees the warm cache. Mirrors healthLoop's immediate probeAll.
	u.resolveOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.resolveOnce(ctx)
		case <-u.poke:
			u.resolveOnce(ctx)
		}
	}
}

// probeAll probes every current backend concurrently and folds outcomes into
// each backend's health FSM. Each backend has its own mutex, so this is
// race-clean.
func (u *Upstream) probeAll(ctx context.Context) {
	backends, _, _ := u.snapshot()
	var wg sync.WaitGroup
	for _, b := range backends {
		wg.Add(1)
		go func(b *backend) {
			defer wg.Done()
			b.probeOnce(ctx, u.probeDoer, u.cfg.Health)
		}(b)
	}
	wg.Wait()
}

// probeOnce runs a single health probe against this backend.
func (b *backend) probeOnce(ctx context.Context, doer Doer, spec *HealthSpec) {
	if spec == nil {
		return
	}
	probe(ctx, doer, b.baseURL, spec, &b.mu, b.fsm)
}

// snapshot returns the current backend set, ring, and id index under a read
// lock. The returned values are immutable (reconcile swaps in fresh ones), so
// callers may use them lock-free.
func (u *Upstream) snapshot() ([]*backend, *ring, map[string]*backend) {
	u.stateMu.RLock()
	defer u.stateMu.RUnlock()
	return u.backends, u.ring, u.byID
}

// resolveOnce resolves every target once and reconciles the backend set. A
// target whose resolution fails retains its existing backends (a transient DNS
// failure must not blackhole a working pool).
func (u *Upstream) resolveOnce(ctx context.Context) {
	desired := make(map[string]endpoint)
	failed := make(map[string]bool) // target.Raw -> resolution failed
	for i := range u.cfg.Backends {
		t := &u.cfg.Backends[i]
		eps, err := resolveTargetTimed(ctx, u.resolver, u.endpointResolver, t)
		if err != nil {
			failed[t.Raw] = true
			continue
		}
		for _, e := range eps {
			desired[e.id] = e
		}
	}
	u.reconcile(desired, failed)
}

// reconcile swaps in a new backend set: existing backends (by id) are preserved
// so their health/inflight/ejection survive re-resolution; new endpoints get
// fresh backends; vanished endpoints are dropped unless their target failed to
// resolve this round. A fresh consistent-hash ring is built over the result.
func (u *Upstream) reconcile(desired map[string]endpoint, failed map[string]bool) {
	u.stateMu.Lock()
	defer u.stateMu.Unlock()

	newByID := make(map[string]*backend, len(desired))
	var newList []*backend

	for id, e := range desired {
		if old, ok := u.byID[id]; ok {
			newByID[id] = old
			newList = append(newList, old)
			continue
		}
		b, err := u.makeBackend(e)
		if err != nil {
			continue // skip an endpoint we can't build a client for
		}
		newByID[id] = b
		newList = append(newList, b)
	}

	// Retain backends whose target failed to resolve this round.
	for id, b := range u.byID {
		if _, kept := newByID[id]; kept {
			continue
		}
		if b.target != nil && failed[b.target.Raw] {
			newByID[id] = b
			newList = append(newList, b)
		}
	}

	ids := make([]string, len(newList))
	for i, b := range newList {
		ids[i] = b.id
	}
	u.backends = newList
	u.byID = newByID
	u.ring = newRing(u.cfg.Replicas, ids)
}

// makeBackend constructs a backend for one endpoint.
func (u *Upstream) makeBackend(e endpoint) (*backend, error) {
	o, err := u.newOrigin(e.baseURL, e.target, u.cfg.Timeouts)
	if err != nil {
		return nil, err
	}
	window, threshold, startUp := 1, 1, true
	if u.cfg.Health != nil {
		window, threshold, startUp = u.cfg.Health.Window, u.cfg.Health.Threshold, false
	}
	b := &backend{
		id:      e.id,
		baseURL: e.baseURL,
		target:  e.target,
		origin:  o,
		fsm:     newHealthFSM(window, threshold, startUp),
	}
	if u.cfg.MaxConns > 0 {
		b.sem = make(chan struct{}, u.cfg.MaxConns)
	}
	return b, nil
}

// Fetch implements origin.Origin. It selects an eligible backend per the policy,
// delegates the fetch, and fails over to another eligible backend on a
// connection error, a 5xx, or a capacity miss — retrying until a backend
// succeeds, a definitive answer arrives (200/206/404/other 4xx), or no eligible
// backend remains (ErrNoBackend). The streaming response is returned UNCHANGED
// except for a transparent close hook that releases the backend's
// inflight/capacity accounting when the caller closes the body.
func (u *Upstream) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	tried := make(map[string]bool)
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		b := u.pick(ctx, req, tried)
		if b == nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ErrNoBackend
		}
		tried[b.id] = true

		resp, err := u.fetchOne(ctx, b, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if !retriable(err) {
			return nil, err
		}
		// Do NOT fail over when the request carries a body. (a) The streamed client
		// body is consumed by this first attempt and is not replayable (no GetBody
		// plumbing), so a second backend would receive a 0-byte/truncated body. (b)
		// Body-carrying methods (POST/PUT/PATCH) are non-idempotent — silently
		// re-issuing them to another backend risks double-submission, which a proxy
		// must not do. Surface the first attempt's error. GET/HEAD (no body,
		// idempotent) keep full failover below.
		if req.Body != nil {
			return nil, err
		}
		// else: fail over to the next eligible backend.
	}
}

// retriable reports whether a per-backend failure should trigger failover. A
// connection/transport error (StatusOf == 0), any 5xx, or a capacity miss are
// retriable; a 404 (ErrNotFound) or other 4xx is a definitive answer and is
// surfaced unchanged.
func retriable(err error) bool {
	if errors.Is(err, errAtCapacity) {
		return true
	}
	st := origin.StatusOf(err)
	return st == 0 || (st >= 500 && st <= 599)
}

// fetchOne acquires capacity, delegates to the backend's origin, records the
// outcome for passive ejection, and (on success) wraps the body so the
// inflight/capacity accounting is released exactly once when the caller closes.
func (u *Upstream) fetchOne(ctx context.Context, b *backend, req *origin.Request) (*origin.Response, error) {
	if b.sem != nil {
		select {
		case b.sem <- struct{}{}:
		default:
			return nil, errAtCapacity
		}
	}
	b.inflight.Add(1)
	u.inflight.Add(1) // pool-level in-flight (for removed-pool drain)
	var released atomic.Bool
	release := func() {
		if !released.CompareAndSwap(false, true) {
			return // release is idempotent (defense-in-depth against a double close)
		}
		b.inflight.Add(-1)
		u.inflight.Add(-1)
		if b.sem != nil {
			<-b.sem
		}
	}

	resp, err := b.origin.Fetch(ctx, req)
	if err != nil {
		release()
		u.recordOutcome(b, err)
		return nil, err
	}
	u.recordOutcome(b, nil)
	resp.Body = &trackedBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// recordOutcome folds a fetch result into the backend's passive-ejection state.
// Success and "definitive" non-failures (404 / other 4xx) reset the failure
// streak; connection errors and 5xx extend it (and may eject).
func (u *Upstream) recordOutcome(b *backend, err error) {
	if err == nil {
		b.passiveSuccess()
		return
	}
	st := origin.StatusOf(err)
	if st == 0 || (st >= 500 && st <= 599) {
		b.passiveFailure(u.passiveThreshold, u.now(), u.ejectDuration)
		return
	}
	// 404 / other 4xx: the backend answered fine; don't penalize it.
	b.passiveSuccess()
}

// pick selects an eligible backend per the policy, excluding any already tried
// this request. It returns nil when none is eligible.
func (u *Upstream) pick(ctx context.Context, req *origin.Request, tried map[string]bool) *backend {
	backends, ring, byID := u.snapshot()
	if len(backends) == 0 {
		return nil
	}
	now := u.now()
	excl := excludedBaseURL(ctx)
	ok := func(b *backend) bool {
		if excl != "" && b.baseURL == excl {
			return false // WithExcludeBaseURL: never route here (e.g. self in a peer pool)
		}
		return !tried[b.id] && b.eligible(now) && b.underCap(u.cfg.MaxConns)
	}

	switch u.cfg.Policy {
	case LeastConn:
		return u.pickLeastConn(backends, ok)
	case Sticky:
		key, has := RoutingKey(ctx)
		if !has {
			return u.pickRoundRobin(backends, ok) // no key ⇒ fall back to RR
		}
		return u.pickRing(ring, byID, key, ok)
	case Shard:
		key, has := u.shardKey(ctx, req)
		if !has {
			return u.pickRoundRobin(backends, ok)
		}
		return u.pickRing(ring, byID, key, ok)
	default: // RoundRobin
		return u.pickRoundRobin(backends, ok)
	}
}

// ResolveUpgrade implements origin.Upgrader for a load-balanced pool: it picks ONE
// eligible backend (honoring the pool's health FSM / passive ejection — the same
// `pick` the Fetch path uses, so an unhealthy or ejected backend is skipped) and
// delegates to that backend's per-upstream origin so the upgrade tunnel reuses the
// backend's own transport (SNI / keepalive / TLS-verify). It returns
// origin.ErrNoUpgradeBackend when the pool currently has no eligible backend (the
// edge equivalent of ErrNoBackend on the Fetch path). The tunnel runs OFF the Fetch
// path, so pool inflight accounting is intentionally not incremented here — a live
// hijacked connection is owned by the server's ReverseProxy, not a trackedBody.
func (u *Upstream) ResolveUpgrade(ctx context.Context, req *origin.Request) (origin.UpgradeTarget, error) {
	// Thread the caller's ctx (carrying lb.WithRoutingKey) into pick so a Sticky /
	// Shard-by-key pool pins the tunnel to the SAME backend the Fetch path would —
	// otherwise a stateful socket.io tunnel would lose affinity to round-robin
	// (Finding 3). Shard-by-URL reads req.Key and health/ejection are unaffected.
	b := u.pick(ctx, req, nil)
	if b == nil {
		return origin.UpgradeTarget{}, origin.ErrNoUpgradeBackend
	}
	up, ok := b.origin.(origin.Upgrader)
	if !ok {
		return origin.UpgradeTarget{}, origin.ErrNoUpgradeBackend
	}
	return up.ResolveUpgrade(ctx, req)
}

// shardKey returns the hash input for the Shard policy: the request URL (Key)
// for ShardURL, or the caller-supplied routing key for ShardKeyVal.
func (u *Upstream) shardKey(ctx context.Context, req *origin.Request) (string, bool) {
	switch u.cfg.Shard {
	case ShardURL:
		return req.Key, true
	case ShardKeyVal:
		return RoutingKey(ctx)
	default:
		return "", false
	}
}

func (u *Upstream) pickRoundRobin(backends []*backend, ok func(*backend) bool) *backend {
	n := len(backends)
	start := int(u.rr.Add(1) - 1)
	for i := 0; i < n; i++ {
		b := backends[(start+i)%n]
		if ok(b) {
			return b
		}
	}
	return nil
}

func (u *Upstream) pickLeastConn(backends []*backend, ok func(*backend) bool) *backend {
	var best *backend
	var bestN int64
	for _, b := range backends {
		if !ok(b) {
			continue
		}
		n := b.inflight.Load()
		if best == nil || n < bestN {
			best, bestN = b, n
		}
	}
	return best
}

func (u *Upstream) pickRing(ring *ring, byID map[string]*backend, key string, ok func(*backend) bool) *backend {
	id, found := ring.lookup(key, func(id string) bool {
		b := byID[id]
		return b != nil && ok(b)
	})
	if !found {
		return nil
	}
	return byID[id]
}

// Owner returns the base URL of the backend that owns key on the consistent-hash
// ring, walking clockwise past ineligible (unhealthy / ejected) backends so the
// result is the node a sharded key currently lives on. ok is false when the pool
// is empty or no backend is eligible. This is the read-side of the SAME ring the
// Shard policy routes on; the cluster layer uses it to decide owner-vs-self for
// ownership routing (#8) while peer fetches go through Fetch on the same pool.
//
// When healthyOnly is false, eligibility is ignored and the raw ring owner is
// returned (used to learn the topology's intended owner even when it is down, so
// the caller can decide strict-vs-degraded fallback itself).
func (u *Upstream) Owner(key string, healthyOnly bool) (string, bool) {
	backends, ring, byID := u.snapshot()
	if len(backends) == 0 || ring == nil {
		return "", false
	}
	now := u.now()
	var eligible func(id string) bool
	if healthyOnly {
		eligible = func(id string) bool {
			b := byID[id]
			return b != nil && b.eligible(now) && b.underCap(u.cfg.MaxConns)
		}
	}
	id, found := ring.lookup(key, eligible)
	if !found {
		return "", false
	}
	b := byID[id]
	if b == nil {
		return "", false
	}
	return b.baseURL, true
}

// Endpoints returns the current backend base URLs (a snapshot). Order is not
// significant. Used by the cluster layer to learn the live peer set.
func (u *Upstream) Endpoints() []string {
	backends, _, _ := u.snapshot()
	out := make([]string, 0, len(backends))
	for _, b := range backends {
		out = append(out, b.baseURL)
	}
	return out
}

// trackedBody wraps a streaming response body with a once-only release hook that
// runs when the caller closes the body, releasing the backend's inflight and
// capacity accounting. Reads pass through unchanged (no buffering), so the
// origin streaming/tee contract is preserved — the only modification is the
// close-time accounting.
type trackedBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (t *trackedBody) Close() error {
	err := t.ReadCloser.Close()
	t.once.Do(t.release)
	return err
}

// drainClose discards a bounded prefix of body then closes it so a keep-alive
// connection can be reused. Mirrors httporigin.drainClose (unexported there).
func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, 4<<10)
	_ = body.Close()
}

// HostHeaderPolicy is the upstream Host-header policy for a pool's backends
// (backlog #11). It mirrors httporigin's policy so lb.Config can carry it without
// every caller importing httporigin. The zero value is "preserve" (Policy ==
// httporigin.HostPreserve, the default).
type HostHeaderPolicy struct {
	// Policy is the host-header mode (preserve / origin / fixed).
	Policy httporigin.HostPolicy
	// Value is the fixed Host for httporigin.HostFixed; ignored otherwise.
	Value string
}

// hostAwareOriginFactory builds the default OriginFactory closing over the pool's
// Host-header policy plus the per-upstream transport knobs (gap-H6 sni/disableReuse
// and TLSVERIFY insecure/rootCAs/alpn), so every backend origin forwards/overrides
// the Host consistently (backlog #11) and, when set, advertises the configured SNI,
// disables connection reuse, and applies the per-upstream origin-TLS verification.
// When no knob is set the forwarded options are no-ops, so the built origin is
// byte-for-byte the legacy one (shared pool, Go-default SNI, keep-alive on, full
// verification).
func hostAwareOriginFactory(cfg Config) OriginFactory {
	hh := cfg.HostHeader
	return func(baseURL string, _ *Target, to Timeouts) (origin.Origin, error) {
		opts := []httporigin.Option{httporigin.WithHostPolicy(hh.Policy, hh.Value)}
		if to.Connect > 0 || to.FirstByte > 0 {
			opts = append(opts, httporigin.WithHTTPClient(clientForTimeouts(to)))
		}
		if cfg.SNI != "" {
			opts = append(opts, httporigin.WithSNI(cfg.SNI))
		}
		if cfg.DisableReuse {
			opts = append(opts, httporigin.WithDisableKeepAlives(true))
		}
		// TLSVERIFY: per-upstream origin TLS verification. Insecure and RootCAs are
		// mutually exclusive (the config layer enforces it); ALPN pins the offered
		// protocol list. All default to the secure/no-op value.
		if cfg.Insecure {
			opts = append(opts, httporigin.WithInsecureTLS(true))
		}
		if cfg.RootCAs != nil {
			opts = append(opts, httporigin.WithRootCAs(cfg.RootCAs))
		}
		if len(cfg.ALPN) != 0 {
			opts = append(opts, httporigin.WithALPN(cfg.ALPN))
		}
		// between_bytes (gap G5): per-upstream body-stall budget. The origin only
		// stamps it onto each Response; the server enforces it as a between-bytes
		// deadline (the origin must never wrap the streaming body).
		if to.BetweenBytes > 0 {
			opts = append(opts, httporigin.WithBetweenBytes(to.BetweenBytes))
		}
		return httporigin.New(baseURL, opts...)
	}
}

// originTLSConfig builds the per-upstream origin *tls.Config from the pool's
// TLSVERIFY/SNI knobs, or returns nil when none is set (so the health probe's
// default transport is byte-for-byte unchanged). It is applied to BOTH the origin
// factory (indirectly, via httporigin options) and the health-probe transport, so
// probes verify the origin with the SAME settings as live fetches — HAProxy
// `http-check connect ssl` parity (this also fixes the pre-existing miss where the
// probe transport ignored even `sni`).
func originTLSConfig(cfg Config) *tls.Config {
	if cfg.SNI == "" && !cfg.Insecure && cfg.RootCAs == nil && len(cfg.ALPN) == 0 {
		return nil
	}
	// Defense-in-depth (Finding 7): Insecure ⊕ RootCAs (tls_insecure ⊕ ca_file) is a
	// compile error, so they never co-exist legitimately. If a future plumbing mistake
	// set both, InsecureSkipVerify=true would win and silently ignore RootCAs — failing
	// OPEN. Prefer verification: skip only when no private CA pool is configured, so the
	// mistake fails CLOSED.
	return &tls.Config{ //nolint:gosec // fields set explicitly; default MinVersion applies
		ServerName:         cfg.SNI,
		InsecureSkipVerify: cfg.Insecure && cfg.RootCAs == nil, //nolint:gosec // opt-in per-upstream `tls_insecure`
		RootCAs:            cfg.RootCAs,
		NextProtos:         cfg.ALPN,
	}
}

// clientForTimeouts builds a streaming HTTP client whose establishment phases
// honor the configured connect/first_byte timeouts. The body transfer is
// uncapped (governed by the request context), per the origin contract.
func clientForTimeouts(to Timeouts) *http.Client {
	connect := to.Connect
	if connect <= 0 {
		connect = 5 * time.Second
	}
	firstByte := to.FirstByte
	if firstByte <= 0 {
		firstByte = 30 * time.Second
	}
	dialer := &net.Dialer{Timeout: connect, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// No ambient proxy (security): upstream dials are explicit; an env-configured
		// HTTP(S)_PROXY diverting them is an SSRF-adjacent footgun. Pairs with the
		// redirect SSRF guard below.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   connect,
		ResponseHeaderTimeout: firstByte,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		// SSRF guard (security review #1): never follow redirects — a 30x escapes the
		// configured backend host. Surfaced as the last response (httporigin passes a
		// 3xx through; other handling is the origin's). Matches httporigin's client.
		CheckRedirect: noFollowRedirect,
	}
}

// defaultProbeDoer builds a fully-bounded HTTP client for active health probes
// (a probe must never hang a prober goroutine). tlsCfg carries the per-upstream
// origin-TLS settings (SNI / tls_insecure / ca_file / alpn) so probes handshake the
// HTTPS origin with the SAME verification as live fetches — HAProxy `http-check
// connect ssl` parity. nil ⇒ the default transport (system roots, Go-default SNI),
// keeping the no-knob datapath unchanged.
func defaultProbeDoer(to Timeouts, tlsCfg *tls.Config) Doer {
	connect := to.Connect
	if connect <= 0 {
		connect = 5 * time.Second
	}
	tr := &http.Transport{
		Proxy:               nil, // no ambient proxy (security) — see clientForTimeouts
		DialContext:         (&net.Dialer{Timeout: connect}).DialContext,
		TLSHandshakeTimeout: connect,
		MaxIdleConnsPerHost: 4,
	}
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		// SSRF guard (security review #1): a health probe must not follow a 30x off
		// the configured backend (e.g. to cloud metadata). Treat the redirect status
		// as the probe result instead of chasing it.
		CheckRedirect: noFollowRedirect,
	}
}

// noFollowRedirect makes an http.Client return the redirect response as-is rather
// than following it (http.ErrUseLastResponse), the SSRF guard shared by the
// per-backend and health-probe clients.
func noFollowRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
