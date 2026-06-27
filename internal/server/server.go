// Package server is cadish's HTTP caching reverse proxy: the layer that turns the
// pure pipeline decisions (internal/pipeline), the two-tier cache (internal/cache)
// and the origin layer (internal/origin) into a live net/http handler.
//
// The request lifecycle implemented here is:
//
//	site selection (Host) -> EvalRequest (respond/purge/pass/cache_key)
//	  -> LOOKUP (fresh HIT | stale HIT + bg revalidate | MISS)
//	  -> ORIGIN (single-flight coalesced fetch, serve-and-cache)
//	  -> EvalResponse (TTL/grace/hit-for-miss/storage)
//	  -> DELIVER (header ops, strip_cookies, CORS, cache-status header)
//
// TLS and load balancing are wired in (M5c):
//
//   - TLS: when any site declares `tls`, Server binds a hardened :443 listener
//     (termination + ACME via internal/tlsacme) plus a :80 server for ACME HTTP-01
//     challenges and HTTPS redirects; otherwise it serves a single plain-HTTP
//     listener. The choice is made from config.Config.TLS.
//   - LB: an `upstream`/`cluster` is built as an internal/lb Upstream (round-robin /
//     least-conn / sticky / shard, active health, dynamic dns:// resolution), which
//     is itself an origin.Origin. The handler routes per request via
//     originFor(routedUpstream) and attaches the {sticky} routing key with
//     lb.WithRoutingKey for sticky / shard-by-key pools. lb background workers run
//     for the server's lifetime (cancelled on Shutdown).
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/metrics"
	"github.com/cadi-sh/cadish/internal/pipeline"
	"github.com/cadi-sh/cadish/internal/proxyproto"
	"github.com/cadi-sh/cadish/internal/ratelimit"
	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// Handler is the cadish http.Handler. It is safe for concurrent use and holds the
// per-request machinery (freshness index, request coalescer, background-fetch
// single-flight, origin stall sweeper) shared across all sites, plus the bound
// sites.
type Handler struct {
	// route is the per-reload routing table (bound sites + host index). It is
	// swapped atomically by Reload so an in-flight request finishes on the routing
	// it loaded while new requests pick up the new one. ServeHTTP / selectSite /
	// LiveState load it exactly once per call. The shared machinery below (freshness
	// index, coalescer, single-flights, sweeper, metrics, tracer) is PRESERVED across
	// a reload — never rebuilt — so the cache hit ratio and in-flight work survive.
	route atomic.Pointer[routing]

	fresh    *freshness
	coalesce *fetchCoalescer
	bg       *singleFlight
	// bgSem is a GLOBAL concurrency cap on background (stale-while-revalidate) origin
	// refreshes. h.bg dedups per KEY, but without a global ceiling a flood of requests
	// across a large warm-but-stale catalog would launch one detached goroutine + one
	// origin dial per distinct key — an uncapped 1:1 origin amplification and goroutine
	// flood. A full semaphore means the refresh is SKIPPED (the object is still served
	// from grace; it just stays stale one more round), never queued or blocked.
	bgSem   chan struct{}
	sweeper *idleSweeper

	log          *slog.Logger
	now          func() time.Time
	idleTimeout  time.Duration // origin stall watchdog (0 disables)
	bgTimeout    time.Duration // background revalidation deadline
	maxBodyBytes int64         // cap on a forwarded client request body (0 = unlimited)

	// unmatchedHostStatus is the status for a request whose Host matched no declared site
	// (and the lenient single-site fallback was suppressed). 0 ⇒ the default 502; the
	// Gateway data plane sets 404 (GW-P1). Does NOT affect the strict_host 421 path.
	unmatchedHostStatus int

	// metrics is the observability seam. It is NIL when no admin block is
	// configured; every *metrics.Metrics method is a nil-safe no-op, so the
	// datapath pays nothing in that case.
	metrics *metrics.Metrics

	// limiter is the in-memory, sharded, per-node token-bucket rate limiter for the
	// native `rate_limit` security primitive (WAF v1b / D51). It is NIL when no site
	// configures rate_limit — a nil *ratelimit.Limiter admits every request and runs
	// no sweeper goroutine, so a non-rate-limited server pays nothing. Constructed
	// once (and PRESERVED across reloads, like the freshness index) when any site uses
	// rate limiting; its per-node counters survive a config reload. Bucket keys are
	// namespaced per site by the server so two sites never share a bucket.
	limiter *ratelimit.Limiter

	// accessHub is the in-memory access-log fan-out (D44). The hot path checks one
	// atomic ("any consumer attached?") and does nothing when idle; only when a
	// `cadish logs` consumer is streaming does it build + fan-out a record. Never
	// nil (NewHandler always constructs one; `access_log off` makes it a disabled
	// hub whose count is always 0).
	accessHub *AccessHub

	// auditLog is the async, non-blocking security-audit sink (WAF v1c / D52). It is
	// NIL unless `security { audit_log <dir|file> }` (or `-security-audit-log PATH`)
	// is configured — OFF by default, zero cost when absent. When set, each ENFORCED
	// or MONITORED security-gate action (deny / ratelimit / would-block) is written
	// off the hot path; a full/slow sink drops + counts and never blocks serving.
	auditLog *AuditLog

	// tracer is the varnishlog-style transaction-trace seam. It is NIL unless
	// `-trace` (or CADISH_TRACE) is set; a nil Tracer yields a nil per-request
	// record whose decision hooks are all no-ops, so a non-tracing cadish pays
	// nothing on the datapath (mirrors the metrics seam gating).
	tracer *Tracer

	// peerClient reverse-proxies requests to peer cadish nodes for cluster
	// ownership routing (#8). Built once; unused (but harmless) when no site is
	// clustered.
	peerClient *http.Client

	// encodeCompressions counts how many times a response body was actually
	// COMPRESSED on the fly (a codec stream was created and fed the body), as
	// opposed to served from a stored compressed variant. It exists purely for
	// tests/observability of the cached-variant optimization (D69): a HIT that
	// serves a stored variant must NOT increment it. It is a no-cost atomic add on
	// the (already opt-in) encode path; the inactive fast path never touches it.
	encodeCompressions atomic.Int64

	// httpDateCache memoizes the formatted "Date" response header (set on every cache
	// HIT) at one-second granularity — http.TimeFormat has 1s resolution, so all serves
	// within the same wall-clock second produce the byte-identical string. The lock-free
	// atomic read skips a time.Time.Format (and its allocation) on the hot HIT path; the
	// reformat+store happens at most once per second (a benign race re-stores the same
	// value). Driven by h.now() so an injected/frozen test clock stays exact.
	httpDateCache atomic.Pointer[httpDate]

	// warm is the warm-readiness gate for the Kubernetes controllers. It starts FALSE at
	// construction and is flipped to true (idempotently) by Server.MarkWarm — the
	// ingress/gateway controllers call it after their FIRST successful reconcile builds
	// the routing table from synced listers, and `cadish run` calls it once the server is
	// serving. ServeHTTP reads it lock-free at the very top to answer the reserved
	// /.cadish/readyz probe (503 until warm, 200 after) so Kubernetes does not route
	// traffic to a pod whose routing table is not yet built (no rollout 502/404).
	warm atomic.Bool
}

// httpDate is a memoized RFC 7231 Date header value plus the unix second it was
// formatted for (see Handler.httpDate).
type httpDate struct {
	sec int64
	str string
}

// routing is an immutable routing table: the bound sites plus the host index used
// to select one per request. It is published via Handler.route (an atomic.Pointer)
// and never mutated after construction, so concurrent ServeHTTP loads are race-free
// and a reload is a single atomic pointer store.
type routing struct {
	sites    []*boundSite
	exact    map[string]*boundSite // host -> site (exact match)
	wildcard []wildcardSite        // "*.example.com" suffix matches
	single   *boundSite            // the only site, used as a lenient fallback
	// strictHost disables the lenient single-site fallback: when true, a Host that
	// matches no declared address selects no site (the handler answers 421) instead
	// of being served by the only site. From the global `strict_host` option.
	strictHost bool
}

// wildcardSite is a "*.suffix" host pattern bound to a site.
type wildcardSite struct {
	suffix string // ".example.com" (the dot-prefixed remainder after "*")
	site   *boundSite
}

// Options configures a Handler/Server. The zero value is usable; New fills sane
// defaults.
type Options struct {
	// Logger receives the per-request access log and warnings. Defaults to
	// slog.Default().
	Logger *slog.Logger
	// Now is an injectable clock for freshness timing (tests). Defaults to
	// time.Now.
	Now func() time.Time
	// IdleTimeout aborts an origin body that stalls for this long mid-stream. 0
	// disables the watchdog. Defaults to 0 (disabled).
	IdleTimeout time.Duration
	// BgRevalidateTimeout bounds a background (grace) revalidation fetch. Defaults
	// to 30s.
	BgRevalidateTimeout time.Duration
	// Metrics is the observability seam fed from the request datapath. Leave nil
	// (the default) when no admin/dashboard surface is configured: a nil *Metrics
	// is a no-op on every recorder, so the datapath pays nothing. The admin server
	// (internal/admin) constructs one and passes it here.
	Metrics *metrics.Metrics

	// AccessLogOff disables the in-memory access-log hub entirely (`access_log off`
	// / `-access-log off`). The DEFAULT (zero value, false) is hub ON — but idle-free
	// until a `cadish logs` consumer attaches. When true, the hub registers no
	// subscribers and the hot-path atomic check is the only cost ever paid (D44).
	AccessLogOff bool

	// AuditLog is the async, non-blocking security-audit sink (WAF v1c / D52). Leave
	// nil (the default) when no `security { audit_log … }` is configured — the audit
	// log is OFF by default and a nil sink is a no-op on every record (zero cost). The
	// run command constructs one from config/flag and passes it here; the Handler owns
	// closing it at Shutdown.
	AuditLog *AuditLog

	// Tracer is the varnishlog-style transaction-trace seam. Leave nil (the
	// default) for zero cost on the datapath; `cadish run -trace` (or CADISH_TRACE)
	// constructs one writing to stderr. When set, every request emits a multi-line
	// decision trace (matched route, cache key, EvalResponse ttl/grace/hit-for-miss,
	// pass reason, routed upstream, transforms).
	Tracer *Tracer

	// HTTPSAddr is the TLS listener address used when any site declares `tls`.
	// Defaults to ":443".
	HTTPSAddr string
	// ACMECacheDir overrides where issued ACME certificates are cached (empty uses
	// the tlsacme default resolution order).
	ACMECacheDir string
	// ACMEDirectoryURL overrides the ACME directory endpoint (e.g. a pebble/staging
	// server for tests). Empty uses Let's Encrypt production.
	ACMEDirectoryURL string

	// MaxRequestBodyBytes optionally caps the size of a CLIENT request body that the
	// proxy will read and forward to origin/peer, via http.MaxBytesReader at ingress.
	// 0 (the DEFAULT) means UNLIMITED — deliberately so: cadish is a media/cache edge
	// and a hard default cap would break large legitimate uploads/streaming. An
	// operator who wants to bound upload size sets a positive value; the cap then
	// applies only to body-carrying methods (anything but GET/HEAD), and a body that
	// exceeds it is rejected by net/http with a 413. When 0 the ingress path takes no
	// extra allocation and the body is streamed straight through (zero cost on the hot
	// GET path, which never has a body anyway).
	MaxRequestBodyBytes int64

	// ForceTLS makes the server bind a TLS-capable :443 (+ :80) listener even when the
	// startup config declares no `tls` — the Ingress-controller mode (D55): TLS hosts
	// arrive later via reconcile, so the listener and the ACME source must already exist
	// at startup (the autocert source is fixed at construction). The ACME HostPolicy
	// still starts empty (never an open issuer) and BYO Secret certs are injected live
	// via Server.SetDynamicCerts. Off (the default) keeps the legacy behavior: bind :443
	// only when a site declares `tls`.
	ForceTLS bool
	// ACMEEmail is the ACME account contact used when ForceTLS builds the autocert
	// source and the startup config has no ACME site to supply one. Optional.
	ACMEEmail string

	// UnmatchedHostStatus overrides the status returned for a request whose Host matched no
	// declared site AND the lenient single-site fallback was suppressed (the
	// genuinely-no-site case — NOT the strict_host 421 case, which is unaffected). 0 (the
	// DEFAULT) keeps the core server's 502 Bad Gateway. The Gateway data plane sets this to
	// 404 (GW-P1): a Gateway API client expects 404 for an unmatched host, and only the
	// gateway controller opts in — the core (non-gateway) server's 502 is unchanged.
	UnmatchedHostStatus int

	// ReloadOptions carries the run-time config.LoadOptions a SIGHUP reload must reuse so
	// the recompiled config keeps the flags the process started with — chiefly the
	// `--kubeconfig` path for out-of-cluster k8s:// resolution (without it, Reload would
	// recompile with the ZERO options and the rebuilt k8s client would silently fall back
	// to the default chain). Set by `cadish run` to LoadOptions{Kubeconfig: *kubeconfig};
	// the zero value (empty) preserves the default chain, so an unset --kubeconfig is
	// unchanged. EndpointResolver is deliberately NOT carried here: in `cadish run` the
	// k8s client is config-owned and a reload intentionally rebuilds it (the ingress
	// controller, which injects a resolver, drives ApplyConfig directly, not Reload).
	ReloadOptions config.LoadOptions
}

func (o Options) withDefaults() Options {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.BgRevalidateTimeout == 0 {
		o.BgRevalidateTimeout = 30 * time.Second
	}
	if o.HTTPSAddr == "" {
		o.HTTPSAddr = tlsacme.DefaultHTTPSAddr
	}
	return o
}

// NewHandler builds the cadish handler from a loaded config.
func NewHandler(cfg *config.Config, opts Options) *Handler {
	opts = opts.withDefaults()

	h := &Handler{
		fresh:               newFreshness(opts.Now),
		coalesce:            newFetchCoalescer(),
		bg:                  newSingleFlight(),
		bgSem:               make(chan struct{}, maxConcurrentBgRevalidations),
		sweeper:             newIdleSweeper(sweepInterval(opts.IdleTimeout)),
		log:                 opts.Logger,
		now:                 opts.Now,
		idleTimeout:         opts.IdleTimeout,
		bgTimeout:           opts.BgRevalidateTimeout,
		maxBodyBytes:        opts.MaxRequestBodyBytes,
		unmatchedHostStatus: opts.UnmatchedHostStatus,
		metrics:             opts.Metrics,
		tracer:              opts.Tracer,
		accessHub:           newAccessHub(!opts.AccessLogOff),
		auditLog:            opts.AuditLog,
		peerClient:          newPeerClient(),
	}

	rt := h.buildRouting(cfg.Sites, cfg.StrictHost)
	h.route.Store(rt)
	// Surface the disk tier's per-shard-cap oversize discard (an object too big for the
	// disk tier, cached nowhere — F6) via the server's logger. Nil-safe per store.
	attachStoreLoggers(cfg.Sites, h.log)
	// Construct the rate limiter only when a site uses `rate_limit` (zero cost — and
	// no sweeper goroutine — otherwise). It shares the injectable clock so the bucket
	// math is deterministic under the test clock.
	if anySiteUsesRateLimit(cfg.Sites) {
		h.limiter = ratelimit.NewWithClock(opts.Now)
	}
	return h
}

// anySiteUsesRateLimit reports whether any site's pipeline configures a rate_limit
// rule. Gates limiter construction (and its sweeper goroutine) in NewHandler/Reload.
func anySiteUsesRateLimit(sites []*config.Site) bool {
	for _, s := range sites {
		if s.Pipeline != nil && s.Pipeline.UsesRateLimit() {
			return true
		}
	}
	return false
}

// buildRouting compiles cfg's sites into an immutable routing table. The warm cache
// store is transplanted separately (Config.TransplantStoresFrom, run by Server.Reload
// before the swap), so a reload does not cold-start the cache.
func (h *Handler) buildRouting(sites []*config.Site, strictHost bool) *routing {
	rt := &routing{exact: map[string]*boundSite{}, strictHost: strictHost}
	for _, s := range sites {
		bs := &boundSite{Site: s}
		rt.sites = append(rt.sites, bs)
		for _, addr := range s.Addresses {
			host := normalizeAddr(addr)
			if strings.HasPrefix(host, "*.") {
				rt.wildcard = append(rt.wildcard, wildcardSite{suffix: host[1:], site: bs})
			} else {
				rt.exact[host] = bs
			}
		}
	}
	if len(rt.sites) == 1 {
		rt.single = rt.sites[0]
	}
	return rt
}

// siteCount returns the number of bound sites in the live routing table.
func (h *Handler) siteCount() int { return len(h.route.Load().sites) }

// AccessHub exposes the in-memory access-log fan-out so the run command can bind the
// streaming unix socket consumers subscribe to. Never nil.
func (h *Handler) AccessHub() *AccessHub { return h.accessHub }

// selectSite resolves the site for a request Host: exact match first, then "*."
// wildcard suffix, then — when exactly one site is configured AND `strict_host` is
// off — that site (lenient fallback so a single-site config serves any Host,
// convenient for tests and IP-only access). It loads the current routing table once
// (atomic) so an in-flight request sees a consistent snapshot.
//
// The second result is strictReject: true when no declared address matched AND the
// lenient fallback was suppressed by the global `strict_host` option. The handler
// answers a strictReject with 421 Misdirected Request (an undeclared Host is a
// misrouted/forged request, not a server error), distinguishing it from the
// genuinely site-less case (no sites configured at all → nil site, false, 502).
func (h *Handler) selectSite(host string) (*boundSite, bool) {
	rt := h.route.Load()
	host = normalizeAddr(host)
	if bs, ok := rt.exact[host]; ok {
		return bs, false
	}
	for _, w := range rt.wildcard {
		if strings.HasSuffix(host, w.suffix) && len(host) > len(w.suffix) {
			return w.site, false
		}
	}
	// No declared address matched. Under strict_host, suppress the lenient single-site
	// fallback and signal a 421 — but only when there IS at least one site to declare
	// against (a truly site-less routing table is the 502 path, not a 421).
	if rt.strictHost {
		if len(rt.sites) > 0 {
			return nil, true
		}
		return nil, false
	}
	return rt.single, false
}

// normalizeAddr lower-cases a host/address token, strips any :port, and strips an
// FQDN trailing dot so the routing index keys `example.com.` and `example.com` the
// same (WB1) — matching normalizeHost, which the request side uses.
// normalizeAddr canonicalizes a site address / request Host for routing. It MUST agree with
// the cache key's host normalization, or a host that selects a site could fork the cache key
// (cache-bust / fragmentation). It therefore delegates to the SINGLE canonical normalizer
// (pipeline.NormalizeHost) the `host` key token and host matchers use — one reader, no split.
func normalizeAddr(addr string) string {
	return pipeline.NormalizeHost(addr)
}

// Shutdown stops the background stall sweeper. The cache stores are owned by the
// config.Config and closed there.
func (h *Handler) Shutdown() {
	h.sweeper.Stop()
	h.fresh.Close()        // stops the freshness reclamation sweeper goroutine
	h.limiter.Stop()       // nil-safe: a no-op when no site uses rate_limit
	_ = h.auditLog.Close() // nil-safe: flushes + closes the audit file when configured
}

// Reload atomically swaps the handler's routing to serve next, preserving the
// shared datapath machinery (freshness index, coalescer, single-flights, sweeper,
// metrics, tracer). In-flight requests finish on the routing they already loaded; new
// requests pick up the swap immediately after the atomic store.
//
// The warm-cache transplant (so a reload does NOT cold the cache) is done by
// next.TransplantStoresFrom(old) BEFORE this call, which is why Server.Reload runs it
// first. Reload itself only rebuilds and swaps the routing table; config validation
// happens earlier in Server.Reload (a bad config never reaches here, so the old
// config keeps serving). Reload does not fail.
func (h *Handler) Reload(next *config.Config) {
	// Lazily construct the limiter if a reload newly introduces rate_limit (it is
	// PRESERVED — never rebuilt — once present, so per-node counters survive reloads).
	if h.limiter == nil && anySiteUsesRateLimit(next.Sites) {
		h.limiter = ratelimit.NewWithClock(h.now)
	}
	h.route.Store(h.buildRouting(next.Sites, next.StrictHost))
	attachStoreLoggers(next.Sites, h.log)
}

// attachStoreLoggers wires the server's logger into each site's cache store so a
// per-shard-cap oversize discard in the disk tier (an object cached nowhere — F6)
// becomes observable. Nil-safe per site/store/logger.
func attachStoreLoggers(sites []*config.Site, log *slog.Logger) {
	if log == nil {
		return
	}
	for _, s := range sites {
		if s.Store != nil {
			s.Store.SetLogger(log)
		}
	}
}

// Server wraps a Handler with its net/http listeners and graceful shutdown. It
// runs in one of two modes, chosen by whether any site declared `tls`:
//
//   - Plain HTTP: a single listener on the HTTP address.
//   - TLS: a hardened :443 listener (TLS termination + ACME via tlsacme) plus a :80
//     server that answers ACME HTTP-01 challenges and 301-redirects to HTTPS.
//
// On start it also launches every lb.Upstream's background workers (active health
// probing + dynamic re-resolution), bound to a serving context cancelled by
// Shutdown.
type Server struct {
	handler   *Handler
	cfg       *config.Config
	mgr       *tlsacme.Manager
	httpAddr  string
	httpsAddr string
	log       *slog.Logger

	// httpSrv is the plain-HTTP server (used only when TLS is off).
	httpSrv *http.Server

	// servingCtx is cancelled by Shutdown to stop lb background workers and (in TLS
	// mode) unblock the tlsacme Servers' run loop so they shut down gracefully.
	servingCtx context.Context
	cancel     context.CancelFunc

	// reloadMu serializes Reload calls so two concurrent SIGHUPs cannot interleave a
	// store transplant with an old-config teardown.
	reloadMu sync.Mutex

	// reloadOpts are the run-time LoadOptions a SIGHUP reload recompiles with, so the new
	// config inherits the startup flags (chiefly --kubeconfig). Set once in NewServer from
	// Options.ReloadOptions; read by Reload. Immutable after construction.
	reloadOpts config.LoadOptions

	// tlsBoundAtStart records whether the server bound a TLS-capable :443 listener at
	// STARTUP (the startup config declared tls/ACME, or ForceTLS). The :443 listener and
	// the autocert source are fixed at construction and never rebuilt, so a server that
	// started plain cannot serve a config that a reload later switches to needing TLS —
	// ApplyConfig reads this to WARN on such a reload. Captured in NewServer (before any
	// reload mutates the TLS manager's state) and immutable thereafter.
	tlsBoundAtStart bool

	mu sync.Mutex
	// tlsServers is the live TLS server pair (nil in plain-HTTP mode).
	tlsServers *tlsacme.Servers
	// poolsCancel stops the CURRENT config's SHARED (non-pool) background workers — the
	// K8s client + cluster memberships, which are not diffed across a reload. Reload
	// starts the new config's shared workers under a fresh child of servingCtx, then
	// calls this to stop the old config's. Shutdown calls it too (then cancel()).
	poolsCancel context.CancelFunc
	// poolCancels holds a per-pool stop func for every CURRENTLY-RUNNING lb pool, keyed
	// by the pool instance. Each pool runs under its OWN child of servingCtx (NOT the
	// shared poolsCancel context), so a transplanted survivor keeps running when the
	// config that first started it is torn down. startPools starts only pools not
	// already here (survivors are skipped); a reload cancels the entries whose pools the
	// new config no longer references (removed pools), after the routing swap. Guarded
	// by mu. (servingCtx cancellation at Shutdown stops every pool regardless, since
	// each per-pool context is a child of it.)
	poolCancels map[*lb.Upstream]context.CancelFunc

	// drainWG tracks the background drain goroutines stopRemovedPools launches for pools a
	// reload removed (B2: removed-pool drain grace). Shutdown waits on it so a drain never
	// outlives the server and no goroutine leaks. Each drain also watches servingCtx so
	// Shutdown's cancel() ends it promptly.
	drainWG sync.WaitGroup
}

// NewServer builds a Server that serves cfg, with httpAddr the plain/redirect/ACME
// HTTP address (e.g. ":80"). The TLS listener address comes from Options.HTTPSAddr.
// It returns an error if the TLS configuration is invalid (e.g. a bad static
// keypair).
func NewServer(cfg *config.Config, httpAddr string, opts Options) (*Server, error) {
	opts = opts.withDefaults()
	h := NewHandler(cfg, opts)
	mgr, err := tlsacme.NewManager(cfg.TLS, tlsacme.Options{
		CacheDir:         opts.ACMECacheDir,
		ACMEDirectoryURL: opts.ACMEDirectoryURL,
		ForceACME:        opts.ForceTLS,
		ACMEEmail:        opts.ACMEEmail,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		handler:     h,
		cfg:         cfg,
		mgr:         mgr,
		httpAddr:    announcedAddr(httpAddr),
		httpsAddr:   opts.HTTPSAddr,
		log:         opts.Logger,
		servingCtx:  ctx,
		cancel:      cancel,
		reloadOpts:  opts.ReloadOptions,
		poolCancels: map[*lb.Upstream]context.CancelFunc{},
		httpSrv: &http.Server{
			Addr:              announcedAddr(httpAddr),
			Handler:           h,
			ReadHeaderTimeout: serverReadHeaderTimeout,
			ReadTimeout:       serverInboundReadTimeout(cfg),
			IdleTimeout:       serverInboundIdleTimeout(cfg),
			MaxHeaderBytes:    serverMaxHeaderBytes,
			// WriteTimeout intentionally unset — see the const block.
		},
	}
	// Capture the startup TLS-listener decision BEFORE any reload can mutate the
	// manager's host state: mgr.NeedsTLS() here is exactly what ListenAndServe uses to
	// decide whether to bind :443 (true for an ACME/static startup site or ForceTLS).
	s.tlsBoundAtStart = s.NeedsTLS()
	// Start the config's background workers now (fail-fast): when a k8s:// target
	// exists this blocks on the informer cache sync and FAILS construction if the
	// API is unreachable or RBAC is missing, rather than serving empty pools. Static
	// pools start their (no-op) workers here too, under servingCtx.
	if err := s.startPools(s.cfg); err != nil {
		s.cancel() // tear down anything startPools spawned (e.g. the k8s informers)
		return nil, err
	}
	return s, nil
}

// Server connection timeouts (security review #7), chosen to be streaming-safe:
//
//   - ReadHeaderTimeout / ReadTimeout bound a slow client sending the request
//     (headers + any body). A cache edge serves GETs with no body, so 30s is ample
//     and blunts slow-request slowloris.
//   - IdleTimeout bounds how long a keep-alive connection may sit idle between
//     requests, reclaiming slow/abandoned client sockets.
//   - WriteTimeout is deliberately LEFT UNSET (0): a global response-write deadline
//     would truncate legitimate large/slow media downloads (the whole point of the
//     cache edge). A silent/stalled ORIGIN is instead bounded by the idle-stall
//     watchdog (idlereader.go); a slow client is bounded by IdleTimeout between
//     requests. Per-response deadlines can be layered later via http.ResponseController.
const (
	serverReadHeaderTimeout = 10 * time.Second
	serverReadTimeout       = 30 * time.Second
	serverIdleTimeout       = 120 * time.Second

	// serverMaxHeaderBytes caps the total size of a request's header block on the
	// public data-plane listeners (plain :80 and TLS :443/:80), replacing net/http's
	// 1 MiB default. A cache edge only ever needs a few KiB of request headers
	// (method line, Host, a handful of conditional/forwarded/cookie headers), so 64
	// KiB is generous for legitimate traffic while blunting a header-flood DoS that
	// would otherwise force the server to buffer up to 1 MiB per connection. The admin
	// server keeps its own (separate) configuration; this is the data plane only.
	serverMaxHeaderBytes = 64 << 10 // 64 KiB
)

// serverInboundReadTimeout / serverInboundIdleTimeout resolve the inbound (data-plane)
// http.Server timeouts: the global `server { read_timeout/idle_timeout }` knob when set
// to a non-zero value, otherwise the shipped default constant. An absent `server` block
// (cfg.Server == nil) or an omitted field keeps the default, so behaviour is unchanged.
func serverInboundReadTimeout(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.Server != nil && cfg.Server.ReadTimeout > 0 {
		return cfg.Server.ReadTimeout
	}
	return serverReadTimeout
}

func serverInboundIdleTimeout(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.Server != nil && cfg.Server.IdleTimeout > 0 {
		return cfg.Server.IdleTimeout
	}
	return serverIdleTimeout
}

// serverMaxConn returns the configured global inbound connection cap (the `server {
// maxconn N }` knob), or 0 when no block/knob is set (meaning NO limit — the bare
// listener, unchanged).
func (s *Server) serverMaxConn() int {
	if s.cfg != nil && s.cfg.Server != nil {
		return s.cfg.Server.MaxConn
	}
	return 0
}

// dataPlaneListenerWrap returns the composed inbound listener wrapper for the public
// data plane: the opt-in PROXY-protocol reader (when configured) BENEATH the optional
// `server { maxconn N }` connection limiter (golang.org/x/net/netutil.LimitListener).
// It returns NIL when neither feature is active, so the default accept path is the bare
// listener, untouched (zero cost). The limiter is the OUTERMOST wrapper so it bounds the
// number of simultaneously-accepted connections (the PROXY reader runs per accepted conn).
func (s *Server) dataPlaneListenerWrap() func(net.Listener) (net.Listener, error) {
	proxy := s.proxyListenerWrap()
	max := s.serverMaxConn()
	if proxy == nil && max <= 0 {
		return nil
	}
	return func(inner net.Listener) (net.Listener, error) {
		ln := inner
		if proxy != nil {
			wrapped, err := proxy(ln)
			if err != nil {
				return nil, err
			}
			ln = wrapped
		}
		if max > 0 {
			ln = netutil.LimitListener(ln, max)
		}
		return ln, nil
	}
}

func announcedAddr(addr string) string {
	if addr == "" {
		return ":80"
	}
	return addr
}

// Handler exposes the underlying http.Handler (for httptest and embedding).
func (s *Server) Handler() http.Handler { return s.handler }

// MarkWarm marks the data plane READY to serve (idempotent): the reserved
// /.cadish/readyz probe returns 200 instead of 503 once this is called. The
// ingress/gateway controllers call it after their FIRST successful reconcile builds the
// routing table from synced listers; `cadish run` calls it once the server is serving
// (its startup config was applied at construction). It is a single lock-free atomic
// store, safe for concurrent use, and a no-op on every call after the first.
func (s *Server) MarkWarm() { s.handler.warm.Store(true) }

// AccessHub exposes the server's in-memory access-log fan-out (D44), so the run
// command can start the unix-socket stream server `cadish logs` consumes.
func (s *Server) AccessHub() *AccessHub { return s.handler.AccessHub() }

// LiveState returns the current per-site observability state (cache fill) for the
// admin/dashboard surface. See Handler.LiveState.
func (s *Server) LiveState() []SiteState { return s.handler.LiveState() }

// NeedsTLS reports whether the server will bind a TLS listener (any site declares
// `tls` with acme or a static keypair, or ForceTLS / a BYO dynamic cert is set).
func (s *Server) NeedsTLS() bool { return s.mgr != nil && s.mgr.NeedsTLS() }

// SetDynamicCerts injects BYO / cert-manager keypairs (from kubernetes.io/tls
// Secrets) into the live TLS manager — the Ingress controller's typed side-channel
// for spec.tls Secrets (D55). It is a hot swap: the :443 listener, *tls.Config and
// autocert source are untouched, so a Secret rotation takes effect with no restart.
// Fail-safe: any bad PEM returns an error and the previous dynamic set keeps serving.
func (s *Server) SetDynamicCerts(certs []tlsacme.DynamicCert) error {
	return s.mgr.SetDynamicCerts(certs)
}

// SetForceRedirectHosts injects the hosts that should be 301'd HTTP→HTTPS even without
// local TLS — the Ingress controller's side-channel for the `cadi.sh/ssl-redirect`
// annotation. A hot swap (no listener rebuild); an empty slice clears the set. Only
// effective when the redirect is gated (Ingress mode); a nil manager is a no-op.
func (s *Server) SetForceRedirectHosts(hosts []string) {
	if s.mgr == nil {
		return
	}
	s.mgr.SetForceRedirectHosts(hosts)
}

// ListenAndServe starts the server and blocks until Shutdown (or a listener error).
// When any site needs TLS it binds :80 (ACME challenge + HTTPS redirect) and :443
// (hardened TLS); otherwise it binds a single plain-HTTP listener. A clean shutdown
// returns nil.
func (s *Server) ListenAndServe() error {
	if s.NeedsTLS() {
		// Background workers were started in NewServer (fail-fast).
		servers := s.mgr.BuildServers(s.handler, s.httpAddr, s.httpsAddr)
		// tlsacme.BuildServers sets ReadHeaderTimeout + IdleTimeout; add the
		// streaming-safe ReadTimeout too (security review #7). WriteTimeout stays
		// unset so large media downloads over TLS are not truncated. The global
		// `server { read_timeout/idle_timeout }` knob overrides the defaults on BOTH
		// the :80 and :443 servers (an absent knob keeps the BuildServers defaults).
		readTO := serverInboundReadTimeout(s.cfg)
		idleTO := serverInboundIdleTimeout(s.cfg)
		servers.HTTP.ReadTimeout = readTO
		servers.HTTPS.ReadTimeout = readTO
		servers.HTTP.IdleTimeout = idleTO
		servers.HTTPS.IdleTimeout = idleTO
		s.mu.Lock()
		s.tlsServers = servers
		s.mu.Unlock()
		// Install the opt-in PROXY-protocol listener wrapper BENEATH TLS (the wire order
		// is PROXY -> ClientHello -> HTTP). Nil when the feature is off, leaving the bare
		// net.Listen path untouched (zero cost).
		servers.WrapListener = s.dataPlaneListenerWrap()
		if s.log != nil {
			s.log.Info("cadish serving (TLS)", "http", s.httpAddr, "https", s.httpsAddr, "sites", s.handler.siteCount(), "proxy_protocol", s.proxyProtoEnabled())
		}
		// Blocks until servingCtx is cancelled (by Shutdown) or a listener fails,
		// then gracefully drains both servers.
		return servers.ListenAndServe(s.servingCtx)
	}

	ln, err := newHTTPListener(s.httpAddr)
	if err != nil {
		return err
	}
	// Wrap the plain-HTTP listener with the PROXY-protocol reader and/or the
	// `server { maxconn N }` connection limiter when enabled (zero cost / bare
	// listener when off).
	if wrap := s.dataPlaneListenerWrap(); wrap != nil {
		wrapped, werr := wrap(ln)
		if werr != nil {
			_ = ln.Close()
			return werr
		}
		ln = wrapped
	}
	return s.Serve(ln)
}

// Serve serves plain HTTP on an already-open listener (used by tests and by
// ListenAndServe's no-TLS path). The lb/k8s background workers were started in
// NewServer (fail-fast), so Serve only begins accepting connections.
func (s *Server) Serve(ln net.Listener) error {
	if s.log != nil {
		s.log.Info("cadish serving", "addr", ln.Addr().String(), "sites", s.handler.siteCount())
	}
	err := s.httpSrv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// startPools launches cfg's lb/cluster background workers (and, when a k8s:// target
// is present, the shared K8s client + informer cache sync) under a fresh child of
// servingCtx, recording the child's cancel func in poolsCancel so a later Reload (or
// Shutdown) can stop exactly this config's workers. It is called once at construction
// (NewServer) and again on each Reload (for the new config). It returns the config's
// Start error (e.g. a k8s cache that failed to sync) WITHOUT having swapped any state
// beyond rotating poolsCancel; callers decide how to recover.
func (s *Server) startPools(cfg *config.Config) error {
	// Shared (non-pool) workers — K8s client (blocking cache sync, fail-fast) + clusters
	// — run under a per-reload child of servingCtx recorded as poolsCancel.
	ctx, cancel := context.WithCancel(s.servingCtx)
	if err := cfg.StartShared(ctx); err != nil {
		cancel()
		return err
	}
	// Pools run under their OWN child of servingCtx (not the shared ctx above), so a
	// survivor transplanted onto a later config is not stopped when this config's shared
	// ctx is cancelled. Start only pools not already running (a transplanted survivor is
	// already in poolCancels and its startOnce has fired).
	s.mu.Lock()
	for _, p := range cfg.Pools() {
		if _, running := s.poolCancels[p]; running {
			continue
		}
		pctx, pcancel := context.WithCancel(s.servingCtx)
		p.Start(pctx)
		s.poolCancels[p] = pcancel
	}
	s.poolsCancel = cancel
	s.mu.Unlock()
	return nil
}

// stopRemovedPools drains, then stops, the per-pool context of every running pool that
// the now-live config no longer references — the pools a reload removed or rebuilt.
// Survivors and freshly-started added pools (all referenced by live) are kept. It is
// called AFTER the routing swap so no in-flight request can still PICK a removed pool;
// the only requests left on it are the ones already in flight when the swap happened.
//
// Rather than cancel a removed pool's context IMMEDIATELY (which stops its health/resolve
// loops and deregisters its resolver watch, so an in-flight request can no longer
// fail over or learn a re-resolved endpoint), we DRAIN it: each removed pool is forgotten
// from poolCancels right away (so a later reload won't re-handle it) and a bounded
// background goroutine waits until the pool's in-flight count hits zero OR the drain grace
// elapses (whichever first), then cancels the pool context. servingCtx cancellation
// (Shutdown) ends the drain immediately. The goroutines are tracked in drainWG so Shutdown
// joins them (no goroutine leak).
func (s *Server) stopRemovedPools(live *config.Config) {
	keep := make(map[*lb.Upstream]bool, len(live.Pools()))
	for _, p := range live.Pools() {
		keep[p] = true
	}
	grace := reloadPoolDrainGrace // read once so the goroutines don't race the var
	s.mu.Lock()
	var removed []struct {
		pool   *lb.Upstream
		cancel context.CancelFunc
	}
	for p, cancel := range s.poolCancels {
		if !keep[p] {
			removed = append(removed, struct {
				pool   *lb.Upstream
				cancel context.CancelFunc
			}{p, cancel})
			delete(s.poolCancels, p)
		}
	}
	s.mu.Unlock()
	for _, r := range removed {
		s.drainWG.Add(1)
		go s.drainPool(r.pool, r.cancel, grace)
	}
}

// drainPool waits for a removed pool to quiesce (in-flight == 0) or for the drain grace
// to elapse — whichever comes first — and only THEN cancels the pool's context (stopping
// its health/resolve loops and deregistering its resolver watch). It also returns
// immediately if servingCtx is cancelled (Shutdown), so a drain never outlives the server.
// It is race-free: it only reads the pool's atomic in-flight counter and calls the
// already-captured cancel func (idempotent). drainPoolHook, when set (tests), is invoked
// with the pool just before the cancel so a test can observe the drain completing.
func (s *Server) drainPool(p *lb.Upstream, cancel context.CancelFunc, grace time.Duration) {
	defer s.drainWG.Done()
	defer cancel()
	if p == nil || p.Inflight() == 0 || grace <= 0 {
		if drainPoolHook != nil {
			drainPoolHook(p)
		}
		return
	}
	deadline := time.NewTimer(grace)
	defer deadline.Stop()
	tick := time.NewTicker(poolDrainPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-s.servingCtx.Done():
			// Shutdown: stop the pool now (servingCtx cancellation already cancels the
			// per-pool child context, but cancel() is idempotent and keeps the contract).
			if drainPoolHook != nil {
				drainPoolHook(p)
			}
			return
		case <-deadline.C:
			if drainPoolHook != nil {
				drainPoolHook(p)
			}
			return
		case <-tick.C:
			if p.Inflight() == 0 {
				if drainPoolHook != nil {
					drainPoolHook(p)
				}
				return
			}
		}
	}
}

// newHTTPListener opens the plain-HTTP listener.
func newHTTPListener(addr string) (net.Listener, error) {
	return net.Listen("tcp", announcedAddr(addr))
}

// proxyProtoEnabled reports whether the opt-in PROXY-protocol listener is configured.
func (s *Server) proxyProtoEnabled() bool {
	return s.cfg != nil && s.cfg.ProxyProtocol != nil
}

// proxyListenerWrap returns a listener-wrap function that installs the opt-in
// PROXY-protocol reader (REQUIRE-from-trusted policy: a PROXY header is honored ONLY
// from a trusted peer; from anyone else the connection is rejected, so a spoofed
// header can never forge the client IP). It returns NIL when the feature is off, so
// the default accept path is the bare listener, untouched (zero cost).
func (s *Server) proxyListenerWrap() func(net.Listener) (net.Listener, error) {
	if !s.proxyProtoEnabled() {
		return nil
	}
	trust := s.cfg.ProxyProtocol.Trust
	log := s.log
	return func(inner net.Listener) (net.Listener, error) {
		return proxyproto.NewListener(inner, proxyproto.Config{
			Trust: trust,
			OnReject: func(err error) {
				if log != nil {
					// A rejected connection is a security-relevant event (an untrusted
					// peer trying to send a PROXY header, a missing/malformed header from
					// a trusted peer). Log at Warn so operators see spoof attempts.
					log.Warn("proxy-protocol: rejected connection", "err", err)
				}
			},
		})
	}
}

// Shutdown gracefully drains in-flight requests (up to ctx's deadline), stops the
// lb background workers and the origin stall sweeper, and closes the cache stores.
// In TLS mode the cancellation unblocks the tlsacme Servers, which drain themselves.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel() // stop lb workers; unblock tlsacme Servers' run loop

	// Wait for any in-flight removed-pool drain goroutines to finish (they observe
	// servingCtx via s.cancel() above and return promptly) so none leaks past Shutdown.
	s.drainWG.Wait()

	// Drain the plain-HTTP server (a no-op in TLS mode, where it never served).
	err := s.httpSrv.Shutdown(ctx)

	// In TLS mode the in-flight requests live on the :443/:80 tlsacme Servers, NOT on
	// httpSrv. s.cancel() above unblocks their run loop so they drain THEMSELVES on the
	// ListenAndServe goroutine, but that drain runs concurrently with this function:
	// without waiting for it we would close the cache stores + handler machinery (below)
	// — and the cli, which exits the process the moment Shutdown returns — WHILE an HTTPS
	// request is still being served, dropping the in-flight request and tearing down the
	// cache underneath it. Drain the TLS servers here, under the caller's deadline, before
	// any teardown. http.Server.Shutdown is safe to call concurrently with the run loop's
	// own call (both simply wait for the connections to go idle).
	s.mu.Lock()
	tlsSrv := s.tlsServers
	s.mu.Unlock()
	if tlsSrv != nil {
		if herr := tlsSrv.HTTP.Shutdown(ctx); herr != nil && err == nil {
			err = herr
		}
		if herr := tlsSrv.HTTPS.Shutdown(ctx); herr != nil && err == nil {
			err = herr
		}
	}

	s.handler.Shutdown()
	// Read the current config under the lock: a concurrent Reload swaps s.cfg under the
	// same lock. (In practice the cli run loop serializes SIGHUP and SIGTERM, but the
	// guard keeps Shutdown race-clean regardless.)
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cerr := cfg.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// Reload re-reads the Cadishfile from disk, re-parses + recompiles it, and — only if
// it is VALID — atomically swaps the new routing into the live handler. On any
// parse/compile/load error it returns that error and KEEPS SERVING the old config
// unchanged (fail-safe: a bad reload never drops the listener or colds the cache).
//
// What is PRESERVED across a successful reload:
//   - the listeners and all in-flight requests (they finish on the old routing);
//   - the freshness index, request coalescer, background single-flight and stall
//     sweeper (the Handler's shared machinery — never rebuilt);
//   - per surviving site (matched by primary host): its warm cache.Store (so the hit
//     ratio is not lost);
//   - each UNCHANGED lb pool (same name + fingerprint): the live *lb.Upstream with its
//     warm health FSM and goroutines (D58 — steady backends are not re-probed).
//
// What is REBUILT: the compiled pipeline + routing, origins, CHANGED/added lb pools,
// clusters, classifiers, geo sources. The TLS HostPolicy (ACME allow-list + static
// keypairs + HSTS) is RELOADED LIVE via the Manager's atomic hostState (D58) — adding
// or removing a TLS hostname needs no restart; only first-time enabling of TLS/ACME on
// a server started without it does, since the autocert source + :443 listener are fixed
// at startup. The plain-HTTP/admin listeners are untouched.
//
// Reload is safe for concurrent calls (serialized by reloadMu) but is normally driven
// by a single SIGHUP handler.
func (s *Server) Reload() error {
	s.mu.Lock()
	path := s.cfg.ConfigPath
	s.mu.Unlock()

	// Recompile with the SAME run-time options the process started with (chiefly the
	// --kubeconfig path) so a reload does not silently drop them — config.Load == the ZERO
	// LoadOptions, which would rebuild a config-owned k8s client against the default chain
	// instead of the operator's kubeconfig. See specs/.../kubeconfig-lost-on-reload.
	next, err := config.LoadWithOptions(path, s.reloadOpts)
	if err != nil {
		if s.log != nil {
			s.log.Error("cadish reload: keeping old config", "err", err)
		}
		return err
	}
	return s.ApplyConfig(next)
}

// ApplyConfig atomically swaps the server to serve next — an ALREADY-LOADED config —
// preserving the shared datapath machinery (freshness index, request coalescer,
// background single-flights, stall sweeper, metrics, tracer, access hub, audit log,
// rate limiter) and the warm cache stores of sites that survive the swap (matched by
// primary host). It is the seam both Reload (load Cadishfile from disk → ApplyConfig)
// and the ingress controller (translate Ingress objects → config.LoadString →
// ApplyConfig) drive.
//
// It is fail-safe: next's pools are started FIRST, so if next cannot start (e.g. its
// k8s informer caches won't sync) the OLD config keeps serving UNCHANGED and the error
// is returned WITHOUT any swap. ApplyConfig takes ownership of next: on a start failure
// it closes next; on success it tears down the old config (preserving transplanted
// stores) in the background after a drain grace.
//
// ApplyConfig is safe for concurrent calls (serialized by reloadMu).
func (s *Server) ApplyConfig(next *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	old := s.cfg

	// Validate the new TLS host policy (ACME allow-list + static keypairs) UP FRONT,
	// without publishing it: a bad static cert path is a fail-safe error here, leaving
	// the old TLS state and the old config entirely intact (D32). It is committed last,
	// alongside the routing swap, so no step after this can leave TLS half-applied.
	tlsState, err := s.mgr.PrepareReload(next.TLS)
	if err != nil {
		if s.log != nil {
			s.log.Error("cadish apply: new TLS config invalid; keeping old config", "err", err)
		}
		_ = next.Close()
		return err
	}

	// Diff the lb pools against the live config: transplant UNCHANGED pools (same name +
	// fingerprint) onto next by instance identity so steady backends keep their warm
	// health FSM / ejection / goroutines and are NOT re-probed. Done BEFORE startPools so
	// it starts only the genuinely-added/rebuilt pools (survivors are already running and
	// recorded in poolCancels). Removed/rebuilt pools are stopped AFTER the swap.
	next.TransplantPoolsFrom(old)

	// Start the new config's shared workers (k8s informer sync, clusters) and its
	// added/rebuilt pools BEFORE any store transplant or routing swap, so a fail-fast
	// error (e.g. the new config's k8s caches won't sync) leaves the OLD config serving
	// UNCHANGED. On failure startPools cancelled its own shared child context and left
	// poolsCancel + poolCancels pointing at the OLD workers, so we only discard next
	// (closing its freshly opened cold stores) and return. TLS was not committed.
	oldPoolsCancel := s.poolsCancel
	if err := s.startPools(next); err != nil {
		if s.log != nil {
			s.log.Error("cadish apply: new config failed to start; keeping old config", "err", err)
		}
		_ = next.Close()
		return err
	}

	// LOUD-ON-SILENT-DEGRADATION (reload observability). Two reload-time footguns are
	// genuinely no-ops on what gets applied but silently mislead the operator; surface
	// them as WARNINGs BEFORE the transplant overwrites the surviving sites' stores.
	s.warnReloadFootguns(next, old)

	// Move warm cache stores from the old config onto the matching new sites (close +
	// discard the cold stores Load just opened) before swapping routing, so the new
	// routing points at warm caches and the hit ratio survives the swap.
	next.TransplantStoresFrom(old)

	// Atomically swap the routing table, then commit the validated TLS host policy. The
	// :443 listener and its *tls.Config are untouched — only the data the cert/HostPolicy
	// closures read changes, so newly-added TLS hostnames go live with no socket churn.
	s.handler.Reload(next)
	s.mgr.Commit(tlsState)

	s.mu.Lock()
	s.cfg = next
	s.mu.Unlock()

	// Stop the OLD config's shared background workers (k8s + clusters) now that nothing
	// routes to them, then cancel the per-pool contexts of pools the new config no longer
	// references (removed or rebuilt) — AFTER the swap, so survivors are never stopped.
	if oldPoolsCancel != nil {
		oldPoolsCancel()
	}
	s.stopRemovedPools(next)

	// Tear down the old config WITHOUT closing the stores transplanted onto next
	// (they are now live under next.Sites). Build the keep set from next's stores;
	// stores of REMOVED sites (not in keep) get closed by CloseExcept — but only after
	// a short grace window, because a request that selected a now-removed site just
	// before the swap may still be streaming from that store. Preserved (transplanted)
	// stores are never closed regardless. The grace teardown runs in the background so
	// Reload returns immediately; servingCtx cancellation (Shutdown) does not race it
	// because Shutdown drains in-flight requests and the old stores are flushed-on-close
	// idempotently.
	keep := make(map[*cache.Store]bool, len(next.Sites))
	for _, st := range next.Sites {
		if st.Store != nil {
			keep[st.Store] = true
		}
	}
	grace := reloadDrainGrace // read once, here, so the goroutine doesn't race the var
	go func() {
		// Let in-flight requests on the previous routing drain off any removed store.
		time.Sleep(grace)
		if cerr := old.CloseExcept(keep); cerr != nil && s.log != nil {
			s.log.Warn("cadish reload: closing old config", "err", cerr)
		}
	}()

	if s.log != nil {
		s.log.Info("cadish config applied", "config", next.ConfigPath, "sites", s.handler.siteCount())
	}
	return nil
}

// warnReloadFootguns emits a high-signal WARNING for the two reload-time changes that
// cadish CANNOT apply live but that look applied to the operator (silent degradation):
//
//  1. A surviving site's cache RAM/disk BUDGET or disk PATH changed. cache.Store has no
//     live resize, so TransplantStoresFrom carries the OLD store unchanged — the resize
//     takes effect only on a full restart. Gated on the actual budget/path values
//     (config.CacheBudgetChanges), so it fires ONLY when a value really changed, never on
//     an unrelated reload. Called BEFORE TransplantStoresFrom, while next still holds the
//     cold stores' new budget/path.
//  2. The new config NEEDS TLS but the server started PLAIN (no :443 listener bound). The
//     routing swaps, but HTTPS never serves: the :443 listener and the autocert source are
//     fixed at startup. Gated on "started plain AND new config needs TLS", so a plain→plain
//     reload is silent and a TLS-at-startup server never warns.
//
// It changes NOTHING about what is applied — observability only.
func (s *Server) warnReloadFootguns(next, old *config.Config) {
	if s.log == nil {
		return
	}
	// #1 cache budget/path resize ignored until restart.
	for _, ch := range next.CacheBudgetChanges(old) {
		s.log.Warn("cadish reload: cache budget/path change is ignored until restart (cache.Store has no live resize); the running cache keeps its old size/path",
			"site", ch.Host,
			"changed", strings.Join(ch.Details, ", "))
	}
	// #2 newly-needed TLS not served because the server started plain.
	if !s.tlsBoundAtStart {
		if hosts := tlsHostsNeedingTLS(next.TLS); len(hosts) > 0 {
			s.log.Warn("cadish reload: new config declares TLS but the server started without a :443 listener; HTTPS will NOT be served until a restart (the :443 listener and ACME source are bound at startup)",
				"hosts", strings.Join(hosts, ", "))
		}
	}
}

// tlsHostsNeedingTLS returns every host across sites that terminates TLS (ACME or a
// static keypair) — i.e. the hosts that require a bound :443 listener. ModeOff sites
// contribute nothing. Used to detect (and name) a plain→TLS reload footgun.
func tlsHostsNeedingTLS(sites []tlsacme.SiteConfig) []string {
	var hosts []string
	for _, sc := range sites {
		if sc.TLS.Mode == tlsacme.ModeACME || sc.TLS.Mode == tlsacme.ModeStatic {
			hosts = append(hosts, sc.Hosts...)
		}
	}
	return hosts
}

// reloadDrainGrace is how long Reload waits before closing the cache stores of sites
// REMOVED by a reload, so a request that selected a removed site just before the swap
// finishes streaming first. Preserved stores are never closed, so this only affects
// the (rare) removed-site case. It is a var only so tests can shrink it.
var reloadDrainGrace = 5 * time.Second

// reloadPoolDrainGrace is how long stopRemovedPools lets in-flight requests on a pool
// REMOVED by a reload finish before it cancels that pool's context (stopping its
// health/resolve loops + deregistering its resolver watch). It matches the store drain
// grace and the typical Kubernetes terminationGracePeriod (a few seconds): new requests
// already stopped routing to the removed pool at the swap, so this only bounds the tail of
// in-flight requests. The pool is cancelled EARLY the moment in-flight hits zero. It is a
// var so tests can shrink it; Shutdown ends every drain immediately regardless.
var reloadPoolDrainGrace = 5 * time.Second

// poolDrainPollInterval is how often a draining pool's in-flight count is polled so the
// pool is cancelled promptly once it quiesces (well before the full grace elapses).
var poolDrainPollInterval = 25 * time.Millisecond

// drainPoolHook, when non-nil, is invoked with a removed pool just before its context is
// cancelled at the end of its drain. Tests set it to observe drain completion; it is nil
// in production (zero cost).
var drainPoolHook func(*lb.Upstream)
