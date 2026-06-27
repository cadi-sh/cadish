# `internal/server` + `internal/config` — the caching reverse proxy (M5b/M5c)

This is the layer that makes cadish serve traffic: it wires the pure pipeline
engine (`internal/pipeline`), the two-tier cache (`internal/cache`), the origin
layer (`internal/origin`), TLS termination (`internal/tlsacme`) and load balancing
(`internal/lb`) into a live `net/http` handler. `internal/config` loads a Cadishfile
and turns each site block into a runtime `*config.Site` the server executes.

M5b delivered the plain-HTTP caching proxy; **M5c wired in TLS termination + ACME
and the `lb.Upstream` load balancer** (see the *TLS termination* and *Origin
composition* / *LB routing-key seam* sections below).

---

## Request lifecycle (as implemented)

```
ServeHTTP(w, r)
  0. READYZ          reserved /.cadish/readyz warm-readiness probe, intercepted at the
                     very top — before site select / security / ACL / cache / access log.
                     200 "ok" once Server.MarkWarm() has been called, else 503 "warming".
                     Host-agnostic, any method, never reaches an origin (see below).
  1. SELECT SITE     by Host (exact → "*." wildcard → single-site fallback)
  2. EvalRequest     respond | purge | pass | request header ops | cache_key
       • respond     → write the synthetic response, done (no cache, no origin)
       • purge       → drop the freshness marker for the key, 200 (see Purge note)
       • pass        → ORIGIN, stream, never store
  3. LOOKUP(key)     consult the freshness index + cache.Store
       • FRESH       → serve from cache (Range/206 aware)            [HIT]
       • STALE/grace → serve stale from cache + ONE async revalidate [HIT-STALE]
       • MISS/expired→ ORIGIN
  4. ORIGIN          single-flight coalesced fetch
       • EvalResponse(status) → TTL / Grace / HitForMiss / Cacheable
       • stream body to client while teeing into cache.Store.Writer
       • commit on full body; ABORT on truncation/error (never cache a partial)
  5. DELIVER         EvalDeliver → response header ops, strip_cookies, CORS,
                     cache-status header (HIT/MISS/HIT-STALE)
  6. ACCESS LOG      one slog line: method host path status bytes cache upstream dur
```

### Warm-readiness gate (`/.cadish/readyz`)

The reserved `/.cadish/readyz` path (step 0 above) is a warm-readiness gate for the
Kubernetes ingress/gateway controllers. A `Server`/`Handler` starts **not warm**;
`Server.MarkWarm()` (idempotent, a single atomic store) flips it. The controllers call it
after their **first successful reconcile** builds the routing table from synced listers;
`cadish run` calls it once the server is serving (its startup config was applied at
construction). The probe is intercepted before host routing, the security gate, the `ip`
ACL, rate-limit, the cache, and the access log/trace, so it is never gated, cached, or
logged and never touches an origin. The controller manifests' `startupProbe`/
`readinessProbe` use it (`httpGet`); `livenessProbe` stays TCP (process-alive, not warm).

### Freshness index (why it exists)

`cache.Store`/`cache.ObjectMeta` carry **no TTL/expiry** — they store only
`Key/Size/ContentType/ETag/LastModified`. The pipeline decides TTL, grace and
hit-for-miss per *response* (`EvalResponse`), so the server keeps a sharded,
memory-only **freshness index** (`freshness.go`) keyed by cache key that records,
per stored object: `expires` (storedAt+TTL), `graceUntil` (+grace), and any
`hit-for-miss` window. LOOKUP classifies fresh / stale-in-grace / expired from it.

Consequences:
- A process restart loses the index. A disk-persisted blob with no freshness entry
  is treated as **expired** and revalidated on first access — never a stale hit,
  only a re-fetch.
- Entries are pruned lazily on access once fully past grace.

### Coalescing (thundering-herd guard)

`coalesce.go` single-flights the origin fetch per cache key: the first request for a
cold key is the **winner** (fetches + serve-and-caches); concurrent duplicates are
**waiters** that block until the winner finishes and then read the now-populated
object from cache. If the winner fails or its object isn't cached, waiters fall
through to their own fetch. Range requests and non-GET methods bypass coalescing (a
partial body must never populate the shared full-object cache).

Background (grace) revalidations are coalesced separately (`singleFlight`): at most
one in-flight revalidation per key, detached from the triggering client's context.

### Origin stall watchdog

`idlereader.go` aborts an origin body that
stalls mid-stream for longer than `Options.IdleTimeout` (the origin layer bounds
only connection establishment, not the body transfer). A reaped body errors the
in-flight read, which aborts the cache tee → a stalled stream is never committed.
`0` disables it (the M5b default in tests; `cadish run` defaults to 60s).

### Serve-and-cache / truncation safety

The body is streamed to the client through an `io.TeeReader` into a
`cache.Store.Writer` (`tee.go`). The write is **committed only** when the copy
finished cleanly *and* the bytes received match the origin `Content-Length`
(`complete`). Any read error, cache-write error, or short body **aborts** the
writer — a truncated object is never served as a hit later. Only `200` full
responses with a positive `cache_ttl` are cached; `206` partials and `pass`
responses are never stored.

---

## Config loading (`internal/config`)

`config.Load(path)` does, once at startup, per site:

1. `pipeline.SpliceImports` (resolving `import` relative to the config dir) **before**
   `pipeline.Compile` — a leftover `import` is a compile error.
2. `cadishfile.SubstituteEnv` resolves `{$ENV}` placeholders against the process env.
3. Builds a `cache.Store` from the `cache { ram …; disk PATH …; tier … }` block.
4. Builds the origin(s) from `upstream`/`origin chain`.

Errors carry source positions (`file:line:col`).

### Cache block → `cache.Store`

| Directive | Effect |
|---|---|
| `ram SIZE` | RAM-tier byte budget (`2GiB` default if `cache` omitted) |
| `disk PATH SIZE` | NVMe-tier directory + budget |
| `tier EXT… -> ram\|disk` | validated; see note |

Sizes accept binary (`KiB/MiB/GiB/TiB`) and decimal (`KB/MB/GB/TB`) suffixes and
fractions (`1.5GiB`). A site with no `disk` still gets a working store: a scratch
temp dir backs the disk tier (removed on `Config.Close`) and a zero disk budget
means large objects stream through uncached.

> **`tier` / `storage` placement.** Placement is **wired**. The cache's default
> routing (always-RAM extensions + a small-object threshold) is overridden by, in
> priority order: the pipeline's `StoreTier` decision from a `storage <selector>
> -> ram|disk` rule (passed through `cache.ObjectMeta.Tier`), then a
> `cache { tier .ext -> ram|disk }` per-extension default. Both apply safety
> fallbacks so an object is never cached *nowhere* (a forced-RAM object larger than
> the per-object RAM cap, or a forced-disk object on a RAM-only deployment, falls
> back to the other tier).

### Origin composition (M5c)

- `upstream NAME { to URL; bucket B }` → `s3origin`.
- `upstream NAME { … sign cloudfront … }` → a `cfsign.Origin` that **re-signs** each
  request URL with the CloudFront private key before fetching (real CloudFront
  re-signing — the S3-miss → CloudFront-resign fallback). It is a plain
  `origin.Origin`, so it composes inside an `origin chain`.
- A **trivial** `upstream NAME { to URL }` — exactly one backend and no
  load-balancing directives — → a plain `httporigin`, so the common single-origin
  hot path never pays for the lb pool machinery.
- Any other `upstream`/`cluster` (multiple `to`, or `sticky`/`health`/`shard_by`/
  `policy`/`timeout`/`max_conns`) → an **`lb.Upstream`** (load balancer):
  round-robin by default, or `least_conn` / `sticky` / `shard` per the block, with
  active `health` probes, passive ejection, per-backend timeouts/`max_conns`, and
  dynamic `dns://` re-resolution.
- `origin chain A -> B [-> C]` → `chain.New` over the named origins (the default).
- Multiple upstreams, no chain → first declared is the default; all remain
  selectable by a `route @m -> NAME` decision (the handler's `originFor` uses
  `RequestDecision.Upstream`).

### TLS termination (M5c)

`config.Load` builds a `tlsacme.SiteConfig` per site from its `tls` directive. The
server constructs a `tlsacme.Manager`; if any site needs TLS it binds **`:443`**
(hardened TLS termination + ACME issuance/renewal, dispatching certs by SNI between
autocert and static keypairs) plus **`:80`** (ACME HTTP-01 challenge +
`301`→HTTPS), with per-host HSTS on HTTPS responses. With no TLS site it serves a
single plain-HTTP listener. The site handler (the whole caching lifecycle) is
identical in both modes.

### LB routing-key seam (M5c)

For `sticky` / `shard_by key` pools the balancer needs a per-request key the server
computes. Before `Upstream.Fetch`, the handler derives the `{sticky}` value from the
routed upstream's `StickySpec` (the configured cookie, with its `else` fallback) —
or the client IP as a best-effort default — and attaches it with
`lb.WithRoutingKey(ctx, key)`. round-robin / shard-by-url pools and plain origins
ignore it. lb background workers (health probing, dns re-resolution) run for the
server's lifetime, cancelled on `Shutdown`.

---

## Public API

```go
// internal/config
func Load(path string) (*Config, error)
func (c *Config) Close() error           // closes every site's store + temp dirs
func (c *Config) CloseExcept(keep map[*cache.Store]bool) error  // close all but preserved stores (reload)
func (c *Config) TransplantStoresFrom(old *Config)              // move warm stores onto matching new sites (reload)
type Config struct { Sites []*Site; TLS []tlsacme.SiteConfig }
func (c *Config) Start(ctx context.Context) error  // launch lb health/resolve workers
type Site struct {
    Addresses           []string
    Name                string
    Pipeline            *pipeline.Pipeline
    Store               *cache.Store
    Origin              origin.Origin             // default backend (single upstream or chain)
    Origins             map[string]origin.Origin  // per-upstream, for routed selection
    DefaultUpstreamName string                    // default origin's upstream name ("" for a chain)
    StickySpecs         map[string]*lb.StickySpec // sticky pools' routing-key specs
}

// internal/server
func NewServer(cfg *config.Config, httpAddr string, opts Options) (*Server, error)
func (s *Server) ListenAndServe() error          // binds :80 (+ :443 when TLS), serves until Shutdown
func (s *Server) Serve(ln net.Listener) error    // serve plain HTTP on a pre-opened listener (tests)
func (s *Server) Handler() http.Handler
func (s *Server) NeedsTLS() bool
func (s *Server) Shutdown(ctx context.Context) error  // drain + stop lb/sweeper + close stores
func (s *Server) Reload() error                       // re-read Cadishfile, atomically swap routing (fail-safe)

func NewHandler(cfg *config.Config, opts Options) *Handler   // the bare http.Handler
func (h *Handler) ServeHTTP(w, r)
func (h *Handler) Reload(next *config.Config)         // atomic routing swap; cache transplant runs first
func (h *Handler) Shutdown()

type Options struct {
    Logger              *slog.Logger
    Now                 func() time.Time // injectable clock (freshness)
    IdleTimeout         time.Duration    // origin stall watchdog (0 disables)
    BgRevalidateTimeout time.Duration    // grace revalidation deadline (30s default)
    HTTPSAddr           string           // TLS listen address (":443" default)
    ACMECacheDir        string           // ACME cert cache dir (empty = default)
    ACMEDirectoryURL    string           // ACME directory (empty = Let's Encrypt prod; set for pebble/staging)
}
```

`cadish run -config FILE [-addr :80] [-https-addr :443] [-idle-timeout 60s]
[-acme-cache DIR] [-access-log off] [-log-socket PATH] [-trace] [-pidfile FILE]
[-max-request-body SIZE]`
loads the config, builds a `Server`, listens (plain HTTP, or :80+:443 when a site
declares `tls`), and shuts down gracefully on SIGINT/SIGTERM.

**Request-body limit.** `-max-request-body SIZE` (e.g. `25MiB`) caps the client
request body the proxy reads and forwards to origin; an oversized body is rejected
with `413`. It applies only to body-carrying methods (never `GET`/`HEAD`). The
default is **unlimited** (`0`/empty) — deliberate for a media/streaming edge, where
the body is streamed straight through at zero extra cost. **For non-streaming
deployments (APIs, forms) set an explicit cap** to bound upload memory/abuse.

### Hot reload (SIGHUP, zero-downtime)

`cadish run` re-reads and recompiles its Cadishfile on **SIGHUP** and **atomically
swaps** the routing in place — a zero-downtime hot config swap. Send it with
`kill -HUP <pid>` or, when the server was started with
`-pidfile FILE`, with `cadish reload -pidfile FILE` (or `cadish reload -pid N`).
Reload always re-reads **the same config path the server was started with** — there
is no `cadish reload -config NEW.Cadishfile`. To change the config, overwrite that
file in place first, then signal the reload.

The swap is a single `atomic.Pointer[routing]` store on the `Handler`: `ServeHTTP`
loads the pointer once per request, so an **in-flight request finishes on the routing
it already loaded** while new requests immediately see the new config. The listeners
and connections are never dropped.

**Preserved across a reload (never rebuilt):**

- the listeners + all in-flight requests;
- the `Handler`'s shared datapath machinery — the **freshness index**, request
  coalescer, background single-flight, and origin stall sweeper;
- per surviving site (matched by its **primary host** = first address), its warm
  **`cache.Store`** (so the hit ratio is *not* lost — the reload does **not** cold the
  cache).

**lb pools are diffed, not rebuilt wholesale (D58).** Each upstream gets a content
**fingerprint** (name + the order-insensitive target set + policy/shard/replicas + the
full health spec + host-header/max_conns/timeouts). An upstream whose fingerprint is
unchanged is **transplanted** — the *same* `*lb.Upstream` instance carries over, keeping
its warm health FSM, ejection windows, consistent-hash ring and running goroutines — so
a reload that changes something unrelated never re-probes a steady backend. Only
genuinely added or changed pools build + start (*before* the swap); removed/changed-out
pools stop (*after* the swap), via per-pool contexts, so no request routes through an
unstarted or stopped pool and survivors are never interrupted. A removed pool is **drained,
not cut**: the routing swap stops new requests from selecting it, and the per-pool context
is cancelled only once the pool's in-flight count hits zero **or** a bounded drain grace
elapses (default a few seconds, matching the store drain / Kubernetes
`terminationGracePeriod`), so an in-flight request started before the swap finishes against
the removed pool. The drain goroutine is tracked and joined at `Shutdown` (no goroutine
leak) and ends immediately when serving is cancelled.

**Rebuilt:** the compiled pipeline + routing, origins, *changed* lb pools, clusters,
classifiers, geo sources.

**TLS hostnames reload live (D58).** The TLS `HostPolicy` (ACME allow-list), the static
keypair set and the HSTS policies live behind an `atomic.Pointer`; `Manager.Reload`
rebuilds and atomically swaps them, so **adding or removing a TLS hostname is a hot
reload** — a newly-added ACME/static host becomes serveable immediately, a removed one
stops, and existing hosts are undisturbed. The **autocert.Manager, the `:443` listener
and its `*tls.Config` are never rebuilt** (no socket reopened, in-flight TLS connections
untouched); a bad static keypair path is a fail-safe reload error (the old host set is
kept). *Limitation:* enabling TLS/ACME (or the first HSTS policy) on a server that
started **without** TLS still needs a restart — the autocert source, the `acme-tls/1`
ALPN advertisement and the HSTS middleware are fixed with the listener at startup.

**Fail-safe:** if the new Cadishfile fails to parse/compile/load, or the new TLS config
has a bad static keypair, or the new config's pools can't start (e.g. a k8s informer
cache won't sync), `Server.Reload` / `ApplyConfig` logs the error, returns it, and
**keeps serving the old config** unchanged — a bad reload never crashes the process or
drops the listener, and nothing is half-applied (the TLS state is validated up front and
committed last, alongside the routing swap).

Mechanically (the shared `ApplyConfig` path used by both SIGHUP `Server.Reload` and the
[Ingress controller](ingress-controller.md)): validate the new TLS host policy (`mgr.PrepareReload`),
`next.TransplantPoolsFrom(old)` to carry over unchanged pools (repointing the origin
graph at the survivors), `s.startPools(next)` to start the shared workers + only the
added pools, `next.TransplantStoresFrom(old)` to move each surviving site's warm store
onto the new config (closing + discarding the cold store `Load` just opened), then the
atomic `Handler.Reload` routing swap + `mgr.Commit` TLS swap, then the old config's
shared workers stop and removed pools are **drained then cancelled** (`stopRemovedPools`
forgets each removed pool and a bounded background goroutine waits for its in-flight to
quiesce before cancelling its context), and the old config is torn down with
`Config.CloseExcept(keep)` so the transplanted stores are **not** closed.

### Observability flags (live debug logging — access tail + decision trace)

cadish keeps the access log **in memory** and streams it to `cadish logs` over a unix
socket — it **never writes the access log to disk** (a memory-only access-log model). The hot
path checks one atomic ("any consumer attached?") and does nothing when idle; persist
by redirecting the consumer (`cadish logs > access.log`).

| Flag | Effect |
|---|---|
| `-log-socket PATH` | The unix socket `cadish run` listens on (and `cadish logs` dials) for the live access-log stream. Default: a **per-instance** path under `${TMPDIR}` keyed on the listen address — `${TMPDIR}/cadish-access-<hash>.sock` (fallback dir `/tmp`) — so two co-located instances don't clash on one socket; override with `$CADISH_ACCESS_SOCKET`. Local-only, created `0600`. Always on unless `access_log off`. |
| `-access-log off` | Disable the in-memory access-log hub entirely — even an attached `cadish logs` consumer receives nothing, and the hot path's only cost is the idle atomic check. (Also settable as the global `access_log off` Cadishfile option.) **The old `-access-log FILE` form is removed**: the server no longer writes the access log to a file; persist via `cadish logs > access.log`. |
| `-trace` | Emit a **per-request decision trace** to stderr: the matched route, computed cache key, LOOKUP outcome, `EvalResponse` ttl/grace/hit-for-miss, pass reason, routed upstream, and body transforms — one transaction block per request. Opt-in only; the trace seam is a nil-checked pointer with **zero cost when off** (mirrors the metrics seam). `CADISH_TRACE=1` is an env alias. |

The trace hooks live at each decision point in `internal/server/handler.go`
(RECV/KEY/LOOKUP/ORIGIN/RESP/DELIVER); the seam itself is `internal/server/tracer.go`.

---

## Seams left for later milestones

- **Purge eviction.** `cache.Store` exposes no key-delete, so an authorized `purge`
  currently drops the **freshness marker** (forcing a revalidation) and returns 200;
  true blob eviction awaits a cache `Delete`/ban API.
- **Negative caching of error statuses (implemented, full-body).** When
  `EvalResponse(status)` marks a failing status cacheable (e.g.
  `cache_ttl status 404 410 ttl 60s grace 1h`), the server stores a negative entry
  under the key — `ObjectMeta.Status` records the code (zero ⇒ 200 for
  positive/legacy entries) — and serves it from cache thereafter (a negative HIT),
  so a deleted object's 404/410 is not re-fetched on every request. An **HTTP
  origin returns a 404/410 as a full-body `*Response` (`Response.Negative`)**, so
  the server caches its **real error-page body + headers** through the *same
  streaming tee path* as a 200 (gated on the same `EvalResponse` cacheability +
  `resp.Negative`) and serves them **verbatim** on a HIT (backlog #21). A
  not-found with no usable body (S3 `NoSuchKey` → `ErrNotFound`, or a transport
  status with no response) takes the **bodyless** negative path in
  `handleOriginError` — `ObjectMeta{Status, Size:0}`, committed empty. Background
  revalidation of a stale 200 likewise **replaces** it with a negative entry when
  the origin now returns a cacheable 404/410. `hit_for_miss` on a transient status
  (e.g. `status not 200 hit_for_miss 5s`) is still honored for non-cacheable
  statuses: it records a short-lived "don't cache this key" decision so the bad
  response is never stored or served (no key poisoning). It does **not** suppress
  the origin re-fetch and does **not** coalesce concurrent error fetches — every
  request re-fetches from origin while the decision holds.
- **Query-string forwarding.** `origin.Request` fetches by path/key; the query is
  part of the cache key (via `cache_key`) but is not forwarded to the origin in M5b.
```
