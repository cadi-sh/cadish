# Changelog

All notable changes to cadish are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and cadish follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] — 2026-06-30

Clustering hardening for the single-location, multi-node "one sharded cache" use case
(`cluster { } mode owner`). Surfaced by exercising a real 3-node cluster on staging: the
in-process tests passed but the binary, behind a shared client hostname, fetched every
object from origin twice. Two latent owner-mode bugs found and fixed, plus the read-through
`pass` symmetry. All changes are gated by the `cluster` block — a non-clustered cadish is
byte-for-byte unchanged.

Also in 0.2.2: a **Cadish Edge** batch that lets the edge tier cache a real production
workload it previously could not. On a high-cardinality media workload, `cadish edge build`
went from **22 forced-pass directives** (a single forced-pass on a selecting directive
fail-opens the whole site → the edge caches nothing) down to a small residual that **correctly
delegates** to the Cadish server behind — chiefly an age-gate classifier keyed on an `ip`
override, which the edge cannot evaluate and must (soundly) hand back to the server rather than
cache a divergent variant. Every change is conformance-proven byte-identical between the Go
pipeline and the JS worker; the IR contract moved `v6 → v9` (additive fields only).

### Added
- **`all` (AND-composite) and `query` (named-value) matchers are now edge-native.** Both were
  previously server-only (`serverOnly`), so any config using `all @a @b` selectors or a
  `query NAME VALUE` test fail-opened the edge to a site-wide pass. The projector now emits an
  `all` matcher's sub-terms (`Matcher.subs`, with per-term negate) and the worker evaluates both;
  an `all` whose sub is itself fail-closed (an `ip`/regex it cannot honor) still fails closed, so
  the edge never silently mis-decides. (IR v7.)
- **`query_present` gains a per-name non-empty-value modifier (`+`).** `query_present adult_content+ ff-*+`
  matches only when the named/globbed param is present **with a non-empty value** (Varnish `=[^&]+`
  parity), so a marketing/`publi` flag no longer over-fires on `?adult_content=`. Server + edge.
- **`redirect … no_store` modifier.** Marks a personalized redirect uncacheable: the short-circuit
  3xx response carries `Cache-Control: no-store, no-cache, must-revalidate, private`. Server + edge.
- **`+cache_age` deliver special and `{device}` / `{geo*}` / `{query.NAME}` template tokens.** `header +cache_age NAME`
  emits a cached object's age in whole seconds on a HIT (absent on MISS); `{device}`, `{geo}`/`{geo.continent}`/
  `{geo.region}` and `{query.NAME}` are usable in `header`/`redirect` values. Reproduces the original worker's
  `X-CF-Cache-Age` / `X-CF-Vary-*` debug headers. Server + edge. **Cache-safe by construction:** a class token
  (`{device}`/`{geo*}`, or a `{classify.NAME}` that buckets on one) reflected in a **request-phase** header
  (forwarded to origin) is rendered **empty unless the SELECTED `cache_key` recipe varies on that class** — so
  the origin can never serve class-specific content that is then cached under a class-independent key (a cross-
  device / cross-region cache leak). Response-phase headers and redirect targets always resolve (they are
  applied per request at delivery and never poison a shared entry). `cadish check` warns when an unkeyed class
  token is forwarded to origin. The edge worker derives the same per-request keyed-class set from the selected
  recipe, so server and worker neutralize identically (IR v9).
- **`cadish edge deploy -origin passthrough` (fetch-through mode).** Fronts a multi-host origin in
  the **same Cloudflare zone**: the worker fetches the original request URL verbatim (host **and**
  scheme preserved) and reaches the real origin via CF same-zone loop-prevention, instead of
  rewriting the authority to a backend host. Rewriting the host (the default, for a *separate*
  cadish server behind) makes a canonicalizing origin (apex→www, http→https) redirect-loop forever
  because CF `fetch()` ignores a Host-header override — `passthrough` is the fix. An empty origin
  binding now throws loudly rather than silently passing through; passthrough is opted into only by
  the explicit sentinel.
- **`cadish edge deploy -allow-public-values`.** Acknowledges that a config carries **non-secret**
  literal cookie/header values (e.g. `userType`, `AdultContent`, `verified-prod`) so the deploy
  safety gate does not reject them. Relaxes only the secret-looking-literal (`ValueExposed`) gate —
  it does **not** relax `ForcedPass` (a forced-pass directive still fails the build).
- **Edge worker-route exclusions — skip the worker for paths it only ever passes.** Two ways:
  opt-in `edge { bypass_passes }` (cadish auto-derives the path-only-`pass` patterns) and
  `edge { bypass PATTERN… }` (operator-declared, the HAProxy `path_beg`-bypass analog). Both
  project the patterns as Cloudflare routes that match but run **no worker**, so those paths skip
  the worker and CF proxies them straight to origin (no wasted invocation/hop). Because the edge is
  **additive** — the cadish server behind reproduces request/response headers, routing, `cors`,
  `replace`, `strip_cookies` — only a path the edge would **cache** (scoped) or **short-circuit**
  (redirect/respond) is disqualified; a conditional or non-glob-reducible pass is too. `cadish edge
  build` **always** reports the excludable set + warns if an explicit `bypass` shadows a cached path.
  Routes are created on `enable`, removed on `disable` (default off). IR v7→v8.
- **`X-Cadish-Edge` response marker.** The edge worker stamps `X-Cadish-Edge` (the CF colo) on every
  response it serves, so its **absence** identifies a response served directly by the origin (a
  `bypass`ed path) — the reliable "did the worker run?" signal the server's own `+cache_status`
  header can't give. Edge-only, always on.

### Security
- **`cache_credentialed`: cross-user cache leak on a no-signal response — fixed (fail-closed).**
  In a `cache_credentialed @scope` the per-response origin signal (`from_header X-Cache-Ttl`) is
  by design the **sole** storage gate, but the response phase only enforced it on the positive
  path. A credentialed in-scope response that carried **no** signal yet was made cacheable by a
  co-existing `cache_ttl default ttl N` (and had no `Set-Cookie`/`Vary`) stayed cacheable and was
  stored under the **shared**, credential-free key — serving one user's private body to the next.
  The response phase now refuses unconditionally when a request is in a credentialed scope without
  the per-response signal. Server **and** edge worker (both had the identical fail-open); the
  conformance golden had encoded the leak, so the Go≡JS check passed while both engines leaked
  (it was present since 0.2.1). Regenerated.
- **Admin `/api/config`: absolute path disclosure in diagnostic messages — fixed.** The
  config-redaction helper scrubbed a diagnostic's *position* but not its *message*, so a failed
  `import`/`ca_file` (`open /abs/path/frag.cadi: …`) leaked the host directory layout to an admin
  token holder. The message is now scrubbed too.
- **Open redirect via a regex capture in a `redirect` target authority — fixed.** A `redirect`
  whose TARGET placed a `$N` capture (or a request-sourced token) in the Location **authority**,
  e.g. `redirect (?i)^(/.*?)?/index\.php(.*)$ 301 https://{host}$1$2?{query}`, could be driven to
  an off-origin host: `GET /index.php@evil.example.com/` expanded to
  `Location: https://{host}@evil.example.com/` — the validated `{host}` becomes mere *userinfo*
  and the attacker string the real navigation origin. The compile-time guard validated only the
  **static** template authority (treating `$N`/literals as inert), so it missed this. A new
  **runtime post-expansion authority assertion** (server `redirectRule.eval` + edge `evalRedirect`,
  byte-identical, conformance-proven) re-expands the target with every request-sourced input
  neutralized (captures + request tokens → empty; the validated host family + scheme kept) and
  **suppresses** the redirect if the resulting authority differs — closing this class generally,
  including the latent relative-target variant (`redirect 302 {query.next}` + `?next=//evil`).
  Hardened further (follow-up adversarial review): the guard now normalizes the expanded
  Location to exactly the bytes the HTTP layer transmits — stripping embedded TAB/LF/CR/FF/NUL
  and trimming **every** leading/trailing byte `<= 0x20` (ASCII space plus the whole C0 control
  range, e.g. a leading vertical-tab `?next=%0b//evil`) — *before* the authority check and
  emission, so a value the wire/UA strips can no longer hide an off-origin authority from the
  inspector. Server + edge, byte-identical.

### Fixed
- **Clustering: objects are now cached *once* per region (store-once restored).** When a
  non-owner reverse-proxied a request to the owning peer, the proxy dropped the original
  client `Host` and client IP, so the owner computed a *different* cache key for a proxied
  request than for a direct one — storing the object twice on the owner (once per host, and
  again per client IP for `{geo}`/`{sticky}` keys) and doubling origin load. cadish now
  forwards the client `Host` and the resolved client IP (`X-Forwarded-For`) on the peer hop
  so proxied and direct requests hash to the same key. (Requires the peer subnet in
  `trust_proxy` — already required for the hop guard — and isolated; the forward also
  overwrites any client-forged `X-Forwarded-For`, closing a peer-hop spoof.) [D103]
- **Clustering: correct client IP for owner-side ACL / rate-limit / geo decisions.** Same
  root cause — the owner previously saw the *peer's* IP for a proxied request, so an `ip`/
  `geo` ACL, a rate-limit bucket, or a `{geo}` lookup evaluated against the peer node rather
  than the client. The forwarded client IP fixes this. [D103]
- **Clustering: a `pass` request no longer hops to a peer in `read_through` mode.** It now
  goes straight to origin in both modes (owner mode already did), matching the operator's
  intent that only cacheable routes are sharded. A "possibly cacheable" request (including
  `cache_credentialed`) still routes to the owner. [D102]
- **Clustering: writes (POST/PUT/…) in `read_through` mode reach origin intact.** Only
  cacheable GET/HEAD are peer-routed; a write now goes straight to the local origin instead of
  being sharded to a peer (where a peer outage could surface as a 404 with the request body
  already consumed). A peer/loop/self/bypass decline is signalled with a dedicated "skip"
  sentinel so the origin chain falls through to the real origin even for a body-carrying request.
- **Clustering: a read-through never dials itself under a flapping owner.** The self-fetch
  guard now resolves the owner *health-aware* (matching where the request would actually
  route) and self is excluded from the peer routing decision intrinsically, so a brief
  owner health flap can no longer route an object back to the local node and stall on the
  coalescer.

### Notes
- A new 3-node single-location **clustering deployment guide** (DNS round-robin entry +
  `/.cadish/readyz` health, the two-health-layer model, trust+isolate requirement) is in
  `deploy/README.md`; the `cluster { }` reference documents the pass behavior and store-once
  trust requirement. Request **scheme** is not reconstructed across the plain-HTTP peer hop
  (not a cache-key input) — prefer a uniform-scheme entry such as DNS round-robin.

## [0.2.1] — 2026-06-27

A batch of capabilities surfaced by consolidating a real multi-tier caching, TLS, and
load-balancing stack into a single cadish process. Every one is **fail-closed and costs
nothing when unused** — the request/response fast path is byte-for-byte unchanged unless you
reach for the feature. All are mirrored in the
Cloudflare-Workers edge tier where they apply (server-only ones are explicitly delegated),
with Go↔JS conformance kept in lockstep.

### Added
- **Normalized cookie vary** — `classify {TOKEN} { derives_from cookie NAME… }` derives a
  low-cardinality cache axis from per-user cookies, then **strips those cookies** and keys by
  the normalized axis (the classic cardinality collapse, e.g. 1.2M → ~64 variations). The strip is the single
  load-bearing safety mechanism: the origin sees an anonymous request and a per-user body can
  never land under the shared key. Any cookie you don't declare-and-key still bypasses. An
  explicit `derives_from cookie NAME… forward` (alias `keep`) keys by the axis but **forwards
  the cookie to the origin unchanged** (for backends that personalize from the raw cookie) —
  covered only when its token is in the selected key recipe; a loud `cookie-forward-uncollapsed`
  warning flags the opt-in.
- **WebSocket / `Upgrade` passthrough** — `upgrade @scope` opts a route into end-to-end
  `Connection: Upgrade` tunnelling (socket.io, live, SSE-over-WS). Off the cache path;
  reuses the routed upstream's health/sticky pick and transport; idle-timeout teardown; an
  active-tunnel gauge (`cadish_upgrades_active`).
- **Per-upstream origin-TLS control** — `tls_insecure` (skip origin certificate verification),
  `ca_file <pem>` (verify against a private CA), and `alpn` (pin origin
  ALPN). Default stays fully verifying; `tls_insecure` warns at `cadish check`; each upstream
  is isolated (one insecure origin never relaxes verification for another).
- **Origin-header-driven grace** — `cache_ttl … grace_from_header NAME` /
  `max_stale_from_header NAME` (the literal stays as the fallback).
- **Upstream-liveness probe** — the `upstream_healthy NAME…` matcher (true when a named pool
  has a live backend); compose with `respond` for an L4/DNS health endpoint that returns
  200/503 by pool liveness.
- **Configurable DNS resolution** — per-upstream `resolve [<interval>] [nameserver <ip:port>…]`
  for `dns://` upstreams (custom nameserver + re-resolve interval). Custom and system resolver
  answers are both filtered against link-local/cloud-metadata addresses.
- **Derived tokens in redirect targets** — `{classify.*}`, `{geo}`/`{geo.continent}`/
  `{geo.region}`, `{client_ip}`, `{http.NAME}`, and `{proto}`/`{scheme}` now resolve inside a
  `redirect` `Location` (the target host stays the validated host — the open-redirect defense
  is preserved). A `redirect @scope PATH_REGEX CODE TARGET` form combines a matcher scope
  **and** `$N` path-regex captures in one rule (e.g. language-conditioned bidirectional slug
  translation, `couples↔parejas`).
- **`{proto}` / `{scheme}` template token** — `https` when cadish terminated TLS, else `http`
  (e.g. `header X-Forwarded-Proto {proto}`).
- **Global inbound limits** — a top-level `server { maxconn N; read_timeout D; idle_timeout D }`
  block (caps the inbound accept set; overrides the inbound timeouts).
- **Cache-key query denylist** — `cache_key … query_strip NAME…`: key on the whole query
  **minus** a name/glob denylist (`utm_* gclid …`) so tracking params stop fragmenting the
  cache. The dual of `query_allow` (mutually exclusive with it).
- **Response-header-scoped TTL** — `cache_ttl resp_header NAME VALUE …` branches freshness on
  what the origin returned (e.g. `X-Powered-By: Express`), evaluated in the response phase.
- **Opt out of client-forced revalidation** — `client_cache_control ignore` makes a site **not**
  honor a request `Cache-Control: no-cache`/`max-age=0` (or `Pragma: no-cache`), so a browser
  hard-refresh can't bust the shared cache and hammer the origin. Default (absent) still
  honors it per RFC 9111 §5.2.1.4.
- **Origin-authoritative caching of credentialed requests** — `cache_credentialed @scope`
  opts a scope out of the safe-default credential bypass. Normally a request carrying a
  `Cookie`/`Authorization` the key doesn't cover is never shared-cached; in this scope caching
  becomes origin-authoritative. Storage is gated **solely by a per-response origin cache
  signal** (an in-scope `cache_ttl … from_header NAME` firing, or an origin `max-age`/
  `s-maxage`) — a static blanket TTL never authorizes it. When the signal fires, the response
  is stored under the **shared** key with `Set-Cookie` and the weak control headers
  (`no-store`/`private`/`no-cache`, `Pragma`, a past `Expires`) stripped from **both** the
  stored entry and the delivered response; **no signal ⇒ never stored** (fail-closed), so a
  per-user route that omits the marker is never shared-cached. The original cookies are
  forwarded to the origin for authentication but never enter the cache key. A `strip_cookies`
  rule over the same scope is a compile error, `cache_unsafe` cannot open an alternate store
  path, and a `cache-credentialed-origin-trust` check warning flags the origin-trust
  requirement. Mirrored at the edge (fail-closed when the scope cannot be projected).
- **Reserved `/.cadish/readyz` warm-readiness probe** — a built-in readiness endpoint that
  reports ready only after the ingress/gateway controller completes its first successful
  reconcile, so a pod is not declared ready while still cold. It is served as 200/503 on plain
  `:80` even in TLS-redirect mode (exempt from the HTTP→HTTPS redirect), so a Kubernetes
  `httpGet` readiness probe is never masked by a 301. Controller readiness probes use it,
  fixing rollout 502/404 when a pod became routable before it was warm.

### Changed
- A global-only block (`server`, `admin`, `proxy_protocol`, `strict_host`, `security`,
  `access_log`) placed inside a **site body** is now a positioned error in both `cadish check`
  and `cadish run` (previously silently ignored).

### Fixed
- A legitimately duplicated forward-covered cookie (same value sent more than once — e.g. a
  domain-scoped and a host-scoped copy of one cookie) no longer forces a cache bypass: it is
  keyed by its derived axis, so identical occurrences cache normally. A differing-value
  duplicate, or a duplicate of a raw-value-keyed cookie, still bypasses (the same fix applies
  at the edge).
- A passed/uncached request now forwards the client's **original** cookies to the origin
  (previously `cookie_allow`/`derives_from` stripped them before the pass/cache decision,
  breaking auth/session on every `pass`ed per-user endpoint — a logged-in user read as GUEST).
  Cacheable requests still normalize the cookie for the key; the same fix applies at the edge.
- The origin control headers a `from_header` TTL/grace rule consumes (`X-Cache-Ttl`,
  `X-Cache-Grace`, `X-Cache-Max-Stale`) are now stripped from the delivered response (and at
  the edge) instead of leaking to the client.
- A lone `to dns://host` upstream now loads (previously failed with a base-URL error).
- **Multi-line site address lists no longer silently drop all-but-the-last line** — the parser
  now reads the full list of comma-wrapped addresses, so a static TLS cert covers every
  declared host (a comma-less wrap or a stray comma is a positioned parse error rather than a
  silent truncation that broke SNI). `cadish check` also warns (`tls-cert-uncovered-address`)
  when a static cert does not cover every declared address.

### Security
- The sandboxed `/api/validate` admin path never reads files from disk: `ca_file` is
  structure-validated there and the PEM is loaded only at run time, preserving the
  no-filesystem trust boundary (and a missing CA is a deploy-time warning, not a hard error).
- The custom-nameserver and default DNS resolution paths both drop link-local and
  cloud-metadata answers (incl. the AWS IPv6 IMDS endpoint).

## [0.2.0] — 2026-06-25

**The first public release (beta).** cadish is a single static binary that consolidates
HTTP caching, TLS termination (with automatic certificates), load balancing, and
reverse-proxying into one process — driven by a flat, readable configuration file, the
**Cadishfile**. It adds a two-tier RAM+NVMe cache, an S3/CloudFront origin layer, an
additive Cloudflare-Workers edge tier, and Kubernetes Ingress + Gateway API controllers,
all from the same binary and the same config.

### What makes it interesting
- **One binary, one plain config.** The whole proxy / cache / TLS / load-balancing stack
  is described by a flat file of per-site matchers + directives — not a programming
  language and not a separate config for each layer.
- **`cadish check` — a config *complexity & safety* report** that is rare in this space:
  regex evaluations per request, directives by lifecycle phase, a weighted per-request
  cost, dead/unreachable-rule detection, and an **unbounded-cache-key-cardinality**
  warning that catches the classic "key on a raw header → ~0% hit-rate" footgun. It is a
  **faithful pre-flight**: a config that passes `check` builds at `run`.
- **Cardinality-reduction normalizers** keep hit-rate high without shattering the cache:
  `{device}` (User-Agent → a small enum), `{geo}` (client IP / trusted header → country
  class), `{tenant}`, and a generic `normalize` bucket toolkit.
- **An additive edge tier from the same config:** `cadish edge build` projects the
  Cadishfile to an IR + a Cloudflare-Workers JavaScript bundle, with a coverage report
  and a core↔edge conformance suite so both planes decide identically.
- **A migration on-ramp:** `cadish adapt` converts an existing reverse-proxy / cache
  configuration to a Cadishfile, mapping the mechanical idioms and flagging the rest with
  `# TODO(adapt)`.
- **Safe by default** (see **Security**): credentialed requests and error responses are
  not cached unless you explicitly opt in.

### Added — Config & tooling
- **Cadishfile** — a flat config of per-site matchers (`@name`) + directives, with
  `import` (incl. globbing) and `{$ENV}` / `{$ENV:default}` substitution.
  - Matchers: `path`, `path_regex`, `host`, `host_regex`, `header`, `header_regex`,
    `method`, `upstream`, `content_type` (response phase), `cookie NAME [VALUE…]`,
    `cookie_json`/`header_json` (a field inside a JSON cookie/header), `geo`,
    `set_cookie`, and the `ip` CIDR ACL.
  - Directives: `tls`, `cache`, `upstream`, `cluster`, `origin chain`, `pass`,
    `cache_key`, `cache_ttl`, `storage`, `header`, `strip_cookies`, `route`, `respond`,
    `purge`, `cors`, `rate_limit`, `deny`/`allow`/`block`, `sign`, `geo`,
    `device_detect`, `normalize`, `tenant`/`group`, `replace`, `import`.
- **`cadish check`** — the complexity/safety report above (`-strict`, `-json`).
- **`cadish fmt`** — canonical Cadishfile formatter (`-w` in place).
- **`cadish run`** — the server; graceful SIGINT/SIGTERM shutdown; `-trace` /
  `-access-log` observability seams.
- **`cadish reload`** — zero-downtime hot reload (SIGHUP); a broken config keeps the
  old one running.
- **`cadish adapt <file>`** — best-effort migration converter from an existing
  reverse-proxy / cache config to a Cadishfile.
- **`cadish version` / `help`**.

### Added — Caching
- Two-tier **RAM + NVMe** cache: sharded LRU, persistent metadata, a restart-safe
  freshness index (a disk blob with no freshness entry revalidates, never a stale hit).
- **Tier placement** is enforced: `storage <sel> -> ram|disk` (per-rule) and
  `cache { tier .ext -> ram|disk }` (per-extension), with fallbacks so an object is
  never cached *nowhere*.
- **Request coalescing** (single-flight): a miss herd collapses to one origin fetch.
- **Per-status TTL / grace** via `cache_ttl`; **grace = stale-while-revalidate**;
  **`hit_for_miss`** records a "don't cache this key" decision so a transient bad
  response can't poison the key.
- **Negative caching** of `404`/`410` (short-TTL bodyless entries).
- **Cardinality normalizers** — `{device}` (`device_detect { … }`, `fold` to collapse
  classes), `{geo}` (`geo { source header|cidr|maxmind; trust_proxy <cidr…> }`),
  generic `normalize`, and `{tenant}` multi-tenant routing (`tenant { … }` + `group`
  site-groups with override-replaces-base inheritance).
- **Range/206** passthrough and Range-from-cache (with correct `If-Range` / conditional
  precedence); **`+cache_status`** emits `HIT`/`MISS`/`HIT-STALE`; cookie stripping;
  CORS; per-`@matcher` header edits.
- **`purge`** (token-guarded) and **cache-wide regex invalidation** (`purge … regex EXPR`)
  via a lazy invalidation pass on the freshness index — O(1) to record, applied on each
  matching key's next lookup.
- **`replace OLD NEW`** — deliver-phase, content-type-scoped body substitution (post-cache,
  ≤1 MiB, skips `Range`/`HEAD`/encoded bodies).

### Added — TLS
- Built-in **TLS termination with automatic certificate issuance** (ACME / Let's Encrypt) —
  no separate proxy in front. `tls { acme … }`, static `cert`/`key`, or `off`. A host
  policy restricts issuance to configured hosts (never an open issuer); on-disk cert cache;
  `:80` serves the ACME HTTP-01 challenge and 301-redirects the rest; TLS-ALPN-01 inline.
  Hardened defaults (min TLS 1.2, modern AEAD ciphers, ALPN h2), optional HSTS.

### Added — Load balancing
- `upstream` / `cluster` pools: **round-robin**, **least-conn**, **sticky** (consistent
  hash on cookie-or-client-IP), **sharded** (`shard_by url|key`).
- Active **health checking** (`health METHOD PATH expect CODE interval/window/threshold`)
  with a window/threshold state machine; only healthy backends serve.
- **Dynamic resolution** of `dns://` / `k8s://` targets (periodic re-resolution, no
  reloads on IP churn). Per-backend timeouts and `max_conns`.

### Added — Origins
- Generic **HTTP/HTTPS** origin and **S3-compatible** origin (Range/206, a streaming tee
  so a body caches while it serves).
- **`origin chain A -> B`** — composable fallback (miss/4xx/5xx/unreachable → next).
- **`sign cloudfront`** — re-sign each request to a CloudFront distribution with a
  canned-policy signature (stdlib RSA-SHA1, no cloud SDK); composes inside a chain.
- **`host_header preserve | origin | <value>`** — controls the upstream `Host`; the
  default is **`preserve`** (forward the client Host), so name-based vhosts / multi-tenant
  origins don't canonical-301.

### Added — Edge tier (Cloudflare Workers)
- **`cadish edge build`** projects the Cadishfile to an edge IR and a Worker JS bundle —
  an *additive* edge tier sharing the same config. A coverage report shows what is
  edge-native vs delegated to the origin server; `-strict` fails on anything not fully
  representable; a conformance suite asserts core↔edge decision parity.

### Added — Kubernetes
- **`cadish ingress`** — an in-cluster **Ingress controller** (`ingressClassName: cadish`,
  `cadi.sh/*` annotations incl. opt-in `ssl-redirect`, status load-balancer writeback,
  BYO `kubernetes.io/tls` secrets with hot cert rotation, leader election).
- **`cadish gateway`** — a **Gateway API** controller (`GatewayClass`/`Gateway`/
  `HTTPRoute`, per-listener status + `attachedRoutes`, `ResolvedRefs`/`BackendNotFound`,
  cross-namespace `ReferenceGrant` fail-closed).

### Added — Observability
- **`cadish logs [-f] [-format text|ncsa|json] [filters]`** — an access-log tail over
  cadish's NDJSON access log (`cadish run -access-log FILE`); host/path/cache/status
  filters; text, NCSA combined-log, or JSON output; never logs auth tokens, cookies, or
  query strings.
- **`cadish run -trace`** (`CADISH_TRACE=1`) — a per-request decision trace (route, cache
  key, lookup, ttl/grace/hit-for-miss, pass reason, upstream, transforms); nil-gated,
  zero cost when off.
- **Admin surface** — `admin { listen … auth_token … metrics }`: a dashboard, Prometheus
  metrics, and `/api/*` JSON (all auth-gated; secrets redacted; no token via query string).

### Security
cadish ships **safe-by-default** for a *shared* cache, and a full pre-release testing
sweep hardened the surface:
- **Credentialed requests are not cached by default.** A request carrying `Authorization`
  or a `Cookie` is non-shareable — it bypasses the shared cache (never served from it,
  never stored) — *unless* you explicitly opt in by keying on the credential
  (`cache_key … header:Authorization` / `cookie:NAME`), which gives a safe **per-user**
  entry. This prevents cross-user / unauthenticated cache leakage, and is enforced
  identically on the core server **and** the edge tier.
- **Error responses are not cached under a broad selector.** `cache_ttl default` does not
  store `4xx`/`5xx` (so a transient outage isn't pinned for the TTL after recovery); only
  an explicit positive `cache_ttl status <code>` opts a status in. `404`/`410` negative
  caching is unchanged.
- **Response-driven safety:** `Set-Cookie`, `Cache-Control: no-store/private/no-cache/
  s-maxage=0`, and `Vary: *` (or any uncovered `Vary`) responses are never cached.
- **SSRF guards** — origin and LB HTTP clients never follow redirects; an origin `3xx` is
  passed through to the client (never followed). Cache-key query re-encoding stops decoded
  delimiters from colliding distinct queries. A request-sourced `purge … regex` is
  length-bounded, must compile, and rejects mass-flush patterns. RE2 regexes (no ReDoS).
  Streaming-safe server timeouts. `strict_host` and an explicit `trust_proxy` CIDR model
  (a client can't forge `X-Forwarded-For`/geo from an untrusted peer).
- **`deny`/`block`** access rules evaluate **all** values of a repeated header (a
  duplicate header line can't slip a blocked value past the rule). Note: `path` matchers
  are case-sensitive (RFC 3986) — use `path_regex (?i)^/admin/` for case-insensitive
  access control.
- First-pass full-surface security review (0 Critical / 1 High; posture in
  [`SECURITY.md`](SECURITY.md)).

### Performance
- Hot-path allocation pass across cache / pipeline / lb; the response fast path is
  zero-extra-copy, and the trace/metrics seams are zero-cost when off. Benchmarks in
  [`docs/benchmarks.md`](docs/benchmarks.md).

### Known limitations
- **Negative cache is bodyless** — caching the full negative response (body + headers) is
  a follow-up.
- **`sign`** implements the `cloudfront` provider only.
- **Edge tier** projects the cacheable/routing core; directives it can't represent are
  reported as *delegated* to the origin server (not silently dropped).
- Future module tracks (not in this release): an own-engine **WAF**, signed-URL inbound
  verification + HLS, and an eBPF/XDP L4 module.

[0.2.2]: https://github.com/cadi-sh/cadish/releases/tag/v0.2.2
[0.2.1]: https://github.com/cadi-sh/cadish/releases/tag/v0.2.1
[0.2.0]: https://github.com/cadi-sh/cadish/releases/tag/v0.2.0
