# Changelog

All notable changes to cadish are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and cadish follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/cadi-sh/cadish/releases/tag/v0.2.0
