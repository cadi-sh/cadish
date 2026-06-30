# Cadishfile reference

The complete matcher + directive reference for cadish v1. Every entry here is
backed by what the engine actually implements (`internal/pipeline`,
`internal/config`, `internal/lb`, `internal/tlsacme`). Where a directive carries a
runtime caveat (e.g. it needs another block to take effect), it says so explicitly
— see [Parsed but not yet wired in v1](#parsed-but-not-yet-wired-in-v1).

For the lexical grammar (tokens, quoting, `\` line continuations, comments,
`{$ENV}` placeholders) see [cadishfile-grammar.md](cadishfile-grammar.md).

## Structure

A Cadishfile is a list of **sites**. A site is one or more comma-separated host
addresses followed by a `{ … }` body of statements:

```
example.com, *.example.com {
    …directives and @matcher definitions…
}
```

- **Addresses** select the site by request Host: an exact host, or a `*.suffix`
  wildcard (suffix match at any depth, e.g. `*.example.com` matches `a.example.com`
  *and* `a.b.example.com`, but not bare `example.com`). When exactly one site is configured,
  it also serves any Host as a lenient fallback (handy for tests / IP access).
  - **Wrapping the address list over multiple lines:** put a `,` after **every** address
    (including at the end of each wrapped line). cadish reads the whole comma-separated list
    up to the `{`. A line that *doesn't* end every element with a comma — or that wraps with
    no commas at all — is a **loud parse error** (never a silent truncation), with one
    inherent exception: a list whose **first** address is a bare dot-less single label (e.g.
    `intranet`, but not `localhost`) is syntactically indistinguishable from a directive, so if
    you also omit the commas it may be mis-read — always comma-separate, or lead with a dotted
    host. (A static TLS cert is issued for the parsed address set, so a dropped address would
    fail that host's SNI — hence the loud error.)
- **Statements** are either `@name` **matcher definitions** or **directives**.

### Matchers vs directives

A **matcher** (`@name TYPE args…`) is a named predicate over the request. A
**directive** does something, optionally scoped to one or more matchers.

```
@images path /img/* /static/*      # a matcher
strip_cookies @images              # a directive scoped to it
```

### Evaluation model

Directives run in a fixed **request lifecycle** (see [pipeline.md](pipeline.md)):

| Phase | When | Directives |
|---|---|---|
| **SETUP** | parsed once, not per request | `tls`, `cache`, `upstream`, `cluster`, `origin`, `normalize`, `classify`, `cache_unsafe` (opt out of safe-by-default caching), `client_cache_control` (opt out of honoring client-forced revalidation) |
| **RECV** | on receiving the request | `respond`, `redirect`, `purge`, `route`, `pass`, `cache_credentialed` (origin-authoritative caching of credentialed requests), `rewrite`, `cookie_allow` (request-cookie allowlist), `header` (request-side) |
| **KEY** | build the cache key | `cache_key` |
| **ORIGIN** | on a miss, against the response | `cache_ttl`, `storage`, `respond on_error` (origin-error fallback) |
| **DELIVER** | just before responding | `header` (response-side), `strip_cookies`, `cors`, `replace`, `encode` |

Within a phase, directives run **top-to-bottom**. The selection directives
(`pass`, `cache_ttl`, `storage`) are **first-match-wins** — order matters, and a
catch-all (`default`, or an unconditioned `pass`) makes later rules of the same
kind dead (`cadish check` flags this).

A `header` directive is request-side if it appears **before** `cache_key`,
response-side if **after** (so put response-header edits below your `cache_key`).

### Combining matchers

- Multiple **args** in one matcher are **OR** (`path /a/* /b/*` = /a/\* or /b/\*).
- A directive referencing multiple **@matchers** (`pass @a @b`) is **OR**.
- **AND across matchers** is available *inside a [`classify`](#classify) `when`
  row*: space-separated matchers there are a **conjunction** — the row fires only
  when **all** match (`when @a @b -> v`). This is the one place AND lives; every
  other directive keeps OR scoping. To AND outside a `classify`, derive a token
  with `classify` and scope on it (`@x classify {tok}==v`), or compose with
  separate rules. (A bare `@a and @b` outside `classify` is still a compile error.)

### Global options block

A Cadishfile may begin with a single global `{ … }` block (before any site),
Block-structured, for process-wide options: the optional `admin`, `security`,
`proxy_protocol` and `server` blocks and the `access_log` / `strict_host` options.

```
{
    access_log off                   # disable the in-memory access-log hub (zero cost)
    strict_host                      # reject an undeclared Host with 421 (off by default)
    admin {
        listen :9090                 # admin bind (default 127.0.0.1:9090)
        auth_token {$CADISH_ADMIN_TOKEN}  # REQUIRED bearer token
        metrics                      # enable the Prometheus /metrics endpoint
    }
    security {
        audit_log /var/log/cadish    # security audit log dir (off by default)
    }
    proxy_protocol {
        trust 10.0.0.0/8 192.0.2.7/32  # REQUIRED trusted LB sources (off by default)
    }
    server {
        maxconn 40960                # cap simultaneously-accepted inbound conns (0 = no limit)
        read_timeout 30s             # inbound request read timeout (default 30s)
        idle_timeout 120s            # keep-alive idle timeout (default 120s)
    }
}

example.com { … }
```

#### `access_log` — in-memory access log (opt-out)

cadish keeps one **access record per request in memory** and fans it out to any
attached `cadish logs` consumer over a unix socket — it **never writes the access
log to disk** (a memory-only access-log model). The hot path checks a single atomic ("any
consumer attached?") and does nothing when idle, so with no consumer it costs
essentially nothing. Persist by redirecting the consumer: `cadish logs > access.log`.

| Value | Meaning |
|---|---|
| `access_log off` | Disable the hub entirely — even an attached consumer receives nothing, and the hot path's only cost is the idle atomic check. (`off` is the only accepted value; any other is a config error.) |

The equivalent run flag is `cadish run -access-log off` (OR'd with this option). The
old `-access-log FILE` form is **removed** — see [`logs.md`](logs.md) for the
streaming model and the migration note.

The live socket path defaults to a **per-instance** path under `${TMPDIR}` derived
from the listen address (`cadish-access-<hash>.sock`), so two co-located cadish
instances on different `-addr`s do not clash on one socket (the older process-global
`${TMPDIR}/cadish-access.sock` silently dropped the second instance's live stream).
`cadish logs` derives the same path from its own `-addr` (default `:80`, matching
`cadish run`), so the no-flag single-instance tail keeps working; point it at a
non-default instance with `cadish logs -addr :8080`. Override the path explicitly on
both sides with `cadish run -log-socket PATH` / `cadish logs -log-socket PATH`, or
pin it process-wide with the `CADISH_ACCESS_SOCKET` environment variable (highest
precedence).

#### `strict_host` — reject an undeclared Host (opt-in)

By default a **single-site** config is **lenient**: it serves *any* `Host:` header
from its one site (convenient for tests and direct-IP access). That means an
undeclared Host gets a `200` with its own cache entry rather than a rejection — a
mild Host-confusion / cache-fragmentation footgun.

The bare `strict_host` global option makes site selection **strict**: a request
whose `Host` matches no declared site address (exact or `*.` wildcard) is answered
with **`421 Misdirected Request`** and **never opens a cache entry**, instead of
falling back to the only site. It takes no arguments and is **off by default**
(behavior unchanged unless you opt in). Multi-site configs are unaffected — an
unmatched Host already gets no lenient fallback there; `strict_host` only changes
the single-site fallback and makes the rejection an explicit `421`.

#### `admin` — command center / dashboard (opt-in, off the datapath)

The `admin` block enables a built-in observability surface — a single-page
dashboard plus a JSON/Prometheus API — on its **own listener**, separate from the
proxy. It is **off by default**: with no `admin` block, no admin listener is
started and the request datapath carries no metrics cost at all.

| Sub-directive | Meaning |
|---|---|
| `listen ADDR` | Admin bind address. Default `127.0.0.1:9090` (loopback — expose deliberately). |
| `auth_token TOKEN` | **Required.** Bearer token gating every admin request (constant-time compared). An `admin` block without it is a config error. Use `{$ENV}` to keep it out of the file. |
| `metrics` | Bare flag; enables the Prometheus text-format `/metrics` endpoint (the JSON API and dashboard are always served). |

Endpoints (all require `Authorization: Bearer <token>`; the token is **never**
accepted via the query string, so it cannot leak into logs / history / `Referer`).
`GET /` (the SPA login shell) is the one unauthenticated route — it holds no
secrets and no live data; the operator pastes the token into the in-page form:

- `GET /` — the embedded single-page dashboard (no external runtime, no build step).
- `GET /api/config` — the compiled rule model as JSON (the same analysis as
  `cadish check`: matchers, directives-by-phase, weighted cost, warnings).
- `GET /api/source` — the running site's Cadishfile text (read fresh from disk),
  used to pre-load the playground editor. Read-only; never writes the file. Secret
  values (`auth_token`, S3 `access_key`/`secret_key`) are **redacted to `***`**
  before being served (`${ENV}` references are preserved).
- `POST /api/validate` — the **playground**: submit Cadishfile source in the
  request body and get back, in one shot, the full compiler verdict computed
  purely in-memory on the posted text (see below).
- `GET /api/metrics` — live counters + derived hit-ratio / p50 / p99 / mean.
- `GET /api/live` — per-site two-tier cache fill.
- `GET /api/upstreams` — every load-balanced pool's backend health (the `lb` FSM).
- `GET /api/stream` — Server-Sent Events push (1 Hz) feeding the live tiles.
- `GET /metrics` — Prometheus exposition (only when `metrics` is set).

Security: the admin surface is auth-gated and binds loopback by default; treat the
token like a credential (`{$ENV}`), and only widen `listen` behind your own network
controls. The metrics layer uses lock-free atomics and never blocks a request.

##### Config playground — `POST /api/validate`

The dashboard ships an **interactive Cadishfile editor**: a `<textarea>`
pre-loaded with the running config (`/api/source`) that validates against the
**real compiler** as you type (debounced) or on a *Validate* click, and shows
errors inline, the `cadish check` report, and the canonical formatted output
side-by-side.

`POST /api/validate` takes raw Cadishfile source as the request body; a body
larger than 1 MiB is **rejected with `413 Request Entity Too Large`** (not
truncated). A within-limit body returns JSON with the complete verdict — produced by reusing the in-tree pipeline
verbatim (no duplicated logic): `cadishfile.Parse`, `pipeline.Compile`,
`check.CheckSource`, `cadishfile.Format`. Response shape:

```jsonc
{
  "ok": true,                  // no parse error and no compile error
  "parse_error": {             // present on a lexical/syntax failure (then nothing else runs)
    "position": "Cadishfile:3:1", "line": 3, "col": 1, "message": "…"
  },
  "compile_errors": [          // per-site pipeline.Compile failures (best-effort: all sites)
    { "position": "Cadishfile:4:3", "line": 4, "col": 3, "message": "unknown directive \"…\"" }
  ],
  "report": { /* the full check.Report: sites, matchers, regex/req, phase_counts, cost, diagnostics */ },
  "formatted": "example.com {\n    …\n}\n"   // canonical `cadish fmt` output
}
```

This is **read-only and off the datapath**: it compiles the *submitted* text
entirely in-memory and **never touches the running server's live pipeline** (zero
datapath risk). It does **not** hot-reload the proxy; applying an edited config is
a separate action (by design).

#### `security` — security observability (audit log, opt-in)

The `security` block carries cross-cutting security **observability**. (The native
security *primitives* — `allow` / `deny` / `rate_limit` — are **site-level**
directives, documented under [the security gate](#security-gate-allow--deny--block);
they are not configured here.) v1 supports one setting:

| Sub-directive | Meaning |
|---|---|
| `audit_log <dir\|file\|off>` | Where to write the **security audit log**. A **directory** writes `<dir>/security-audit.log`; a **file path** appends to that file; `off` (the default) disables it. **Off by default.** |

When enabled, cadish appends **one JSON line per ENFORCED or MONITORED security
action** (an enforced `deny`/`block`, an enforced `rate_limit` throttle, or a
monitor-mode *would-block* / *would-429*). Each record carries the timestamp, the
action, whether it was enforced or monitor-only, the matched rule name, the
request `method`/`host`/`path`, the resolved **real client IP**, and the status
returned:

```jsonc
{"time":"2026-06-24T12:00:00Z","msg":"security","action":"deny","monitor":false,
 "rule":"scanners","method":"GET","host":"example.com","path":"/.env",
 "client":"203.0.113.9","status":403}
```

**Privacy.** Unlike the [access log](#access_log--in-memory-access-log-opt-out),
which deliberately **omits** the client IP and query string (signed-URL signatures
are sensitive), the security audit log **does record the real client IP** — naming
*who* was blocked is the entire point of an audit trail. It is therefore **off by
default**; enable it deliberately. It never records the query string (so a signed-URL
signature is never written here either).

**Non-blocking.** The writer is **asynchronous and best-effort**: records are
enqueued on a buffered channel and serialized to disk by a single background
goroutine, so a slow or full sink **drops + counts** rather than ever blocking
request serving. With the audit log off (the default) the datapath pays one
nil-check and nothing else.

The equivalent run flag is `cadish run -security-audit-log PATH` (it **overrides**
`security { audit_log … }` when set). Log rotation is out of scope for v1 — point
`audit_log` at a directory and rotate the file externally (e.g. `logrotate`).

The admin dashboard's **Security** panel surfaces the live security counters
(allowed / denied / would-block, and rate-limit throttled / would-429 / pass) from
the same metrics seam.

#### `proxy_protocol` — PROXY-protocol listener (real client IP behind an L4 LB, opt-in)

When cadish sits behind an **L4 / TCP-passthrough load balancer** (HAProxy
`send-proxy` / `send-proxy-v2`, AWS NLB, GCP TCP LB) the connection arrives over a
fresh TCP socket whose peer is the LB, and there is no `X-Forwarded-For` to consult —
so every client would look like the LB, breaking the [`ip`](#matchers) ACL,
[`rate_limit`](#rate_limit) and [`{geo}`](#geo). The **PROXY protocol** is the
standard fix: the LB prepends a small header carrying the original client tuple before
the TLS/HTTP bytes.

The `proxy_protocol` block makes cadish read that header. When enabled, the inbound
listener(s) are wrapped so each accepted connection first reads a PROXY **v1** (text)
or **v2** (binary) header and rewrites the connection's reported client address. That
recovered address then feeds the **single** real-client-IP resolution path unchanged —
so the `ip` ACL, `rate_limit` bucket key and `{geo}` all see the real client, with no
other config change. The wrapper sits **beneath TLS** (the wire order is PROXY →
ClientHello → HTTP), so the TLS handshake still sees a clean stream.

| Sub-directive | Meaning |
|---|---|
| `trust CIDR…` | **Required.** Trusted PROXY-header source CIDRs — typically the LB's addresses. A PROXY header is honored **only** from a peer in this set. An empty `trust` set is a config error. |

```
{
    proxy_protocol {
        trust 10.0.0.0/8 192.0.2.7/32
    }
}
```

**Security — this is the load-bearing property.** A PROXY header lets the sender
*assert* an arbitrary client IP, so it must be honored **only from sources you
control**. cadish enforces a **REQUIRE-from-trusted** policy:

- A PROXY header is parsed **only** when the immediate TCP peer is inside the `trust`
  set. A connection from a peer **outside** the set is **rejected** (closed) — its
  bytes are never parsed as a PROXY header, so a spoofed header from an untrusted peer
  can **never** forge the client IP.
- Because the listener is dedicated to traffic fronted by the LB, the policy is
  **REQUIRE**, not "ignore": a *trusted* peer that sends **no** header — or a
  malformed/truncated one — is also rejected (no raw-socket fallback, which would be a
  downgrade an attacker could force).
- The `trust` set is **mandatory and non-empty**: an enabled listener with no trusted
  sources would let *anyone* forge their source address, so an empty set is a config
  error.
- The v2 **LOCAL** command and v1 **UNKNOWN** (the LB's own health-check connections,
  which carry no client tuple) fall back to the real socket peer rather than failing.

This `trust` set is independent of the XFF [`trust_proxy`](#trust_proxy) set (they
operate at different layers — TCP vs HTTP) but typically overlap (the LB's addresses).
For a pure L4 LB the recovered address **is** the client and there is no XFF; if an L7
hop also sends XFF, the existing `trust_proxy` walk composes on top (PROXY fixes the
socket peer first, XFF refines from there).

**Zero cost when off.** With no `proxy_protocol` block the listener wrapper is never
installed — the accept path is the bare `net.Listener`, byte-for-byte unchanged. This
is a **server-only** concern (Cadish Edge runs on Cloudflare; PROXY protocol does not
apply there).

The equivalent run flags are `cadish run -proxy-protocol -proxy-protocol-trust
10.0.0.0/8,192.0.2.7/32` (the flag form **overrides** the `proxy_protocol` block when
set; the same non-empty-`trust` requirement applies).

#### `server` — inbound connection limits & timeouts (opt-in)

The `server` block tunes the **inbound (data-plane) listener** — the HAProxy
`maxconn` / connection-timeout equivalents. Every field is **optional** and defaults
to cadish's shipped value, so an absent block (or an omitted field) leaves behavior
**byte-for-byte unchanged**.

| Sub-directive | Meaning |
|---|---|
| `maxconn N` | Cap the number of **simultaneously-accepted** inbound connections (a `LimitListener`): the `N+1`-th connection waits until one is freed. `0` (the default) means **no limit** — the bare listener. Governs the public data plane only (the admin listener is separate). |
| `read_timeout D` | Inbound request read timeout (headers + body), bounding a slow-request / slowloris client. Default `30s`. |
| `idle_timeout D` | How long a keep-alive connection may sit idle between requests before cadish reclaims it. Default `120s`. |

```
{
    server {
        maxconn 40960                # sized for ~30k concurrent connections
        read_timeout 30s
        idle_timeout 120s
    }
}
```

Notes:

- `ReadHeaderTimeout` (10s) and the streaming-safe **unset** `WriteTimeout` policy
  are **not** exposed as knobs — a global write deadline would truncate legitimate
  large/slow media downloads (a stalled origin is bounded by the idle-stall watchdog
  instead). On the TLS path the `read_timeout` / `idle_timeout` knobs apply to both
  the `:80` (ACME/redirect) and `:443` servers.
- **Zero cost when off.** With no `server` block — or a `maxconn` of `0` — no
  connection limiter is installed and the inbound timeouts keep their default
  constants. This is a **server-only** concern (Cadish Edge runs on Cloudflare).

---

## Matchers

`@name TYPE args…` — define once, reference by `@name`. A matcher may also be
written **inline** in a directive's scope position (`strip_cookies path_regex …`),
though inline regex/host matchers take a single arg; richer scopes need a name.

| Type | Matches when | Notes |
|---|---|---|
| `path` | the URL path matches any glob arg | `*` is a wildcard; compiled to a trie/set (one lookup, not N regexes). Cheap. **Case-SENSITIVE** (RFC 3986 paths are case-sensitive), unlike `method`/`content_type`. ⚠️ **Security note:** `deny path /admin/*` does **not** block `/ADMIN/` — for a case-insensitive access-control rule use `path_regex (?i)^/admin/` (or `deny` on both casings). This matters when the origin/filesystem treats paths case-insensitively. |
| `path_regex` | the URL path matches the RE2 regex | one regex; matched against the **path only** (no query string). The expensive matcher — `cadish check` counts these. |
| `host` | the Host equals any arg | supports a `*.` wildcard (plain suffix match at any depth: `*.example.com` matches `a.example.com` *and* `a.b.example.com`, not bare `example.com`). |
| `host_regex` | the normalized Host (lower-cased, port stripped) matches the RE2 regex | |
| `header` | header `K` is present (`header X-Foo`) or equals a value (`header X-Foo bar`) | multiple values are OR'd; value match is exact string equality. |
| `header_present` | the named request header is present (`header_present Origin`), any value incl. empty | request-phase; takes **exactly** the header name (value args are a compile error — use `header NAME VALUE` to test a value). The general "only when header X is present" guard: e.g. scope a reflected-Origin CORS op on `@has_origin header_present Origin` so `header @has_origin +Access-Control-Allow-Origin {http.Origin}` fires **only** on a CORS request (no malformed empty `Access-Control-Allow-Origin:` otherwise). Cheap exact lookup. |
| `header_regex` | the named request header's value matches the RE2 regex (`header_regex User-Agent (?i)\bbeta\b`) | request-phase; `header_regex NAME PATTERN` — a `path_regex`/`host_regex`-style RE2 test (RE2 inline flags like `(?i)` supported; unanchored unless you write `^`/`$`) applied to a header **value**. A multi-valued header matches if **any** value matches. The "expensive" tier — `cadish check` counts it in *regex evals / request*. See [`header_regex`](#header_regex). |
| `cookie` | a cookie in the `Cookie` header is present (`cookie sessionid`), equals a value (`cookie tier premium`), or — with a trailing `*` — has a name with that **prefix** (`cookie wordpress_logged_in_*`) | parses the request `Cookie` header; multiple values OR'd; equality is constant-time (cookie values may be session secrets). A trailing `*` on the **name** is a prefix glob (matches `wordpress_logged_in_<md5>`); it is **presence-only** — a glob name cannot take value args (compile error). Request-phase (usable anywhere `header` is). |
| `cookie_json` / `header_json` | a dotted **field inside a JSON** cookie/header value is present (`cookie_json nsfwCookie needVerify`) or its scalar equals a value (`cookie_json nsfwCookie needVerify true`, `header_json X-Session plan.tier pro enterprise`) | request-phase; **mirrors `cookie`** (presence vs OR-of-values) but reaches **one level into a structured value** via a `PATH`. See [JSON field matchers](#cookie_json--header_json) below for the PATH grammar, value coercion, the fail-safe table, and the 8 KiB / depth-32 DoS caps. |
| `method` | the request method is in the arg list | case-insensitive (`GET`, `POST`, …). |
| `upstream` | the request was routed to the named upstream | set by `route`; lets ORIGIN/DELIVER rules target a backend. |
| `content_type` | the **response** `Content-Type` contains any arg | **response-phase**: case-insensitive substring (so `text/css` matches `text/css; charset=utf-8`); multiple args are OR'd. May scope the response/DELIVER directives (`cache_ttl`, `storage`, `header`, `strip_cookies`, `cors`) but not request-phase ones (a compile error). |
| `set_cookie` | the **response** carries a `Set-Cookie` header — bare `set_cookie` = any cookie set; `set_cookie NAME…` = a cookie of that name was set (OR) | **response-phase**: cookie names are case-sensitive (RFC 6265). The session-safety primitive — drive `cache_ttl … hit_for_miss` off it so a per-user `Set-Cookie` response is never cached/shared. Same scoping rules as `content_type`. |
| `resp_header` | a named **response** header's value matches: `resp_header X-Powered-By Express` (exact), `resp_header X-Powered-By Exp*` (`*`-glob), `resp_header X-Powered-By *` or `resp_header X-Powered-By` (presence) | **response-phase**: branch freshness on what the **origin returned**, e.g. SSR vs PHP by `X-Powered-By`. Header **name** match is case-insensitive; the **value** is exact or `*`-glob (same engine as `query_present`); a multi-valued header matches if any value matches. In a `cache_ttl`/`storage` selector it consumes exactly `NAME VALUE` and may be ANDed with a trailing `status`/`@scope` in the same rule (`cache_ttl resp_header X-Powered-By Express status 404 ttl 1m grace 24h`). Same scoping rules as `content_type` (response/DELIVER directives only; a request-phase use is a compile error). |
| `classify` | a derived [`classify`](#classify) token equals (`{TOK}==v`) or differs from (`{TOK}!=v`) a value | turns a derived enum token into a reusable scope: `@gated classify {age}==gate`. Request-phase (usable anywhere `header` is). |
| `geo` | the resolved geo class at a granularity is in the arg list: `geo country US ES`, `geo continent EU`, `geo region US-UT US-TX` | request-phase. The granularity (`country`/`continent`/`region`) selects which resolved class is tested (same source as `{geo}`/`{geo.continent}`/`{geo.region}`); the remaining args are an OR set, compared case-insensitively. Needs a [`geo`](#geo) source (and `region_header` for `region`). Feeds `classify` for geo→business mapping (below). |
| `query_present` | **any** named query param is present: `query_present adult_content t a ff-* pub-*` | request-phase (usable anywhere `header` is). Presence-OR: matches as soon as one named param exists (even with an empty value, `?a=`). A trailing/embedded `*` is a glob over the param *name* (`ff-*` matches `ff-foo` but not `ff`); a bare `query_present *` matches any param. Tests the param *name*, never the value — pair it with [`classify`](#classify) to collapse "any of these present" to a 0/1 flag (the `publi` boolean, below). **Non-empty modifier:** append `+` to a name to require a non-empty value — `query_present adult_content+ t+ ff-*+` matches `?t=abc` but NOT `?t=` (empty value) or `?t` (no value). Mixed: `query_present foo+ bar` — `foo+` requires non-empty, `bar` is plain presence (empty value still matches). The `+` is stripped to recover the name/glob; param names never contain a literal `+` in practice (URL-encoded as `%2B`). Mirrors the Varnish `=[^&]+` semantics for marketing/publi param detection. |
| `query` | a **named** query param's **value** is in the arg list: `query channel beta canary` | request-phase. Tests ONE param name against an OR set of exact values (`query NAME VALUE…`); with no value (`query NAME`) it is a presence test of that one param. A repeated param (`?a=1&a=2`) matches if any value is accepted. Complements `query_present` (presence-OR over several *names*). Used by the Gateway controller for an HTTPRoute `queryParams` Exact match. |
| `ip` | the **real client IP** is in any IP/CIDR arg: `ip 203.0.113.43/32 10.0.0.0/8 ::1 2001:db8::/32` | request-phase, IPv4 + IPv6, CIDR or bare IP (bare = a host route `/32`/`/128`); args are an OR set. Matches the **trusted-proxy-resolved real client IP** — the *same* resolution as `{geo}` (`geo { trust_proxy … }`), never the immediate peer — so behind a CDN/LB it ACLs the actual client, not the proxy. The IP/CIDR ACL primitive for the [security gate](#security-gate-allow--deny--block) (`allow`/`deny`). **Server-only:** an `ip` matcher is never projected to the edge. |
| `all` | **every** referenced (optionally `!`-negated) sub-matcher matches (AND): `@m all @path @hdr !@internal` | request-phase composite. References other named matchers and ANDs them into ONE reusable matcher, so a single `route @m -> u` (and a correct terminal `respond !@m 404`) expresses a multi-criteria condition. Sub-refs must be plain matchers (no nesting); a response-phase sub-matcher is a compile error. The Gateway controller emits it for a multi-criteria HTTPRoute match (path AND headers AND method AND query). |
| `upstream_healthy` | **any** named upstream **pool** has a live backend (`nbsrv()>0`): `upstream_healthy cache_pool` (or several: `upstream_healthy a b`) | request-phase liveness probe. True as soon as ONE listed pool has ≥1 backend that is health-FSM **up** and **not ejected** — an O(1) read of the maintained health state, **no dial, no probe**. Names pools EXPLICITLY (independent of routing), so it evaluates in RECV. Compose with scoped [`respond`](#respond) for an LB health endpoint (the AWS `/aws-health-check` 200/503 signal — see below). **Server-only:** live pool health has no edge analogue, so it is never projected to the edge (delegated). |

```
@ajax      header X-Requested-With XMLHttpRequest
@static    host_regex ^static
@images    upstream images
@nocache   path /admin/* /checkout/* /account/*
@longcache content_type text/css image/svg+xml   # matches the RESPONSE Content-Type
@authed    cookie sessionid                       # has a session cookie
@session   set_cookie sessionid                   # the RESPONSE set a session cookie
@ssr       resp_header X-Powered-By Express       # the RESPONSE came from the SSR origin
@eu        geo continent EU                       # client is in Europe
@regulated geo region US-UT US-TX                 # a regulated US state (needs region_header)
@adparams  query_present adult_content t a p ff-* pub-*   # any ad/tracking param present
@office    ip 203.0.113.43/32 10.0.0.0/8                 # office / monitoring IPs (real client IP)
```

Geo → business mapping — the `geo` matcher provides the granular inputs (country /
continent / region); the *policy* is expressed by the operator with a `classify`
(or `normalize`) table over them, not hard-coded:

```
geo {
    source        header CF-IPCountry   # country (→ continent, in-tree)
    region_header CF-Region             # US state / subdivision (upstream header)
}
@eu        geo continent EU
@regulated geo region US-UT US-TX US-LA   # …the regulated states
normalize  currency { from header X-Continent; map EU -> EUR; default USD }
classify {access} {                       # regulated states get the age gate
    when @regulated -> gate
    default         -> open
}
cache_key host path {geo.continent} {access}   # EU→EUR, gate→separate cache bucket
redirect @agegate 302 https://example.com/age-check   # @agegate classify {access}==gate
```

**Caching is safe by default.** Even when a `cache_ttl` rule matches, cadish — like
every RFC 9111 shared cache and CDN — **refuses to store (and serve cross-user) a
response that is not safely shareable**. After a rule sets a TTL, the response is
*downgraded to non-cacheable* when it carries any of:

- a `Set-Cookie` header (a per-user credential the origin is minting **right now**) —
  this refusal is **ironclad**: a `Set-Cookie` response is **never** stored, **not even
  under `cache_unsafe`** (exactly like `Vary: *`). Caching it would hand one user's
  brand-new session to everyone who reads the entry, so it is not behind any opt-out flag.
  The **only** way to cache a cookie-stamping origin is to **control the cookie** —
  see [`strip_cookies`](#strip_cookies) below, or
- a `Cache-Control` with a `no-store`, `private`, or `no-cache` directive (parsed as
  a proper token list — `max-age=60` and a value like `private-data` still cache), or
- a `Vary` header that is **not** part of the [cache key](#cache_key) and is not
  solely `Accept-Encoding` (cadish handles `Accept-Encoding` variance in its `encode`
  layer). `Vary: *` is **never** cacheable.

This matches the Cadish **Edge** tier, which enforces the same invariant. So the
naïve `cache_ttl default ttl 5m` no longer risks serving one user's `Set-Cookie:
session=…` (or a `private` page) to everyone.

`set_cookie` remains the explicit, scopable primitive — drive `hit_for_miss` off it
to record a short negative-cache window for session-bearing responses:

```
@session set_cookie sessionid        # or bare `set_cookie` for any Set-Cookie
cache_ttl @session hit_for_miss 0s   # session-bearing responses are never stored
cache_ttl default ttl 1h             # everything else caches normally (safe by default)
```

**To cache an origin that stamps `Set-Cookie` on every response, strip it first.** Many
backends set a bootstrap/session cookie on every reply. The faithful equivalent of
Varnish's `unset beresp.http.Set-Cookie` is a [`strip_cookies`](#strip_cookies) rule
covering the cacheable classes: it removes `Set-Cookie` **before the response is stored or
delivered**, so the cached representation carries no cookie and caches safely. This is an
**explicit, per-class opt-in** — you cannot cache a `Set-Cookie` response by accident, only
by declaring the cookie controlled (stripped):

```
@assets   path_regex \.(css|js|png|jpe?g|svg|ico)$
strip_cookies @assets                 # drop Set-Cookie on these classes -> they cache
# @assets responses now cache even though the origin set a cookie; everything else that
# carries Set-Cookie is still refused (never stored).
```

> `cache_unsafe` governs only the *other* refusals (`private` / `no-store` / `no-cache` /
> uncovered `Vary`). It does **not** — and cannot — force a `Set-Cookie` response into the
> cache. Stripping the cookie is the only path.

#### Credentialed requests are never shared-cached by default

The safe-default above is the **response** side (a `Set-Cookie` reply is not stored).
There is a matching **request** side: a request carrying a per-user **credential** — an
`Authorization` header **or** a `Cookie` — **bypasses the shared cache entirely by
default** (it is never served a cached entry, and its response is never stored). This is
automatic — no directive needed — and it is what stops a private page returned for one
user's session cookie or bearer token (with *no* `Set-Cookie` on the response, the
common case the response-side guard cannot see) from being cached under a
credential-agnostic key and served to every other user, including anonymous ones. It
mirrors Varnish's builtin VCL (`vcl_recv` passes `Authorization || Cookie`) and RFC 9111
§3.5.

So `cache_ttl default ttl 5m` on a site that mixes anonymous and logged-in traffic is
safe out of the box: anonymous GETs cache; any request with a cookie/token goes straight
to origin.

**To cache credentialed traffic, you must KEY by the credential** — the only opt-in:

```
cache_key host path cookie:session     # per-session caching: one entry per session value
cache_ttl default ttl 60s
```

`cache_key … header:Authorization` does the same per bearer token. The coverage check is
**name-aware and strict**: a request is cached only when the selected key captures
**every** credential it carries — for a Cookie that means a `cookie:NAME` token for
**each** cookie the request sends (or `header:Cookie`, which keys the whole header).
Anything left uncovered bypasses. So:

- `cache_key … cookie:session` caches a request only if its session cookie is literally
  named `session` **and** it carries no other cookie. A second cookie (`cart_count`,
  `_ga`, …) or a session named `PHPSESSID`/`JSESSIONID`/`connect.sid` is **not** captured
  → the request bypasses (it is **not** silently shared — no cross-user leak).
- To cache despite extra cookies, key each one (`… cookie:session cookie:cart_count`),
  each distinct combination getting its own entry, or key the whole header with
  `header:Cookie` (highest cardinality, fully safe).
- An `Authorization`-bearing request is covered only by `header:Authorization`.

There is deliberately **no flag escape**: [`cache_unsafe`](#cache_unsafe) governs only
the *`private`/`no-store`/uncovered-`Vary`* response refusals and does **NOT** enable
caching of credentialed requests — you cannot accidentally cache credentialed traffic
under a shared key. (To cache cookie traffic you either key by the credential, or
*control* the cookies with [`cookie_allow`](#cookie_allow).)
(`cadish check -strict` flags a `cookie:`/raw `header:` key token as high-cardinality, so
you confirm per-user keying is intended.)

> **Edge tier:** the Cadish Edge worker is more conservative — it bypasses the shared
> edge cache for **every** credentialed request (no per-user keyed caching at the edge in
> v1). The Go server behind it still does the per-user keyed caching described above.

#### `cache_credentialed` — origin-authoritative caching of credentialed requests

`cache_credentialed @scope` is the **scoped opt-out** of the credential bypass for sites whose
origin serves **shared** content on credentialed requests and marks the genuinely per-user
replies uncacheable — the classic Varnish custom-VCL `return(hash)`-on-cookie-traffic pattern.
It is the faithful translation of:

```
# VCL: shared readmodel endpoints cache for everyone, keyed off the response signal
if (beresp.http.X-Cache-Ttl) { unset beresp.http.Set-Cookie; unset beresp.http.Cache-Control; set beresp.ttl = ...; }
```

For a request whose scope matches, caching becomes **origin-authoritative**:

1. the request-time **credential bypass is skipped** (a `Cookie` *or* `Authorization` request is
   no longer bypassed — v1 covers both);
2. the request's **original cookies are forwarded to the origin** (for the per-user routes to
   authenticate) — this is for **origin auth only**, the credential never enters the cache key;
3. the response is stored under the **shared, credential-free key** **only** on a **positive
   in-scope `cache_ttl` signal** — the response **affirmatively** carries the operator's cache
   directive (e.g. an in-scope `cache_ttl … from_header X-Cache-Ttl` with the header present, or
   a positive `max-age`/`s-maxage` the rule honors). **That is the sole storage gate.**

When the positive signal fires, it **force-overrides and strips** the per-user `Set-Cookie`
**and** the weak `Cache-Control: no-store/private/no-cache`, `Pragma: no-cache`, and a past
`Expires` from **both the stored entry and the delivered response** — exactly the VCL `unset
set-cookie; unset Cache-Control; set ttl`. So a stored object **never** carries a `Set-Cookie`
(the absolute confidentiality invariant holds), and a later HIT serves none.

```
@readmodel path_regex ^/v3/readmodel/cache/
cache_credentialed @readmodel                       # forward cookies, cache shared on the signal
cache_ttl @readmodel from_header X-Cache-Ttl        # the positive signal (the VCL X-Cache-Ttl)
cache_ttl default     hit_for_miss 0s               # everything else: not stored
```

The shared endpoints (which emit `X-Cache-Ttl`) cache once and **HIT for everyone, logged-in
included**; the per-user endpoints (`favorites`, `usernotifications`, …) emit **no**
`X-Cache-Ttl`, so **no positive signal → never stored** — fetched fresh with each user's cookie.
**No per-endpoint deny-list**, present or future.

**Leak model — fail-closed, the same trust a custom VCL `return(hash)` assumes.** Safety rests
on the **positive-signal gate**: a per-user route that emits no `X-Cache-Ttl` is never
shared-cached *even if it forgot `Set-Cookie`*. Cross-user confidentiality then rests on the
**origin** emitting the cache signal **only** on genuinely shareable bodies (a misbehaving origin
that stamps `X-Cache-Ttl` on a per-user body would share it — but its `Set-Cookie` is still
stripped, so no session token is ever stored). `cadish check` **warns** the origin-trust posture
(like [`cache_unsafe`](#cache_unsafe)), and warns a scope with **no** positive-store `cache_ttl`
rule (it can never store — a no-op).

> **`Set-Cookie` note:** a positive in-scope signal **overrides and strips** `Set-Cookie` here
> (matching the VCL) — it is **not** a refusal. Without the signal the response is simply not
> stored. The codebase-wide invariant "a `Set-Cookie` value is never written into a cached
> object" stays intact because the cookie is stripped *before* the object is cached.

> **Guards.** `cache_unsafe` does **not** create an alternate store path in a
> `cache_credentialed` scope — only the positive signal stores. And `strip_cookies` in the same
> scope is a **compile error**: the directive already strips `Set-Cookie` on the store path, so a
> redundant `strip_cookies` would only obscure where the safety comes from (the old
> `strip_cookies @readmodel` is subsumed — drop it).

> **Edge tier:** the opt-out + the precedence project to the Cadish Edge worker, so an edge
> deployment behaves identically. A `cache_credentialed` scope that references a server-only or
> untranslatable matcher **fails closed** at the edge (the worker passes the whole site to the
> Cadish server behind, and `cadish edge build` fails loud).

Session-aware bypass — the credential default already does this, but you can also make it
explicit (or bypass on a cookie the default would not treat as a credential):

```
@authed cookie sessionid        # or: cookie sessionid token  (one cookie, OR values)
pass    @authed                 # authenticated requests go straight to origin
```

To OR over several cookie *names* (`sessionid` OR `token`), define one matcher per
name and reference both in the scope: `@a cookie sessionid`, `@b cookie token`,
then `pass @a @b` (a scope ORs its matcher references).

WordPress logged-in bypass — the logged-in cookie name carries a dynamic suffix
(`wordpress_logged_in_<md5-of-site>`), so an exact name cannot match it. A trailing
`*` on the cookie *name* matches any cookie with that prefix:

```
@wp_logged_in cookie wordpress_logged_in_*   # any wordpress_logged_in_<hash>
pass          @wp_logged_in                  # logged-in users bypass the cache
```

A glob name is **presence-only**: `cookie wordpress_logged_in_*` tests that *some*
cookie with that prefix exists. It cannot be combined with value args
(`cookie wordpress_logged_in_* tok` is a compile error), because a value would be
ambiguous across the matched set — constant-time value comparison is reserved for
an exact, single-named cookie. A bare `cookie NAME` (no `*`) stays an exact name
match as before.

#### `cookie_allow`

Cache cookie-bearing traffic by controlling the cookies. `cookie_allow NAME…` is a
**request-cookie allowlist**: it keeps only the named cookies
and **strips every other cookie** from the request — before the [cache key](#cache_key),
before the [credential bypass](#credentialed-requests-are-never-shared-cached-by-default),
and before the origin fetch. It is the cookie analog of
[`query_allow`](#cache_key) (exact names **and** trailing-`*` globs), and the request-side
mirror of [`strip_cookies`](#strip_cookies) (which controls the *response* `Set-Cookie`).

This is the **explicit opt-in to caching cookie-bearing traffic**, modeled on Varnish's
`unset req.http.Cookie`. It does **two** things, both safe by construction:

1. **It strips every cookie you do not list** — so the stripped cookies (any session, `_ga`,
   …) never reach the origin and never make the response per-user. Forget a cookie and it is
   *removed*, not cached: you cannot cache a credentialed request by accident.
2. **The cookies you keep must still be KEYED to cache.** Allow-listing a cookie does **not**
   exempt it from the [credential rule](#credentialed-requests-are-never-shared-cached-by-default):
   a kept cookie is forwarded to the origin and can personalize the reply, so it is cacheable
   only when the [cache key](#cache_key) isolates it (a `cookie:NAME` token, or `header:Cookie`).
   A kept-but-unkeyed cookie **bypasses** the cache (never cached cross-user) — the safe
   default, exactly as if it were an uncontrolled credential.

So: `cookie_allow` controls *which* cookies survive; the `cache_key` must still cover the
survivors, or the request bypasses. The valid pattern is **strip the rest, key what you keep**:

```
cookie_allow lang darkMode wp_logged_in_*       # keep these; strip session, _ga, everything else
cache_key    host path cookie:lang cookie:darkMode   # …and KEY the kept cookies that vary the response
cache_ttl    default ttl 60s
```

- An **empty** `cookie_allow` (no names) strips **every** cookie — the request reaches the
  origin anonymous and caches as anonymous content (the simplest safe pattern).
- `Authorization` is **never** controlled by `cookie_allow`; a bearer token still bypasses
  unless the key covers it (`header:Authorization`).
- A kept cookie that is **not** keyed makes its requests **bypass** (never cache). `cadish
  check` flags this with a **`cookie-allow-unkeyed`** warning so you notice the cache isn't
  engaging — fix it by keying the cookie (`cache_key … cookie:NAME`) or dropping it from the
  allowlist. The runtime is safe regardless; the warning is about cache *effectiveness*.

Applied at **RECV**, *after* the security gate (so `deny`/`allow` cookie rules still see the
original cookies) but before the cache key, the credential bypass, and the origin fetch. The
Cadish **Edge** worker enforces the same name-aware rule: a kept-but-unkeyed cookie bypasses
the edge cache too (it never does blanket per-cookie exemption).

- **A `pass`ed (uncached) request forwards the *original* Cookie to the origin.** Cookie
  normalization is a **cache-key** concern, so it is **skipped when nothing is cached**: a
  request whose decision is `pass` (an explicit [`pass`](#pass) rule, or a credential
  **bypass** from a kept-but-unkeyed cookie / `Authorization`) reaches the origin carrying the
  **full, pre-filter** Cookie header — *not* the `cookie_allow`/`derives_from`-stripped one.
  This keeps auth/session intact on uncached per-user endpoints (`/me`, account, cart, APIs):
  stripping a session that will never be cached has no caching benefit and only makes the
  backend see an anonymous request. It is **safe** because a passed response is **never
  stored**, so the per-user cookie cannot contaminate a shared cache entry (the same reason a
  WebSocket-upgrade tunnel already forwards the original cookie). **Cacheable** requests are
  unchanged: they still normalize the Cookie for the key + cross-user collapse. The Edge worker
  applies the identical rule.

#### `header_regex`

`header_regex NAME PATTERN` matches a named request header's **value** against an RE2
regex — the header analog of [`path_regex`](#path_regex) / [`host_regex`](#host_regex),
and the third form alongside `header NAME VALUE` (exact equality) and `header_present
NAME` (presence). It is a substring-style match on the raw value (anchor with `^`/`$`
for a prefix/whole-value test); the same RE2 dialect and inline flags as the other regex
matchers apply (`(?i)` for case-insensitive). Cost is the regex tier, so `cadish check`
counts each in *regex evals / request*. A multi-valued header matches if **any** value
matches.

```
@beta_ua  header_regex User-Agent (?i)\bbeta-client\b
@json_req header_regex Accept       application/json
```

> **Multi-line caveat:** a genuinely multi-LINE header (the same name sent on several
> lines) is OR-matched per line on the server but comma-JOINED into one value at the CF
> edge, so a pattern spanning the join could differ. Single-line comma-separated values
> (the common case) behave identically.

Like the other regex matchers it projects to the **edge** IR (the RE2 `(?i)` is lifted
to a JS `RegExp` flag so the worker never crashes on the inline flag group); the
cross-runtime conformance suite proves Go and the edge JS decide the same.

#### `cookie_json` / `header_json`

Test **one field inside a JSON cookie/header value**. These mirror the `cookie`
matcher exactly — presence, or OR-of-values — but reach one level into a structured
value via a `PATH`:

```
cookie_json NAME PATH [VALUE…]      # a field inside a JSON cookie value
header_json NAME PATH [VALUE…]      # a field inside a JSON header value (same engine)
```

- **NAME** — the cookie/header name. The `{$ENV}` macro works here
  (`cookie_json verified-{$ENV} …`); it is resolved before the matcher compiles, so
  the matcher sees the literal name.
- **PATH** — a **bounded dotted field path**: object keys and array indices
  (`\d+`): `needVerify`, `user.verified`, `flags.0.kind`. It is **not** JSONPath —
  no wildcards, filters, recursion, slices, or functions.
- **VALUE…** — zero or more literals, with **the exact `cookie` semantics**:
  - **no value** → the field **exists** (present and non-null) — like bare `cookie NAME`.
  - **one or more values** → the field's scalar value (coerced to its JSON string
    form) **equals any** listed value (OR) — like `cookie NAME a b c`.

There are **no operators** (no `eq`/`one_of`/`lt`/`ge`). A boolean is just the
literal: `cookie_json nsfwCookie needVerify true` (JSON `true` coerces to `"true"`,
`42` to `"42"`, a string to itself). Numeric comparison (`age >= 18`) is a
deliberate non-goal.

**Scalar coercion is exact and deterministic** (and identical on the server and the
edge worker — see [Cadish Edge](edge.md)):

- A **number** coerces to its **exact JSON source digits**, *not* a re-rendered
  float: `1e3` → `"1e3"` (not `"1000"`), `1.0` → `"1.0"` (not `"1"`), `1.50` →
  `"1.50"` (not `"1.5"`). Match the value as it appears in the JSON.
- A **string** coerces to itself; `true`/`false` to `"true"`/`"false"`.
- A **duplicate object key** resolves to the **last** occurrence (the JSON `parse`
  de-facto rule): `{"k":"a","k":"b"}` → `"b"`.
- A `%`-encoded value is decoded **once** with percent-unescaping that **preserves
  `+`** (a JSON cookie is not form-encoded — `+` is a literal `+`, never a space).

```
@nsfw_needverify  cookie_json nsfwCookie needVerify true      # boolean field == true
@plan_pro         header_json X-Session   plan.tier  pro enterprise   # OR of values
@has_flags        cookie_json session     flags                # presence only
@gate_kind        cookie_json nsfwCookie  flags.0.kind gate    # array-index path
```

**Fail-safe (boolean, false on anything weird).** The matcher only ever returns
true/false, and is `false` on every anomaly — so malformed input can never flip a
gate open; it falls through to the operator's `classify default`:

| Condition | Result |
|---|---|
| cookie/header **absent** | `false` |
| value present but **not valid JSON** | `false` |
| value exceeds the **size cap** (8 KiB) | `false` (no parse attempted) |
| value **too deeply nested anywhere** (whole-document depth > 32) | `false` (rejected up front, even if the target field is shallow) |
| **path missing** / segment not found / array index out of range | `false` |
| field is an **object/array** (not a scalar) under a value or presence test | `false` |
| field is JSON **null** | `false` |
| URL-encoded value (`%7B…`) | **decoded once** before parsing (`+` preserved, not turned into a space) |

**Security / cost.** A crafted cookie cannot DoS the parser: a raw value over the
**8 KiB** size cap is rejected before any parse, and the decode is bounded to a
**depth-32** nesting cap. It is request-phase and operates on a header value already
in hand (no body buffering — the zero-copy invariant holds); the result is memoized
per request, so a `classify` table that tests the same cookie several times parses
it once. `cadish check` charges it at the regex cost tier (a small bounded JSON
parse — pricier than a plain `cookie`), but it is **not** an RE2 evaluation, so it
does not count toward the "regex evals / request" headline.

This is what closes the age-verification JSON state machine as *config* (see the
[`classify` geo→business example](#classify) and its red-line note): reading
`needVerify`/`verified` out of a JSON `nsfwCookie` and feeding them to a `classify`
row or an origin request header.

> **Note (response-phase matchers):** every other matcher tests the *request*
> (path/host/header/method) and works in any phase. `content_type`, `set_cookie`,
> and `resp_header` test the **response**, which is only known once the origin has
> answered — at `EvalResponse` (the ORIGIN phase, where `cache_ttl`/`storage`
> decide) and at DELIVER. So they may scope the response/DELIVER directives
> (`cache_ttl`, `storage`, `header`, `strip_cookies`, `cors`) but **not** the
> request-phase ones — using one to scope a
> `pass`/`route`/`purge`/`cache_key`/a pre-cache_key `header` is a compile error.
> Examples: `header @longcache Cache-Control "public, max-age=31536000"` sets a
> long TTL on CSS/SVG *responses* (not by path); `cache_ttl @session hit_for_miss
> 0s` refuses to cache a session-bearing response;
> `cache_ttl resp_header X-Powered-By Express ttl 1m grace 2w` gives an SSR origin
> (it signals its kind in the response header) a different freshness tier than a
> PHP origin behind the same path — including the residual 404 split that a `status`
> selector alone can't tell apart:
>
> ```
> cache_ttl resp_header X-Powered-By Express status 404 ttl 1m grace 24h   # SSR 404
> cache_ttl resp_header X-Powered-By Express ttl 1m grace 2w               # SSR default
> cache_ttl status 404 ttl 10s grace 1m                                    # PHP 404
> cache_ttl default ttl 5s grace 1m                                        # PHP default
> ```

---

## Directives

### SETUP

#### `tls`
TLS termination for the site. Three modes (full details in [tls.md](tls.md)):

```
tls { acme you@example.com }        # automatic Let's Encrypt (issue + renew)
tls { cert /etc/c.pem key /etc/k.pem }   # static keypair (your own / internal CA)
tls off                             # plain HTTP (e.g. behind a TLS-terminating LB)
```

Optional HSTS knob: `tls { acme …; hsts max_age 31536000 includeSubdomains preload }`.
Certificates are issued **only** for configured hostnames (never an open issuer).

**Keep a probe / data-plane path answering on plain `:80`** — `http_redirect_except`:

```
tls {
    acme you@example.com
    http_redirect_except /aws-health-check       # one or more paths; repeatable
}
respond @probe /aws-health-check 200             # answered on BOTH :80 and :443
```

With TLS configured, the standalone `:80` listener 301-redirects **every** request to
HTTPS before any site rule runs — so a path meant to answer on plain HTTP (an L4/DNS
health-check probe, a webhook, a monitor) gets a `301` instead of its real `200`/`503`.
`http_redirect_except` lists request paths that the `:80` listener must **not** redirect:
they fall through to the site pipeline and answer on plain HTTP (whatever your `respond`/
`redirect`/`route` produces), while every other path still 301s to HTTPS. Notes:

- Matching is **exact** on the request path (the query string is ignored);
  `/aws-health-check` does not exempt `/aws-health-check/extra`. Repeat the option or pass
  several paths to exempt more (`http_redirect_except /healthz /webhook`).
- It is strictly an **opt-out for named paths** — the default (TLS ⇒ redirect-all on `:80`)
  is unchanged, and it never *forces* a redirect. The `X-Forwarded-Proto: https` loop guard
  is untouched (a request that already arrived over HTTPS is still served plain). No
  redirect loops are introduced.
- Scope is **`cadish run`** (standalone TLS). It composes with the ingress controller's
  per-host redirect gating but is primarily a run-mode knob (ingress hosts gate the
  redirect per host via `spec.tls`).

#### `cache`
The two-tier cache store for the site (details in [cache.md](cache.md)):

```
cache {
    ram  8GiB                       # RAM-tier budget
    disk /var/cache/cadish 2TiB     # NVMe-tier directory + budget
    tier .ts .mp4 -> disk           # per-extension placement hint (see caveat)
}
```

Omit `cache` and you get a default ~2 GiB RAM tier (with a scratch disk dir).
`tier .ext -> ram|disk` sets a **per-extension default placement** (a `storage`
rule overrides it per-request); both are honored by the cache.

> **RAM-only caveat.** A `cache { ram … }` block with **no `disk` line** is a
> RAM-only deployment (zero disk budget). It caches always-RAM extensions
> (`.m3u8 .jpg …`) and other objects with a **known `Content-Length`** small enough
> for RAM, but **unknown-length (chunked / streamed) and large objects route to the
> disk tier — which doesn't exist — so they are cached nowhere and stream through
> uncached.** A dynamic origin replying `Transfer-Encoding: chunked` gets **zero
> caching** here. Watch the `DiskNoTierDiscards` cache stat (and a throttled log line)
> to detect it; add a `disk` tier, or have the origin send a `Content-Length`, to fix
> it. See [cache.md](cache.md#routing-ram-vs-disk).

#### `upstream` / `cluster`
A named backend pool. `upstream` is a normal origin; `cluster` is a peer pool
(the cache-sharding case). Both accept the same block (details in
[load-balancing.md](load-balancing.md)):

```
upstream web {
    to          http://10.0.0.1:8080  https://10.0.0.2:8080   # ≥1; repeatable
    to          dns://backend.svc:8080       # dns:// = periodic A/AAAA re-resolution
    to          k8s://web.prod:8080          # k8s:// = live EndpointSlice discovery
    host_header preserve | origin | VALUE    # Host sent upstream (default: preserve)
    sni         www.example.com              # TLS ClientHello server name (HTTPS backends)
    http_reuse  never                        # disable backend connection reuse
    resolve     10s nameserver 10.0.0.10:53  # dns:// re-resolve interval + nameserver(s)
    policy      round_robin | least_conn | sticky | shard     # (or inferred)
    sticky      by cookie PHPSESSID else client_ip            # pin a user to a backend
    shard_by    url | key                                     # consistent-hash (clusters)
    health      GET / expect 301 interval 5s window 6 threshold 3
    health      GET /list/ expect 2xx 3xx interval 5s            # list / class form
    timeout     connect 5s first_byte 600s between_bytes 30s
    max_conns   800
}
cluster peers { to k8s://cadish-peers.default:6081; shard_by url }
```

- `to` targets: `http(s)://host:port` (static), `dns://host:port` (re-resolves
  A/AAAA periodically), or `k8s://service.namespace:port` (live Kubernetes
  EndpointSlice discovery — see below) — so pod/IP churn needs no reload. A bare
  `host:port` (no scheme) is taken as `http://`. A malformed target (bad URL,
  empty, unsupported scheme, missing host) is rejected by `cadish check` at lint
  time with a `file:line`, not just at startup.
- A single static `to` is the degenerate (valid) pool. Multiple backends +
  `policy`/`sticky`/`shard_by`/`health` make it a load balancer.
- `health … expect …` accepts a single status (`expect 301`), a list
  (`expect 200 301`), or a status **class** (`expect 2xx`, `expect 2xx 3xx`). A
  probe is a success when the response status matches **any** of them — so a
  WordPress root that answers 200 on one deploy and 301 on the next stays UP under
  `expect 2xx 3xx` (HAProxy `http-check expect rstatus 2|3..` parity). Single-int
  is unchanged.
- `health … window N` is the sliding count of recent probe outcomes (default 3); the
  FSM allocates one `N`-entry ring **per backend**, so `N` is **bounded** (max 100000).
  An absurd window (e.g. `window 2000000000`, which would allocate ~2 GB per backend at
  pool construction) is rejected — both by `cadish check` at lint time with a `file:line`
  and at load — rather than driving the allocation. A real health window is a handful of
  samples; the cap is far above any legitimate tuning.

##### `k8s://` — Kubernetes EndpointSlice resolution

`to k8s://service.namespace:port` resolves a backend against the Kubernetes API:
cadish watches the service's **EndpointSlices** and load-balances over the live
set of **ready pod `IP:port`** addresses directly — bypassing kube-proxy/`ClusterIP`
so its own policies (`sticky`, `shard_by url`, `least_conn`, per-pod health +
passive ejection) act on real pods.

- **Namespace is mandatory** and must be a single label: `k8s://web.prod:8080`,
  not `k8s://web:8080` and not the FQDN `k8s://web.prod.svc.cluster.local:8080`.
- **Port** is either numeric (`:8080`, passed through) or a **named** service port
  (`:http`, resolved to its number from the EndpointSlice). A named port that the
  service does not expose is rejected at resolve time.
- Only **ready** endpoints are used; addresses are unioned across all the service's
  slices and de-duplicated. A scaled-to-zero service yields no backends (the pool
  returns 503) — a transient API error instead retains the last-known set.
- Resolution is **event-driven**: an EndpointSlice change pokes a re-resolve within
  sub-second (plus a 30 s safety re-resolve), all off the request hot path.
- **Zero-cost when absent**: the Kubernetes client is built lazily, only when a
  loaded Cadishfile actually contains a `k8s://` target.

**Auth.** In-cluster, cadish uses its ServiceAccount token automatically. Out of
cluster, point it at a kubeconfig: `cadish run --kubeconfig PATH` (precedence:
`--kubeconfig` > `KUBECONFIG` > in-cluster > `~/.kube/config`).

**RBAC (least privilege).** cadish only needs `get/list/watch` on
`discovery.k8s.io/endpointslices` — named ports come from the EndpointSlices' own
port list, so no `services` access is required. Apply the ready-made read-only
manifest [`deploy/k8s/rbac-resolver.yaml`](../deploy/k8s/rbac-resolver.yaml);
the out-of-cluster kubeconfig recipe is in [`deploy/README.md`](../deploy/README.md).
- An `upstream` with a `bucket` line is an **S3 origin** instead:
  `upstream s3 { to https://s3.endpoint; bucket media }`. Credentials are optional:
  - `access_key VALUE` / `secret_key VALUE` — static credentials (use `${ENV}` to keep
    secrets out of the file, e.g. `access_key ${S3_KEY}`). `region VALUE` sets the S3
    region (default `us-east-1`; any non-empty value works for most S3-compatible stores).
  - `anonymous` — fetch unsigned, for a public-read bucket. **Anonymous is also the
    default when no `access_key`/`secret_key` are given** (signing with empty credentials
    is rejected by S3/MinIO, so "no creds" means "don't sign").

  ```
  upstream s3 { to https://s3.endpoint; bucket media
                access_key ${S3_KEY}; secret_key ${S3_SECRET}; region gra }
  upstream public { to http://minio:9000; bucket assets; anonymous }
  ```

##### `host_header` — which Host the origin sees

Go builds the upstream request from the `to` URL, so without this directive an
origin receives `Host: <upstream>` (e.g. `wordpress:80`). Name-based vhosts and
multi-tenant SaaS origins (WordPress, Apache/nginx vhosts, shared hosting) then
**canonical-301** the request to their internal hostname — which broke the
WordPress homepage in the staging POC. `host_header` controls the Host sent
upstream:

| Form | Host sent to the origin |
|---|---|
| `host_header preserve` | the **original client Host** (e.g. `www.example.com`). **This is the default** — no directive needed. |
| `host_header origin` | the upstream `to` URL's host (the legacy/Go-default behavior). Use for origins that key on their own hostname. |
| `host_header VALUE` | a fixed Host, e.g. `host_header origin.internal`. |

The chosen value sets the request's `Host` field (a `Host` entry written via
`header` is ignored by Go). It applies to the whole `upstream` — a single
httporigin and every backend of an lb pool alike — and flows through an
`origin chain`. On a background grace-revalidation (when the client headers are
gone) `preserve` still forwards the original Host; if it is somehow unknown it
falls back to the upstream host. `bucket` (S3) and `sign cloudfront` upstreams
ignore `host_header` (S3/CloudFront don't use a vhost Host).

> **Note.** The default is `preserve` (what real CDNs do): cadish forwards the
> client's Host to the origin. If your origin relies on receiving its own internal
> hostname instead, set `host_header origin`.

##### `sni` / `http_reuse` — TLS server name + connection reuse

Two per-`upstream`/`cluster` transport knobs for HTTPS backends. They are
**explicit-only**: an upstream that sets neither is byte-for-byte unchanged
(shared pool, Go-default SNI, keep-alive on).

```
upstream blog {
    to          https://1.2.3.4:443
    host_header www.placercams.com   # HTTP-layer Host (vhost routing)
    sni         www.placercams.com   # TLS-layer ClientHello server name
    http_reuse  never                # no cross-request connection reuse
}
```

| Directive | Effect |
|---|---|
| `sni <server-name>` | Sets the TLS ClientHello **ServerName** for HTTPS dials. Needed when the `to` is a bare **IP fronting multiple vhosts/certs** — without it Go derives SNI from the dialed host (the IP), so the origin presents the wrong cert or returns **421 Misdirected Request**. |
| `http_reuse never` | Disables backend connection reuse (`Transport.DisableKeepAlives`) — a fresh connection per request. Use against a multi-vhost origin (e.g. Apache) that 421s when a pooled keep-alive connection opened for one vhost is reused for another. **Only `never` is supported**; the default (no directive) is connection reuse. `safe`/`aggressive`/`always` are rejected. |

**SNI is the TLS layer; Host is the HTTP layer.** `sni` is the name in the
handshake (cert/vhost selection); `host_header` is the `Host:` header inside the
request (vhost routing). They usually match for a single-vhost target but are set
**independently** — `sni` is **not** defaulted from `host_header`. When `sni` is
unset cadish injects nothing and leaves Go's dialed-host default, so existing
HTTPS upstreams (CloudFront, S3, real-hostname origins) are unaffected.

Both knobs are no-ops on an all-plaintext (`http://`) upstream — `cadish check`
emits a **warning** (`sni-without-https`) if you set them there. `bucket` (S3) and
`sign cloudfront` upstreams ignore both (like they ignore `host_header`). The
knobs allocate a dedicated transport only when set; the default path keeps the
shared pooled client at zero cost.

##### `tls_insecure` / `ca_file` / `alpn` — origin TLS verification

Three per-`upstream`/`cluster` knobs that control how cadish verifies the **origin's
TLS certificate** and which ALPN protocol it offers. The default is **secure**: full
verification against the system roots, h2 auto-negotiated. They are **explicit-only**
— an upstream that sets none is byte-for-byte unchanged.

```
upstream placercams_blog {
    to          https://placercams-blog.production.svc.cluster.local:443
    sni         www.placercams.com
    host_header www.placercams.com
    http_reuse  never
    alpn        http/1.1        # pin the origin ALPN (disables the h2 auto-upgrade)
    tls_insecure                # skip verification (= HAProxy `ssl verify none`)
    # ca_file   /etc/cadish/internal-ca.pem   # the SECURE alternative — verify against a private CA
}
```

| Directive | Effect |
|---|---|
| `tls_insecure` | Disables verification of the origin cert (`InsecureSkipVerify`) for this upstream only — the equivalent of HAProxy `ssl verify none`. A **bare flag** (no argument). Use only for a self-signed / internal origin you cannot otherwise trust. `cadish check` always emits a security **warning** (`insecure-origin-tls`). |
| `ca_file <path>` | Verifies the origin against a **private CA** loaded from a PEM bundle (per-upstream `RootCAs`) — the secure alternative to `tls_insecure`. The PEM is loaded and validated at `cadish check` time, so a missing / unparseable / empty file fails the build loudly. |
| `alpn <proto…>` | Pins the origin TLS **ALPN** list (`NextProtos`), e.g. `alpn http/1.1` or `alpn h2 http/1.1`. Pinning a list **disables Go's automatic HTTP/2 upgrade** (the supported way to force HTTP/1.1 to the origin). Unset ⇒ Go's default (h2 still attempted). |

`tls_insecure` and `ca_file` are **mutually exclusive** — one skips verification, the
other strengthens it — and setting both is a compile error. Verification is
**per-upstream**: an insecure origin never relaxes verification for any other
upstream (each gets its own `http.Transport` / `tls.Config`). The same settings are
applied to **active health probes**, so a probe handshakes the HTTPS origin exactly
as a live fetch does (HAProxy `http-check connect ssl` parity). `bucket` (S3) and
`sign cloudfront` upstreams ignore these knobs (like `host_header`/`sni`).

##### `resolve` — DNS re-resolution interval + custom nameserver

`resolve [<interval>] [nameserver <ip:port>…]` controls how a **`dns://`** upstream
re-resolves: how often, and which DNS server(s) to query (instead of the system
`/etc/resolv.conf`). It is the HAProxy `resolvers … nameserver …` / `hold valid`
equivalent for a non-Kubernetes DNS backend. **Explicit-only** — an upstream that
omits it is byte-for-byte unchanged (system resolver, 30s re-resolution).

```
upstream legacy_dns {
    to      dns://some-legacy-host.internal:80
    resolve 10s nameserver 10.134.8.94:53 10.134.8.95:53
}
```

| Form | Effect |
|---|---|
| `resolve <interval>` | Sets the dynamic re-resolution interval (e.g. `resolve 10s`). Unset ⇒ the 30s default. |
| `resolve nameserver <ip:port>…` | Queries the listed DNS server(s) — each a literal `ip:port` (e.g. `10.134.8.94:53`) — instead of the system resolver. Multiple servers are tried in order. |
| `resolve <interval> nameserver <ip:port>…` | Both at once. |

A bare `resolve` (neither interval nor nameserver) is a compile error. The interval
also applies to `k8s://` targets (which additionally re-resolve sub-second on pod
churn). A custom nameserver only affects `dns://` targets — `http(s)://` static
targets are resolved per-request by the Go HTTP client, and `k8s://` uses the
EndpointSlice resolver, not DNS.

> **Note (scope).** This is the *sound subset* of the RESOLVER spec. DNS-record-**TTL**
> honoring (`ttl_respect`/`min_ttl`/`max_ttl`) is intentionally **not** implemented:
> Go's stdlib resolver does not surface the record TTL, and a fixed interval is
> already outcome-equivalent to HAProxy's `hold valid <dur>` (itself a fixed timer).
> A backend that must follow DNS TTL precisely should use `k8s://` (event-driven) or a
> short `resolve` interval.

> **Security.** A custom nameserver is partly untrusted: cadish drops any
> **link-local / cloud-metadata** address (`169.254.0.0/16`, `fe80::/10`) it returns,
> so a hostile DNS answer cannot turn a backend into the instance metadata service.
> (The default system resolver is assumed trusted and is not re-filtered, matching the
> pre-existing behavior.)

#### `origin chain`
Composable origin fallback — try A, fall through to B on miss/4xx/5xx:

```
upstream s3         { to https://s3.endpoint; bucket media }
upstream cloudfront { to https://d111.cloudfront.net }
origin chain s3 -> cloudfront
```

The chain becomes the site's default origin. Members remain individually
selectable by `route`.

#### `cluster { … }` — region-local peer cache (clustering)

A **nameless** `cluster { peers … }` block turns N cadish nodes in a region into a
sharded / cooperative cache. (This is distinct from the named `cluster NAME { to … }`
LB pool above; the membership block has no name and a `peers` line.) It is fully
opt-in — **a cadish with no `cluster` block behaves exactly as before**, at zero
cost.

```
cluster {
    self     http://10.0.0.1:6081           # this node (must be one of peers)
    peers    http://10.0.0.1:6081 http://10.0.0.2:6081 http://10.0.0.3:6081
    peers    dns://cadish-peers:6081         # static and/or dns:// / k8s://… discovery
    region   gra                             # scopes the cluster; the hop-guard value
    mode     read_through | owner            # default read_through
    fallback strict | degraded               # owner mode, owner-down (default degraded)
    health   GET /.cadish/readyz expect 200 interval 1s window 3 threshold 2
}
```

> **Health path.** `/.cadish/readyz` is cadish's built-in readiness endpoint (200 when
> warm, 503 while warming) — host-agnostic, no Cadishfile rule needed. Use it for both the
> peer `health` probe above and an **external** DNS/L4 health checker that decides whether a
> node receives client traffic (see the 3-node deployment guide in `deploy/README.md`).

| Directive | Meaning |
|-----------|---------|
| `self URL` | This node's own peer URL; identifies "us" on the ring. Must appear in `peers` (enforced when all peers are static). |
| `peers URL…` | Peer cadish nodes (repeatable). Reuses the `upstream` `to` target syntax: static `http(s)://`, `dns://` periodic discovery, or `k8s://service.namespace:port` EndpointSlice discovery. |
| `region NAME` | Cluster scope. Stamped as the `X-Cadish-Peer` hop header; a hop from a different region is treated as a fresh client request. |
| `mode read_through\|owner` | How #7 and #8 coexist (below). Default `read_through`. |
| `fallback strict\|degraded` | Owner-mode behavior when the key's owner is down. Default `degraded`. |
| `health …` | Active peer-health probe (same spec as `upstream`); reuses the lb health FSM. |

**`mode read_through` (#7 — opportunistic peer read-through).** On a local cache
MISS the node asks the **owning peer** (consistent-hash over peers, keyed on the
request path) for the object before going to origin; a peer hit is streamed and
stored locally (same tee contract as origin), a peer miss/unreachable falls
through to origin. No request is re-routed — every node may serve any key. Modeled
as a peer `origin.Origin` composed *before* the real origin in a chain.

**`mode owner` (#8 — authoritative ownership routing).** One node **owns** each key
on the ring. A request landing on a non-owner is **reverse-proxied to the owner**
(health-gated), so the object is cached **once per region** — cadish acts as its
own L7 director. If the owner is **down**: `fallback strict` serves the request
locally (accepts a transient duplicate); `fallback degraded` tries the next ring
node, then local.

**A `pass` goes straight to origin — never via a peer (both modes).** A request whose
URL is defined `pass` (and the credential bypass that is never stored) is fetched
directly from origin: owner mode skips the owner seam, and read-through skips the
peer `PeerOrigin` (since v0.2.2). A "possibly cacheable" request still follows the
full path to the owner even if its response later proves uncacheable. So you don't
"go around" the cluster for uncacheable routes — only the routes the cluster can
actually cache once are sharded.

> **Store-once requires the peer to trust + isolate its peers.** When a non-owner
> reverse-proxies to the owner, the owner re-derives the cache key from the request
> (its `Host` and client IP). cadish forwards the original client `Host` and the
> resolved client IP (`X-Forwarded-For`) on the peer hop **so a proxied request and a
> direct request hash to the same key** (otherwise the owner would store one object
> twice — once per host/IP it sees). For the owner to honor that forwarded client IP,
> the peer subnet **must** be in `trust_proxy` (the same trust that enables the
> `X-Cadish-Peer` hop guard) **and** isolated to cadish nodes only. This supersedes
> any older advice to keep the peer subnet out of `trust_proxy`: for a cluster, trust
> **and** isolate the peer network. (Request **scheme** is not reconstructed across
> the plain-HTTP peer hop — it is not a cache-key input, but `{proto}`/scheme-based
> redirects differ for a proxied request; prefer a uniform-scheme entry such as DNS
> round-robin over one scheme.)

**Loop / storm safety.** A request forwarded to a peer carries `X-Cadish-Peer:
<region>`; a node that sees it serves locally and **never re-forwards** (no
owner-route, no read-through), so a key hops at most once. Coalescing still
single-flights, and per-peer health (passive ejection) comes from the reused lb pool. A node
never reads through to *itself* (that would deadlock against coalescing) — a
self-owned key is served locally.

> **Security — `X-Cadish-Peer` is trust-gated.** The hop guard is an inter-node
> signal, never a client header. cadish honors an inbound `X-Cadish-Peer` **only when
> the immediate socket peer is a trusted proxy/peer** — the same `trust_proxy` gate
> used for `X-Forwarded-For` and header geo (the single trust-boundary policy). From
> any untrusted/direct peer the header is **stripped** before routing, so a client
> that forges `X-Cadish-Peer: <your-region>` can no longer suppress a peer fetch
> (which would bypass the cluster cache and amplify origin load). **Declare your peer
> network in `trust_proxy`** (e.g. `trust_proxy 10.0.0.0/8`) so genuine inter-node
> hops are honored; with no `trust_proxy` the peer is never trusted, so the loop
> guard is disabled (cadish still serves correctly via the self/owner checks, but the
> defense-in-depth storm guard is inactive). The guard still **fails safe** either
> way: a spoofed value can only *disable* peer routing, never cause a loop, redirect,
> or SSRF (peer targets come solely from `peers`, never the request).

> **Security — peer network must be isolated (hard deployment requirement).** Cadish
> has **no mutual peer authentication** (no mTLS, no shared secret, no token). The
> peer endpoint is the same listener port as client traffic. Because peer responses
> are teed into the local cache, **anyone who can reach a node's port over the peer
> path can read cached objects by key and inject arbitrary content into the regional
> cache**. This is the same trust-boundary assumption as any
> clustered cache: **the peer subnet must be reachable only by other cadish nodes,
> never by untrusted clients**. Enforce it with firewalling, a VPC security group,
> or a Kubernetes `NetworkPolicy`.
>
> The security gate (IP ACLs, `allow`/`deny` rules) runs **before** cluster routing,
> so those controls still fire for forged peer requests — but they are only effective
> if the real client IP resolves correctly. A clustered deployment **must** list the
> peer subnet in `trust_proxy` (the hop guard and the owner's client-IP/cache-key
> derivation both depend on it) **and** isolate that subnet to cadish nodes only — so
> there is no untrusted client on it that could forge `X-Forwarded-For`. cadish helps
> here: when a non-owner forwards a request to the owner it **overwrites** any
> client-supplied `X-Forwarded-For` with its own authoritative resolution, so a forged
> XFF cannot survive the peer hop. The "trust **and** isolate" pair is the load-bearing
> requirement; do not trust the peer subnet without isolating it.
>
> Mutual peer authentication (mTLS or a shared-secret header) is a planned
> improvement but is **not currently implemented**. Until then, network isolation is
> the required control. See [SECURITY.md](../SECURITY.md#cluster--peer-network-must-be-isolated)
> for the full threat model and mitigations.

#### `edge { … }` (Cadish Edge — Cloudflare Workers)

Configures **Cadish Edge**: running the *same Cadishfile* as an additive caching
tier on Cloudflare Workers (the Go binary projects the compiled pipeline to a
portable IR a small generic worker interprets — "one Cadishfile, two runtimes").
This block affects only the **edge** plane; it has no effect on the cadish server
itself. Parse-once (SETUP). Full guide: [`edge.md`](edge.md).

```
edge {
    account  <account-id>      # Cloudflare account (or env CF_ACCOUNT_ID)
    zone     example.com       # zone name or 32-hex zone id
    worker   cadish-edge-example
    route    example.com/*      # repeatable; defaults to the site hosts (host/*)
    kv       EDGE_CACHE         # optional; only needed when you `distribute`
    default  local              # default edge cache tier: local | distribute | skip
    distribute @html            # per-scope tier override (L2 KV — global)
    skip       @assets          # never cache at the edge (Cloudflare serves natively)
    kv_ttl       5m             # cap KV (L2) retention (default: object ttl+grace)
    kv_max_bytes 1MB            # objects larger than this never enter KV (L1-only)
}
```

| Setting | Meaning |
|---|---|
| `account` / `zone` / `worker` | Cloudflare deploy identity. **Never** shipped in the public worker IR — management-plane metadata only (D41/D43). |
| `route PATTERN…` | Worker route(s) attached by `cadish edge enable`. Defaults to `host/*` for each site host. |
| `kv NAME` | L2 KV namespace title. Created/bound only when an L2 tier is used. |
| `default TIER` | Edge cache tier when no per-scope policy matches. `local` = L1 (per-POP Cache API) only; `distribute` = L1 + L2 (global KV); `skip` = don't cache at the edge. |
| `distribute`/`local`/`skip @scope` | Per-scope tier override (first-match-wins; evaluated with the origin response in scope, so `content_type` works). |
| `kv_ttl DURATION` | **Global** cap on KV (L2) *retention* — how long a blob physically stays in KV before auto-deleting. This is **not** the object's cache TTL: freshness (HIT/STALE/expired) is decided by the object's own `cache_ttl`/`grace`, the same at every POP. Effective KV retention = `clamp(ttl+grace, 60s, kv_ttl)` (60s is KV's hard floor). Default: `ttl+grace` (no cap). Keep it **short** for `distribute` scopes — it bounds how long a purged/stale entry can stay warm across POPs (see below). |
| `kv_max_bytes SIZE` | **Global** hard size bound for the KV tier. A response body larger than this is written to **L1 only, never KV**, regardless of its `distribute` tier (it still caches per-POP). Protects the KV write rate/storage and stays under Workers KV's 25 MB hard cap. Default `1MB`; a value > 25 MB is a build warning. |

> **KV invalidation is TTL-only — purge is not globally immediate.** A `purge`/BAN
> invalidates the cadish **server** and per-POP L1, but does **not** reach into the
> global KV tier (there is deliberately no epoch/version key and no server→KV purge
> call). A purged object stays warm in KV until its `expirationTtl` (`kv_ttl`)
> elapses. **If you enable the KV tier (`distribute`), accept that purge is
> eventually-consistent across POPs and bound it with a short `kv_ttl`** (e.g.
> `kv_ttl 5m` makes a purge globally effective within ~5 min as entries age out). KV
> is eventually consistent (~≤60s cross-POP propagation) and best-effort: any KV
> read/write error degrades to origin/L1 — it is never a single point of failure.

The cache-tier policies (`default` + per-scope + `kv_ttl`/`kv_max_bytes`) ARE projected into the worker IR;
the deploy identity is not. Deploy with `cadish edge deploy` (uploads, no routes),
`enable` (attach routes), `disable` (instant kill switch). Auth via `CF_API_TOKEN`;
the upstream URL is a deploy-time binding (`-origin` / `CADISH_EDGE_ORIGIN`), never
in the IR.

### RECV

#### Security gate (`allow` / `deny` / `block`)

The **security gate** is the *first* thing evaluated in RECV — **before the cache
key is computed, before the cache is consulted, and before the origin is dialed**.
A blocked request therefore touches **neither the cache nor the origin** (so an
attacker can neither poison the cache nor hammer the upstream). These are **core
directives, always available** — no `waf { }` block is required (that block is the
OWASP module, a later phase). When a site declares no `allow`/`deny`/`block` rule
the entire gate is skipped (one cheap branch) — **zero cost when no security is
configured**.

The engine is a [`classify`](#classify)-style **first-match decision table**: each
rule is a **conjunction** of matchers (AND within a rule, `!` negation per term),
rules are tried in order (OR across rules), and the first match wins — yielding a
**security action** instead of a token. Internal order: **`allow` → `deny`**
(rate-limit / OWASP / challenge are later slices that slot in after `deny`).

| Directive | Action |
|---|---|
| `allow <matchers>` | **Allowlist** — the matching request **short-circuits the gate** (no `deny` runs). Office / monitoring IPs are never blocked. `allow` never disrupts (a trailing `monitor` is ignored). |
| `deny <matchers>` / `block <matchers>` | **Block** — return `403` immediately, before cache + origin. `block` is an exact alias for `deny`. |
| `monitor` (global) | Turn the **whole gate** to monitor mode: every `deny` logs a *would-block* and **passes** (no 403). `monitor` / `monitor on` enables; `monitor off` is the default no-op. |
| `deny <matchers> monitor` (per-rule) | Per-rule monitor: this one `deny` logs a *would-block* and passes; other rules still enforce. |

`<matchers>` is a conjunction: one or more `@matcher` references (optionally
`!`-negated, e.g. `!@office`), or a single inline matcher (`deny ip 10.0.0.0/8`).
Geo-block reuses the [`geo`](#matchers) matcher; pattern-deny reuses
`path` / `header` / `method` / `host`; the IP/CIDR ACL is the new [`ip`](#matchers)
matcher.

```
# native security primitives — no waf{} block required
@office   ip 203.0.113.43/32 10.0.0.0/8     # real client IP (trusted-proxy resolved)
allow @office                               # allowlist short-circuits the gate

@ru_cn    geo country RU CN
deny @ru_cn                                 # geo-block -> 403

@scanners path /.env /.git/*
deny @scanners                              # pattern-deny -> 403

@admin    path /wp-admin/*
deny @admin !@office                        # AND + negation: admin, but not from office

monitor                                     # (optional) tune in production: deny -> would-block, passes
```

**Block response.** `403` by default (a `respond`-style customization is a later
slice).

**Real client IP.** The `ip` matcher resolves the **real client IP** via the same
`trust_proxy` / `X-Forwarded-For` logic as [`{geo}`](#geo) — never the immediate
peer. **Behind a CDN/LB you MUST configure trusted proxies** — either the standalone
[`trust_proxy <CIDR…>`](#trust_proxy) site directive (no geo block required) or
`geo { trust_proxy … }` — so the gate ACLs the actual client rather than the proxy.
**Without it the `ip` ACL silently no-ops**: it matches the proxy's IP for every
request, so a `deny @badips` never fires and an `allow @office` misbehaves.
`cadish check` warns (`ip-acl-without-trust-proxy`) when a site has an `ip` ACL but
no trusted-proxy set. (Omit `trust_proxy` only when cadish is the edge with direct
client connections — then the peer *is* the client.) A request with no resolvable
client IP matches no `ip` rule.

> **`allow` should be keyed only on TRUSTWORTHY matchers (`ip` / `geo`).** An
> `allow` short-circuits the *entire* gate — every later `deny` / (future)
> rate-limit / WAF rule. If you key it on a **client-settable** input
> (`header` / `cookie` / `query_present`), any client can set that value and
> bypass all of your security. Use a server-attested signal (the trusted-proxy
> resolved client `ip`, or a CDN-attested `geo` class) for an allowlist; reserve
> `header`/`cookie`/`query_present` for `deny` rules (where a client setting the
> value only blocks *itself*).

> **Security is server-only — it never runs at Cadish Edge.** The whole security
> stack (the `ip`/geo/pattern ACL gate here, and the future rate-limit / OWASP /
> challenge layers) lives in **Cadish Server only**. At the edge, Cloudflare
> provides the security layer, so the edge worker does **not** execute any security
> gate and the IR projector does **not** emit these rules (they are simply *absent*
> there — not delegated). This is the answer to "what if we *don't* have
> Cloudflare?" — the standalone-server deployment.

**Observability.** Each decision is counted in `internal/metrics`
(`cadish_security_allow_total` / `_deny_total` / `_monitor_total`, surfaced on the
admin metrics + Prometheus endpoints) and traced (`-trace`).

#### `rate_limit`

A **native, stateful** security primitive (no `waf { }` block required). It is the
**third step of the security gate**, after `allow` and `deny` (order
`allow → deny → rate_limit`): an allow-listed request is never rate-limited, and a
denied request is rejected before a counter is spent. Like the rest of the gate it
runs **before the cache key / cache lookup / origin**, so a throttled request
touches **neither cache nor origin** (an attacker cannot poison the cache or hammer
the upstream past the limit). When a site declares no `rate_limit` rule the limiter
is **not even constructed** (no goroutine, no memory) — zero cost when absent.

```
rate_limit [@scope… | INLINE-MATCHER] RATE [burst N] [key ip|header NAME|global] [monitor]
```

| Part | Meaning |
|---|---|
| `@scope…` / inline matcher | *(optional)* limit only matching requests (`rate_limit @api …` limits only `@api`). Omit to limit every request to the site. |
| `RATE` | **required** — `Nr/s`, `Nr/m`, or `Nr/h` (requests per second / minute / hour; `N` may be a decimal). This is the steady refill rate. |
| `burst N` | *(optional)* the bucket **capacity** is `max(1, N)` — a full bucket admits exactly `N` requests in an instant (NOT `N+1`), then throttles to `RATE`. Default `0` → capacity 1 (strict, one token at a time). |
| `key ip` *(default)* | bucket per **real client IP** — the trusted-proxy-resolved client IP, the *same* resolution as [`{geo}`](#geo) / the [`ip`](#matchers) matcher (never the immediate peer). |
| `key header NAME` | bucket per value of request header `NAME` (e.g. an API key). |
| `key global` | one whole-site bucket (every client shares it). |
| `monitor` | per-rule monitor: log a *would-429* and **pass** instead of throttling (also enabled site-wide by the global `monitor` directive). |

On exceed: **`429 Too Many Requests`** with a **`Retry-After`** header (whole
seconds until the next token). The bucket is a **token bucket** refilled at `RATE`,
capped at `max(1, burst)`.

> **Not a permanent block.** `rate_limit` throttles a *rate*; it is not an
> access-control primitive. A `RATE` of `0` never refills, but the initial capacity
> is still admitted and an idle bucket is reclaimed after ~10 min (a returning client
> then gets a fresh capacity), so `rate 0` is **not** a durable block — use
> [`deny`](#matchers) for that. (A blocked `rate 0` request reports a long
> `Retry-After` rather than `0`.)

```
@api  path /api/*
trust_proxy 203.0.113.0/24                 # so key ip resolves the REAL client behind the LB
rate_limit @api 100r/s burst 50 key ip     # per-client API limit, 429 + Retry-After
rate_limit path /login 5r/m key ip         # (inline matcher form — needs the matcher keyword)
rate_limit 10000r/s key global             # a coarse whole-site ceiling
rate_limit 100r/s key header X-Api-Key monitor   # per-API-key, log-only while tuning
```

> **Per-node only — the cluster caveat.** The token bucket is **in-memory and
> per-node**; there are **no distributed counters** (no Redis, no gossip — a locked
> design decision). With **N** cadish nodes behind a load balancer each counts
> independently, so the **effective limit is ≈ N× the configured rate**. Mitigate by
> setting `limit = target / N`, or accept the headroom. (Buckets are sharded by key
> hash to avoid a global lock, and idle buckets are evicted so memory stays bounded
> under a high-cardinality key space such as per-IP during a flood.)

> **`key ip` needs `trust_proxy` behind a proxy/LB.** Like the `ip` ACL, `key ip`
> resolves the real client IP via the same `trust_proxy` / `X-Forwarded-For` logic.
> **Without trusted proxies set, every client behind the LB shares the proxy's IP
> bucket** — one bucket for everyone. `cadish check` warns
> (`ip-acl-without-trust-proxy`) when a `rate_limit … key ip` rule has no
> trusted-proxy set. (`key header` / `key global` do not depend on the client IP.)

**Server-only** — like the rest of the security gate, `rate_limit` never runs at
Cadish Edge and is never projected into the worker IR (Cloudflare provides the edge's
own rate limiting). **Observability:** `cadish_rate_limit_throttle_total` /
`_monitor_total` / `_pass_total` (admin metrics + Prometheus) and `-trace`.

#### `respond`
Synthetic response — short-circuits cache and origin (great for health checks):

```
respond /health-check 200 "OK"      # PATH CODE ["BODY"]   (exact-path form)
```

**Scoped form** — `respond @scope… STATUS ["BODY"]`: instead of an exact path, a
**conjunction of (optionally `!`-negated) matcher refs** (the same grammar as
`allow`/`deny`) decides when the synthetic fires. The synthetic is returned when the
conjunction matches; an unmatched request falls through to routing/cache/origin.

```
@api  path /api /api/*
@docs path /docs /docs/*
respond !@api !@docs 404            # 404 every path that is NEITHER /api… NOR /docs…
```

This is how the Kubernetes Ingress controller enforces **path-scoped routing**: a
site whose paths are all explicit (no catch-all `route ->` and no
`spec.defaultBackend`) gets a terminal `respond !@r0 !@r1 … 404`, so a request that
matches none of the declared paths 404s instead of falling back to the site's first
upstream. Like the exact-path form it runs in **RECV** (request-phase matchers only;
a response-phase matcher is a compile error) and is **not projected to the edge IR**
(server-only).

**Conditional health endpoint** — compose the scoped form with the
[`upstream_healthy`](#matchers) matcher for an LB liveness probe that returns **200**
when a pool has a live backend and **503** otherwise (the AWS / HAProxy
`nbsrv() gt 0` health-check signal), with **no origin dial**:

```
@probe path /aws-health-check
@live  upstream_healthy cache_pool      # ≥1 live backend in cache_pool?
respond @probe @live 200 "OK"           # pool live  -> 200
respond @probe 503                      # pool down  -> 503 (first-match: @live failed)
```

The matcher is evaluated against live load-balancer health, so an AWS/ELB (or any LB)
target-group probe pulls the node out of the DNS pool the moment its cache origin is
down, and adds it back when the origin recovers.

`upstream_healthy` (the `AnyHealthy` signal) reflects **liveness only** — true as soon as
**≥1** backend in a listed pool is passing health — **not spare capacity**: it does not
report how many backends are up or whether they can absorb more load. This is
intentional, mirroring Varnish's `nbsrv() > 0`; use it to answer "is this pool serving at
all?", not "does it have headroom?".

> Every `upstream_healthy NAME…` argument must name a **declared** `upstream`/`cluster`
> pool. A typo (`upstream_healthy cache_poool`) is a `cadish check`/compile error — never
> a silent always-down probe — because an unknown pool would fail closed at runtime and
> answer **503 forever**, pulling the node out of rotation.
>
> A named pool only carries an active **health FSM** when it is a real load-balancer pool:
> a `cluster NAME { … }`, a multi-backend `upstream`, or a single-backend `upstream` that
> declares a `health { … }` block. A **trivial** single-backend `upstream NAME { to … }`
> with no lb features (and an `s3`/`sign` upstream) is a plain origin with no FSM —
> `upstream_healthy` resolves it **assumed healthy** (it exists and is served) and can
> never report it down. `cadish check` warns (`upstream-healthy-non-pool`) so you add a
> `health { … }` block when you want the backend actively probed.

**Origin-error fallback** — `respond on_error [@scope] STATUS BODY [content_type T]`:

```
respond on_error 503 "We'll be right back"            # site-wide maintenance page
respond on_error @api 503 "{\"error\":\"down\"}" content_type "application/json"
```

A configured synthetic body+status served when the origin **hard-fails** (a
transport error / unreachable upstream, or a non-cacheable 5xx) and there is **no
servable object** — neither a stale-in-grace copy, nor a within-`max_stale`
last-good copy, nor a cacheable negative-cache entry. This serves a branded
maintenance/error page in place of the default error response (the upstream's own
non-2xx body when it answered, or the bare `502`/`503` synthetic on a transport
failure).

- `STATUS` is the status sent to the client (e.g. `503`), independent of the
  upstream's failing code. `BODY` is the synthetic body. `content_type T`
  overrides the default `text/html; charset=utf-8`.
- `@scope` is an optional matcher OR-set so a path/host subset can carry its own
  page; a non-matching request falls through to the bare fallback. First match
  wins across multiple `respond on_error` rules.
- **Request-phase scope only.** `respond on_error` is a request-phase fallback, so a
  response-phase `content_type` / `set_cookie` matcher cannot scope it and is a
  **compile error** here — scope on `host` / `path` / `method` / request `header`
  only.
- **Precedence (load-bearing).** On origin failure the full order is:
  **fresh `HIT` > grace-stale `HIT-STALE` > `max_stale`-on-error `HIT-STALE-ERROR`
  > cacheable negative cache (`cache_ttl status …`) > `respond on_error` > the bare
  `502`/`503`/`404` fallback.** (`502` for a bad upstream reply / transport error,
  `503` when no backend is eligible, `404` for a not-found.) (`fresh` and
  `grace-stale` are decided *before* the
  origin fetch and never reach the error path; the rest are the error-path
  fallbacks, most-preferred first.) So `on_error` fires only for an *uncacheable*
  hard failure with nothing else to serve. `max_stale` outranks both the negative
  cache and `on_error` because a real (if old) representation beats a synthetic
  error page or a cached failure — and it fires on **every** failure shape,
  including a `404`/`410` (serving the last good copy of a page whose origin now
  404s *during an outage* beats a 404). (A `cache_ttl default` makes a 5xx
  negatively cacheable, so — once past `max_stale` — it would be served from the
  negative cache before `on_error`; scope `cache_ttl` to the statuses you actually
  want cached if you want `on_error` to cover the rest.)
- **Not cached.** The synthetic is an availability stopgap, not an origin answer —
  caching it would mask recovery, so it is written straight to the client and a
  later request re-evaluates (a recovered origin serves a fresh `MISS`).
- **Upstream non-2xx bodies are delivered.** An origin that *answers* with a
  structured error — `401`/`403` auth, a `422` validation envelope, a `5xx`
  maintenance JSON — has that response delivered to the client **verbatim**: its real
  status, headers (`Content-Type`, `WWW-Authenticate`, `Retry-After`, …) and body,
  exactly like an upstream `2xx`. On a `pass`/uncacheable request this is a straight
  passthrough (never stored, so no cache-poisoning risk); on a `hit_for_miss`-matched
  status the body reaches **this** client while the HFM marker is set and nothing is
  stored. `404`/`410` keep their full-body negative-caching behavior. `respond
  on_error` and `max_stale`-on-error still **outrank** passing the live error through
  (see precedence) — they replace what the client sees, not the verbatim default.
- **The bare `502`/`503` synthetic is a transport-failure path only.** When the
  origin produced **no response** — a transport error / unreachable upstream
  (`502 origin error`), or no eligible backend (`503`) — there is no upstream body to
  deliver, so cadish writes a short synthetic status + message (and no
  `X-Cache`/cache-status header). Use a `respond on_error` page if you want a branded
  body for these, and rely on metrics/access logs (not response headers) to observe
  them. (A not-found maps to `404 not found`.)
- HEAD sends the status + headers with no body; a Range request gets the **full**
  synthetic (never a 206 slice of an error page).
- **Edge-native** for the outage path (D76): the Cadish Edge worker serves this
  synthetic on an origin hard-failure with no salvageable cached object, with the same
  precedence as the server (stale-within-window > negative cache > `on_error` > 502).
  See [`edge.md`](edge.md).

#### `redirect`
Computed 3xx redirect — short-circuits cache and origin like `respond`, but emits
a `Location` built from the request (host + path) instead of a body. Evaluated in
RECV, first-match-wins (after `respond`). Four forms:

**Regex form** — `redirect PATH_REGEX CODE TARGET`:

```
redirect (?i)^/(women|femmes)/?$ 301 https://{host}/mujeres
redirect (?i)^/es(/.*)?$         302 https://{host}/espanol$1
```

- `PATH_REGEX` is an [RE2](https://github.com/google/re2/wiki/Syntax) pattern
  matched against the request **path** (query excluded). Its capture groups feed
  `$1`…`$9` in the target.
- `CODE` is the redirect status: `301`, `302`, `303`, `307`, or `308`.
- `TARGET` is a **template** (see below) — typically `https://{host}/…`.

**Scoped form** — `redirect @scope CODE TARGET` — fires when `@scope` matches
(any matcher, including a [`classify`](#classify) token matcher), instead of a path
regex. This is how you express **language-aware / conditional** redirects (pick the
redirect by a classified `{lang}`/`{age}` token rather than by URL shape):

```
@es classify {lang}==es                 # token-as-scope (a named classify matcher)
redirect @es 302 https://{host}/es{path}
```

- `@scope` is one or more `@matcher` refs (OR'd): the redirect fires if **any**
  matches. A leading `@name` selects this form — `redirect @x …` is the scoped form,
  not a path regex (the old footgun where it parsed as a never-matching path regex
  is gone — and `cadish check` counts `@x` as a reference, not an unused matcher).
- `TARGET` may use the `{host}`/`{path}`/`{query}`/`{uri}` templates **but not** the
  `$N` capture groups (there is no path regex in this form).
- A response-phase matcher (`content_type`/`set_cookie`) cannot scope a redirect
  (RECV runs before the origin response exists).

**Scoped path-regex form** — `redirect @scope PATH_REGEX CODE TARGET` — combines a
matcher scope **and** a path regex in one rule: the redirect fires only when the
scope matches **and** the regex matches the path, and the regex capture groups feed
`$1`…`$9` in the target. This expresses **"rewrite a path segment only when a signal
holds"** — e.g. translate a URL slug only for a given language — in a single rule:

```
@es_target classify {langredir}==es                 # token-as-scope
@en_target classify {langredir}==en
redirect @es_target (?i)^(.*)/(couples|parejas)/?$ 301 https://{host}$1/parejas
redirect @en_target (?i)^(.*)/(couples|parejas)/?$ 301 https://{host}$1/couples
```

- The leading `@scope` (one or more refs, OR'd) is evaluated first; the `PATH_REGEX`
  follows and is matched against the request **path**. Both must hold for the rule to
  fire — otherwise evaluation falls through to the next rule (first-match-wins).
- The target may use the `$N` captures **and** the derived tokens (`{host}`,
  `{classify.NAME}`, `{geo}`, …) together, so one rule can both rewrite a segment and
  reflect a signal. `{host}`/`{host.base}`/`{host.sub}` remain the validated redirect
  host (open-redirect defense, F12) and are the **only** tokens allowed in the Location
  **authority**; a `{classify.*}`/`{geo*}`/etc. token may appear only in the **path or
  query** (see the open-redirect note below). To pick a subdomain, use `{host.sub}`/
  `{host.base}`, not a request-sourced token in host position.
- The form is disambiguated from the scope-only form by the argument count after the
  leading refs: two trailing args (`CODE TARGET`) is scope-only, three
  (`PATH_REGEX CODE TARGET`) is this combined form. The first trailing arg is read as the
  `CODE` only when it is a valid 3xx status (301/302/303/307/308); otherwise it is the
  `PATH_REGEX` — so a numeric path regex (e.g. `12`) is not mistaken for a status code.
  `cadish check` counts the path regex as one regex eval/request on top of the scope match.

**Translation-map form** — `redirect CODE map { PFX -> NEWPFX … }` — sugar for the
common "rewrite a leading path prefix, keep the rest" language/i18n case:

```
redirect 301 map {
    /registro -> /register
    /mujeres  -> /women
    /es       -> /english
}
```

Each entry rewrites a leading path prefix and **preserves the remainder**, so
`/registro/step2` → `https://{host}/register/step2`. Map targets are paths; the
`https://{host}` prefix is supplied automatically.

##### Target template syntax (shared with [dynamic header values](#dynamic-header-values))

| Placeholder | Expands to |
|---|---|
| `{host}` | request Host (lower-cased, port stripped) |
| `{host.base}` | the **registrable base domain** of `{host}`, public-suffix aware (`es.brand-a.example` → `brand-a.example`, `www.brand-b.example` → `brand-b.example`, the multi-label public-suffix `myapp.tech555.io` → `myapp.tech555.io`) |
| `{host.sub}` | the leading **subdomain** label(s) below the registrable domain (`es`, `www`, `pt`); `""` for a bare base host |
| `{path}` | request path |
| `{query}` | canonical query string (no leading `?`); `""` if none |
| `{uri}` | `{path}` plus `?{query}` when a query is present |
| `{client_ip}` | resolved client IP (no port) |
| `{http.NAME}` | request header `NAME` (absent → `""`) |
| `{classify.NAME}` | the derived value of the `classify`'d `{NAME}` token (a bounded server enum) |
| `{geo}` | resolved geo class (country code, e.g. `ES`, or `unknown`) |
| `{geo.continent}` | resolved continent class (e.g. `EU`/`NA`, or `unknown`) |
| `{geo.region}` | resolved region/subdivision class (e.g. `US-UT`; requires an upstream region header) |
| `{proto}` / `{scheme}` | `https` when cadish terminated TLS for the request, else `http` (primarily for `X-Forwarded-Proto`; also resolved on the redirect path, so a `{proto}://…` Location reflects the inbound scheme — `https` on a TLS listener) |
| `$0` | the whole regex match |
| `$1`…`$9` | regex capture groups (out-of-range → empty) |
| `$$` | a literal `$` |

An unknown `{name}` is left verbatim. `cadish check` counts the path regex as one
regex eval/request (RECV phase), the same cost class as a `path_regex` matcher.
All of these request-scoped/derived placeholders resolve in a `redirect` target
just as they do in dynamic `header` values — e.g. `{classify.langredir}` can pick
the target subdomain, or `{geo}` branch a Location by country. `{host}`/`{path}`/
captures remain the most common.

**Open-redirect caveat.** A redirect `Location` drives a browser navigation, so be
deliberate about what you reflect into it:

- `{host}` is **always the validated redirect host** — the request Host is echoed
  only when it is one of the site's configured addresses, otherwise the canonical
  host is used (open-redirect defense, F12). An attacker-supplied Host cannot send a
  visitor off-site. `{host.base}`/`{host.sub}` are **derived from that same validated
  host**, so the open-redirect defense applies to the computed base/subdomain too —
  an untrusted Host falls back to the canonical host's base, never the attacker's.
- `{classify.NAME}` and `{geo}`/`{geo.continent}`/`{geo.region}` are **bounded,
  server-derived enums** — safe to interpolate into a Location.
- `{http.NAME}` and `{client_ip}` are **attacker-influenceable** (a client controls
  its own headers/forwarded IP). Reflecting them into a Location is attacker-shaped
  navigation; `net/http` already blocks CRLF header-splitting, but you own the
  redirect-target semantics — prefer the validated `{host}`/`{host.base}`/`{host.sub}`
  family for routing decisions and treat reflected `{http.*}`/`{client_ip}` as untrusted.
- The redirect `TARGET` **authority** (`scheme://AUTHORITY/…`, including any protocol-
  relative `//AUTHORITY/…`) accepts **only** the validated host family
  `{host}`/`{host.base}`/`{host.sub}` (plus literal text and `$N` regex backrefs).
  **Any** other request-sourced token in host position — `{http.*}`, `{query.*}`,
  `{client_ip}`, `{geo*}`, `{classify.*}`, `{device}`, `{currency}`, … — is an **open
  redirect** (unvalidated, attacker-influenceable origin) and `cadish check`/load/`edge
  build` **rejects** it at compile (e.g.
  `redirect … 302 https://{http.x-forwarded-host}/login`,
  `https://{query.next}/login`, or a protocol-relative `//{http.host}/…`). The same
  tokens in the **path or query** of the Location stay allowed (they can never become
  the navigation origin), so to pick a target subdomain from a `classify`/header signal,
  put it in the path or use `{host.sub}`/`{host.base}` — not the authority. A token
  whose expansion is rooted at `/` (`{uri}`, `{path}`) **ends** the authority, so
  `https://{host.base}{uri}` is the validated host with the path supplied by `{uri}`.

`{client_ip}` is the **trust-proxy-resolved** client: behind a `trust_proxy`-declared
LB/CDN it is the real client walked out of `X-Forwarded-For` (the same resolution as
`{geo}` and the `ip` ACL), not the proxy's socket address. With no `trust_proxy`
configured — or an `X-Forwarded-For` from an untrusted peer — it is the immediate
socket peer (a spoofed header is ignored).

##### `no_store` modifier

Append `no_store` as the last token on any non-map redirect line to attach
`Cache-Control: no-store, no-cache, must-revalidate, private` to the 3xx response:

```
@lang cookie lang es
redirect @lang 302 https://es.example.com{uri} no_store
```

Use this when the redirect is **personalized** — driven by a cookie, classified
token, or `Accept-Language` header — so no shared cache or browser caches a
per-user redirect and serves it to another user. A deterministic (URL-only) redirect
that is the same for every visitor does not need `no_store`; omitting it keeps the
response cacheable by the downstream client (which is the default for a 301).

The modifier is effective in the regex form, scoped form, and scoped path-regex
form. The translation-map form (`redirect CODE map { … }`) does not support it
(map entries produce deterministic URL-shaped rewrites that are safe to cache).

Both the cadish server and the edge runtime (Cadish Edge) attach the header
byte-identically when `no_store` is present.

*Language-redirect example* (subdomain + path translation in one 301):

```
@es_subdomain host es.example.com
redirect (?i)^/registro(/.*)?$ 301 https://www.example.com/register$1
redirect 301 map {
    /mujeres  -> /women
    /chicas   -> /girls
}
```

*Language-aware redirect by a classified token* (scoped form — send Spanish
speakers to the localized home, driven by a `classify`'d `{lang}` token rather than
the URL):

```
classify {lang} {                                    # derive a bounded {lang} enum
    when header_regex Accept-Language (?i)^es  -> es  # header_regex, not exact `header`:
    when header_regex Accept-Language (?i)^fr  -> fr  # a real Accept-Language is never
    default                                    -> en  # the literal "es" — match its prefix
}
@es classify {lang}==es                              # token-as-scope
@fr classify {lang}==fr
redirect @es 302 https://{host}/es{path}       # no $N captures — {path} carries the rest
redirect @fr 302 https://{host}/fr{path}
```

*Brand-agnostic subdomain rewrite* (`{host.base}`/`{host.sub}`) — rewrite the
**subdomain** of any brand to `www.<same-base>` (or a per-language host) with **one**
rule instead of N literal targets per brand. The base is public-suffix aware, so a
whitelabel host family across many registrable domains collapses to a handful of
generic rules:

```
# Trusts every brand host; one rule sends a bare/sub host to its own www host:
es.brand-a.example, www.brand-a.example, brand-a.example, es.brand-b.example, www.brand-b.example, brand-b.example {
    @needs_www host brand-a.example es.brand-a.example brand-b.example es.brand-b.example
    redirect @needs_www ^/(.*)$ 302 https://www.{host.base}/$1   # -> www.<brand>/…
    # …or branch the target subdomain by language, still brand-agnostic:
    @spanish classify {lang}==es
    redirect @spanish ^/(.*)$ 302 https://es.{host.base}/$1      # -> es.<brand>/…
}
```

`{host.base}` strips the leading subdomain down to the registrable domain
(`es.brand-a.example` → `brand-a.example`), and `{host.sub}` is what was stripped
(`es`); both derive from the **validated** redirect host. A multi-label public suffix is
handled correctly (`myapp.tech555.io` → base `myapp.tech555.io`, not `tech555.io`). Scope
the rule (here `@needs_www host …`) to the hosts that should move so a request already
on the target host does not redirect to itself.

#### `purge`
Token-guarded cache invalidation:

```
purge when header X-Purge-Token {$PURGE_TOKEN}
purge when header X-Purge-Token {$PURGE_TOKEN} regex {http.X-Purge-Regex}
purge when header X-Purge-Token {$PURGE_TOKEN} regex-path {http.X-Purge-Regex}
```

`when <condition>` is a matcher scope (here a header equality). There are three
invalidation forms:

- **Single-key purge** (no `regex`): drops the freshness marker for *this request's
  own* cache key, forcing the next request for that key to revalidate.
- **Cache-wide regex invalidation** (`regex EXPR`): a regex mass-invalidation over the
  cache — every cached object whose **cache key** matches `EXPR` and that was stored
  *before* the invalidation is dropped (re-fetched on its next lookup). It is applied
  **lazily**: the purge request records the pattern in O(1) and returns immediately;
  the store is never scanned. A matching key is treated as a MISS on its next LOOKUP
  and then re-fetched and re-cached fresh; an object stored *after* the invalidation
  is unaffected; a non-matching key keeps HITting. With no active pattern the lookup
  path pays a single atomic load — zero cost when the feature is unused.
- **Path-anchored regex invalidation** (`regex-path EXPR`): like `regex`, but `EXPR`
  matches the **PATH component** of the key only. Use this for patterns written
  against `req.url`, e.g. `regex-path ^/nocookie`. See the key-shape note below for
  why this matters.

`EXPR` (for `regex`) is an RE2 regex matched against the **full cache key** — by
default `METHOD\x1fHOST\x1fPATH` (the separator is the ASCII unit separator
`\x1f`), plus any `cache_key` variations like `{device}`/`{geo}`. **The key starts
with the method and host, not the path**, so a path-anchored
pattern like `^/nocookie` written with the bare `regex` form can **never match** (it
would need the *method* to start with `/`) — a silent no-op. Two ways to avoid the
footgun:

1. Use the **`regex-path EXPR`** form — it rewrites a path-anchored `^/foo` to
   anchor against the path token of the key, so `ban.sh`-style patterns just work.
2. Or write the bare `regex` form unanchored against a path substring, e.g.
   `regex /video/42/` to drop every variant of that path.

**Matched count (no false confidence).** A regex/regex-path purge returns `200`
with an **`X-Purge-Count: N`** response header, where `N` is the number of live
freshness entries the ban invalidated at ban time. `X-Purge-Count: 0` means the
pattern **compiled but matched nothing indexed** — the purge was a no-op, so a `200`
alone never lulls an operator into thinking a mistyped/anchored pattern worked.
(The count reflects the in-memory freshness index; lazily-tracked, it is a
best-effort signal, not a guarantee of every blob on disk.) A single-key purge omits
the header (nothing to count).

**Security (request-sourced patterns are bounded).** An operator literal — a regex
written directly in the Cadishfile, e.g. `purge when @tok regex ^/assets/.*` — is
**trusted** and used verbatim (an operator may deliberately flush broadly). A
pattern sourced from a request header — `regex {http.X-Purge-Regex}` — is
attacker-influenced, so it is bounded exactly like every request-sourced purge
regex: it is length-capped, must compile as RE2, and a mass-flush "match everything"
pattern (e.g. `.*`, `.+`, `^.*$`) is **rejected**. A rejected request-sourced pattern
falls back to the safe single-key purge of the request's own key — it can never
nuke the cache.

**No `purge` directive ⇒ `PURGE` is forwarded to origin.** A `PURGE` request is
only intercepted when a `purge` directive is configured (and its `when` guard
matches). With **no** `purge` directive there is no method gate: cadish treats
`PURGE` like any other method and **forwards it to the origin** (transparent-proxy
behavior) — it does **not** return `405`. If you want `PURGE` handled locally,
configure a `purge` directive.

#### `route`
Pick the upstream for matching requests:

```
route @static -> images             # @matcher -> UPSTREAM
route @a @b -> images               # several refs are an OR (matches if @a OR @b)
route @gw_match -> api              # AND of criteria: reference one `all` composite
route -> default                    # bare catch-all (terminal fallback)
```

The scope before `->` is the **OR** form — a run of `@matcher` refs (matches if **any**
ref matches, consistent with `pass`) or one inline matcher — or empty for the catch-all.
To require **every** criterion (an AND), reference a single [`all`](#matchers) composite
matcher (`@gw_match all @path @method @hdr`, then `route @gw_match -> u`); this keeps the
route a single ref, so a terminal `respond !@gw_match … 404` stays correct. The Gateway
controller emits exactly this shape for a multi-criteria HTTPRoute match.

The target must be a declared `upstream`/`cluster`. A routed request's effective
upstream is visible to the `upstream` matcher and to ORIGIN/DELIVER rules.

#### `pass`
Bypass the cache entirely (fetch from origin, never store). First-match-wins;
an unconditioned `pass` passes everything (and makes later `pass` rules dead).

```
pass @ajax              # by named matcher (OR over several: pass @a @b)
pass method POST        # by inline matcher
pass path /admin/*      # inline path
```

#### `upgrade`
Enable a **WebSocket / `Connection: Upgrade` passthrough tunnel** for the matching
scope. Mirrors `pass` exactly (RECV-phase, OR-set scope, first-match-wins) and
**implies `pass`** — a tunnel is entirely off the caching path. Pair it with a
`route @scope -> upstream` to choose which upstream the tunnel dials.

```
upstream chat { to k8s://chatserver.production:80 }
@sock path /socket.io/* /chatserver/socket.io/*
route   @sock -> chat
upgrade @sock
```

- A request matching the scope is tunnelled **only when it is a genuine upgrade** —
  it carries a `Connection` header with an `upgrade` token **and** an `Upgrade`
  header. A non-upgrade request on the same scope is served as a normal `pass`
  (plain proxy), so a `socket.io` long-poll that has not yet upgraded still works.
- On a genuine upgrade cadish forwards the `Upgrade`/`Connection`/`Sec-WebSocket-*`
  handshake headers to the routed upstream, returns its `101 Switching Protocols`,
  then byte-copies both directions until either side closes. The tunnel honors the
  upstream's load-balancer pick (health/sticky) and per-upstream transport knobs
  (`sni`, `http_reuse`, `tls_insecure`/`ca_file`/`alpn`, connect/TLS timeouts).
- The tunnel **never caches, coalesces, ranges, transforms, or encodes** — it is a
  new server path that bypasses LOOKUP/ORIGIN. For every NON-tunnel request the
  global hop-by-hop strip is unchanged, so `Upgrade`/`Connection` are still removed
  on the normal path (no header smuggling).
- An idle tunnel is torn down by the global `server { idle_timeout … }` (0 = the
  default, unbounded-until-close). The active tunnel count is exported as the
  `cadish_upgrades_active` gauge.
- **Server-only.** A live tunnel cannot run on the stateless Cloudflare Workers edge
  tier, so `cadish edge build` **delegates** any `upgrade` route to the Cadish server
  behind (it is reported, never silently dropped; `-strict` flags it).

#### `rewrite`
Rewrite the **path and/or query sent to the ORIGIN**, *without* changing the
client-facing URL. This is the HAProxy `replace-path` / SSR query-reconstruction
parity primitive: serve one public URL but dial the backend with a different one.
RECV-phase, applied in source order (each op operates on the result of the
previous one), with an optional leading `@scope` to make it conditional.

```
rewrite path ^/old/(.*)$ /new/$1   # regex replace on the path ($1.. = captures)
rewrite strip_query utm_*          # drop query params before forwarding (globs ok)
rewrite set_query publi 1          # add / override one query param (SSR publi)
rewrite @legacy path ^/v1/(.*)$ /v2/$1   # conditional: only when @legacy matches
```

- **`path PATTERN REPLACEMENT`** — RE2 regex replace on the path. `REPLACEMENT`
  uses Go's `$1`/`${name}` capture syntax. A non-matching path leaves the path
  unchanged (the op is a no-op for that request).
- **`strip_query NAME…`** — remove the named params (exact names or `*`-globs like
  `utm_*`) from the forwarded query. Everything else is preserved.
- **`set_query NAME VALUE`** — add the param, or override it if present. `VALUE`
  may interpolate `{http.NAME}` (a request header), `{host}`, `{path}`, `{query}`,
  or be a literal.
- The `@scope` is one or more `@matcher` refs (OR'd); a response-phase matcher
  (`content_type`/`set_cookie`) is rejected (RECV runs before the response exists).

> **Cache-key interaction (read this).** `rewrite` affects **only the origin
> request** — the path/query cadish dials upstream. It **does NOT change the cache
> key**, which is always computed from the **client-facing** request (see
> [`cache_key`](#cache_key)). This is deliberate and load-bearing: two clients
> hitting the same public URL must share one cache entry even when a deterministic
> rewrite differs per request (e.g. a per-request `set_query`), and a rewrite must
> never poison the key. So `rewrite strip_query utm_*` lets `?utm_source=fb` and
> `?utm_source=tw` **share a HIT** while the origin sees neither — provided your
> `cache_key` doesn't already key on `utm_*` (use `query_allow` to keep only the
> params that should split the key). If you want a rewritten value to affect the
> key, set it on the `cache_key` line instead — that is the one place that controls
> the key. The background revalidation of a stale object applies the same rewrite,
> so the refreshed object is fetched from the same upstream URL.
>
> **Edge note:** `rewrite` is **server-only** in v1 (the Cadish Edge worker does
> not yet apply it; an edge request is served/delegated without the rewrite). The
> `cache_ttl from_header` TTL — and the `grace_from_header` / `max_stale_from_header`
> windows — **are** surfaced in the edge IR (the worker resolves them identically, per
> the cross-runtime conformance suite).

### KEY

#### `cache_key`
Compose the cache key from tokens. Default when omitted: `method host path`.

```
cache_key url host
```

Tokens: `method`, `host`, `path`, `url` (path+query), `query`, `query_allow NAME…`
(only the listed params — globs ok), `query_strip NAME…` (the full query *minus* the
listed params — globs ok), `header:NAME` (vary on a header), `cookie:NAME`
(vary on a single cookie's value — the way to cache per-user content; it lifts the
[credentialed-request bypass](#credentialed-requests-are-never-shared-cached-by-default)
only when it captures **every** cookie the request sends — see there),
the normalizers `{sticky}`, `{device}`, `{geo}`, `{tenant}` (the site's
[`tenant`](#tenant--group) name), any user-defined `{NAME}` from a
[`normalize`](#normalize) block, and any derived `{NAME}` from a
[`classify`](#classify) table.

**Scoped (per-request) recipes.** Like `cache_ttl`/`pass`/`route`, `cache_key`
takes an optional leading **selector** and is **first-match-wins** — so one site can
key different request classes with **different recipes**:

```
@ssr header X-IS-SSR-URL true
cache_key @ssr     host path query_allow genre age   # SSR backend: strip the query
cache_key default  host url                          # PHP backend: key on the full query
```

The KEY phase evaluates the lines top-to-bottom; the **first** whose selector matches
supplies the recipe. The selector is `@matcher…` (one or more refs, OR'd), or the
keyword `default` (the catch-all). Rules:

- **Exactly one recipe per request** — recipes do not merge (mirrors `cache_ttl`).
- **A `default` (or one unscoped line) is required** when any scoped `cache_key` is
  present, so every request resolves to a recipe — otherwise compilation fails and
  `cadish check` reports `cache-key-no-default`.
- **Selectors are request-phase only.** `cache_key` runs before the origin response,
  so a response-phase selector (`status …`, or a `content_type`/`set_cookie` matcher)
  is a compile error — use `cache_ttl` for status-based rules.
- A single unscoped `cache_key TOKENS` line behaves **exactly as before** (100%
  backward compatible). `cadish check` flags an unreachable recipe after a catch-all
  and a duplicate selector.
- **Edge (Cloudflare Workers):** a scoped `cache_key` is **edge-native** (D70). The
  projector ships the full ordered recipe list + each recipe's selector, and the worker
  selects the recipe first-match-wins exactly like the server, so a scoped site keys
  **byte-identically** at the edge (proven by the Go↔JS conformance suite). No
  delegation, no need to keep a single unscoped recipe for edge.

> **Cardinality matters.** Keying on a raw, high-cardinality value (`header:NAME`,
> the whole `query`, or `{sticky}`'s per-user cookie) fragments the cache — one
> entry per distinct value. Prefer a **bounded** token: `{device}`/`{geo}`, or a
> `normalize { … }` that buckets the value to a small enum. `cadish check` warns
> on the unbounded tokens and notes the bounded ones (with their bucket count).

- `query_allow NAME…` keys on **only** the listed query params, dropping every
  other param (so `utm_*` and other tracking junk can't fragment the cache). The
  kept params are canonicalized and **sorted** exactly like the whole-`query` token
  (re-encoded, key/value order normalized), so the key is byte-stable regardless of
  the incoming param order. A name may be a `*` glob over the param name
  (`pub-*` keeps `pub-foo`, `pub-bar`); a bare `*` keeps everything (= `query`). It
  greedily consumes the param names that follow it up to the next token keyword, so
  it can sit before other tokens: `cache_key path query_allow genre age camLang {publi}`.
  Unlike the whole `query`, it is **bounded by the allowlist** — `cadish check` does
  not flag it. This is the "keep only `genre/age/camLang`, strip `utm_*`" home-filter
  recipe:

  ```
  cache_key host path query_allow genre age camLang   # only these 3 params key; utm_* dropped
  ```

  For the binary `publi` flag — "is *any* ad param present?" as a 0/1, not the
  values — pair `query_present` with `classify` so the key varies on one bounded
  bit instead of the high-cardinality param values:

  ```
  classify {publi} {
      when query_present adult_content t a p ff-* pub-*  -> 1
      default                                            -> 0
  }
  cache_key host path query_allow genre age camLang {publi}
  ```

- `query_strip NAME…` is the **dual** of `query_allow`: it keys on the **full**
  canonical query **minus** the listed params (a *denylist*), so every meaningful
  param still keys but known tracking junk (`utm_*`, `a_mute`, `gclid`, `fbclid`, …)
  is dropped and cannot fragment the cache. Use it when the origin takes an
  open-ended set of meaningful params you don't want to enumerate (so an allowlist
  can't express it) and you only want to *remove* the junk:

  ```
  cache_key host path query_strip utm_* a_mute gclid fbclid   # key on everything BUT the tracking params
  ```

  Names follow the same rules as `query_allow` — exact names or a `*` glob over the
  param name (`utm_*` drops `utm_source`, `utm_medium`); a bare `*` strips every param
  (= an empty query). The surviving params are canonicalized + **sorted** identically
  to the whole-`query` token, so the key is byte-stable regardless of incoming order.
  It greedily consumes the param names that follow it up to the next token keyword, so
  it can sit before other tokens: `cache_key host path query_strip utm_* {publi}`.
  `query_allow` and `query_strip` are **mutually exclusive** in one recipe (allowlist
  *xor* denylist) — using both is a `cadish check`/compile error. Like `query_allow`,
  it is **key-only**: it changes the cache key, not the origin request. To forward a
  *cleaned* URL upstream — not just key on it — use the separate `rewrite strip_query`
  (the two are independent: key vs fetch).
  Note: `query_strip` does **not** bound key cardinality the way `query_allow` does — an
  origin that varies on many distinct *non-stripped* params still fragments the key into
  one entry per combination (bounded by LRU eviction, not a memory leak, but it dilutes
  the hit rate). Prefer `query_allow` whenever you can enumerate the params that actually
  matter; reach for `query_strip` only when the meaningful set is open-ended and you can
  enumerate just the junk to drop.
- `{sticky}` is **live**: it folds the sticky cookie (or client IP) into the key,
  so a per-user route varies on the small sticky enum, not the raw cookie.
- `{device}` is **live (v2a)**: the server classifies the `User-Agent` into a
  small, bounded device class (`desktop`/`mobile`/`tablet`/`bot`) and varies the
  key on the class — not the raw UA. A built-in ruleset ships, so
  `cache_key … {device}` works with no extra config; customize it with a
  [`device_detect`](#device_detect) block. The classifier runs only when a key
  actually uses `{device}`.
- `{geo}` is **live (v2b)**: the server resolves the client's geo class (a country
  code, or `unknown`) from a CDN country header, a CIDR→country table, or a local
  MaxMind `.mmdb` (by client IP) and varies the key on it. It needs an explicit
  [`geo`](#geo) source (no universal default); without one it renders `""` and
  `cadish check` warns. Runs only when a key uses a geo token (or a `geo` matcher).
- `{geo.continent}` is the **continent** granularity (`EU`/`NA`/`AS`/…): derived
  from the resolved country via an **in-tree static table** (no GeoIP dependency, D11).
  Needs only the country source (the same `geo { source … }`); it is the EU→EUR knob
  (`map EU -> EUR`). Bounded (7 continents + `unknown`), so it is a safe key token.
- `{geo.region}` is the **region / subdivision** granularity (`US-UT`, `US-WA`, …):
  it comes from either a **configurable upstream CDN header**
  (`geo { region_header CF-Region }`, exactly like the country comes from
  `CF-IPCountry`) **or** a local MaxMind **City** database
  (`geo { source maxmind … }`), which resolves the subdivision from the raw client IP
  — no upstream header required. A MaxMind **Country** edition has no subdivisions, so
  pair it with a `region_header` (or use a City DB). Without either a `region_header`
  or a maxmind City source it renders `""` and `cadish check` warns.

> **HEAD is not served from a cached GET (deliberate non-goal).** The default cache
> key includes the **`method`** token, and cadish does not store HEAD bodies or
> synthesize a HEAD response from a cached GET entry. So every `HEAD` request goes to
> origin even when the same URL's `GET` is cached — they key to different entries.
> This is intentional for v1: HEAD-from-GET synthesis (stripping the body, replaying
> headers) is a deliberate non-goal here, not a bug. If HEAD traffic is significant,
> let the origin answer it (it is cheap — headers only) or drop `method` from your
> `cache_key` *only if* every method that reaches the site is safe to share one entry
> (rarely true — leave `method` in).

#### `device_detect`
Customize the `{device}` classifier. The block is an ordered ruleset (first match
wins). Omit it to use the built-in default ruleset (desktop/mobile/tablet/bot).
Lines:

- `CLASS ua_contains SUBSTR… [ua_excludes SUBSTR…]` — a rule: any *contains*
  substring (OR, case-insensitive) selects CLASS, **unless** an *excludes*
  substring is also present. (The exclude is how the built-in says "Android but
  not Mobile ⇒ tablet" — Android tablets omit "Mobile", phones include it.)
- `default CLASS` — the fallback class (default "desktop").
- `fold FROM INTO` — remap class FROM onto INTO after matching, to **collapse the
  enum**. A block with only folds builds on the built-in ruleset.

```
device_detect {
    mobile  ua_contains Mobile Android iPhone
    tablet  ua_contains iPad Tablet
    tablet  ua_contains Android ua_excludes Mobile   # Android tablet
    bot     ua_contains bot crawler spider
    default desktop
}
cache_key host path {device}     # vary on the class, not the raw UA
```

Collapse to the cardinality-2 (desktop/mobile) case — fold the rest onto desktop:

```
device_detect {
    fold tablet desktop
    fold bot    desktop
}
```

It is a SETUP directive (parsed once at load; no per-request cost beyond the
substring scan, which the server runs only when a `cache_key` uses `{device}`).
The emitted classes are bounded — `cadish check` notes `{device}` as a safe,
low-cardinality key normalizer.

#### `geo`
Configure the geo sources (no built-in default — geo needs explicit data). One
block feeds three granularities — `{geo}` (country), `{geo.continent}`, and
`{geo.region}` — plus the [`geo` matcher](#matchers). Sub-directives:

- `source header NAME` — read the **country** class from a CDN/LB-set country header
  (e.g. `CF-IPCountry`). The common case when a CDN fronts cadish. **Security:** a
  header-sourced geo value is honored **only when the immediate peer is a trusted
  proxy** (requires `trust_proxy` covering the peer — the same trust model as
  `X-Forwarded-For`); from an untrusted/direct client the header is **ignored** (geo
  resolves to `unknown`) so a client cannot spoof its country to bypass a geo-fence or
  choose its `{geo}` cache bucket.
- `source cidr FILE` — resolve the real client IP against a `CIDR,COUNTRY` table
  (one per line; `#` comments) by longest-prefix match. Path is relative to the
  Cadishfile. Stdlib only — no GeoIP database/dependency.
- `source maxmind FILE` — resolve the **real client IP** against a local
  **MaxMind `.mmdb`** database (GeoLite2/GeoIP2 *City* or *Country* edition). Path
  is relative to the Cadishfile. This supplies the country (both editions) and —
  with a **City** edition — the **region / subdivision** (`{geo.region}`, e.g.
  `US-WA`) **without any upstream geo header** — closing the self-hosted-region gap
  for deployments with no geo-aware CDN in front. **cadish bundles no database:**
  *you* supply the `.mmdb` (GeoLite2 needs a free MaxMind account/license; GeoIP2 is
  commercial — the database and its MaxMind EULA are your responsibility). The
  database is **memory-mapped at startup** (a missing/corrupt file is a fatal startup
  error) and **reloaded on `SIGHUP`** alongside config hot-reload — a bad swapped-in
  DB is rejected and the old one keeps serving. The reader is always compiled in (no
  build tag); only an ISC-licensed, pure-Go reader is added, and continent is still
  derived **in-tree** from the country (the DB's continent field is ignored), so the
  single continent mapping with its transcontinental pins (RU/TR) is preserved.
- `region_header NAME` — *optional.* Read the **region / subdivision** class
  (e.g. `US-UT`, `US-TX`) from a configurable upstream CDN header (`CF-Region`,
  `X-Geo-Region`, or whatever your CDN/LB names it). Enables `{geo.region}` and
  `geo region …`. **Why a header, not the IP:** a US state can't be derived from a
  raw client IP without a **GeoIP database**, a dependency cadish deliberately does
  **not** ship (D11) — so the region is sourced from an upstream geo header the CDN
  already computed, exactly like the country comes from `CF-IPCountry`. There is no
  bundled GeoIP DB and no CIDR-subdivision table: **region granularity requires an
  upstream geo header.**
- `trust_proxy CIDR…` — CIDRs whose `X-Forwarded-For` is trusted when resolving
  the **real** client IP. XFF is honored only when the socket peer is a trusted
  proxy (otherwise it is spoofable and ignored); the rightmost non-trusted XFF
  hop is the client. **`trust_proxy` is now also a standalone site-level
  directive** (see [`trust_proxy`](#trust_proxy)) so you can declare trusted
  proxies *without* a geo block (e.g. a pure-security site using the `ip` ACL).
  When both forms are present they **union**.

```
geo {
    source        header CF-IPCountry     # or: source cidr geo.csv  (the country)
    region_header CF-Region               # optional: US state / subdivision
    trust_proxy   10.0.0.0/8 ::1/128
}
cache_key host path {geo} {geo.continent} {geo.region}   # vary on the geo classes
```

The three granularities:

| Token | Source | Example values |
|---|---|---|
| `{geo}` | the `source` (country header, CIDR table, or maxmind `country.iso_code`) | `US`, `ES`, `unknown` |
| `{geo.continent}` | **derived in-tree** from the country (no GeoIP dep; the maxmind DB's continent field is **not** used) | `EU`, `NA`, `AS`, `AF`, `SA`, `OC`, `AN`, `unknown` |
| `{geo.region}` | the `region_header` (upstream CDN header) **or** a maxmind **City** DB (`subdivisions[0].iso_code`) | `US-UT`, `US-WA`, `unknown` |

**MaxMind edition → field support:**

| Token | City edition | Country edition |
|---|---|---|
| `{geo}` (country) | ✅ `country.iso_code` | ✅ `country.iso_code` |
| `{geo.continent}` | ✅ in-tree from the country | ✅ in-tree from the country |
| `{geo.region}` | ✅ `COUNTRY-SUBDIVISION` (`US-WA`) | ❌ no subdivisions — pair a `region_header` or use a City DB |

**Source precedence / fallback (CDN *and* MaxMind).** A single `source` is the
norm. To honour "trust the local DB, fall back to a CDN header" you may declare
**exactly the pair** `maxmind` + `header` (in either order); any other combination
of two `source` lines is an error (the duplicate-`source` rule still applies). The
**first-declared source wins per lookup; on an `unknown`/empty result it falls
through to the second.** Typical self-hosted ordering is `maxmind` then `header`
(use the DB; fall back to a CDN header when the request arrived via one); a
CDN-fronted operator who wants the DB only for direct-origin traffic writes `header`
then `maxmind`. Sources are never merged at finer granularity — one source answers a
given lookup, the next only fills a total miss.

```
geo {
    source maxmind /etc/cadish/GeoLite2-City.mmdb   # primary: local DB by client IP
    source header  CF-IPCountry                       # fallback when the DB misses
    trust_proxy    10.0.0.0/8 ::1/128
}
```

For region, an explicit `region_header` takes precedence; otherwise a maxmind
**City** source supplies `{geo.region}` directly.

Exactly one `source` is required (or the `maxmind`+`header` fallback pair);
`region_header` is optional (only needed for `{geo.region}` / `geo region` when no
maxmind City source is configured). It is a SETUP directive; the resolution runs
only when the site varies on geo (a geo token in the key **or** a `geo` matcher) —
so an opened-but-unused MaxMind DB costs nothing per request. The classes are
bounded — continent and country codes are low-cardinality, and the region is a
bounded subdivision set — so all three are safe key normalizers. `cadish check`
warns if a geo token is used with no `geo` block, and specifically if `{geo.region}`
is used without a region source (no `region_header` **and** no maxmind City DB).

> **Security — the geo header is a trust boundary.** A `source header` /
> `region_header` value is a **request header**: it is authoritative only when an
> upstream you control (the fronting CDN/LB) *overwrites* it on every request. If
> cadish is reachable directly, a client can spoof `CF-IPCountry` / `CF-Region` to
> select geo-gated content or, when a geo token is in the `cache_key`, to fragment
> the cache. cadish defends the cache by **bounding** an injected value: a geo
> header is accepted only as a short (≤16-byte) ISO-ish code (`A–Z`, `0–9`, `-`);
> anything longer or out-of-charset (including CRLF) maps to `unknown`, so a spoofed
> header cannot blow up key cardinality or smuggle a header. It cannot, however,
> tell a *real* CDN value from a *spoofed* one — terminate the geo header at a
> trusted edge (and strip the client's copy) for geo to be authoritative.

The **geo → business mapping** (EU→EUR, a regulated-state flag) is expressed by the
operator with a `classify` / `normalize` table over these granular inputs — cadish
provides the inputs, not the policy. See the [`geo` matcher](#matchers) example.

#### `trust_proxy`
Declare the CIDRs of the **proxies / load-balancers / CDNs that front cadish**,
whose `X-Forwarded-For` is trusted when resolving the **real client IP**. This is a
**standalone site-level directive** — it needs **no `geo { … }` block**:

```
example.com {
    trust_proxy 10.0.0.0/8 172.16.0.0/12 ::1/128   # the fronting LB/CDN subnets
    @badips ip 203.0.113.0/24
    deny @badips                                    # ACLs the REAL client, not the LB
}
```

`trust_proxy` is the **single source of truth** for trusted-proxy resolution: it
feeds [`{geo}`](#geo), the security gate's [`ip`](#matchers) ACL, the cluster
[`X-Cadish-Peer`](#cluster----region-local-peer-cache-clustering) hop guard, the
`:80` [HTTP→HTTPS redirect loop guard](#tls), **and the X-Forwarded-* headers cadish
sends to the origin** (one trust boundary). XFF is honored only when the socket peer
is a trusted proxy (otherwise it is client-spoofable and ignored); the rightmost
non-trusted XFF hop is the client. It is a SETUP directive (parsed once at load).

**Forwarded headers to the origin.** cadish always sends the origin a *trustworthy*
client identity rather than relaying the client's spoofable values: from a **direct/
untrusted** peer it OVERWRITES `X-Forwarded-For` and `X-Real-IP` with the verified
socket-peer IP, sets `X-Forwarded-Proto`/`X-Forwarded-Host` from the inbound request,
and drops any client `Forwarded`. Behind a **trusted** proxy (`trust_proxy`) it KEEPS
the vetted `X-Forwarded-For` chain and APPENDS the socket peer (standard reverse-proxy
semantics), and sets `X-Real-IP` to the resolved real client. So an XFF-trusting
origin can rely on the value — a client can no longer spoof its source IP through
cadish. (An explicit `header_up X-Forwarded-For …` still wins.)

**Why it matters (security):** the `ip` ACL resolves the real client only through a
trusted proxy. **Without `trust_proxy`, behind an LB/CDN the `ip` matcher matches
the proxy's IP for every request** — so `deny @badips` never fires and
`allow @office` misbehaves: the control silently no-ops. `cadish check` warns
(`ip-acl-without-trust-proxy`) when a site has an `ip` ACL but no trusted-proxy set.

**Relationship to `geo { trust_proxy … }`:** the legacy in-block form still works
(back-compat). When **both** are present they **union** (deduplicated): declaring a
proxy trusted can only let the resolver walk *past* it to the real client, so a
union is the fail-safe rule for a security control. Use the standalone directive for
pure-security sites (an `ip` ACL with no geo); use either (or both) otherwise.

#### `normalize`
Define a named, generic request→bucket normalizer — the VARY-cardinality toolkit
that generalizes `{device}`/`{geo}` to **any** header, cookie, or query param.
`normalize NAME { … }` makes `{NAME}` available as a `cache_key` token:

```
normalize plan {
    from    header X-Plan         # or: cookie NAME | query NAME
    map     pro,enterprise -> paid   # comma-list several values per bucket
    map     free           -> free
    default free
}
cache_key host path {plan}       # vary on {paid, free}, not the raw header
```

- `from header|cookie|query NAME` — the request value to read (required).
- `map VALUE[,VALUE…] -> BUCKET` — exact-match value→bucket; several source
  values can map to one bucket via a comma-list (repeatable).
- `default BUCKET` — bucket for any unmapped value.

It is **pure** — resolved entirely from the request, so unlike `{device}`/`{geo}`
it needs no server pre-pass. The buckets are bounded, so `{NAME}` is a safe,
low-cardinality key token (the fix `cadish check` suggests for a raw `header:`/
bare `query` key). `NAME` may not shadow a built-in (`sticky`/`device`/`geo`/
`tenant`). `cadish check` reports `{NAME}`'s bucket count.

#### `classify`
Where `normalize` maps **one** request value to a bucket, `classify` reduces
**several matchers** to a bounded enum — a first-match-wins rule table that
derives a named `{TOKEN}`. It is how you express conditional / multi-input vary
(the workers-cache "3-state" age-gate, publi flag, language selection, …)
**without an expression language**: the values are literals, the conditions are
named matchers combined only by AND (within a row) and OR (across rows), and the
table is evaluated once, purely, with no control flow.

```
@regulated  header X-Region gated      # any matcher that reads the request
@verified   cookie verified_prod
classify {age} {
    when @verified              -> ok      # row = AND of its matchers;
    when @regulated             -> gate     #   first matching row wins
    default                     -> open     # fallthrough (required)
}
cache_key method host path {age}       # consume it like {device}/{geo}/{plan}
```

This worked 3-state example derives `{age}` ∈ {`ok`, `gate`, `open`}:

- A **verified** request → `ok` (the first row wins even if it is *also*
  regulated — first-match-wins).
- An unverified **regulated** request → `gate`.
- Anything else → `open` (the `default`).

A row's matcher may be **inline** — the home-page `publi` boolean folds "is *any*
ad/tracking param present?" to a single bit with an inline `query_present`:

```
classify {publi} {
    when query_present adult_content t a p ff-* pub-*  -> 1   # any ad param present
    default                                            -> 0
}
cache_key host path query_allow genre age camLang {publi}     # filters + 1 bit
```

Grammar:

- `classify {TOKEN} { … }` — `TOKEN` is the derived placeholder name; it may not
  shadow a built-in (`sticky`/`device`/`geo`/`tenant`) or a `normalize` of the
  same name.
- `when <matchers> -> VALUE` — one or more `@matcher` refs (or one inline
  `TYPE arg…` matcher) forming a **conjunction (AND)**: the row fires only when
  **all** match. `VALUE` is a literal. Rows are tried top-to-bottom; the first
  whose conjunction holds wins. An optional `and` reads as a connector
  (`when @a and @b` ≡ `when @a @b`).
- `default -> VALUE` — the value when no `when` row matches (required).
- `derives_from cookie NAME… [forward|keep]` *(optional)* — names the request
  **cookies this axis consumes**, so cadish can do the Varnish *cardinality collapse*:
  read the per-user cookies → derive the low-cardinality token → **strip the raw
  cookies** → cache keyed by the normalized token. Without it, a kept per-user cookie
  forces a credential **bypass** (you can read the cookie *or* cache, not both); with it
  the request caches under the bounded axis (e.g. `1.2M` cookie combinations collapse to
  `~64` entries). A trailing **`forward`** (alias `keep`) modifier on the line keeps the
  named cookies in the request — they are **forwarded to the origin** unchanged instead
  of stripped, while still keyed + covered by `{TOKEN}` (the loud opt-in for backends
  that personalize from the raw cookie). See the worked example below.

The token is consumed exactly like the other key normalizers:

- **In the cache key**: `cache_key … {age}` varies on the bounded enum.
- **As a header value**: `header X-Age {classify.age}` interpolates the value.
- **As a scope** — define a matcher `@gated classify {age}==gate` (or
  `{age}!=open`) and use it anywhere a matcher is accepted:
  `pass @gated`, `header @gated X-Age-Gate 1`, `route @gated -> origin`, ….

It is **pure** — its matchers read only the request, so `{TOKEN}` resolves in the
request phase with no server pre-pass (a classify row may therefore not use a
response-phase matcher like `content_type`/`set_cookie`). The values are bounded,
so the token is a safe, low-cardinality key.

> A `when` row's matchers are resolved in **dependency order**, so a classify-type
> matcher (`@gated classify {age}==gate`) **may feed another `classify` row** —
> classifiers and classify-matchers can be chained to any depth (e.g.
> `classify {regulated}` → `@regulated` → `classify {ageverify}`), in any source
> order. A true reference cycle (`{a}` → `@b` → `{b}` → `@a`) is rejected with a
> `compile-error` naming both ends. Every `VALUE` (including the `default`) must be
> **non-empty** — `default -> ""` is rejected. Both are caught by
> `cadish check`, which compiles the pipeline (see [check.md](check.md),
> finding code `compile-error`): a config that fails to compile fails `check`
> with the same `file:line:col` it would print at `cadish run`.

> **The red line (why this is not VCL).** `classify` is a *switch/lookup table*,
> not a program: no arithmetic, no string building, no variables, no control flow
> beyond the first-match table, no `restart`. Reaching **one bounded field out of a
> JSON cookie/header as a predicate** stays on the config side — that is what
> [`cookie_json`/`header_json`](#cookie_json--header_json) is for (it feeds a
> `classify` row or an origin header). The red line is **JSONPath-the-language**
> (wildcards/filters/recursion) or a **computed output** (string building,
> arithmetic): the moment a requirement needs that, it is a Go module (the escape
> hatch) — not a richer Cadishfile.

> **`derives_from` — normalized cookie vary (derive → strip → key).** Browser traffic
> always carries per-user cookies, so a `classify` that *reads* a cookie would still
> **bypass** the shared cache (a kept, unkeyed cookie is a credential — see
> [`cookie_allow`](#cookie_allow) and the bypass rule). `derives_from cookie NAME…`
> closes that gap by declaring the cookies an axis consumes:
>
> ```
> @verified   cookie verified-prod 1
> @registered cookie userType registered
> classify {ageverify} {
>     derives_from cookie verified-prod userType   # the axis inputs
>     when @verified   -> 0
>     when @registered -> 1
>     default          -> 2
> }
> cookie_allow                                     # strip everything else
> cache_key default host url {ageverify}           # {ageverify} in the key ⇒ active
> ```
>
> When `{ageverify}` is in the **selected** `cache_key` recipe, cadish (1) lets the
> declared cookies **survive** `cookie_allow` so the classifier reads the original
> value and the key is built from it, then (2) **strips** them from the request *after*
> the key is captured and *before* the credential check + the origin fetch (Varnish's
> `unset req.http.Cookie`). The origin therefore gets an **anonymous** request and its
> reply is safely stored under the collapsed key.
>
> **Fail-closed, by design.** Auto-strip is the *only* mechanism — a `derives_from`
> token never "covers" a cookie that is still forwarded. An axis must list **all** its
> inputs: a per-user cookie that is *not* declared and *not* keyed still bypasses (no
> silent cross-user store), and `Set-Cookie` is still never cached. The strip is
> **gated** on the token being in the selected recipe — a `derives_from` whose token is
> in no recipe is read but never stripped (it would leak to origin), which `cadish
> check` flags (`derives-from-not-stripped`); and a covered cookie no longer raises
> `cookie-allow-unkeyed`. Edge parity: the worker replicates the exact derive→strip
> ordering, so the edge and server collapse cardinality identically.
>
> **`forward` mode — derive + key + cover, but FORWARD the cookie.** Sometimes the
> origin still personalizes server-side from the *raw* cookie (some code paths read it
> directly). A trailing **`forward`** (alias `keep`) keeps the named cookies in the
> request instead of stripping them:
>
> ```
> classify {adult_php} {
>     derives_from cookie AdultContent forward   # read + key + cover + FORWARD (don't strip)
>     when @adultcookie -> 1
>     default           -> 0
> }
> cookie_allow
> cache_key default host url {adult_php}
> ```
>
> A forward cookie is **read pre-key, contributes to `{TOKEN}`, forwarded to origin
> unchanged, and treated as covered** by `{TOKEN}` for the credential bypass — so the
> request still caches under the collapsed key. The coverage is gated **exactly like the
> strip**: the token must be in the *selected* recipe, so a forward cookie is **always
> keyed** (no shared-key leak along the axis). A forward cookie whose token is *not* in
> the selected recipe is **not** covered and falls through to the normal path (bypass /
> `cookie_allow`) like any kept cookie. Per-cookie granularity is by **separate lines**
> (one strip, one `forward`) for *different* cookies — declaring the **same** cookie both
> strip (bare) and `forward` within one `classify` block is a **compile error** (a cookie
> cannot be both stripped and forwarded; the safe-default strip is never silently
> downgraded). Because the collapsed key now hides the raw cookie, `cadish
> check` emits a loud advisory **`cookie-forward-uncollapsed`**: you are asserting the
> cookie's only cache-relevant effect is `{TOKEN}` — if the origin personalizes on it
> along a dimension the key does not capture, that per-user body would be served under the
> shared key. `Set-Cookie` is still never cached. Use bare `derives_from` (strip — the
> safe default) unless the backend genuinely reads the raw cookie.
>
> **Duplicate forward cookies.** A browser may legitimately send one cookie name more
> than once (e.g. a domain-scoped and a host-scoped copy under RFC 6265). A
> forward-covered cookie sent **more than once with identical values still caches** —
> it is keyed by the derived `{TOKEN}` (occurrence-independent) and the origin sees N
> identical values, so no cross-user divergence is possible. If the occurrences carry
> **differing** values (genuinely ambiguous), or the cookie is keyed by a raw
> `cookie:NAME` token (the raw value enters the key, which captures only the first
> occurrence), a duplicate still forces a **bypass** — fail-closed.

#### `tenant` / `group`
Serve many brands/hosts from one config (whitelabel multi-tenancy) without
duplicating the shared policy. A `group { … }` block holds the **shared base**
plus one `tenant NAME { host HOST…; <overrides> }` per brand:

```
group {
    # --- shared base (every tenant inherits this) ---
    cache     { ram 10GiB }
    cache_key {tenant} host path        # brands never share cache entries
    cache_ttl default ttl 2s
    header    X-Frame-Options SAMEORIGIN

    tenant acme {
        host  acme.example www.acme.example
        upstream web { to http://acme-origin:8080 }   # override the origin
        cache_ttl default ttl 60s                      # override the TTL
    }
    tenant globex {
        host  globex.example
        upstream web { to http://globex-origin:8080 }
    }
}
```

This expands at load into one ordinary site per tenant. Each tenant's directives
take priority and the base is the **fallback**:

- A tenant's first-match-wins rule (`pass`/`route`/`cache_ttl`/`storage`/
  `header`…) is placed before the inherited base, so it wins; the base still
  applies to anything the tenant didn't cover.
- A tenant's at-most-one directive (`cache`/`cache_key`/`tls`/`cors`/
  `device_detect`/`geo`) and any same-name `upstream`/`cluster`/`normalize`/
  `@matcher` REPLACE the base's.

`{tenant}` resolves to the tenant's `NAME` (a per-site constant) — put it in the
`cache_key` so brands get isolated cache entries. A standalone site may also set
its identity with a bare `tenant NAME` directive (no group). `cadish check`
expands groups and reports one site per tenant.

**Request-derived `{tenant}` (one site, many brands).** When a single site serves
many hosts, derive the tenant from the request instead of expanding per-tenant
sites — a `tenant { … }` block (the same shape as `normalize`, resolved purely
in the pipeline):

```
*.example, *.shop.example {
    tenant {
        from    host                       # or: from header X-Tenant
        map     *.acme.example   -> acme   # exact or *.suffix host patterns
        map     globex.example   -> globex
        default other
    }
    cache_key {tenant} host path           # brands get separate namespaces
}
```

`from host` (default) matches the request Host (case/port-insensitive, with
`*.suffix` wildcards); `from header NAME` matches a header value (exact). The
emitted tenant ids are bounded, so `{tenant}` stays low-cardinality — `cadish
check` reports the id count. (A site uses either the constant `tenant NAME` /
group form, or a `tenant { … }` block — not both.)

### ORIGIN

#### `cache_ttl`
Per-response freshness policy, first-match-wins. Selector + action:

```
cache_ttl status 404 410   ttl 60s grace 1h            # selector: status codes
cache_ttl status not 200   hit_for_miss 5s             # selector: status NOT in {200}
cache_ttl @images          ttl 24h grace 365d          # selector: a matcher
cache_ttl default          from_header X-Cache-Ttl grace 1h  # TTL from an origin header
cache_ttl default          ttl 2s  grace 24h           # catch-all fallback
cache_ttl @pages           ttl 60s grace 5m max_stale 24h    # serve-stale-on-outage
cache_ttl @v3 from_header X-Cache-Ttl grace_from_header X-Cache-Grace grace 5m  # grace from an origin header
```

- Selectors: `status CODE…`, `status not CODE…`, `@matcher`, `default`.
- Actions: `ttl DUR [grace DUR|grace_from_header NAME] [max_stale DUR|max_stale_from_header NAME]`,
  `from_header HEADER [grace DUR|grace_from_header NAME] [max_stale DUR|max_stale_from_header NAME]`,
  or `hit_for_miss DUR`. Each window may be a literal **or** sourced from an origin
  response header; `grace_from_header`/`max_stale_from_header` are rejected on
  `hit_for_miss`.
- **A broad selector (`default`, `@scope`, `status not …`) stores only `200`, `404`
  and `410`** — a success body, or the canonical negative-cache entries. It will **not**
  cache a transient `4xx`/`5xx`: caching a `5xx` under a generic `cache_ttl default`
  would pin an outage for the whole TTL even after the origin recovers, and caching a
  `401`/`403` would compound credential leaks. To cache another error status you must
  name it in an **explicit positive** `status <code>` selector
  (`cache_ttl status 500 503 ttl 5s`) — that is the deliberate opt-in. A `3xx` redirect
  is never stored through any path, so `cache_ttl status 301 ttl …` is **dead config**
  and `cadish check` warns (`dead-status-rule`). `hit_for_miss` is a deliberate
  *don't-store* decision and is honored for any failing status.
- `grace` is the stale-while-revalidate window: a stale-but-in-grace object is
  served immediately while cadish revalidates in the background — **regardless of
  origin health** (it trades freshness for latency on every request). A stale-in-grace
  serve is a deliberate, operator-authoritative relaxation: it is served **even when the
  origin response carried `Cache-Control: must-revalidate`** (which RFC 9111 §5.2.2.1
  would otherwise forbid). With **no** `grace` configured (the default, `grace 0`) cadish
  never serves stale, so `must-revalidate` is honored by default — only an explicit
  `grace` opt-in serves stale, and that operator decision is authoritative over the
  origin's directive (see ADR D97).
- **Downstream freshness on a HIT/MISS.** A response cadish **stores** is served — on
  both the MISS that stored it and every later HIT — with cadish's **own** authoritative
  `Cache-Control: public, max-age=<the cache_ttl you set>` (and the absolute `Expires` is
  dropped), plus an `Age` header. cadish is authoritative over the origin's freshness (your
  `cache_ttl` already overrides the origin's `max-age`), so a downstream shared cache (or
  the Cadish Edge tier in front) sees the **same** remaining lifetime cadish itself uses —
  never the origin's overridden value and never RFC 9111 heuristic freshness from a bare
  `Last-Modified`. An explicit `header Cache-Control "…"` directive **overrides** this. A
  `pass` / hit-for-miss / uncacheable response keeps the origin's `Cache-Control` verbatim
  (see ADR D96).
- **`max_stale DUR`** is the **third freshness tier** (the serve-stale-on-origin-
  *failure* window). A past-grace object stays in reserve for this additional span
  and is served **only when the origin fetch fails** — never to a healthy request.
  A request inside the max_stale window behaves exactly as expired (it goes to
  origin); `max_stale` adds a fallback *only* for when that fetch fails. The serve
  carries cache-status **`HIT-STALE-ERROR`** (distinct from grace's `HIT-STALE`),
  and it does **not** refresh the freshness marker (a persistently-down origin
  keeps serving the same last-good copy until the window finally elapses, rather
  than silently re-arming grace). The servable ceiling is
  `storedAt + ttl + grace + max_stale`. Constraints: `max_stale` is accepted only
  on the `ttl` and `from_header` actions (never `hit_for_miss`), must be **`≥
  grace`** (a smaller value would be dead — grace already covers that span), and is
  **server-only** in v1 (not projected to the Cadish Edge IR; the Workers cache has
  its own MAX_STALE knob). `max_stale` differs from a long `grace`: grace would
  serve day-old content to *healthy* requests (wrong); `max_stale` preserves
  availability *only* during an outage.
- `hit_for_miss` caches the *decision* "don't cache this key" for a short time so
  a transient bad response doesn't poison the key — it is never stored or served.
  Note: it does **not** suppress the origin re-fetch and does **not** coalesce
  concurrent error fetches; while the decision holds every request still re-fetches
  from origin.
- **`from_header HEADER`** reads the TTL from a named **origin response** header
  (e.g. `from_header X-Cache-Ttl`), letting the backend declare per-object
  freshness (parity with origin-driven TTL semantics). The value is parsed
  as a cadish duration (`300s`, `5m`, `1h`, `1d`); a **bare integer is seconds**
  (matching `Cache-Control: max-age`, e.g. `X-Cache-Ttl: 300` = 5 min). If the
  header is **absent, empty, non-positive, or unparseable**, the rule does **not**
  apply and evaluation **falls through** to the next `cache_ttl` rule — so put a
  static `cache_ttl default ttl …` after it to supply a fallback. An optional
  `grace DUR` adds a static stale-while-revalidate window on top of the dynamic
  TTL.
- **`grace_from_header NAME`** and **`max_stale_from_header NAME`** source the
  **grace** / **max_stale** window from an origin response header the same way
  (bare integer = seconds; otherwise a cadish duration; one-year cap). They are valid
  on the `ttl` and `from_header` actions (rejected on `hit_for_miss`). Unlike the
  header **TTL**, an absent/unparseable value does **not** make the rule fall through —
  it falls back to the in-rule **literal** `grace` / `max_stale` (so
  `grace_from_header X-Cache-Grace grace 5m` means "grace from the header, or 5m if it
  is missing", matching the Varnish `std.duration(beresp.http.X-Cache-Grace, 5m)`
  idiom). The `max_stale ≥ grace` rule is enforced against the **resolved** values: an
  origin `max_stale` below the effective grace is **ignored** (no error-fallback
  window) rather than erroring at request time.
- **Consumed control headers are stripped from the delivered response.** When a rule
  reads any `from_header`-family header (the TTL, grace, or max_stale header name,
  whichever are configured) and applies, cadish **removes those headers** from the
  response before storing and delivering it — they are an internal origin↔cache
  control contract, not for the client (mirroring Varnish's `unset beresp.http.X-Cache-
  Ttl`). Non-control origin headers are untouched, and a site with no `from_header`-
  family rule strips nothing.

> **Wiring note:** `hit_for_miss` **is** applied on a transient upstream
> 4xx/5xx. **Negative caching is wired** — a `cache_ttl status 404 410 ttl 60s`
> rule stores the failing response and serves it from cache (recording the
> negative status). For an HTTP origin the **real error-page body + the cached
> headers (Content-Type / ETag / Last-Modified)** are stored and served verbatim
> on a HIT (full-body negative caching, backlog #21); a not-found with no usable
> body (S3 `NoSuchKey`, or a transport error with no response) stores a bodyless
> negative entry. Durations are parsed with `ns`/`us`/`ms`/`s`/`m`/`h`/`d`/`w`
> units (compound forms like `1d12h` allowed); a bogus duration (`ttl 5xz`) is
> rejected by `cadish check` at lint time with a `file:line`, not just at startup.

#### `cache_unsafe`
Site-level **opt-out of safe-by-default caching**. Takes no arguments:

```
cache_unsafe
```

By default cadish refuses to cache (and serve cross-user) a response that a
`cache_ttl` rule matched but that is **not safely shareable** — one bearing a
`Set-Cookie`, a `Cache-Control: no-store|private|no-cache`, or a `Vary` not covered
by the [cache key](#cache_key) (and not solely `Accept-Encoding`). This is exactly
what every RFC 9111 shared cache / CDN does, and it mirrors the Cadish **Edge**
tier's invariant. `cache_unsafe` **disables the `private`/`no-store`/`no-cache`/
uncovered-`Vary` part of that refusal for the whole site**, so a matched `cache_ttl`
rule caches such a response regardless.

**Two refusals are NOT overridable**, even with `cache_unsafe`:

- a **`Set-Cookie`** response (ironclad — the cookie is a per-user credential the origin
  is minting right now). To cache a cookie-stamping origin you must **strip** the cookie
  with [`strip_cookies`](#strip_cookies), which is the explicit per-class opt-in.
- a **`Vary: *`** response (never servable from a shared cache).

Use `cache_unsafe` only when you have your own discipline for the `private` content you
are caching. Prefer the scoped [`set_cookie`](#matchers) guard
(`cache_ttl @session hit_for_miss …`) or [`strip_cookies`](#strip_cookies) over the blanket
opt-out whenever you can. It carries **no per-request cost** — it is read once at config
load.

> **`cache_unsafe` is NOT a credential escape.** It governs only the *response*
> shareability refusal above. It does **not** lift the default
> [bypass of credentialed *requests*](#credentialed-requests-are-never-shared-cached-by-default)
> (`Authorization`/`Cookie`): the only way to cache those is to **key** by the
> credential (`cache_key … cookie:session` / `header:Authorization`), so you cannot
> accidentally cache credentialed traffic under a shared key.

#### `client_cache_control`
Site-level **opt-out of honoring a request's client-forced revalidation**. Takes one
value, `ignore`:

```
client_cache_control ignore
```

By default (directive absent) cadish honors the RFC 9111 §5.2.1.4 rule that a request
`Cache-Control: no-cache` / `max-age=0` (or the HTTP/1.0 `Pragma: no-cache`) forbids
serving a stored response without first revalidating with origin. A standard **browser
hard-refresh sends `Cache-Control: max-age=0`**, so every reload becomes a `MISS` that
goes to origin — engaged users who refresh never benefit from the shared cache, and the
origin absorbs the full load. That is a **cache-bust / DoS** vector.

`client_cache_control ignore` makes cadish **not honor** that client directive for the
whole site: a fresh or in-grace entry is served as a normal `HIT`/`HIT-STALE` and the
client cannot force a `MISS`. It is the Cadish equivalent of Varnish's
`unset req.http.Cache-Control` / `unset req.http.Pragma`.

The opt-out **only** suppresses the *client*-forced revalidation. Everything else is
unchanged:

- normal **TTL / grace** revalidation still applies — an entry past its grace window is
  **never** served stale; it revalidates with origin regardless of this flag;
- **`Set-Cookie` / credential / `no-store`-response** safety, the unsafe-method serve
  guard, and the credentialed-request bypass are all untouched.

It carries **no per-request cost** — read once at config load; when set, the server skips
the client-revalidation header scan entirely on the hot path. `ignore` is the only
accepted value (any other value, or none, is a config error).

> Scope: this is a **per-site** flag. Unlike `cache_unsafe` (which governs the *response*
> shareability refusal), `client_cache_control` governs only whether a *request* directive
> can force a revalidation.

> **Edge tier:** the Cloudflare Workers edge tier **always serves operator-TTL-fresh
> content and never honors client-forced revalidation** — it does not scan the request
> `Cache-Control` / `Pragma`, so a client `no-cache` / `max-age=0` can never punch a stored
> edge entry through to origin. In other words the edge behaves as if `client_cache_control
> ignore` were permanently set, **regardless of this directive** (the EdgeIR carries no
> client-revalidation flag). This is deliberate: a CDN-style additive cache must not let a
> client bust the shared edge cache (the cache-bust / DoS vector), and Cloudflare's own cache
> layer in front of the worker applies whatever request-`Cache-Control` handling the zone is
> configured for. On the origin (Go) tier the directive behaves exactly as described above.

#### `storage`
Which tier stores the object:

```
storage @images -> disk
storage default -> ram
```

**Honored** — a `storage <selector> -> ram|disk` rule overrides the cache's
default size-based routing for matching objects (with safety fallbacks so an
object is never cached *nowhere*: a forced-RAM object too large for the per-object
RAM cap, or a forced-disk object on a RAM-only deployment, falls back to the other
tier). A `cache { tier .ext -> … }` block sets a per-extension default that
`storage` overrides.

### DELIVER

#### `header`
Add/remove/append response (or request) headers. Multiple ops per line:

```
header -Server -X-Powered-By -Via       # remove (each -NAME)
header X-Frame-Options SAMEORIGIN       # set (NAME VALUE)
header +Link "</a>; rel=preload"        # append (+NAME VALUE)
header +cache_status X-Cache            # emit HIT/MISS/HIT-STALE/HIT-STALE-ERROR into X-Cache
header +cache_key X-Cache-Key           # emit the cache-key HASH (12-hex) into X-Cache-Key
header @images Cache-Control "public, max-age=31536000"   # scoped by @matcher
```

A leading `@matcher` (or an inline single-arg matcher) scopes the edit.
Request-side vs response-side is decided by position relative to `cache_key`.

##### Dynamic header values

A set/append header **value** may interpolate request-derived placeholders using
the same [template syntax](#target-template-syntax-shared-with-dynamic-header-values)
as `redirect` targets. The two request-scoped placeholders are:

| Placeholder | Expands to |
|---|---|
| `{client_ip}` | the resolved client IP (no port) |
| `{http.NAME}` | the request header `NAME` (canonicalized); an **absent** header → empty string |
| `{classify.NAME}` | the derived [`classify`](#classify) token `NAME`'s value |
| `{geo}` / `{geo.continent}` / `{geo.region}` | the resolved geo classes (when a `geo` source is configured) |
| `{device}` | the resolved device class (`desktop`/`mobile`/`tablet`/`bot`) — the same bucket the `cache_key {device}` token uses; requires a [`device_detect`](#device_detect) block (or uses the built-in ruleset when `{device}` already keys the cache). **Resolves to empty string if the cache key does not also use `{device}`** (the classifier runs only when the key varies on it — add `cache_key … {device}` to enable it). |
| `{query.NAME}` | the first decoded value of query param `NAME` (e.g. `{query.genre}` → `comedy`); empty when the param is absent |
| `{proto}` / `{scheme}` | `https` when cadish **terminated TLS** for the inbound connection, else `http` (the `X-Forwarded-Proto` value) |

The value is expanded **per request** (the cache stores nothing about it). A plain
literal value with no `{`/`$` does zero per-request work — only templated values are
expanded. `{host}`/`{path}`/`{query}`/`{uri}` also resolve (regex captures `$1…`
do not apply here — there is no selecting path regex on a header op, so they expand
to empty).

```
# Echo the client IP to the origin (request-side: before cache_key).
header X-Real-IP {client_ip}

# Forwarded-header set the origin expects (the `option forwardfor` +
# `X-Forwarded-Proto https if { ssl_fc }` equivalent):
header +X-Forwarded-For   {client_ip}     # APPEND our hop; the client's existing
                                          # X-Forwarded-For chain is forwarded verbatim,
                                          # so the origin sees `client, …, cadish`.
header X-Forwarded-Proto  {proto}         # https when cadish terminated TLS, else http

# Reflect the request Origin back as the allowed CORS origin (response-side).
header Access-Control-Allow-Origin {http.Origin}
header +Vary Origin
```

> **`X-Forwarded-For` (the `option forwardfor` equivalent).** Use the **append**
> form `header +X-Forwarded-For {client_ip}` (the leading `+`): it *adds* cadish's
> resolved client-IP hop to the request's existing `X-Forwarded-For` chain rather
> than replacing it, so a multi-proxy chain stays intact (`client, proxy1, cadish`).
> A plain `header X-Forwarded-For {client_ip}` would **overwrite** the chain with a
> single hop. There is no separate `append` keyword — the `+` op is the append.

> ⚠️ **Security — reflected `Origin` is a footgun.** `header
> Access-Control-Allow-Origin {http.Origin}` echoes *whatever* `Origin` the caller
> sent, which together with `Access-Control-Allow-Credentials: true` effectively
> disables the same-origin policy for credentialed requests (any site can read the
> response). cadish does **not** enable this for you — it is opt-in, exactly the
> directive you wrote. If you reflect `Origin`, **gate it** with a scope that only
> matches trusted callers (e.g. `header @trusted_origin Access-Control-Allow-Origin
> {http.Origin}`, where `@trusted_origin` is a `header Origin https://app.example.com`
> matcher), **do not** combine an unbounded reflect with
> `Access-Control-Allow-Credentials: true`, and always pair it with `Vary: Origin`
> so a cached response is not served to a different origin. An absent `Origin`
> resolves to an empty header value (`Access-Control-Allow-Origin:`), which browsers
> treat as no permission — fail-closed.

`cadish check` treats a templated header value as a literal string (it contributes
no regex evals and raises no matcher warning).

##### `+cache_key` — expose the computed cache key (debug)

A delivery-only debug special, parsed exactly like `+cache_status`, that emits the
request's **computed cache key** into a response header — the natural companion to
`+cache_status` (which says *whether* the key hit, this says *which* key):

```
header +cache_key X-Cache-Key                 # emit the cache-key HASH (default)
header @debug +cache_key X-Cache-Key raw      # emit the RAW key string (scoped)
```

- **`+cache_key NAME`** emits the **hash**: the first **12 hex chars** of
  `sha256(key)` (e.g. `X-Cache-Key: 9f2a1c4e7b30`). Short, fixed-width, and exactly
  the form Cloudflare Workers exposes. Two requests share a cache entry iff they
  share this hash.
- **`+cache_key NAME raw`** emits the **raw** key string (the token recipe joined by
  the ASCII unit separator `\x1f`). `raw` is the **only** allowed trailing modifier;
  anything else is a compile error. A missing target header name is also an error.
- It is **delivery-only** (response-side) like `+cache_status`; scope it with a
  leading `@matcher`. It is emitted **only on a request that has a key** — a `pass`,
  `respond` synthetic, or `redirect` has no cache key, so the header is omitted.

> 🔒 **Privacy.** The raw key can embed path/query-derived material and
> `header:`/cookie values (via `{sticky}`/`header:NAME` cache-key tokens). The
> **hash is the default** because it reveals nothing about the recipe. `raw` is
> opt-in for deep fragmentation debugging and **should be scoped** to trusted
> callers — the same way operators gate any debug header behind an `@debug` /
> internal-IP matcher:
>
> ```
> @debug ip 10.0.0.0/8 192.168.0.0/16          # the operator's network
> header @debug +cache_key X-Cache-Key raw     # only internal IPs see the raw key
> header +cache_status X-Cache                  # status is safe for everyone
> ```

It also works at the **edge**: the Cadish Edge worker computes the *same*
`sha256`-first-12-hex over the cache key it builds per request and sets the header,
so the Go server and the JS edge runtime emit the **identical** value for the same
request (a cross-runtime conformance fixture asserts this). The directive compiles
to a semantics-free op marker — no key value is baked into the AST or the Edge IR.

##### `+cache_age` — expose the object age in seconds (debug)

A delivery-only debug special, parsed exactly like `+cache_status`, that emits the
**age of the cached object in whole seconds** into a response header — the natural
complement to `+cache_status` (which says *whether* the key hit, this says *how old*
the cached object is):

```
header +cache_status X-Cache            # HIT / MISS / HIT-STALE
header +cache_age    X-CF-Cache-Age     # e.g. 45 (on a HIT)
```

- **`+cache_age NAME`** emits an **integer** (e.g. `"45"`) representing the number of
  whole seconds since the object was stored into the cache — the equivalent of the HTTP
  `Age` response header, limited to cadish's own cache layer.
- It is **emitted only on a cache HIT** (fresh or stale). On a MISS or a bypassed
  (`pass`) request the header is absent — there is no stored age to report.
- It is **delivery-only** (response-side) like `+cache_status`; it can be scoped with a
  leading `@matcher`. The value is never baked into the IR — it is computed from the
  object's stored timestamp at serve time.
- It also works at the **edge**: the Cadish Edge worker materializes the age from the
  cache-tier `meta.storedAt` timestamp, matching the Go server's freshness-index age
  computation byte-identically (proven by the conformance suite).

#### `strip_cookies`
Drop the response `Set-Cookie` on matching responses — the faithful equivalent of
Varnish's `unset beresp.http.Set-Cookie`:

```
strip_cookies path_regex \.(css|js|png|jpe?g|ico)$
strip_cookies path / /pagina/*
strip_cookies @images
strip_cookies                           # unscoped = all responses
```

A `strip_cookies` rule does **two** things on the classes it covers, both **before** the
response leaves cadish:

1. **It makes a `Set-Cookie` response cacheable.** A `Set-Cookie` reply is otherwise
   [never stored](#caching-is-safe-by-default) (ironclad, not even under `cache_unsafe`).
   When `strip_cookies` covers it, the cookie is removed **before the cacheability decision
   and before storing**, so the now-cookieless response caches normally. This is the
   **explicit, per-class opt-in** for caching an origin that stamps a session/bootstrap
   cookie on every reply — you cache it *because* you declared the cookie controlled.
2. **It removes `Set-Cookie` on delivery**, so the client (and every later cache HIT) never
   receives the stripped cookie.

Scope it to the **cacheable** classes only — never to `pass` traffic (login/checkout
endpoints that legitimately set a session cookie): on a `pass` class the cookie should be
preserved. A common pattern is an `@cacheable` matcher that excludes the passed classes:

```
@dynamic    method POST
@cacheable  all !@nocache !@ajax !@dynamic
strip_cookies @cacheable               # strip on everything that is cached; pass keeps its cookie
```

It is the **response**-side mirror of [`cookie_allow`](#cookie_allow)
(which controls the *request* `Cookie`). The Cadish **Edge** worker strips `Set-Cookie`
before writing to its L1/L2 cache too, so a covered class caches identically at the edge.

#### `cors`
Emit CORS headers:

```
cors *                                  # allow any origin
cors https://a.com https://b.com methods GET POST headers X-Token
cors @api *                             # scoped by @matcher
```

`cors *` emits `Access-Control-Allow-Origin: *`. With an explicit allow-list,
cadish **echoes the request's `Origin`** back as a single value when it is on the
list (adding `Vary: Origin`) and emits **no** `Access-Control-Allow-Origin` when
the request `Origin` is absent or not allowed — never a comma-joined list, which
browsers reject. This matches the edge tier byte-for-byte.

> **`cors` decorates responses; it does not answer the OPTIONS preflight.** `cors`
> only *adds* the `Access-Control-*` headers to a response — it does **not** short-
> circuit a CORS **preflight** (`OPTIONS` with `Access-Control-Request-Method`). The
> `OPTIONS` request is **forwarded to origin** like any other method, so the origin
> must answer it (typically `204`). If the origin returns `405`/`501` for `OPTIONS`,
> the browser preflight fails even though `cors` is configured — point the preflight
> at an origin that handles `OPTIONS`, or add a `respond OPTIONS … 204` rule. This is
> deliberate and matches both the edge worker and the Fetch spec (decoration is a
> response transform, not a request handler). A built-in `204`-answer mode is a
> possible future opt-in; it is not implemented today.

### Anywhere

#### `import`
Splice another Cadishfile fragment in place (paths resolve relative to the
importing file). Use it **inside a site block** to share a big matcher set across
sites:

```
example.com {
    import nocache.cadish
    …
}
```

A fragment is a bare list of matchers/directives (no site wrapper) parsed with the
**full site-body grammar** — including brace-bodied directives. A fragment may
contain `classify {…}`, `upstream {…}`, `tls {…}`, `cache {…}`, `geo {…}`,
`device_detect {…}`, etc.; each splices in as exactly the block it would be inline
at the `import` point, so splitting a config into fragments is byte-for-behavior
identical to the single file. An unclosed/malformed block in a fragment is a
positioned error, never a silent flatten. Missing/cyclic imports are positioned
errors (`cadish check` reports them) — including a file that imports **itself**. A
*top-level* `import` (outside any site, in a file that already has site blocks) is
a no-op — both `cadish run` and `cadish check` ignore it — so put `import` inside
the site that uses the fragment.

The path may be a **glob** (`*`, `?`, `[…]`): `import conf.d/*.cadish` splices every
match in sorted order (nested imports inside a fragment resolve recursively). A glob
that matches **no** files is a positioned error, never a silent empty splice.

#### `replace`

```
replace [@scope…] OLD NEW
```

A **deliver-phase response-body transform**: every occurrence of the literal
`OLD` becomes `NEW`. Repeatable; applied in the order written. Scope it with a
`content_type` matcher (the common case) so it only touches the right responses:

```
@html content_type text/html
replace @html {{brand}} Acme
replace @html https://old.cdn https://new.cdn
```

Semantics:

- **Post-cache, per-delivery.** Transforms run when the response is written to the
  client, *after* the cache. The cache always stores the **canonical origin body**,
  so transforms re-apply on every HIT and MISS (no double-application).
- **Size-bounded.** Only bodies within a 1 MiB cap are transformed; larger
  responses stream through **untransformed** (never fully buffered — the
  large-media fast path is preserved). `Range` (206), `HEAD`, and
  content-encoded (compressed) responses are skipped.
- A length-changing replace re-derives `Content-Length` and drops the upstream
  `ETag` (the delivered body no longer matches it).
- **Edge-native within the cap** (D75): the Cadish Edge worker applies the same
  within-cap literal substitution byte-identically (skipping Range/HEAD/encoded),
  passing an over-cap body through untransformed. See [`edge.md`](edge.md).

Intended for light "SSR-lite" rewrites (brand/string injection, base-URL
rewriting), not full server-side rendering.

#### `encode`

```
encode                          # enable with the default order (zstd br gzip)
encode zstd br gzip             # explicit preference order (any subset)
encode gzip                     # gzip only
```

On-the-fly **deliver-phase response-body compression**, negotiated on the client's
`Accept-Encoding`. A bare `encode` enables the default codec preference order
`zstd → br → gzip`, the default text-like `Content-Type` include list, and a
1 KiB minimum-size floor. Pass a codec subset to narrow/reorder the preference;
`brotli` is accepted as an alias for `br`. (The `encode { … }` block form for
tuning `types`/`min_length` is reserved for a later refinement; v1 is the line
form above.)

Codecs: **gzip** (stdlib), **brotli** (`github.com/andybalholm/brotli`), **zstd**
(`github.com/klauspost/compress/zstd`).

Negotiation:

- The client's `Accept-Encoding` is parsed per RFC 9110: `q=0` excludes a coding
  (including `identity;q=0` / `*;q=0`); a bare `*` accepts any unnamed coding.
- cadish picks the **first configured codec the client accepts**. If the client
  accepts none (or sends no `Accept-Encoding`, i.e. identity only), the response
  is served **uncompressed** — no change to the body or headers.

Compression engages only when **all** hold (otherwise the raw fast path is
untouched — the zero-extra-copy invariant):

- a codec was negotiated;
- the request is **not** `Range` and **not** `HEAD`;
- the origin response has **no** existing `Content-Encoding` (never double-encode);
- the response `Content-Type` is in the include list (text/HTML/CSS/JS/JSON/XML/
  SVG/WASM by default — already-compressed images, video, fonts and archives are
  skipped);
- the body is at or above the `min_length` floor (1 KiB) — tiny bodies aren't
  worth the CPU.

When it engages cadish sets `Content-Encoding`, appends `Vary: Accept-Encoding`,
**drops `Content-Length`** (the response goes out chunked since the compressed
size isn't known up front), and **weakens a strong `ETag`** to `W/"…"` (a
compressed representation is not byte-identical, so the strong validator would
mismatch). `encode` runs **after** `replace` — `replace` rewrites the plaintext,
then the result is compressed.

**Cache interaction — cached compressed variants.** The cache always stores the
**uncompressed (identity) origin representation** under the logical cache key; the
identity and any compressed forms share that **one** logical entry (the raw
`Accept-Encoding` header is never folded into the cache key, so cardinality cannot
explode). In addition, on the **first HIT** that needs a given content-coding,
cadish compresses the cached body once and stores that compressed form as a
**precompressed variant** keyed by the negotiated codec (`gzip` / `br` / `zstd`).
Every later HIT for the same coding then serves the **stored compressed bytes
directly — no re-compression**, eliminating the per-HIT CPU cost for hot text
assets. The variant set is bounded to at most one blob per supported codec per
entry (≤3), so the cache footprint grows by a small, fixed multiplier — never
per-client.

A variant is only cached when the cached representation carries a **validator**
(an `ETag` and/or `Last-Modified`): the variant records that validator and is
served only while it still matches the current identity, so a re-fetched, changed
body under the same key never serves a stale precompressed copy (the stale variant
is detected and replaced). A representation with **no** validator is compressed
**per HIT** (the prior v1 behavior) rather than risk a stale variant. The
precompressed variant is also bypassed for the `replace`-transform path and for an
oversized body (larger than the in-memory transform cap), both of which compress on
the fly so the large-media / zero-extra-copy fast path is never made to buffer.

A negotiated-identity client (or one that accepts none of the codings) is always
served the uncompressed body; a `Range` or `HEAD` request never engages
compression or a variant. A large non-compressible body (e.g. an image) — being
outside the include list — streams through verbatim and is **never buffered**,
preserving the large-media fast path.

---

## Normalizers

`{sticky}`, `{device}`, `{geo}` reduce a high-cardinality input to a small enum
so `cache_key` can vary on the enum, not the raw value (the VARY-cardinality
optimization). All are live: **`{sticky}`** (cookie-or-IP, wired into
`upstream sticky`), **`{device}`** (UA → `desktop`/`mobile`/`tablet`/`bot`, via
`device_detect`), and **`{geo}`** (client IP / CDN header → country code, via
`geo`) plus its granularities **`{geo.continent}`** (derived in-tree from the
country) and **`{geo.region}`** (US state / subdivision from an upstream CDN
header). All geo tokens require an explicit `geo` source (`{geo.region}` also a
`region_header`). The `geo` matcher (`geo country|continent|region …`) tests the
same classes and feeds `classify` for geo→business mapping (EU→EUR, regulated-state
flags).

---

## Runtime tuning — garbage collector (GC)

cadish is a long-lived caching proxy that intentionally holds a large RAM cache,
so on startup the `cadish run` path applies a GC posture tuned for that shape
(Go's defaults target short-lived, small-heap programs). This is **startup-only
configuration — it never touches the request datapath** — and it trades resident
heap for fewer GC cycles, which tightens the p99 latency tail and lifts
throughput on hot HITs.

| Lever | cadish default (run path) | Go default | Why |
|---|---|---|---|
| `GOGC` (`runtime/debug.SetGCPercent`) | `200` | `100` | Let the heap grow to 3× the live set before collecting (vs 2×). Fewer collections → fewer/shorter GC pauses → tighter p99. |
| `GOMEMLIMIT` (`runtime/debug.SetMemoryLimit`) | `1.5 × (total RAM cache budget) + 512 MiB`, floored at 1 GiB | none (no limit) | A **soft** backstop set comfortably above the cache so the cache fits without forcing a GC death-spiral, while still capping total heap so `GOGC=200` cannot run away under a burst and OOM the box. |

**Precedence — the operator always wins.** If you export `GOGC` and/or
`GOMEMLIMIT` in the environment, the Go runtime applies your value at process
start and cadish does **not** override that lever — it only fills in its default
for a lever you left **unset**. Detection is by *presence* (the variable being
exported at all), not value, so an explicit empty value still counts as "set"
and is respected. Set both to keep Go's stock posture, or tune either one for
your box:

```sh
# Operator overrides cadish's GC defaults (both respected verbatim):
GOGC=100 GOMEMLIMIT=12GiB cadish run -config Cadishfile

# Cap heap only; keep cadish's GOGC=200:
GOMEMLIMIT=24GiB cadish run
```

The `GOMEMLIMIT` default is only applied when the **total configured RAM cache
budget** (the sum of every site's `cache { ram … }`) yields a soft limit of at
least 1 GiB; for a tiny or unknown cache cadish leaves `GOMEMLIMIT` unset (Go's
"no limit"), because a too-tight soft limit harms more than it helps. The applied
values are logged at startup (`cadish gc: applied default …`).

---

## Parsed but not yet wired in v1

Forward-compatibility corner: directives `cadish check` accepts whose runtime
behavior carries a caveat worth calling out. The big v1 gaps that used to live here
(non-200 negative caching, regex purge BANs) have since **shipped** and are kept in
the table only to record that they are now wired and how they behave; the remaining
row is a real "needs more config to take effect" caveat.

| Feature | Status | Effect today |
|---|---|---|
| `cache_ttl status <non-200> ttl …` | **wired (safe-default scoped)** | `404`/`410` negative caching is wired under any selector (incl. `default`). A `4xx`/`5xx` error is cached **only** when named by an explicit positive `status <code>` selector — a broad `default`/`@scope`/`status not` selector will NOT store it (so `cache_ttl default` never caches an outage). The stored failing response is bodyless. (`hit_for_miss` **is** honored for any status.) |
| `cache_key {geo}`/`{geo.continent}`/`{geo.region}` without a `geo` source | keys on `""` | Needs a `geo { source … }` block (`{geo.region}` also a `region_header`); `cadish check` warns otherwise. |
| `purge … regex EXPR` / `regex-path EXPR` | **wired** | An authorized regex purge registers a cache-wide **lazy mass-invalidation** (D27): every cached key matching `EXPR` that predates the invalidation is dropped on its next lookup (re-fetched). `regex` matches the whole key (`host path …`); `regex-path` anchors against the PATH token only (e.g. `^/foo`). The response carries `X-Purge-Count: N` (`0` = matched nothing indexed). True blob eviction is still deferred — an invalidated object's blob lingers until LRU-evicted, but it is never served (the freshness marker is superseded, so the next lookup is a MISS + re-fetch). Request-sourced patterns stay bounded (D12). |

Behavioral edges worth knowing:

- An origin **3xx** (redirect) is not followed — cadish never dials the redirect
  target (an SSRF guard) — but it **is passed through** to the client as a streaming
  3xx carrying the origin's real status and `Location`, so the browser follows it
  itself (never cached, since only 200/206 are stored). Only **200/206** are cached;
  **404/410** are negative-cached; any other **4xx/5xx** falls through the origin
  chain (and surfaces as **502** when no member answers).
- `path_regex` matches the path only (no query string); host matching is on the
  normalized (lower-cased, port-stripped) host.

For the request lifecycle these map onto, see [pipeline.md](pipeline.md).
