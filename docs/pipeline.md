# `internal/pipeline` — the request-evaluation engine

`pipeline` compiles a parsed Cadishfile **site** into an executable `*Pipeline`
and turns each request into structured **decisions** that the server layer (M5b)
applies to `net/http`, `internal/cache`, and `internal/origin`.

It implements the request-lifecycle contract. It is **pure**:
no listeners, no network I/O, no goroutines. `Compile` validates once; the per-
request `Eval*` methods are allocation-light and **safe for concurrent use** (a
`*Pipeline` is immutable after `Compile`).

> The one place the package touches the filesystem is the optional
> `FileImportResolver` helper used to splice `import` fragments — deliberately
> separate from `Compile`, which never does I/O.

---

## Lifecycle → decision split

The request lifecycle is split into three evaluation calls because `cache_ttl`
selectors can branch on the **response status**, which is unknown at RECV time:

| Phase(s) | Method | Reads | Produces |
|---|---|---|---|
| RECV + KEY | `EvalRequest(req)` | request | `respond` / `redirect` / `purge` / `route` / `pass` / request `header` / `rewrite` / `cache_key` |
| ORIGIN/store | `EvalResponse(req, status, respHeader)` | request + status + origin response headers | `cache_ttl` / `storage` (first-match-wins) |
| DELIVER | `EvalDeliver(req, respHeader, cacheStatus)` | request + response headers + cache outcome | response `header` / `strip_cookies` / `cors` / `replace` / `encode` / cache-status |

`EvalResponse` and `EvalDeliver` take the origin/response `http.Header` (which may
be nil) so response-phase matchers (`content_type`, `set_cookie`) resolve against
the real response. A fourth call, `EvalOnError(req, status)`, resolves the
origin-error-phase synthetic for a `respond on_error` rule (gated by `HasOnError`).

The routed upstream (from `route`) is recomputed deterministically in each phase
from the request, so all three phases can evaluate `upstream` matchers without
threading state between calls.

---

## Decision API (what M5b codes against)

```go
func Compile(site *cadishfile.Site) (*Pipeline, error)

func (p *Pipeline) EvalRequest(req *Request) RequestDecision
func (p *Pipeline) EvalResponse(req *Request, status int, respHeader http.Header) ResponseDecision
func (p *Pipeline) EvalDeliver(req *Request, respHeader http.Header, cacheStatus CacheStatus) DeliverDecision
func (p *Pipeline) HasOnError() bool
func (p *Pipeline) EvalOnError(req *Request, status int) *OnError
func (p *Pipeline) Addresses() []string

// Import splicing (do this BEFORE Compile; a leftover `import` is a compile error)
func SpliceImports(site *cadishfile.Site, resolve func(path string) ([]cadishfile.Node, error)) (*cadishfile.Site, error)
func FileImportResolver(baseDir string) func(string) ([]cadishfile.Node, error)
```

### Request (decoupled from net/http)

```go
type Request struct {
	Method       string      // "" => GET; matched case-insensitively
	Host         string      // :port stripped, lower-cased for matching/keys
	Path         string      // percent-decoded path
	Query        url.Values  // rendered canonically (sorted) for url/query key tokens
	Header       http.Header // may be nil
	ClientIP     string      // {sticky} fallback when no sticky cookie
	RealClientIP netip.Addr  // trusted-proxy-resolved real client IP for the `ip` ACL (security gate)
	Device       string      // {device} class (server UA pre-pass); "" when unused
	Geo          string      // {geo} country class (server geo pre-pass); "" when unused
	GeoContinent string      // {geo.continent} class (derived from country); "" when unused
	GeoRegion    string      // {geo.region} subdivision (upstream CDN header); "" when unused
}
```

`Device`, `Geo`, `GeoContinent`, and `GeoRegion` are populated by the server's
pre-passes (UA classification / geo source) before `EvalRequest`, gated on whether
the compiled site actually uses them (`UsesDeviceToken` / `UsesGeoToken`), so a site
that never varies on device or geo pays nothing. `RealClientIP` is set before the
security gate (`EvalSecurity`) and is the zero (invalid) `netip.Addr` on sites with
no security rules — an `ip` matcher against an invalid address matches nothing.

### Decision structs

```go
type RequestDecision struct {
	Pass         bool        // bypass cache (no store), stream from origin
	Synthetic    *Synthetic  // canned response (respond); short-circuits everything
	Redirect     *Redirect   // computed 3xx (redirect); also short-circuits in RECV
	Upstream     string      // routed upstream/cluster name ("" = site default)
	CacheKey     string      // composed key (default: method host path)
	Purge        *PurgeDecision
	ReqHeaderOps []HeaderOp        // request-header edits (header directives before KEY)
	Rewrite      *RewriteDecision  // origin-only path/query rewrite; NEVER feeds the cache key
}
type Synthetic       struct { Status int; Body string }
type Redirect        struct { Status int; Location string }       // 301/302/307/308 + resolved Location
type RewriteDecision struct { Path, RawQuery string }             // rewritten origin request line
type PurgeDecision   struct { Authorized bool; Regex string }     // non-nil only when guard matched
type OnError         struct { Status int; Body []byte; ContentType string } // from EvalOnError

type ResponseDecision struct {
	TTL        time.Duration // fresh lifetime (0 if not positively cacheable)
	Grace      time.Duration // stale-while-revalidate window
	MaxStale   time.Duration // serve-stale-on-origin-failure window after grace (D60); HIT-STALE-ERROR
	HitForMiss time.Duration // >0 => cache the "don't cache" decision; body not stored
	StoreTier  string        // "ram" | "disk" | "" (server default routing)
	Cacheable  bool          // a positive cache_ttl rule matched (TTL set)
}

type CacheStatus int // zero = CacheStatusUnknown (String: "MISS")
// CacheStatusUnknown/Hit/Miss/HitStale/HitStaleError -> "MISS"/HIT/MISS/HIT-STALE/HIT-STALE-ERROR

type DeliverDecision struct {
	RespHeaderOps     []HeaderOp     // response-header edits, in order
	StripCookies      bool           // a strip_cookies rule matched
	CORS              *CORSDecision  // a cors directive applies
	CacheStatusHeader string         // header name targeted by `header +cache_status`
	CacheKeyHeader    string         // header name targeted by `header +cache_key` (server fills the value)
	CacheKeyRaw       bool           // `raw` modifier: emit the raw key instead of its 12-hex hash
	Transforms        []Replacement  // ordered `replace OLD NEW` body substitutions (POST-cache)
	Encode            *EncodeDecision // site-wide `encode` compression policy (POST-cache)
}

type HeaderOp struct { Op HeaderOpKind; Name string; Value string; ValueTpl bool } // OpSet/OpAppend/OpRemove/OpCacheStatus/OpCacheKey
type Replacement   struct { Old, New string }
type EncodeDecision struct { Codecs, Types []string; MinLength int }
type CORSDecision  struct { AllowAllOrigins bool; Origins, Methods, Headers []string }
```

**Header ops to apply (uniform):** apply `RespHeaderOps` / `ReqHeaderOps` in order:
`OpSet` replaces, `OpAppend` adds, `OpRemove` deletes. The `header +cache_status
NAME` special is already **materialized** into an `OpSet` writing the
`HIT`/`MISS`/`HIT-STALE`/`HIT-STALE-ERROR` token into `NAME` (and `CacheStatusHeader`
is also set, for servers that want to special-case it). `OpCacheStatus` never appears
in a `DeliverDecision`. The `header +cache_key NAME [raw]` debug special is likewise
**not** materialized into an op — the cache key is the server-held RECV key, not in the
deliver-phase match context — so it surfaces as `CacheKeyHeader`/`CacheKeyRaw` and the
server fills the value (the 12-hex hash, or the raw key with `raw`) from the key it
holds. A `header NAME {http.X}` / `{client_ip}` / `{geo*}` value carrying a template
placeholder (`ValueTpl`) is resolved here, so a surfaced `HeaderOp` always carries a
fully-resolved literal `Value` and the server never sees the template.

**Terminal / ordering in `EvalRequest`:** a matching `respond` returns immediately
with `Synthetic` set, then a matching `redirect` returns with `Redirect` set — both
short-circuit cache and origin (respond is checked first so an exact-path respond can
pre-empt a broader redirect). Otherwise `Purge`, `Pass`, request headers, `Rewrite`,
and `CacheKey` are all populated. `Rewrite` changes only the bytes dialed upstream —
it NEVER feeds `CacheKey`, which is always built from the unmodified client request.

---

## Matcher engine

Compiled once at `Compile`. Types (from the design catalog):

| Type | Match | Notes |
|---|---|---|
| `path` | path glob | `*` = any run of chars; `/a/*` = prefix. Compiled into an **exact set + prefix trie + glob list** — never N regexes. |
| `path_regex` | RE2 on path | compiled once; multi-token (continuation-split) regexes are concatenated |
| `host` | host equals / `*.` wildcard | case-insensitive, port-stripped |
| `host_regex` | RE2 on host | |
| `header` | `NAME` present, or `NAME V...` equals (V's OR'd) | value compare is constant-time (purge-token guard) |
| `method` | method ∈ set | case-insensitive |
| `upstream` | routed upstream ∈ set | depends on `route` |
| `cookie` | named cookie present / `NAME V…` equals / `NAME*` prefix glob | value compare constant-time; glob form is presence-only |
| `cookie_json` / `header_json` | dotted field inside a JSON cookie/header value | `NAME PATH [VALUE…]`; fail-closed on malformed/missing |
| `query_present` | ANY named query param present | OR set with `*` globs; presence-only |
| `ip` | real client IP ∈ IP/CIDR set | trusted-proxy-resolved; the WAF ACL primitive |
| `geo` | resolved geo class at a granularity | `geo country\|continent\|region VALUE…` (OR) |
| `content_type` | **response** Content-Type substring (OR) | response-phase only |
| `set_cookie` | a **response** Set-Cookie present / of a named cookie (OR) | response-phase only |
| `classify` | a `classify` token equals/≠ a value | `{TOKEN}==VALUE` / `{TOKEN}!=VALUE` |

`content_type` and `set_cookie` are **response-phase** matchers: they need the origin
response, so they may scope only `cache_ttl` / `storage` / `header` / `strip_cookies` /
`cors` — Compile rejects scoping a request-phase directive (`pass`, `purge`, `route`, a
pre-KEY `header`) with one.

**Combination:** args **within** a matcher are **OR**. A directive referencing
**multiple** `@matchers` (e.g. `pass @a @b`) is **OR**. AND across matcher types is
**not supported in v1** and is rejected with a clear error (`@a and @b` →
"AND across matchers is not supported in v1").

Within one phase, a matcher referenced by several directives is evaluated **once**
(memoized per request).

---

## `cache_key` composition

Tokens: `method`, `host`, `path`, `url` (path + sorted query), `query` (sorted),
`query_allow NAME…` (only the listed params, globs ok, canonicalized), `header:NAME`,
the normalizers `{sticky}` / `{device}` / `{geo}` / `{geo.continent}` / `{geo.region}`,
`{tenant}`, a user-defined `normalize` bucket `{NAME}`, and a `classify` derived token
`{NAME}`. Any other bare word is a literal. Default when the directive is omitted:
**`method host path`**. Tokens are joined with the ASCII unit separator (`0x1f`) so
distinct token lists never collide.

`cache_key` is **first-match-wins** like `cache_ttl`: an optional leading selector
(`@matcher…`, OR'd, or the keyword `default`) picks **one** recipe per request via
`selectKeyTokens` (the first `keyRule` whose selector matches). Selectors are
request-phase only. A single unscoped `cache_key` behaves exactly as before; once any
scoped line is present a `default`/unscoped catch-all is required, or compilation fails
and `cadish check` reports `cache-key-no-default`.

- `{sticky}` = value of the upstream's sticky cookie (auto-detected from
  `upstream … sticky by cookie NAME …`) else `ClientIP`.
- `{device}` = `req.Device`, `{geo}` / `{geo.continent}` / `{geo.region}` = the resolved
  geo fields. These are filled by the server's UA-classification / geo pre-pass before
  `EvalRequest` (the pipeline reads them off `Request`); `""` when the corresponding
  pre-pass did not run.
- `{NAME}` resolves against the site's `normalize NAME { … }` (pure, request-derived)
  or `classify {NAME} { … }` (pure, resolved through the request's match context); an
  unknown `{NAME}` is a compile error. `{tenant}` is the site's tenant — a per-site
  constant or a request-derived `tenant { … }` resolver.

---

## Directive → phase mapping

`respond` `redirect` `purge` `route` `pass` `rewrite` are always RECV, as are the
server-only security-gate directives `allow` `deny` `block` `rate_limit`
(evaluated first, in `EvalSecurity`; never projected to the edge). `monitor` is
the parse-once toggle that flips that gate to log-only, so it is Setup, not RECV. `cache_key` is KEY.
`cache_ttl` `storage` are ORIGIN. `strip_cookies` `cors` `replace` `encode` are
DELIVER. A `header` directive is **request-phase if it appears before the KEY boundary**
(the first of `cache_key`, `cache_ttl`, `storage`, `strip_cookies`, `cors`, `replace`,
`encode`) and **response-phase otherwise** — matching the design's "before KEY ⇒
request; in DELIVER ⇒ response" rule.

`cache_ttl` and `storage` are **first-match-wins**; selectors are `status CODE…`,
`status not CODE…`, `@matcher`, `default`. A `cache_ttl` action is `ttl DUR [grace DUR]
[max_stale DUR]`, `from_header HEADER [grace DUR] [max_stale DUR]`, or `hit_for_miss
DUR`. `pass` is effectively OR (first match sets `Pass`). Only one `cors` and one
`encode` per site.

Setup directives (`tls`, `cache`, `upstream`, `cluster`, `origin`, `lb`, `sticky`,
`device_detect`, `geo`, `normalize`, `tenant`, `classify`) are accepted
and ignored in Pass 2 — they belong to the cache/LB/server layers or are compiled in
Pass 1/1b — except that `upstream … sticky by cookie NAME` is read to wire `{sticky}`,
and declared upstream/cluster names validate `route` targets.

---

## Errors

`Compile` returns `*CompileError{Pos, Msg}` (rendered `file:line:col: msg`) for:
unknown matcher type, bad regex, malformed `cache_ttl` selector/action, bad
duration (supports `s/m/h/d/w`, e.g. `365d`), bad/duplicate matcher reference,
unknown header op or missing value, unknown directive, `route` to an undeclared
upstream, AND-across-matchers, and a leftover `import` (splice first).

---

## Usage sketch (M5b)

```go
site, _ := pipeline.SpliceImports(file.Sites[0], pipeline.FileImportResolver(dir))
p, err := pipeline.Compile(site)            // once, at config load
// ... per request:
rd := p.EvalRequest(req)
if rd.Synthetic != nil { /* write canned response */ }
if rd.Redirect != nil  { /* write status + Location */ }
if rd.Purge != nil     { /* invalidate */ }
// LOOKUP(rd.CacheKey) unless rd.Pass ...
sd := p.EvalResponse(req, originStatus, respHeader) // TTL/Grace/MaxStale/HitForMiss/StoreTier
dd := p.EvalDeliver(req, respHeader, cacheStatus)   // header ops, strip_cookies, cors, replace, encode
```
