# Cadish Edge — `cadish edge` (build / deploy / enable / disable)

> **Status: runnable end-to-end.** **Cadish Edge** runs the *same Cadishfile* as an
> additive caching tier on Cloudflare Workers. Shipped: the Go **IR projector**
> (`cadish edge build`), the generic **JS worker runtime** (a faithful IR interpreter
> + cache tiers + geo + origin), the **worker bundle** (`-bundle`), the **`edge {}`
> block** (deploy identity + cache-tier policy), and the **Cloudflare deploy plane**
> (`deploy`/`enable`/`disable`). A cross-runtime conformance suite proves the Go
> pipeline and the JS interpreter decide identically.

## The idea: one Cadishfile, two runtimes

Cadish Edge runs your existing Cadishfile config close to the client, in front of a
Cadish server. The Go `cadish` binary is the single brain: it parses, compiles, and
**projects** the config into a portable JSON **IR** that a small, generic JavaScript
worker will interpret. The worker never sees the Cadishfile — only the IR.

The worker is best-effort and additive: if Cloudflare is down or disabled, the Cadish
server behind keeps doing everything. Anything the edge cannot faithfully execute is
**delegated** — the worker passes the request to the Cadish server behind, which handles
it. The edge never serves something wrong.

## `cadish edge build`

```
cadish edge build [-config Cadishfile] [-o FILE] [-bundle FILE] [-strict] [-json]
```

`build` compiles your Cadishfile (resolving `import`s, `{$ENV}` substitution and
`group { … }` expansion, exactly like `cadish run`), **projects** each site into an
`EdgeIR`, writes the IR JSON, and prints a **coverage report** (what is edge-native vs
delegated). It uploads nothing.

| Flag | Effect |
|---|---|
| `-config PATH` | Cadishfile to project (default `Cadishfile`). |
| `-o FILE` | Write the IR JSON to `FILE`. `-o -` writes to **stdout**. Default: one `build/<host>.edgeir.json` per site (the gitignored `build/` dir — `rm -rf build/` to clean). |
| `-bundle FILE` | Also assemble the worker bundle (generic runtime + baked IR) and write it to `FILE`. `-bundle -` writes to **stdout**; `-bundle auto` writes one `<host>.worker.js` per site. Omitted: no bundle (IR only). |
| `-strict` | Exit non-zero if **anything** is delegated (a coverage regression — the CI gate, the edge equivalent of `cadish check -strict`), if the site configures a **security gate** (`allow`/`deny`/`block`/`rate_limit`) the edge cannot enforce, or if a **literal/env-expanded value** would be exposed in the public worker bundle — a matcher value, a `header` op value, a `replace`/`respond on_error`/`redirect` value, or a cache_key `literal:` token. See below. |
| `-json` | Print the coverage report as JSON instead of text. |

The IR JSON goes to the file/stdout you choose; the **coverage report goes to stderr**, so
`cadish edge build -o - > site.edgeir.json` keeps the pipe clean.

### Example

```console
$ cadish edge build -config storefront.cadish -o storefront.edgeir.json
edge coverage — example.com,*.example.com (IR v6)
  edge-native: 21 directive(s)
  delegated:   1 directive(s)
    - purge x1 → pass: purge auth guards compare a SECRET token (the purge token, D12) that must never ship to a public edge worker; delegated to the Cadish server behind
```

`-strict` would exit non-zero here, because the config delegates one directive.

### `cadish edge build` fails LOUD when a selecting directive can't be honored

A **selecting** directive — `pass`, `route`, `redirect`, a scoped/`classify`-token `cache_key`,
`cache_ttl`, `storage`, an `edge {}` tier policy, or `upgrade` — that is scoped by a matcher the
edge **cannot evaluate** (a server-only Gateway/lb matcher, the **`ip`** ACL, or an untranslatable
RE2 regex such as `(?U)` / a scoped `(?i:…)` group) cannot be reproduced at the edge. Rather than
silently mis-decide, the projector **fails open**: it passes ALL traffic for that site (the edge
caches nothing) and the precise directive runs on the Cadish server behind.

Because that is a major, **silent** capability change for a config that otherwise "builds fine",
`cadish edge build` exits **non-zero EVEN WITHOUT `-strict`** in this case (the coverage report
prints a `forced-pass:` line and a `…-FAIL-OPEN` warning naming the directive). Keep that directive
on the Cadish server behind, or rewrite it so the edge can express it. In particular, an
**`ip`-scoped** `pass`/`route`/`cache_key` is server-only — the edge has no real-client-IP concept.

### Secrets never reach the edge

The IR is **baked into a public Cloudflare Worker bundle**, so it must carry no
secrets. Two structural guarantees:

- **`purge` is always delegated.** A `purge when header X-Purge-Token {$PURGE_TOKEN}`
  guard compares a secret token; after `{$ENV}` substitution that literal lives in the
  compiled matcher. A public worker must never hold it (nor could it do the constant-time
  compare safely), so **every** `purge` — single-key and regex BAN — is delegated to the
  Cadish server behind, which holds the secret. The guard matcher's value is **redacted**
  from the IR (its name/kind survive for the report; the token does not).
- **No origin URL, sign key, ACME email or credential is reachable.** The projector sees
  only the compiled `*pipeline.Pipeline`, which holds upstream *names* — not URLs, not
  `sign cloudfront` keys, not TLS/ACME data. The worker resolves the concrete upstream
  URL from its own binding at deploy time.

`cadish edge build` also prints a **warning** for any `header`/`cookie`/`cookie_json`/
`header_json` matcher whose literal *value* still ships in the IR (e.g.
`@ajax header X-Requested-With XMLHttpRequest`), so you can confirm none is a secret. These
warnings are printed in non-strict mode, but **under `-strict` they FAIL the build**
(non-zero exit) so a CI pipeline catches a secret (e.g. `@auth header X-Internal-Auth "s3cr3t"`)
baked into the public bundle. The build does **not** redact the value automatically — that
could change matching semantics — it fails so a human decides (remove the literal, or move
it to an env ref / let Cloudflare's layer handle the check).

The same secret-exposure gate also scans the other IR string fields whose source could
be an **unquoted `{$VAR}` env placeholder** — `header` op *values* (request and response),
`replace` transform OLD/NEW, `respond on_error` bodies, `redirect` targets, and cache_key
`literal:` tokens. An unquoted `{$VAR}` is env-expanded to its literal value **before**
projection (so the secret would be baked into the public bundle), and `-strict` now trips
on it in any of those positions — not just in matcher values. A **quoted** `"{$VAR}"` is
*not* expanded (it stays the literal text `{$VAR}` and ships no secret), so quoting an
origin-auth header — `header X-Internal-Auth "{$HDR_SECRET}"` — keeps it server-side and
strict-clean; the idiomatic *unquoted* form fails the build so the secret never ships.

### The security gate is NOT enforced at the edge

**`allow` / `deny` / `block` / `rate_limit` are SERVER-ONLY.** They are evaluated by the
Cadish server (in the RECV phase, before cache or origin) and are **never projected into the
worker IR** — the worker has no security-gate step. So if you enable the edge for a site that
configures a security gate, those rules become a **no-op for all edge-served traffic**: an
operator's `deny @admin` would let admin paths straight through once the edge is live.

Because this is a silent ACL bypass, `cadish edge build`:

- **emits a loud warning** naming the site's `allow`/`deny`/`block`/`rate_limit` rules as
  NOT enforced at the edge, and
- **fails `-strict`** (non-zero exit) while a security gate is present — the gate is recorded
  as a delegated `security` directive in the IR's `delegate[]`.

Enforce these rules with **Cloudflare's own security layer** (WAF / firewall rules / rate
limiting) in front of the worker. Cloudflare provides the edge's security tier; Cadish does
not duplicate it at the edge.

## What is edge-native vs delegated

The **projector is the single decision point** for this (neither the compiler nor the
worker decides). Anything not edge-expressible is recorded in the IR's `delegate[]` with a
reason — never silently dropped — and surfaced in the coverage report.

| Edge-native | Delegated to the Cadish server behind |
|---|---|
| `pass` / `route` | `replace` on a **huge / streaming body** — only the OVER-CAP case (a body larger than the worker's transform cap) streams through to the server; a within-cap `replace` is edge-native (next row) |
| `replace` — **size-bounded** body transforms (D75): the worker applies the literal substitution post-cache, on delivery, to a within-cap body (skipping Range/HEAD/already-encoded), byte-identically to the server. A body OVER the cap passes through untransformed (server-only, below) | `purge … regex` — regex **BAN** (cache-wide eviction) |
| `respond on_error` — the **outage synthetic** (D76): on an origin hard-failure with no servable cached object, the worker serves the configured status+body+content_type instead of a bare 502 | |
| `cache_key` — **all tokens AND scoped, first-match-wins recipes** (`cache_key @scope …`, D65/D70): `{device}`/`{geo}`/`{geo.continent}`/`{geo.region}`/`{tenant}`/`{sticky}`, `normalize`, `classify`, `query_allow`, `header:` | |
| `device_detect` — the `{device}` User-Agent classifier runs **natively** at the edge (D70): the worker classifies from the request's `User-Agent` against the projected ruleset, no `X-Cadish-Device` header needed | |
| `cache_ttl` (ttl / grace / hit_for_miss / **`max_stale`**, D70 — the edge bounds stale-on-error to the configured window) | |
| `storage` (tier intent) | |
| `respond`, `redirect` (regex + scoped + map) | |
| `strip_cookies`, `cors` | |
| `header` (set/append/remove, `+cache_status`, `+cache_key`, dynamic `{…}` values) | `purge` — **all** forms (single-key + regex BAN): the guard compares a secret token a public edge worker must not hold (D34) |
| matchers: `path`/`path_regex`/`host`/`host_regex`/`header`/`header_regex`/`method`/`upstream`/`cookie`/`cookie_json`/`header_json`/`set_cookie`/`content_type`/`geo`/`query_present`/`classify` | `allow` / `deny` / `block` / `rate_limit` — the **security gate** is SERVER-ONLY (see "What the edge intentionally does NOT do" below) |

Every `purge` is delegated — its guard compares a secret token that must never ship to
a public edge worker (see "Secrets never reach the edge" above, and D34). A site's
**security gate** (`allow`/`deny`/`block`/`rate_limit`) is likewise delegated: it is never
enforced at the edge, and `-strict` fails while one is present.

### Scoped `cache_key` at the edge (D70)

A scoped, first-match-wins `cache_key` (D65) is **edge-native**: the projector emits the
**full ordered recipe list** with each recipe's request-phase selector, and the worker
selects the matching recipe exactly like the Go server (`pipeline.selectKeyTokens`). So a
multi-backend site that keys an SSR request differently from a PHP request keys
**byte-identically** at the edge — the conformance suite proves the two runtimes compute
the same key (the `+cache_key` debug hash is the assertion vehicle). Earlier edge versions
delegated a scoped site to the server; that delegation is gone.

### Edge device classification (D70)

`{device}` no longer needs a server pre-pass or an `X-Cadish-Device` header. The worker
ports the Go classifier (`internal/classify`) — the ordered `device_detect` substring
ruleset (mobile/tablet/bot/desktop, with the `ua_excludes` fold rules and `fold` remaps)
— and classifies the request's own `User-Agent` natively. The same User-Agent yields the
same `{device}` bucket (hence the same cache key) on the edge and on the server; the
conformance suite asserts it across representative UAs. The edge deliberately ignores any
client-supplied `X-Cadish-Device` header (attacker-controllable at the first hop) and does
not trust Cloudflare's own device signal — it runs the Cadishfile's own ruleset so the two
runtimes stay in lockstep.

### `max_stale` bounds edge stale-on-error (D70)

`cache_ttl … max_stale DUR` (D60) is projected into the edge TTL IR. On an origin failure
with no servable fresh/grace copy, the edge salvages a past-grace stored copy **only while
it is within `ttl + grace + max_stale`** — it no longer serves an unboundedly-old copy.
With no `max_stale` configured, the edge does not serve past `grace` on error at all (it
returns 502), matching the server's bounded behavior.

### Size-bounded `replace` at the edge (D75)

A `replace OLD NEW` body transform is **edge-native within a size cap**. The worker projects
the ordered rule list (`response.transforms`) plus the cap (`response.transformMaxBytes`,
1 MiB — the same `maxTransformBody` the server uses) and applies the **literal** substitution
(`String.replaceAll`, every occurrence, in rule order) on the **delivered** body, **after**
cache store, mirroring the server's deliver-phase V2e gating exactly:

- applied per delivery on both HIT and MISS (the cache always stores the canonical origin
  body — a transform never poisons the cache);
- **skipped** for `Range` requests, `HEAD`, and an **already-encoded** body (a partial/empty
  or compressed body can't be safely substituted);
- a transformed body drops the stored `ETag` (it no longer describes the served bytes), same
  as the server.

A body **larger than the cap streams through UNTRANSFORMED** — identical to the server's
large-object behavior, and the same outcome an operator gets for huge/streaming media. So
only the **over-cap / streaming** `replace` remains server-only (see the non-goals table
below); a within-cap `replace` (the common HTML/JSON page case) is fully edge-native and
conformance-proven byte-identical Go↔JS (incl. the over-cap pass-through assertion).

### `respond on_error` outage page at the edge (D76)

`respond on_error [@scope] STATUS BODY [content_type T]` (D57) is **edge-native** for the
outage path. The worker projects the ordered rule list (`response.onError`: scope + status +
body + content_type). On an origin **hard-failure** with **no servable cached object** (no
fresh/grace copy and no stale copy within the `max_stale` window), the worker serves the
**first** matching synthetic instead of a bare 502 — mirroring the server's precedence:

```
serve-stale-within-grace/max_stale  >  cacheable negative cache  >  respond on_error  >  bare status / 502
```

An origin **hard-failure** at the edge is **two** shapes, both of which run this same chain
(parity with the Go server's `handleOriginError`):

- a **thrown** transport failure (the upstream `fetch` rejects — connection refused, DNS,
  timeout): no status, so the bare fallback is **502**.
- an origin that **RETURNS** any non-success status **except `404`/`410`** — `5xx` (the
  common flapping/maintenance shape) **and** a `4xx` such as `403`/`429`/`405`/`401`
  (`fetch` resolves with the Response). The Go origin maps every such status to a
  `*StatusError` (`negativeStatus` is *only* `404`/`410`), so the worker treats it as a
  failure and runs the chain rather than forwarding the raw status blind; the bare fallback
  **forwards the returned status** (e.g. a `503` or a `403`), matching the server's
  `writeStatus(code)`.

A returned **`404`/`410`** is *not* this hard-failure path: it is a **negative** response the
worker serves directly (after a `max_stale` salvage check) — negatively cached when
`cache_ttl status …` opts in, else served as the bare `404`. It never triggers `on_error`,
exactly as on the server.

So a real (if stale) copy within its window still **wins** over the synthetic (an old page
beats a maintenance page), a cacheable negative status is stored+served, and a request
matching no `on_error` scope falls back to the bare status (or 502 for a thrown failure). The
synthetic body is operator config (never reflected request data) and is not cached — it is an
availability stopgap, identical to the server's `writeOnError`.

## The IR contract

The `EdgeIR` is a **versioned, serializable** projection of the compiled pipeline — an
**explicit contract** (not raw internal structs). The JS interpreter mirrors these field
names 1:1, so they are stable. `irVersion` is `6` (D70 added `key.recipes`, `device`, and
`response.ttl[].maxStale`; D74 added `site.redirectHosts` + `site.canonicalHost`; D75/D76
added `response.transforms` + `response.transformMaxBytes` and `response.onError`; v5 added
`response.ttl[].stripHeaders`; v6 (D101) added `cacheCredentialed`); the runtime refuses a
version it does not understand.

Top-level shape:

```jsonc
{
  "irVersion": 6,
  "site":     { "hosts": ["example.com", "*.example.com"] },
  "upstream": { "to": "web" },            // default upstream name ("" if none)

  "matchers": {                           // defined once, referenced by id
    "ajax":     { "kind": "header", "name": "X-Requested-With", "values": ["XMLHttpRequest"] },
    "nocache":  { "kind": "path",   "patterns": ["/panel/*", "*sitemap*"] },
    "listings": { "kind": "path_regex", "regex": "^/catalog/" }
  },
  "classifiers": {                        // classify {TOKEN} tables
    "age": { "rows": [ { "conj": ["verified"], "value": "ok" },
                       { "conj": ["adult"],    "value": "gate" } ],
             "default": "open" }
  },
  "normalizers": { /* normalize NAME — {source, sourceName, map, default} */ },
  "tenant":      { /* request-derived tenant resolver, when present */ },
  "device": {                             // {device} UA classifier (only when the key uses {device})
    "rules": [ { "class": "bot", "substrings": ["bot", "crawler"] },
               { "class": "tablet", "substrings": ["android"], "exclude": ["mobile"] } ],
    "default": "desktop",
    "folds": [ { "from": "tablet", "into": "desktop" } ]   // omitted when none
  },

  "recv": {                               // RECV phase, in source order
    "pass":      [ { "names": ["ajax"] }, { "inline": [ { "kind": "method", "methods": ["POST"] } ] } ],
    "respond":   [ { "path": "/health-check", "status": 200, "body": "OK" } ],
    "redirect":  [ { "regex": "^/old", "status": 301, "target": "https://{host}/new" } ],
    "purge":     [],   // always empty: every purge is delegated (the guard holds a secret), see delegate[]
    "route":     [ { "scope": { "names": ["static"] }, "upstream": "images" } ],
    "headerReq": [ /* request-phase header ops */ ]
  },
  "key": {
    // tokens is the catch-all (default/unscoped) recipe — the worker's fallback.
    "tokens": [ { "kind": "url" }, { "kind": "host" }, { "kind": "classify", "ref": "age" } ],
    // recipes is the FULL ordered scoped recipe list (D70). The worker selects
    // first-match-wins by each recipe's request-phase selector (Always = catch-all).
    "recipes": [ { "selector": { "names": ["ssr"] }, "tokens": [ { "kind": "host" }, { "kind": "path" } ] },
                 { "selector": { "always": true },   "tokens": [ { "kind": "host" }, { "kind": "url" } ] } ]
  },

  "response": {
    // maxStale (D70) bounds the edge's stale-on-error serving to ttl+grace+maxStale.
    "ttl": [ { "selKind": "status_in", "codes": [404, 410], "ttl": "1m0s", "grace": "1h0m0s" },
             { "selKind": "status_not_in", "codes": [200], "isHFM": true, "hitForMiss": "5s" },
             { "selKind": "scope", "scope": { "names": ["listings"] }, "ttl": "2s", "grace": "24h0m0s" },
             { "selKind": "default", "ttl": "2s", "grace": "24h0m0s", "maxStale": "24h0m0s" } ],
    "storage": [ { "selKind": "scope", "scope": { "names": ["images"] }, "tier": "disk" },
                 { "selKind": "default", "tier": "ram" } ],
    "stripCookies": [ { "names": ["images"] } ],
    "headerResp":   [ /* response-phase header ops */ ],
    "cors":         { "scope": { "always": true }, "allowAllOrigins": true },

    // transforms (D75): size-bounded `replace` body substitutions, applied on delivery
    // within transformMaxBytes; an over-cap body streams through untransformed.
    "transforms":        [ { "scope": { "names": ["html"] }, "old": "__TITLE__", "new": "Welcome" } ],
    "transformMaxBytes": 1048576,
    // onError (D76): the origin-failure synthetic served when no cached object is
    // salvageable (precedence: stale-within-window > negative cache > onError > 502).
    "onError":           [ { "scope": { "names": ["api"] }, "status": 503, "body": "down for maintenance",
                            "contentType": "text/html; charset=utf-8" } ]
  },
  "deliver": { "cacheStatusHeader": "X-Cache" },

  "edge": {                               // projected from the edge {} block (cache-tier policy)
    "default": "local",                   // local | distribute | skip
    "policies": [ { "scope": { "names": ["html"] }, "tier": "distribute" },
                  { "scope": { "names": ["assets"] }, "tier": "skip" } ],
    "kvTtlSeconds": 300,                   // omitted unless kv_ttl is set
    "kvMaxBytes": 1048576                  // omitted unless kv_max_bytes is set
  },

  "delegate": [ { "directive": "rewrite", "reason": "…", "scope": { "names": ["old"] } } ]
}
```

Key contract notes:

- **Matchers serialize as `{kind, fields}`.** Only the fields relevant to `kind` are
  present (`omitempty`). `path`/`host` carry reconstructed glob/wildcard **patterns**;
  `path_regex`/`host_regex` carry the RE2 **regex** source. `content_type`/`set_cookie`
  matchers set `responsePhase: true` (they need the origin response).
- **Scopes reference matchers by id** (`names`, OR semantics). An unconditional directive
  is `{ "always": true }`. An anonymous **inline** matcher (e.g. `pass method POST`)
  surfaces under `inline` rather than `names`.
- **`classify`** is `{ rows: [{ conj: [matcherId], value }], default }` — first-match over
  the rows' AND-conjunctions, else the default. Identical to the server's resolver.
- **Cache-key tokens** are an ordered list of `{ kind, arg?, ref?, allow? }`. `kind` is one
  of `method|host|path|url|query|query_allow|header|sticky|device|geo|geo.continent|geo.region|normalize|classify|tenant|literal`.
- **Durations** (`ttl`/`grace`/`hitForMiss`) are Go duration strings (`"1m0s"`, `"24h0m0s"`)
  so both runtimes parse them identically.
- **`delegate[]`** records every non-edge-capable directive with a `reason` (and the
  `scope` it applied to). The worker passes these to the Cadish server behind.
- **`edge`** projects the `edge { }` Cadishfile block (L1 Cache API / L2 KV tiers): a
  `default` tier (`local|distribute|skip`), per-scope `policies` (each `{ scope, tier }`),
  and the optional KV guardrails `kvTtlSeconds` / `kvMaxBytes` (omitted when unset). With
  no `edge { }` block, `default` is `local` and `policies` is empty. **Deploy identity**
  (account/zone/worker/routes/kv) is **never** projected — it is management-plane metadata
  the CLI reads directly, not shipped to the public worker (D43). See
  [The `edge {}` block](#the-edge--block) below.

## How it fits

```
Cadishfile ─compile─▶ *pipeline.Pipeline ─Project()─▶ EdgeIR ─bundle─▶ worker.js ─deploy─▶ Cloudflare
                              │                          │                  │
                      (the single brain)         (stable contract     (generic runtime +
                                                  the JS mirrors)       baked IR; no JS toolchain)
```

## The worker runtime (one Cadishfile, two runtimes)

`edge/runtime/` is a small, generic ES-module worker that **interprets the IR** — it
never sees the Cadishfile. `interpreter.js` is a faithful, pure port of the Go matcher
switch + the `EvalRequest/EvalResponse/EvalDeliver` walk; the IO modules orchestrate it:

| Module | Does |
|---|---|
| `interpreter.js` | pure IR interpreter: matchers, classify/normalize/tenant, cache key, redirects, header ops, response-phase matchers, edge-tier resolution |
| `geo.js` | `request.cf` → geo classes; inject `CF-IPCountry` + continent/region headers so the cadish server behind resolves geo identically |
| `origin.js` | fetch the resolved upstream `to`; apply request header ops + geo headers; set the `X-Cadish-Peer` hop-guard |
| `cache-tiers.js` | L1 (Cache API) + L2 (KV) as one cache: read-through, store-by-tier, fresh/stale/expired, SWR, the security invariant |
| `entry.js` | `export default { fetch }` — geo → RECV/KEY → lookup (HIT / HIT-STALE+SWR) → miss → origin → store → DELIVER; origin failure → stale-on-error else 502 |

**The conformance suite is the contract.** `test/conformance` runs both runtimes over
the same fixtures and asserts identical decisions, so the JS can never silently drift
from the Go pipeline (see D42). The dependency-free Node harnesses
(`conformance.test.mjs`, `runtime.test.mjs`) are the CI gate; `npm run test:miniflare`
adds real Cache-API/KV fidelity on workerd.

## The `edge {}` block

Self-describing deploy identity + edge cache-tier policy:

```
edge {
    account  <account-id>          # or env CF_ACCOUNT_ID
    zone     example.com           # zone name or 32-hex id
    worker   cadish-edge-example
    route    example.com/*         # optional; defaults to the site hosts (host/*)
    kv       EDGE_CACHE            # optional; only needed if you distribute
    default  local                 # local | distribute | skip
    distribute @html               # per-scope L2 (KV) caching
    skip       @assets             # never cache at the edge (let Cloudflare's native cache serve)
    kv_ttl       5m                # cap KV (L2) retention (default: object ttl+grace)
    kv_max_bytes 1MB               # bodies larger than this stay L1-only (never KV)
}
```

The **cache-tier policies** (default + per-scope + the two KV guardrails) are projected
into the worker IR. The **deploy identity** (account/zone/worker/routes/kv) is **never**
in the public worker IR — it is management-plane metadata the CLI reads directly (D43).

### The global (cross-POP) KV tier

`distribute` opts a scope into the **global L2/L3 tier: Cloudflare Workers KV**, shared
by every POP and sitting behind the per-POP L1 Cache API. On an L1 miss the worker reads
KV before the origin; on a fill it write-throughs KV — so **one origin fill warms the
whole planet** (a cold POP serves a HIT from KV instead of re-hitting origin). KV is
opt-in and OFF by default; `local` is L1-only, `skip` caches at neither tier.

Two **guardrails** bound the KV tier (both global, one per block):

- **`kv_ttl DURATION`** caps KV *retention* — how long a blob physically stays in KV
  before auto-deleting. This is a **different clock** from the object's cache TTL:
  freshness (HIT / stale-within-grace / expired) is always decided by the object's own
  `cache_ttl`/`grace` (its `storedAt`/`ttlMs`/`graceMs` metadata), identically at every
  POP — KV's own expiry never drives HIT/STALE. Effective KV retention =
  `clamp(ttl+grace, 60s, kv_ttl)` (60s is KV's hard floor). Default `ttl+grace` (no cap).
- **`kv_max_bytes SIZE`** is a hard size bound: a body larger than it is written to **L1
  only, never KV**, regardless of its `distribute` tier (large media stays out of KV; it
  still caches per-POP). Default `1 MiB`; KV's own hard ceiling is 25 MB and a `kv_max_bytes`
  above it is a build warning.

**Invalidation is TTL-only.** A `purge`/BAN invalidates the cadish **server** and the
per-POP L1, but does **NOT** reach into global KV — there is deliberately no epoch/version
key, no edge ban-lurker, and no server→KV purge call (owner decision 2026-06-24; this also
keeps the purge secret off the edge entirely, D34). A purged object stays warm in KV until
its `expirationTtl` (`kv_ttl`) elapses. **So if you enable the KV tier, accept that purge
is not globally immediate — bound it with a short `kv_ttl`** (e.g. `kv_ttl 5m` ⇒ a purge is
globally effective within ~5 min as entries age out). Changing the worker/key recipe (a new
deploy) is the one blunt global-flush lever.

**Eventual consistency / degrade-to-origin.** KV is eventually consistent (~≤60s cross-POP
propagation) and additive/best-effort: a KV read error → treated as an L2 miss → origin; a
KV write error → ignored (the object still lives in L1 at that POP). KV is **never a single
point of failure**, and the security invariant (a `Set-Cookie`/private/`Authorization`
response is never written to **either** tier) holds across L1 and L2 regardless.

## Deploy / enable / disable

```
cadish edge build  -bundle worker.js   # assemble the worker bundle (runtime + baked IR)
cadish edge deploy -origin https://cadish-behind.example.com   # upload, NO routes (dark)
cadish edge enable                     # attach routes → traffic flows through the edge
cadish edge disable                    # detach routes → instant bypass (kill switch)
```

- **Auth:** a Cloudflare API token in `CF_API_TOKEN` (never in the file). The origin URL
  is a deploy-time binding (`-origin` or `CADISH_EDGE_ORIGIN`) — the IR carries upstream
  *names* only.
- **Deploy ≠ activation:** `deploy` uploads without routes (test via the `*.workers.dev`
  URL, no production traffic); `enable` goes live; `disable` is the instant kill switch
  back to the Cadish server behind. KV is created/bound only when a `distribute` policy
  (or explicit `kv`) is present.

## What the edge intentionally does NOT do (permanent server-only non-goals)

Some Cadishfile behaviors are **permanently server-only by design** — they will never be
edge-native, and that is a deliberate choice, not a backlog item. This is distinct from a
**delegation** (something the edge *passes through* but the Cadish server behind still
handles): the items below are server-only because they need state, a secret, or origin-side
context the edge has no faithful way to hold. The coverage report and `-strict` surface
them; this section records *why* so they stop reappearing as "gaps".

| Server-only (never edge-native) | Why |
|---|---|
| **Security gate** — `allow` / `deny` / `block`, the `security {}` monitor toggle (D49) | The ACL resolves the *trusted-proxy real client IP* (the `ip` matcher), which the edge — the first hop — has no concept of. Cloudflare owns the edge's security layer (WAF/firewall rules); enforce these there. The `ip` matcher is actively filtered out of the IR. |
| **`rate_limit`** (D51) | A stateful per-node token bucket. A stateless, per-POP, ephemeral Worker isolate cannot keep a correct global counter; Cloudflare Rate Limiting Rules are the edge equivalent. |
| **WAF** (v2/v3, when built) | Server-only per the WAF design — same trust-model and statefulness reasons as the security gate. |
| **`purge`** — single-key **and** regex BAN (D34) | The guard compares a **secret token** that must never ship to a public Worker bundle, and a regex BAN is a cache-wide eviction the stateless edge cannot express. Always delegated to the server, which holds the secret and does the constant-time compare. |
| **`ip` matcher** (D49/D50) | A trusted-proxy real-client-IP ACL; the edge uses Cloudflare's own IP layer + `request.cf` instead. Never projected. |
| **Body `replace` on a huge / streaming body (OVER the cap)** | Body rewriting in a Worker is CPU/memory-bounded; a body larger than the worker's transform cap (`response.transformMaxBytes`, 1 MiB) streams through to the server, which transforms it zero-extra-copy, rather than being buffered or truncated at the edge. A **within-cap** `replace` IS edge-native (D75, see "Size-bounded `replace`" above) — only the over-cap/streaming case is server-only. |
| **`encode`** (on-the-fly compression, D46/D69) | Cloudflare compresses at its own edge, and the Cadish server compresses for origin fetches — there is no edge work to do. Recorded as handled-elsewhere, not as a cadish-edge feature. |

These are also restated as the design's permanent non-goals (the edge-completion roadmap
spec, §4.4/§8): security gate, `rate_limit`, WAF, the `purge` token + regex BAN, and the
`ip` matcher are **server-only forever**; cache warming/cron stays a separate parked module,
never an edge directive.

### Delegated-but-server-handles-it (distinct from a non-goal)

By contrast, these are **not** edge-native today but are not permanent non-goals either —
they are absorbed by the standard edge→server-behind topology (the server re-runs its full
pipeline on the MISS forward), so they are *honesty* entries in the coverage report rather
than correctness gaps:

- **`rewrite`** — rewrites the origin-dialed path/query (never the cache key); the server
  behind applies it on the MISS forward.

It is recorded in `delegate[]` so nothing is silently dropped.

> **Reconciled in v1.2 (D75/D76):** earlier versions listed a within-cap `replace` and the
> `respond on_error` outage path here as "delegated but the server handles it". Both are now
> **edge-native** — a size-bounded `replace` (the over-cap case streams to the server, above)
> and the `respond on_error` synthetic served on an origin hard-failure with no salvageable
> cached object. They no longer appear in `delegate[]`.
