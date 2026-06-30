# `cadish check` — the config complexity report

`cadish check` loads a Cadishfile, resolves its `import`s, validates it, and
prints a **per-site complexity report**: how expensive your config is to evaluate
on every request, which rules are dead, and how to make it cheaper.

No comparable proxy ships this. The point is to push you toward
**cheap configs** — to make "this rule costs a regex on every request" visible
*before* it shows up as p99 latency.

`check` is also a true **pre-flight gate**: it runs the same structural config
build `cadish run` does, so the invariant **`cadish check` exits 0 ⇒ `cadish run`
will not fail at config-build time** holds. It catches the errors that would make
`run` refuse to start — a site with no `upstream`, a duplicate upstream, an
`origin chain` referencing an undeclared upstream, a malformed `sticky` line —
and prints them with the same `file:line:col` diagnostic `run` would. The build
validation is **side-effect-free**: it does no network/DNS resolution, opens no
listeners, and creates no cache directories (those are deferred to `run`).

```
cadish check [-config Cadishfile] [-strict] [-json]
```

| Flag | Effect |
|---|---|
| `-config PATH` | Cadishfile to analyze (default `Cadishfile`). |
| `-strict` | Treat warnings as errors (non-zero exit on any warning). |
| `-json` | Emit the report as JSON for tooling instead of the text report. |

**Exit code:** `0` on success (warnings are allowed unless `-strict`); non-zero
when there are errors or a parse failure. Parse/import errors are printed as
`file:line:col: message`.

## A sample report

```
cadish check — test/migration/storefront/Cadishfile

Site: example.com, *.example.com
  Matchers:               6
  Directives:             28
  Regex evals / request:  3   (path_regex/host_regex/regex-valued header on the hot path)
  Directives by phase:    SETUP 5  RECV 6  KEY 1  ORIGIN 7  DELIVER 9
  Est. per-request cost:  41   (7 exact×1 + 2 glob×2 + 3 regex×10)
  Suggestions:
    • good: @nocache collapses 24 paths into one matcher (a single set/trie lookup, not 24 compares)

Summary: 1 site, 0 errors, 0 warnings
```

## What each number means

### Matchers / Directives
The number of named matcher definitions (`@name …`) and the total number of
directives in the site. A high directive count is not itself bad — what matters
is how many run *per request* and how expensive each is.

### Regex evals / request
The headline metric. A request evaluates each reachable matcher **once** (results
are cached for the request — see the MATCH phase of the request lifecycle).
This counts how many of those are
**regular-expression** matches: `path_regex`, `host_regex`, `header_regex`, and
`header` matchers whose value looks like a regex. Regexes are by far the most expensive predicate,
so this is the first number to drive down.

Only matchers actually **referenced** on the request path count — a regex matcher
that is defined but never used is reported as dead, not as per-request cost.

### Directives by phase
Directives grouped by the lifecycle phase in which they run:

| Phase | When | Directives |
|---|---|---|
| `SETUP` | parsed once, not per request | `tls`, `cache`, `cache_unsafe`, `client_cache_control`, `upstream`, `cluster`, `origin`, `lb`, `sticky`, `host_header`, `sni`, `http_reuse`, `tls_insecure`, `ca_file`, `alpn`, `resolve`, `import`, `device_detect`, `geo`, `trust_proxy`, `normalize`, `tenant`, `classify`, `edge`, `access_log`, `strict_host`, `admin`, `proxy_protocol`, `server`, `security`, `monitor` |
| `RECV` | on receiving the request | `respond`, `redirect`, `rewrite`, `purge`, `route`, `pass`, `upgrade`, `allow`, `deny`, `block`, `rate_limit`, `cookie_allow`, `cache_credentialed` |
| `KEY` | building the cache key | `cache_key` |
| `ORIGIN` | on a miss, against the origin response | `cache_ttl`, `storage` |
| `DELIVER` | just before responding | `header`, `strip_cookies`, `cors`, `replace`, `encode` |

`SETUP` directives never contribute to per-request cost. (The authoritative phase
mapping is `internal/check/catalog.go`; this table mirrors it.)

### Est. per-request cost
A single weighted score summed over every predicate a request evaluates:

| Class | Weight | Examples |
|---|---|---|
| exact | 1 | `host`, `method`, `header NAME` (presence/equality), `status` selector |
| glob | 2 | `path /a/*`, `host *.example.com` (one trie/set lookup) |
| regex | 10 | `path_regex`, `host_regex`, `header_regex`, regex-valued `header` |

So `cost = exact·1 + glob·2 + regex·10`. The breakdown after the number tells you
exactly where the cost is. It is a **relative** figure for comparing configs and
spotting hot spots, not a wall-clock measurement.

> **Note:** the cost model counts only RECV/KEY matchers. An ORIGIN-phase selector —
> e.g. the matcher on a `storage @sel -> disk` rule — is evaluated at runtime (on
> misses only) but is reported as "free" here, so its predicate does not appear in
> the per-request cost.

## Findings

Findings are `warning`s (advisory) or `error`s (fail the check). Each carries a
`file:line:col` position and a short code.

| Code | Meaning |
|---|---|
| `unknown-directive` / `unknown-matcher-type` | Name is not in the v1 catalog. Also fires (as an **error**) for a key not in the known set **inside** an `upstream {}` / `cluster {}` pool block — e.g. a typo'd `host_hedaer` that would otherwise silently fall back to the default Host. (The unnamed `cluster { self peers … }` membership block is linted against its own key set.) |
| `undefined-matcher` | A directive references a `@matcher` that is never defined. |
| `duplicate-matcher` | A matcher name is defined twice; the later one shadows. |
| `unused-matcher` | A matcher is defined but never referenced (dead). |
| `arity` | A known directive is missing required arguments (light, non-strict). |
| `dead-rule` | A selection rule can never be reached: a scoped `cache_key` / `cache_ttl` / `storage` rule that sits after a `default` catch-all, or that repeats an earlier selector (see below). |
| `cache-key-no-default` | A site mixes scoped `cache_key` rules but has no `default` / unscoped catch-all, so some requests would resolve to no key. |
| `unbounded-key-token` | A `cache_key` keys on a raw, high-cardinality value (`header:NAME`, the whole `query`, `{sticky}`) → cache fragmentation. |
| `cache-credentialed-origin-trust` / `cache-credentialed-noop` | `cache_credentialed @scope` makes caching origin-authoritative (warns you to verify the origin only marks shareable bodies cacheable); the second fires when the scope has no positive in-scope `cache_ttl` signal, so it can never store (a no-op). |
| `cookie-forward-uncollapsed` / `derives-from-not-stripped` / `cookie-allow-unkeyed` | `derives_from`/`cookie_allow` hygiene: a cookie forwarded to origin under a collapsed key (asserting `{token}` captures its only cache-relevant effect), a derived cookie not stripped, or a `cookie_allow` cookie that no `cache_key` recipe keys on. |
| `ip-acl-without-trust-proxy` / `sni-without-https` / `geo-unconfigured` | Config-hygiene warnings: an `ip` ACL with no `trust_proxy`, `sni` on a non-HTTPS upstream, or a `{geo}` token with no `geo` source. |
| `unused-normalize-token` | A `normalize NAME { … }` bucket is defined but its `{NAME}` token is used in no `cache_key` recipe — the bucket is computed for nothing and the cache silently does not vary on it. Key it (`cache_key … {NAME}`) or remove the block. |
| `unused-device-detect` | A `device_detect { … }` block is configured but no `cache_key` recipe keys on `{device}` — the device classifier is computed for nothing, so the cache silently does not segment by device class. Key it (`cache_key … {device}`) or remove the block. |
| `acme-host-unissuable` | A site requests automatic TLS (`tls acme`) for an address a public ACME CA can never issue for — an IP literal, `localhost`, a single-label dotless name, or a reserved special-use TLD (`.local`/`.localhost`/`.test`/`.invalid`/`.example`/`.internal`). It checks clean but silently never serves TLS (the challenge fails only at the first handshake). Use a static `tls { cert … key … }`, `tls off`, or a public DNS name. |
| `upstream-healthy-non-pool` | An `upstream_healthy NAME` matcher names an upstream that does not build as a load-balancer pool (a trivial single-backend `upstream`, or an `s3`/`sign` origin) — it has no active health probe, so the matcher always reports it healthy and can never detect it down. Add a `health { … }` block to actively track it. |
| `noop-top-level-statement` | A directive or `@matcher` sits at the top level OUTSIDE any site block while site blocks are present — it never runs (cadish builds pipelines per site). Often a site-address list that lost a comma and dropped an address into the top-level body (e.g. `intranet` then `api.internal {`); comma-separate the addresses, or move the statement into the right site. |
| `default-key-omits-query` | A site caches (`cache_ttl`) but defines no `cache_key`, so the default key `method host path` ignores the query string — `/api?id=1` and `/api?id=2` collide on one entry (Varnish hashed the query by default). Add `cache_key … query` (or `query_allow …`) if responses vary by query; safe to ignore for query-independent content. |
| `invalid-duration` / `invalid-size` / `invalid-upstream-url` / `invalid-listen` / `invalid-geo-source` | A directive argument is malformed (bad duration, byte size, URL, listen address, or geo source). |
| `compile-error` | The site lints clean at the AST level but fails to **compile** into the runtime pipeline — i.e. it would refuse to `cadish run` (e.g. `undefined matcher @x`, `classify value must be non-empty`, `pass needs a matcher or condition`). `check` compiles every site and surfaces the compiler's own `file:line:col`, so "passes check ⇒ will boot" holds. (error) |
| `build-error` | The site compiles but fails the **structural config build** `cadish run` performs — a site with no `upstream` to fetch from, a duplicate `upstream`/`cluster` name, an `origin chain` referencing an undeclared upstream, or a malformed `sticky` line. Carries the same `file:line:col` `run` would print. (error) |
| `missing-import` / `bad-import` / `import-cycle` | Import could not be resolved. |

### Dead / unreachable rules
cadish evaluates selection directives (`pass`, `cache_ttl`, `storage`)
**first-match-wins**. So a rule is dead when an earlier one always matches first:

- a `cache_ttl default` / `storage default` makes every later rule of that kind
  unreachable;
- an unconditioned `pass` bypasses every request, so later `pass` rules are dead;
- a duplicate selector (`storage @api` twice) — the second never wins;
- a `pass` whose paths are a strict subset of an earlier `pass` (conservative,
  best-effort: only clear cases are flagged).

## Suggestions

Cheap rewrites the report nudges you toward, for example:

- **Collapse repeated `pass path` rules.** `N` separate `pass path /x` rules are
  `N` rules to evaluate; one `@matcher path /a /b …` is a single set lookup.
- **`path_regex` → `path` glob.** An anchored-literal regex like `^/legacy` is a
  regex (weight 10) doing a job a `path /legacy*` glob (weight 2) does cheaper.
- It also calls out the *good* pattern — a matcher that already collapses many
  paths into one lookup — to reinforce it.

## Imports

`import PATH` splices another Cadishfile fragment in place. Paths resolve relative
to the importing file. A missing or unparseable import, or an import cycle, is a
reported `error` carrying the import directive's position; analysis continues with
that import dropped so you still get the rest of the report.

`import` is meaningful **inside a site block** (it splices the fragment into that
site). A *top-level* `import` (outside any site, when the file already has site
blocks) is a no-op at `cadish run`, so `check` treats it as one too — it is not
spliced and not flagged. This keeps `check` and `run` in agreement on imports.

## JSON output

`-json` emits the same data as a JSON object (`path`, `errors`, `warnings`, and a
`sites` array with `matcher_count`, `directive_count`, `regex_evals_per_request`,
`phase_counts`, `estimated_cost`, `cost_breakdown`, `suggestions`, and
`diagnostics`). Use it to gate CI on, say, `regex_evals_per_request` or
`estimated_cost` per site.
