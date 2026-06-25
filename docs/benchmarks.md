# Benchmarks & performance baseline

Go micro-benchmarks for cadish's hot-path packages, plus the baseline numbers
they produced. This is the reference point for a later performance-optimization
pass: re-run after a change and compare (ideally with `benchstat`). The
benchmarks are additive `bench_test.go` (and `feature_bench_test.go`) files —
they ship no production code, change no behavior, and are independent of the
server.

## What's covered

| Package | Benchmark file | Hot path measured |
|---------|----------------|-------------------|
| `internal/cache` | `bench_test.go` | two-tier `Store`: RAM-hit / disk-hit get, put, concurrent mixed — across 1 KiB / 64 KiB / 4 MiB |
| `internal/pipeline` | `bench_test.go` | per-request `EvalRequest`/`EvalResponse` on the real storefront site; matcher engine (glob/trie vs regex); compile |
| `internal/pipeline` | `feature_bench_test.go` | `Feature*` zero-cost-when-unused audit — baseline vs one-feature-each (`classify`, `query_allow`/`query_present`, `geo`, dynamic headers) |
| `internal/lb` | `bench_test.go` | consistent-hash ring lookup / rebuild + policy `pick` across pools of 3 / 16 / 64 |
| `internal/origin/chain` | `bench_test.go` | origin chain dispatch + fall-through (in-memory origins, no network) |
| `internal/server` | `bench_test.go` | full `ServeHTTP` HIT / MISS / parallel + freshness-index lookup (whole serve path, end-to-end) |
| `internal/edgeir` | `bench_test.go` | offline `cadish edge build` IR projection (`Project`, `ProjectLargeConfig`) — not on the request path |

## Running

```sh
# one package
go test ./internal/cache/ -run '^$' -bench . -benchmem

# all hot-path packages
go test -run '^$' -bench . -benchmem ./internal/...

# stable comparison across a change (with benchstat)
go test -run '^$' -bench . -benchmem -count=10 ./internal/... > old.txt
#   …make a change…
go test -run '^$' -bench . -benchmem -count=10 ./internal/... > new.txt
benchstat old.txt new.txt
```

`-run '^$'` skips the unit tests so only benchmarks run. `-benchmem` reports
`B/op` and `allocs/op`, which matter as much as ns/op on these paths. Benchmarks
run **without** `-race`; the unit tests in these packages still pass `go test
-race`.

## Baseline

Environment: **Apple M4 Pro** (`darwin/arm64`), **Go 1.26.0**, single run
(`-benchmem`, default benchtime). `-14` is `GOMAXPROCS`. Absolute ns/op will
differ on the production Linux/amd64 fleet — treat these as a same-machine
regression reference, not a fleet SLA. Throughput (`MB/s`) is shown where the
benchmark sets it.

### `internal/cache` — two-tier Store

| Benchmark | ns/op | throughput | B/op | allocs/op |
|-----------|------:|-----------:|-----:|----------:|
| `StoreGetRAM/1KiB` | 152.1 | 6730 MB/s | 160 | 3 |
| `StoreGetRAM/64KiB` | 1219 | 53780 MB/s | 160 | 3 |
| `StoreGetRAM/4MiB` | 70536 | 59463 MB/s | 160 | 3 |
| `StoreGetDisk/1KiB` | 16070 | 64 MB/s | 651 | 7 |
| `StoreGetDisk/64KiB` | 27818 | 2356 MB/s | 685 | 7 |
| `StoreGetDisk/4MiB` | 560531 | 7483 MB/s | 652 | 7 |
| `StorePut/1KiB` (RAM) | 1070 | 957 MB/s | 1439 | 8 |
| `StorePut/64KiB` (RAM) | 42612 | 1538 MB/s | 65896 | 7 |
| `StorePut/4MiB` (disk) | 2941446 | 1426 MB/s | 1807 | 20 |
| `StoreMixedParallel` (1 KiB, ~7:1 r:w, concurrent) | 117.0 | — | 310 | 3 |

RAM hits are **constant 3 allocs / 160 B regardless of object size** (the body is
streamed, not copied into the hit path) — only the drain cost scales. Disk hits
cost a blob `open`/`stat` (~16 µs fixed overhead, dominating the 1 KiB case at
64 MB/s; amortized away by 4 MiB at 7.5 GB/s). The concurrent mixed load holds
~117 ns/op — the per-shard LRU locking avoids a global-mutex cliff. The `64KiB`
put `B/op` reflects the RAM tier buffering the whole small object before commit.

### `internal/pipeline` — request evaluation (real storefront site)

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| `EvalRequest/cacheable` (full matcher scan + cache-key) | 353.1 | 288 | 6 |
| `EvalRequest/pass_ajax` (early pass on header matcher) | 210.4 | 216 | 3 |
| `EvalRequest/route_static` (host_regex route) | 243.7 | 240 | 3 |
| `EvalRequest/respond` (synthetic short-circuit) | 83.3 | 72 | 2 |
| `EvalRequestParallel` (cacheable, concurrent) | 127.4 | 288 | 6 |
| `EvalResponse` (status cache_ttl + headers) | 197.5 | 0 | 0 |
| `Compile` (one-time, per reload) | 33097 | 93650 | 953 |
| `MatcherPathSet` (glob/trie engine) | 47.2 | 0 | 0 |
| `MatcherPathRegex` (equivalent `path_regex`) | 78.9 | 0 | 0 |

Sub-microsecond per request even on the full path; the evaluation core is
read-only and scales under concurrency. `EvalResponse` is allocation-free. The
glob/trie `path` matcher is **~1.7× faster than the equivalent `path_regex`** and
both are alloc-free — confirms preferring `path` over `path_regex` where possible.
`Compile` is a startup/reload cost (~33 µs for the full storefront site with its
imported fragment), not per request.

### `internal/lb` — consistent-hash ring & selection

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| `RingLookup/backends=3` | 151.2 | 0 | 0 |
| `RingLookup/backends=16` | 326.1 | 936 | 3 |
| `RingLookup/backends=64` | 526.3 | 3496 | 3 |
| `RingLookupHalfDown/backends=3` | 230.3 | 0 | 0 |
| `RingLookupHalfDown/backends=16` | 345.5 | 936 | 3 |
| `RingLookupHalfDown/backends=64` | 573.8 | 3496 | 3 |
| `RingRebuild/backends=3/{add,remove}` | ~45–56 k | ~58–62 k | 32–33 |
| `RingRebuild/backends=16/{add,remove}` | ~242–256 k | ~253 k | 55–56 |
| `RingRebuild/backends=64/{add,remove}` | ~1.29–1.33 M | ~1.0–1.08 M | 111–112 |
| `StickyPick/backends=3` | 163.8 | 0 | 0 |
| `StickyPick/backends=16` | 328.0 | 936 | 3 |
| `StickyPick/backends=64` | 707.8 | 3496 | 3 |
| `PickPolicies/round_robin` | 44.3 | 0 | 0 |
| `PickPolicies/least_conn` | 115.1 | 0 | 0 |
| `PickPolicies/sticky` | 332.2 | 936 | 3 |
| `PickPolicies/shard_url` | 316.5 | 936 | 3 |

Lookup/pick is sub-µs for realistic pools. `round_robin`/`least_conn` are
allocation-free. Ring **lookup allocates once the pool is ≥~16 backends** — a
per-lookup `seen` map de-dupes virtual nodes during the clockwise walk (936 B at
16, 3.5 KB at 64). Ring **rebuild** is the expensive op (160 MD5 vnodes ×
N backends, ~1.3 ms / ~1 MB at 64) but is paid only on a membership change
(dynamic re-resolution), never per request.

### `internal/origin/chain` — fallback dispatch

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| `ChainHitFirst` (primary serves) | 45.1 | 96 | 3 |
| `ChainFallThrough` (404 → secondary) | 49.8 | 96 | 3 |
| `ChainDeepFallThrough` (3 miss → 4th) | 178.5 | 120 | 6 |

Chain dispatch overhead over a bare origin is ~5 ns per extra hop plus the
fall-through predicate — negligible next to a real network fetch. (The allocs
here are the fake origin's per-call response body, not chain overhead.)

## Hot-spot candidates identified in the baseline pass

These were the three candidates the baseline measurement surfaced — **all three
addressed in the perf pass below** ("Perf pass — 2026-06 (allocation
elimination)"). Kept here as the record of what the baseline pointed at.

1. **`lb` ring lookup allocates a `seen` map per call** (936 B / 3 allocs at 16
   backends, 3.5 KB at 64) on the **sticky/shard request hot path**. The map
   de-dupes virtual nodes during the clockwise walk. Pools ≤8 are already
   0-alloc. Fix candidates: a small stack-backed slice instead of a map (pools
   are small), or skip de-dup entirely when the first ring point is already
   eligible (the overwhelmingly common case). **Top target** — it's per-request
   and the win is a clean alloc-elimination.
2. **`pipeline` cacheable request path is 6 allocs / 288 B** — mostly the
   cache-key string building (`EvalResponse` is already 0-alloc, so the request
   phase is where to look). A reusable per-request key buffer / `strings.Builder`
   reuse could trim it; matters at high request rates.
3. **`cache` small-object RAM put is ~8 allocs and buffers the whole object**
   (the 64 KiB put shows 65 KB/op). The write path is the heaviest cache op;
   a pooled write buffer (`sync.Pool`) for the common small-object band would cut
   both the allocation and GC pressure under write-heavy load.

Secondary: `lb` ring rebuild is O(N · 160) MD5 — fine as an occasional
re-resolution cost, but churny `dns://`/`k8s://` pools could use incremental
ring updates (add/remove a node's points) rather than a full rebuild.

Re-run the relevant table after any change and confirm no regression elsewhere.

## Perf pass — 2026-06 (allocation elimination)

The three hot-spot candidates above were optimized (behavior-identical; all
package tests stay green under `-race`). Same machine/Go as the baseline.

| Benchmark | Before | After | Δ |
|-----------|--------|-------|---|
| `lb RingLookup/backends=16` | 290 ns · 936 B · **3 allocs** | 139 ns · 0 B · **0 allocs** | −52% time, alloc-free |
| `lb RingLookup/backends=64` | 517 ns · 3496 B · **3 allocs** | 143 ns · 0 B · **0 allocs** | **−72% time**, alloc-free |
| `lb StickyPick/backends=64` | 512 ns · 3496 B · 3 allocs | 167 ns · 0 B · 0 allocs | −67% time, alloc-free |
| `pipeline EvalRequest/cacheable` | 350 ns · 288 B · **6 allocs** | 288 ns · 256 B · **3 allocs** | −18% time, −3 allocs |
| `cache StorePut/1KiB` | 840 ns · 1384 B · **7 allocs** | ~850 ns · 1336 B · **6 allocs** | −1 alloc |
| `cache StorePut/64KiB` | ~38 µs · 65896 B · 7 allocs | ~20 µs · 65850 B · 6 allocs | −1 alloc, buffer reuse |
| `cache StoreMixedParallel` | 117 ns · 310 B · 3 allocs | 85 ns · 304 B · 3 allocs | −27% time (pooled buffers) |

What changed:

1. **`lb` ring lookup (`ring.go` `lookup`)** — the per-call `seen`
   `map[string]bool` (which de-dupes virtual nodes during the clockwise walk)
   became a fixed **stack array + linear scan** (`ringSeenStack = 64`). Lookups
   are now allocation-free for realistic pools, and dropping the map made the
   64-backend lookup **~3.6× faster**. A pool larger than 64 backends spills the
   slice to the heap once — still cheaper than the map, and never on the common
   first-hit path.
2. **`pipeline` cache-key build (`cachekey.go` `buildKey`)** — replaced the
   `make([]string)` + `strings.Join` + intermediate query strings with a single
   `strings.Builder` that renders every token (and the query, via
   `writeCanonicalQuery`, with stack-backed key/value sorting) in place.
   6 → 3 allocs; the remaining allocs are the key string itself and the
   decision's request-header-op slice (real work, not overhead). Output is
   byte-for-byte identical (verified by the existing `cachekey_test.go`).
3. **`cache` small-object RAM put (`ram.go`)** — write buffers now come from a
   `sync.Pool`. On commit a **small** object (≤ 64 KiB) is copied into an
   exact-size slice the cache entry owns and its buffer is recycled; a **large**
   object keeps the existing zero-copy hand-off (its backing becomes the entry's
   bytes, so it is never pooled). This trims one alloc per put and, more
   importantly, recycles buffers under sustained write load — visible as the
   −27% on the concurrent mixed benchmark.

**Do not optimize from the baseline tables alone** — they are the reference; this
section records the changes already applied. Re-run with `-count≥10` + `benchstat`
for publication-grade deltas (the single-run µs figures above are noisy on the
disk-backed put path; the alloc counts are exact).

## Perf pass — 2026-06 (matcher memo: kill the per-request map)

The previous pass left `EvalRequest` at **3 allocs / 256 B**. A memory profile
pinned the remaining two *overhead* allocations (the third is the cache-key string
itself — real output) on the per-evaluation `matchContext`: the context struct
heap-escaped, and its matcher-result memo was a fresh `map[*matcher]bool` per call.
Both are now gone. Same machine/Go as the baseline; `benchstat`, `-count=10`,
all `p=0.000`.

| Benchmark | Before | After | Δ time | Δ allocs |
|-----------|--------|-------|-------:|---------:|
| `EvalRequest/cacheable`     | 270 ns · 256 B · **3** | 197 ns · 96 B · **2** | −27% | −1 (−62% B) |
| `EvalRequest/pass_ajax`     | 204 ns · 256 B · 3     | 144 ns · 96 B · 2     | −30% | −1 |
| `EvalRequest/route_static`  | 224 ns · 256 B · 3     | 151 ns · 96 B · 2     | −33% | −1 |
| `EvalRequest/respond`       | 80 ns · 72 B · 2       | 63 ns · 56 B · 2      | −20% | — |
| `EvalRequestParallel`       | 112 ns · 256 B · 3     | 51 ns · 96 B · 2      | **−54%** | −1 |
| `EvalResponse`              | 178 ns · 0 B · 0       | 142 ns · 0 B · 0      | −20% | — (stays 0-alloc) |

What changed (all in `internal/pipeline`):

1. **Matcher memo is now a stack-backed tri-state slice, not a map.** Each compiled
   matcher gets a **stable per-Pipeline index** (`matcher.idx`), assigned by a new
   `indexMatchers` pass at the end of `Compile` that walks every scope across all
   rule lists (a cheap pointer walk — `Compile` did not regress: ~27 µs / 889
   allocs). The memo becomes a `[]int8` (0=unknown/1=false/2=true) indexed by that
   idx. `matchContext.memo` is backed by a fixed stack array (`memoStack = 32`,
   covering ≤32-matcher sites with zero heap; a larger site spills the slice once).
2. **The `matchContext` no longer heap-escapes.** The `Eval*` methods build the
   context **inline** as a stack local (escape analysis confirms "does not escape"
   for all three) instead of via a `*matchContext`-returning helper. `EvalResponse`
   was already 0-alloc but is **20% faster** purely from the map-free memo path.
3. **Behavior identical.** Route resolution still uses its **own** memo (an
   `upstream` matcher is evaluated against upstream "" during routing, so that
   result must not leak into later phases). The cache key is byte-for-byte
   unchanged — the storefront golden tests (`internal/pipeline`, `internal/server`)
   and the full `go test ./... -race` stay green. Matchers defined but never
   referenced by a scope keep `idx = -1` and are evaluated uncached, so standalone
   matcher unit tests are unaffected.

The two remaining `EvalRequest` allocs are real output, not overhead: the
cache-key string (`buildKey` → `Builder.String()`) and the decision's
request-header-op slice (or the `Synthetic` for `respond`).

## Perf pass — round 2, 2026-06 (new features: zero-cost-when-unused audit + a fix)

This pass audits the session's new hot-path features — `classify`, `geo` (key
tokens + matcher + server pre-pass), `query_allow`, `query_present`, dynamic
header values (#17), and the purge/ban path — against two invariants:
**zero-cost-when-unused** (a config that uses none of them does
the same per-request work as the round-1 baseline) and **zero-extra-copy**. Same
machine/Go as the baseline (Apple M4 Pro, darwin/arm64, Go 1.26).

### Regression found and fixed: dynamic-header path re-escaped the match context

The D19 pass left `EvalRequest` at **2 allocs / 96 B** by building the per-request
`matchContext` inline on the stack (it must not escape). The dynamic-header
feature (#17) added `headerTemplateEnv`, which stored a **ctx-capturing closure**
(`env.classify = func(name){ … cl.resolve(ctx) … }`) on the returned
`*TemplateEnv`. Go's escape analysis is static: the closure path *existing* forced
`ctx` — and so the whole `matchContext` plus its stack-backed memo array — to the
heap on **every** `EvalRequest`/`EvalDeliver`, even for the overwhelming majority
of requests that fire no templated header. The storefront `EvalRequest/cacheable`
had silently regressed from **2 allocs / 96 B** (D19) to **3 allocs / 160 B**.

The fix (behavior-identical): the `{classify.NAME}` resolver is no longer a
closure stored on `TemplateEnv`. It is a small `classifyResolver` value
(`{ctx, classifiers}`) passed **by value** as a separate argument to
`expandTemplate`. A value copied through a call is never stored into a
heap-reachable location, so the match context stays on the stack. `expandTemplate`
is also built from a caller-owned stack `TemplateEnv` (filled in place by
`fillHeaderTemplateEnv`) rather than a `*TemplateEnv`-returning helper — a helper
returning a pointer forces the heap unconditionally. Escape analysis now confirms
`&matchContext{…} does not escape` for all three `Eval*` methods (it already did
for `EvalResponse`, which never calls `applyHeaderRules`).

| `EvalRequest` (storefront) | Before fix | After fix | Δ |
|----------------------------|-----------|-----------|---|
| `cacheable`     | 232 ns · 160 B · **3** | 200 ns · 96 B · **2** | −1 alloc, −40% B |
| `pass_ajax`     | 166 ns · 160 B · 3     | 141 ns · 96 B · 2     | −1 alloc |
| `route_static`  | 178 ns · 160 B · 3     | 156 ns · 96 B · 2     | −1 alloc |
| `respond`       | 80 ns · 120 B · 3      | 64 ns · 56 B · 2      | −1 alloc |
| `EvalRequestParallel` | 73 ns · 160 B · 3 | 51 ns · 96 B · 2 | −1 alloc, −30% time |
| `EvalResponse`  | 153 ns · 0 B · 0       | 144 ns · 0 B · 0      | (already 0-alloc) |

`EvalRequest` is back to the D19 baseline exactly. The two remaining allocs are
real output (the cache-key string + the request-header-op slice), not overhead.

### Zero-cost-when-unused, proven per feature

`feature_bench_test.go` compiles a **minimal baseline site** that uses none of the
new features and a one-feature variant for each. `EvalRequest` on every variant
matches the baseline's **2 allocs / 96 B** exactly — the feature adds **zero**
allocation to the request path when present but not exercised differently, and
contributes nothing at all when absent.

| Benchmark (per-request `EvalRequest`) | ns/op | B/op | allocs/op |
|---------------------------------------|------:|-----:|----------:|
| `FeatureBaseline` (no new feature)            | 126 | 96 | **2** |
| `FeatureClassify` ({tier} key token + table)  | 107 | 96 | **2** |
| `FeatureQueryAllow` (allowlist key token)     | 134 | 96 | **2** |
| `FeatureQueryPresent` (presence-OR matcher)   | 195 | 96 | **2** |
| `FeatureGeo` ({geo} key token + geo matcher)  |  80 | 96 | **2** |
| `FeatureDynHeaderUnusedReq` (classifiers compiled in, **static** headers) | 58 | 96 | **2** |

`FeatureDynHeaderUnusedReq` is the critical case the regression above broke: a
site that *declares* a `classify` (so the resolver machinery is compiled in) but
whose header ops are all static. It is back to the baseline 2 allocs — the
dynamic-header path costs nothing until a header value actually carries a
placeholder. (The per-feature ns/op differences are just rule-count noise across
the small configs; the alloc/B figures are the invariant and are identical.)

Server-side gates (no benchmark needed — they are simple `if` guards in
`internal/server/handler.go`, each verified by reading the code):

- **geo pre-pass** runs only when `site.Geo != nil && site.Pipeline.UsesGeoToken()`
  — `UsesGeoToken` is precomputed at Compile (`computeUsesGeo`) and false unless a
  geo key token or a `geo` matcher (named, inline, or inside a classify row) is
  referenced. A site with no geo does **zero** geo work (no client-IP resolution,
  no country/continent/region lookup) per request.
- **device pre-pass** runs only when `site.Device != nil && UsesDeviceToken()`.
- **ban / purge** is fully behind `if rd.Purge != nil`, reached only when a purge
  guard matched; the regex ban (`h.fresh.ban`) compiles only on an authorized
  purge with a non-empty bounded regex. A normal request never touches it.
- **cluster routing** is behind `if site.Cluster != nil`; a non-clustered site
  never enters it.

### Cost when used (bounded / reasonable)

| Path | Cost | Notes |
|------|------|-------|
| `classify` table eval | **0 extra allocs**, ~table-walk ns | first-match over the rows; row matchers memoize in the same stack context, so a matcher shared with other directives is evaluated once |
| `query_allow` / `query_present` | **0 extra allocs** | per-param exact-set / glob filter in place inside `writeCanonicalQuery` / the matcher; stack-backed key/value sort |
| `geo` matcher + `{geo}` token | **0 extra allocs** (pipeline side) | a map lookup over the upper-cased OR set; the server pre-pass (gated) resolves the class once per request, reused by every geo token/matcher |
| dynamic header (`EvalDeliver`, **templated** value) | 5 allocs · 216 B vs **2 allocs · 144 B** static | the +3 allocs/+72 B are the single-pass `strings.Builder` expansion of the placeholder(s); the stack `TemplateEnv` itself does not escape. Static header values stay at the same 2 allocs as before #17. |
| response-body transform (`replace`, V2e) | unchanged | deliver-phase, post-cache, size-bounded, skips Range/HEAD/encoded — zero-extra-copy fast path untouched (verified by reading `serveFromCache`/`serveOrigin`) |

`EvalDeliver` static-vs-templated is the only place a *used* feature adds
allocations, and it is bounded to the expansion of the actual placeholder values
on the delivery path (not the cache-key or large-body fast paths).

### Reproduce

```sh
go test ./internal/pipeline/ -run '^$' -bench 'EvalRequest|EvalResponse|BenchmarkFeature' -benchmem -count=10
# escape-analysis proof (all three Eval* must say "does not escape"):
go build -gcflags='-m' ./internal/pipeline/ 2>&1 | grep -E 'pipeline.go:(64|121|150):.*matchContext'
```

## Perf pass — round 3, 2026-06 (full server request path under concurrency)

Rounds 1–2 measured the **pure pipeline** (`EvalRequest`/`EvalResponse`) in
isolation. Round 3 audits the **whole `internal/server` serve path** end-to-end
through `Handler.ServeHTTP` (site selection → EvalRequest+key → freshness lookup →
RAM-tier serve → EvalDeliver → access-log/metrics/tracer seams), plus the cache I/O
hand-off and the offline `cadish edge build` projection. New benchmarks ship in
`internal/server/bench_test.go` (full `ServeHTTP` HIT/MISS through a `discardRW`
that isolates the *handler's* allocations from httptest's recorder) and
`internal/edgeir/bench_test.go`. Same machine/Go as the baseline (Apple M4 Pro,
darwin/arm64, Go 1.26).

### The big find: every RAM HIT allocated a 32 KiB throwaway buffer

`serveFromCache` ends in `io.Copy(rec, reader)` where `reader` is a `*cache.Reader`.
`io.Copy` uses the source's `WriteTo` when present to avoid its 32 KiB scratch
buffer — and the RAM tier's content reader (`*bytes.Reader`, via `io.NopCloser`)
**does** implement `WriteTo`. But `cache.Reader` *embeds the `io.ReadCloser`
interface*, whose method set is only `Read`/`Close`: `WriteTo` is **not promoted**,
so `io.Copy(dst, reader)` saw no `WriterTo` and fell back to its buffered loop —
**allocating a fresh 32 KiB buffer on every single HIT**, scaling GC pressure with
the cache's hit rate (the hottest path in the whole proxy).

Two behavior-identical fixes restored the zero-copy hand-off:

1. **`cache.Reader.WriteTo` delegator** (`internal/cache/cache.go`) — forwards to
   the underlying reader's `WriteTo` when it has one (RAM `*bytes.Reader`, disk
   `*os.File`), else a plain buffered copy from the *embedded* reader (never `r`
   itself — that would recurse). `io.Copy` now finds `WriterTo` on `*cache.Reader`
   and hands the whole object off in one shot.
2. **`bytesReadCloser`** (`internal/cache/ram.go`) — the RAM tier handed out
   `io.NopCloser(bytes.NewReader(data))` = **two** allocations (the `*bytes.Reader`
   + the nop-closer wrapper). It now returns one `*bytesReadCloser` holding a
   `bytes.Reader` **by value**, forwarding `Read`/`WriteTo` and a no-op `Close`.
   One allocation instead of two, and it carries `WriteTo` through.
3. **Skip `url.ParseQuery` for query-less requests** (`buildPipelineRequest`) —
   `ParseQuery("")` still allocates an empty `url.Values` map; every pipeline
   consumer treats a nil Query as "no params". The vast majority of cache GETs
   carry no query, so this drops one alloc from the common path.

| Benchmark | Before | After | Δ |
|-----------|--------|-------|---|
| `ServeHTTPHit/1KiB`  (full HIT serve) | 5087 ns · 33625 B · **19 allocs** | 1478 ns · **752 B** · **16 allocs** | **−71% time, −98% B, −3 allocs** |
| `ServeHTTPHit/64KiB` (full HIT serve) | 5348 ns · 33628 B · 19 allocs | 1610 ns · **752 B** · 16 allocs | −70% time, −98% B (HIT B is now object-size-independent) |
| `ServeHTTPHitParallel` (−4 cpu)       | 6304 ns · 33758 B · 19 allocs | 538 ns · 752 B · 16 allocs | per-HIT 32 KiB buffer + its GC churn gone |
| `cache StoreGetRAM/1KiB`              | 152 ns · 160 B · **3 allocs** | 120 ns · 160 B · **2 allocs** | −1 alloc (NopCloser+bytes.Reader → one bytesReadCloser) |
| `cache StoreGetRAM/64KiB`            | 1219 ns · 160 B · 3 allocs | 101 ns · 160 B · 2 allocs | drain now zero-copy via WriteTo |

The post-fix HIT B/op (**752 B**) is now **independent of object size** — the only
per-HIT allocations are real output (the response-header `Set`s, the cache-key
string, the `cache.Reader` + `bytesReadCloser`, the EvalDeliver header-op slice, the
access-log slog line). The 32 KiB-per-HIT buffer that scaled with traffic is gone.

### Full ServeHTTP numbers (post-fix)

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|------:|-----:|----------:|-------|
| `ServeHTTPHit/1KiB`        | 1478 | 752 | 16 | full HIT: select+EvalRequest+key+freshness+RAM serve+EvalDeliver+log |
| `ServeHTTPHit/1KiB-4`      | 1226 | 752 | 16 | scales (work parallelizes) |
| `ServeHTTPHit/64KiB`       | 1610 | 752 | 16 | B/op size-independent (zero-copy body) |
| `ServeHTTPHitParallel`     | 1540 | 752 | 16 | 1 cpu |
| `ServeHTTPHitParallel-4`   |  538 | 752 | 16 | −65% — clean concurrency scaling, no lock cliff |
| `ServeHTTPMiss`            | ~116 k | 47032 | 117 | dominated by the in-process loopback HTTP round-trip, **not** handler overhead; the handler's own per-MISS allocs are the origin header copy in/out + the tee + the freshness store |

`ServeHTTPMiss` ns/op rises at `-4` because the *single in-process httptest origin*
contends, not the handler — the MISS alloc count is what matters and it is steady.

### Concurrency / contention audit

- **Freshness index** is 64 shards, each a `sync.Mutex` + map. `lookup` takes an
  exclusive lock (it may prune an expired entry), so a single-key hammer contends
  (`FreshnessLookup`: 48→93 ns 1→4 cpu). But realistic traffic spreads keys across
  shards: `FreshnessLookupSpread` (4096 keys) **scales the right way** — 70→31 ns as
  cpu rises (near-linear), confirming no global-mutex cliff. No fix warranted; the
  sharding already does its job. (A RWMutex read-fast-path for the fresh case was
  considered and rejected: it adds complexity for a win only on the pathological
  same-key workload, which real traffic never sustains.)
- **Cache RAM tier** is already per-shard locked (round-1 verified); the WriteTo
  fix removed the per-HIT buffer alloc without touching the lock domains.
- **Coalescer / bg single-flight** locks are touched only on a MISS / origin
  result, never on a HIT — off the hot path entirely.
- **Metrics + tracer seams**: re-confirmed nil-safe no-ops (every method early-returns
  on a nil receiver); the BAN check on lookup is a single lock-free `atomic.Int64`
  load when no ban is active (`banned()` fast path) — zero datapath cost, verified
  by reading `freshness.banned` and by the alloc-free `FreshnessLookup`.

### Goroutine / memory hygiene

Reviewed (no leak found): the idle-stall **sweeper** is one process-wide goroutine
started lazily, stopped on `Shutdown`; readers register on wrap and deregister on
any terminal Read error or Close (idempotent `sync.Once`). **Background grace
revalidation** spawns at most one goroutine per stale key (coalesced by
`singleFlight`, released via `defer h.bg.end(key)`) on a detached, timeout-bounded
context. The coalescer and bg maps delete their entry on finish/end; the freshness
map prunes expired entries on access (bounded by live-key cardinality, same as the
cache). lb health/resolve workers are bound to the serving context and cancelled on
`Shutdown`. All of `go test ./... -race` stays green.

### `cadish edge build` (offline — sanity only)

Not on the request path (a per-reload projection). `Project` on the realistic
storefront site is **~5.5 µs / 69 allocs**; a synthetic 200-rule site projects in
**~186 µs / 2026 allocs** (≈10 allocs/rule — linear, not pathological). Fine for an
offline operation.

### Reproduce

```sh
go test ./internal/server/ -run '^$' -bench 'ServeHTTP|Freshness' -benchmem -cpu=1,4
go test ./internal/cache/  -run '^$' -bench 'StoreGetRAM' -benchmem
go test ./internal/edgeir/ -run '^$' -bench 'Project' -benchmem
```
