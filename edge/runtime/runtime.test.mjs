// runtime.test.mjs — plain-Node tests for the edge IO layer (entry + cache-tiers
// + origin), driven by mock Cache API / KV / fetch and a real generated IR. No
// dependencies (runs anywhere node does). Covers: MISS→store→HIT, SWR over grace,
// expiry, the security invariant (never cache Set-Cookie), pass bypass, synthetic
// respond, redirect, stale-on-error salvage, and cache-status header materialization.
//
// Usage: node edge/runtime/runtime.test.mjs
// (Miniflare adds real Cache-API/KV binding fidelity in edge/runtime/worker.test.js;
// this harness covers the orchestration logic and is the dependency-free CI gate.)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert";
import { handle } from "./entry.js";
import { EdgeCache } from "./cache-tiers.js";
import { fetchOrigin, EDGE_TRUST_HEADERS } from "./origin.js";

const here = dirname(fileURLToPath(import.meta.url));
const genDir = join(here, "..", "..", "test", "conformance", "generated");
const IR = JSON.parse(readFileSync(join(genDir, "01-storefront.ir.json"), "utf8"));
const EDGE_IR = JSON.parse(readFileSync(join(genDir, "06-edge-tiers.ir.json"), "utf8"));
// OUTAGE_IR carries `respond on_error @api 503`, `cache_ttl status 404 410` (negative
// cache) and `cache_ttl status 200 … max_stale 24h`, used by the Fix #2 origin-returned-5xx
// integration tests (the worker must run the handleOriginError precedence on a RETURNED 5xx).
const OUTAGE_IR = JSON.parse(readFileSync(join(genDir, "26-origin-returned-5xx.ir.json"), "utf8"));
const COOKIE_ALLOW_IR = JSON.parse(readFileSync(join(genDir, "32-cookie-allow.ir.json"), "utf8"));
// 33 keys on the WHOLE Cookie header (`cache_key host path header:Cookie`) with
// `cookie_allow sess` + `cache_ttl default ttl 60s grace 1h` — used to pin (H1) that the
// edge key reads the FILTERED cookie (so stripped cookies don't fragment it) and (M1) that
// cookie_allow traffic is re-stored on SWR revalidation.
const COOKIE_ALLOW_HDR_IR = JSON.parse(readFileSync(join(genDir, "33-cookie-allow-header-cookie.ir.json"), "utf8"));
// 35 allow-lists `session` but does NOT key it (default key) — used to pin that the edge
// BYPASSES an allow-listed-but-unkeyed cookie (a kept cookie must be keyed to cache).
const COOKIE_ALLOW_UNKEYED_IR = JSON.parse(readFileSync(join(genDir, "35-cookie-allow-unkeyed.ir.json"), "utf8"));

// --- mocks ------------------------------------------------------------------

class MockCache {
  constructor() {
    this.map = new Map();
  }
  async put(req, res) {
    const body = await res.arrayBuffer();
    this.map.set(req.url, { status: res.status, headers: [...res.headers], body });
  }
  async match(req) {
    const e = this.map.get(req.url);
    if (!e) return undefined;
    return new Response(e.body, { status: e.status, headers: e.headers });
  }
}

class MockKV {
  constructor() {
    this.m = new Map();
    this.puts = []; // every put({ key, expirationTtl }), for assertions
  }
  async put(k, v, opts) {
    const buf = v instanceof ArrayBuffer ? v : await new Response(v).arrayBuffer();
    const expirationTtl = (opts && opts.expirationTtl) || 0;
    this.puts.push({ key: k, expirationTtl });
    // Record an absolute wall-clock expiry so getWithMetadata can model TTL-only
    // eviction (KV deletes the blob once expirationTtl elapses). storedAt is the
    // edge's own metadata clock, which the tests advance via the injected now().
    const storedAt = (opts && opts.metadata && opts.metadata.storedAt) || 0;
    this.m.set(k, { v: buf, metadata: (opts && opts.metadata) || null, storedAt, expirationTtl });
  }
  // getWithMetadata models KV retention: if `nowMs` is supplied and the entry's
  // expirationTtl window has elapsed since storedAt, the blob is gone (auto-deleted)
  // — this is the TTL-only invalidation path (there is no purge/epoch).
  async getWithMetadata(k, _opts, nowMs) {
    const e = this.m.get(k);
    if (!e) return { value: null, metadata: null };
    if (typeof nowMs === "number" && e.expirationTtl > 0 && nowMs - e.storedAt >= e.expirationTtl * 1000) {
      this.m.delete(k);
      return { value: null, metadata: null };
    }
    return { value: e.v, metadata: e.metadata };
  }
}

function mockCtx() {
  const tasks = [];
  return {
    waitUntil(p) {
      tasks.push(p);
    },
    async drain() {
      await Promise.all(tasks);
    },
  };
}

// originStub returns a fetch impl yielding a fixed response; counts calls.
function originStub(status, headers, body = "BODY") {
  const stub = async () => new Response(body, { status, headers });
  stub.calls = 0;
  const counted = async (...a) => {
    counted.calls++;
    return stub(...a);
  };
  counted.calls = 0;
  return counted;
}

function req(path, init = {}) {
  return new Request("https://example.com" + path, init);
}

// prime issues a request and drains its deferred (waitUntil) cache writes, so a
// subsequent request observes the stored entry (mirrors a settled isolate).
async function prime(path, opts) {
  const ctx = mockCtx();
  const r = await handle(req(path), {}, ctx, opts);
  await ctx.drain();
  return r;
}

// --- test harness -----------------------------------------------------------

let clock = { t: 1_000_000 };
function freshCache(distribute = false, opts = {}) {
  return new EdgeCache({
    cache: new MockCache(),
    kv: new MockKV(),
    distribute,
    now: () => clock.t,
    kvTtlSeconds: opts.kvTtlSeconds || 0,
    kvMaxBytes: opts.kvMaxBytes || 0,
  });
}

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push({ name, err: e });
    console.error(`✗ ${name}\n  ${e.stack || e.message}`);
  }
}

// --- tests ------------------------------------------------------------------

await test("MISS then HIT (store in L1, second read is fresh)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const ctx = mockCtx();
  const r1 = await handle(req("/catalog/a"), {}, ctx, { ir: IR, cache, fetchImpl, originBase: "http://o" });
  await ctx.drain();
  assert.equal(r1.headers.get("X-Cache"), "MISS");
  assert.equal(r1.headers.get("Server"), null, "Server header should be removed");
  assert.equal(fetchImpl.calls, 1);

  const r2 = await handle(req("/catalog/a"), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "HIT");
  assert.equal(fetchImpl.calls, 1, "a fresh HIT must not hit the origin again");
});

await test("cookie_allow: edge strips non-allowed cookies (origin never sees the session) and caches per allowed cookie", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const seen = [];
  // fetchOrigin calls doFetch(urlString, init) — the forwarded Cookie is in
  // init.headers (a Headers built from the request + the cookie_allow header op),
  // not in the first arg (a plain URL string). Read it from there.
  const fetchImpl = Object.assign(
    async (_url, init) => {
      seen.push((init && init.headers && init.headers.get("Cookie")) || "");
      return new Response("body", { status: 200, headers: { "Content-Type": "text/html" } });
    },
    { calls: 0 },
  );
  const deps = { ir: COOKIE_ALLOW_IR, cache, fetchImpl, originBase: "http://o" };

  // lang is allow-listed and keyed; session is stripped before the key AND the origin.
  const ctxA = mockCtx();
  const ra = await handle(req("/page", { headers: { Cookie: "lang=es; session=AAA; _ga=X" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(ra.headers.get("X-Cache"), "MISS", "first lang=es request is a cacheable MISS");

  // The origin must have received ONLY lang=es — never the session or _ga.
  const last = seen[seen.length - 1];
  assert.ok(!/session/.test(last), `origin saw a stripped cookie: ${last}`);
  assert.ok(!/_ga/.test(last), `origin saw a stripped cookie: ${last}`);
  assert.ok(/lang=es/.test(last), `origin should still receive lang=es, got: ${last}`);

  // A DIFFERENT session with the same lang shares the safe generic entry (HIT).
  const rb = await handle(req("/page", { headers: { Cookie: "lang=es; session=BBB" } }), {}, mockCtx(), deps);
  assert.equal(rb.headers.get("X-Cache"), "HIT", "same lang shares the entry regardless of session");
});

await test("cookie_allow + header:Cookie: the edge key reads the FILTERED cookie (parity with the server)", async () => {
  // H1 regression: with `cache_key … header:Cookie`, the edge must key on the cookie_allow-
  // FILTERED header, not the raw one — so two requests sharing the allow-listed cookie but
  // differing in a stripped cookie collide on one entry (as on the server), and the origin
  // only ever sees the allow-listed cookie.
  clock.t = 1_000_000;
  const cache = freshCache();
  const seen = [];
  const fetchImpl = Object.assign(
    async (_url, init) => {
      seen.push((init && init.headers && init.headers.get("Cookie")) || "");
      return new Response("body", { status: 200, headers: { "Content-Type": "text/html" } });
    },
    { calls: 0 },
  );
  const deps = { ir: COOKIE_ALLOW_HDR_IR, cache, fetchImpl, originBase: "http://o" };

  const ctxA = mockCtx();
  const ra = await handle(req("/page", { headers: { Cookie: "sess=AAA; track=1" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(ra.headers.get("X-Cache"), "MISS", "first request is a cacheable MISS");
  assert.equal(seen[seen.length - 1], "sess=AAA", "origin must see ONLY the allow-listed cookie");

  // Same sess, DIFFERENT stripped cookie → same filtered key → HIT (no fragmentation).
  const rb = await handle(req("/page", { headers: { Cookie: "sess=AAA; track=2" } }), {}, mockCtx(), deps);
  assert.equal(rb.headers.get("X-Cache"), "HIT", "a differing STRIPPED cookie must not change the key");
});

await test("cookie_allow: an allow-listed but UNKEYED cookie bypasses the edge cache (no cross-user store)", async () => {
  // The kept `session` cookie is forwarded to origin but the key does NOT capture it, so the
  // edge must bypass — never store user A's session body under a session-agnostic key.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const deps = { ir: COOKIE_ALLOW_UNKEYED_IR, cache, fetchImpl, originBase: "http://o" };

  const ctxA = mockCtx();
  await handle(req("/page", { headers: { Cookie: "session=AAA" } }), {}, ctxA, deps);
  await ctxA.drain();
  // A different session: if the first had been stored, this would HIT it (a leak). It must MISS.
  const b = await handle(req("/page", { headers: { Cookie: "session=BBB" } }), {}, mockCtx(), deps);
  assert.equal(b.headers.get("X-Cache"), "MISS", "an unkeyed allow-listed cookie must bypass, not HIT a stored entry");
  assert.equal(fetchImpl.calls, 2, "both unkeyed-cookie requests bypass to origin (nothing cached cross-user)");
});

await test("cookie_allow: SWR revalidation re-stores the entry (post-grace requests stay cached)", async () => {
  // M1 regression: a cookie_allow request stores on MISS, and once stale-within-grace the
  // revalidate path must RE-STORE (it is exempt from the credential bypass) — otherwise every
  // post-grace request would be a perpetual MISS, diverging from the Go server.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const deps = { ir: COOKIE_ALLOW_HDR_IR, cache, fetchImpl, originBase: "http://o" };

  const a = await prime("/page", { ...deps, ir: COOKIE_ALLOW_HDR_IR });
  assert.equal(a.headers.get("X-Cache"), "MISS");
  assert.equal(fetchImpl.calls, 1);

  // Advance past ttl (60s) into grace → stale: served HIT-STALE and revalidated behind it.
  clock.t += 120_000;
  const ctxB = mockCtx();
  const b = await handle(req("/page"), {}, ctxB, deps);
  assert.equal(b.headers.get("X-Cache"), "HIT-STALE", "within grace, serve stale + revalidate");
  await ctxB.drain(); // let the SWR revalidation (and re-store) settle
  assert.equal(fetchImpl.calls, 2, "revalidation hit the origin once");

  // The re-store refreshed the entry: a request right after is fresh again (HIT, no origin).
  const c = await handle(req("/page"), {}, mockCtx(), deps);
  assert.equal(c.headers.get("X-Cache"), "HIT", "the revalidated entry was re-stored fresh");
  assert.equal(fetchImpl.calls, 2, "a fresh HIT must not re-hit the origin");
});

await test("security: a Cookie request bypasses the edge cache (never stored/served cross-user)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  // First, an anonymous request primes the cache for /catalog/a.
  const a = await prime("/catalog/a", { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(a.headers.get("X-Cache"), "MISS");
  // A cookie-bearing request must NOT be served the cached anonymous entry, and must
  // NOT store its own (credentialed) response — it bypasses to origin every time.
  const c1 = await handle(req("/catalog/a", { headers: { Cookie: "session=AAA" } }), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(c1.headers.get("X-Cache"), "MISS", "a Cookie request must bypass the edge cache");
  assert.equal(fetchImpl.calls, 2, "the cookie request must reach origin (not served from cache)");
  // An Authorization request likewise bypasses.
  await handle(req("/catalog/a", { headers: { Authorization: "Bearer T" } }), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(fetchImpl.calls, 3, "the Authorization request must reach origin too");
});

await test("SWR: stale-within-grace serves HIT-STALE and revalidates in background", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  await prime("/catalog/b", { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(fetchImpl.calls, 1);
  // ttl 2s; advance 5s -> within 24h grace -> stale.
  clock.t += 5_000;
  const ctx = mockCtx();
  const r = await handle(req("/catalog/b"), {}, ctx, { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.headers.get("X-Cache"), "HIT-STALE");
  await ctx.drain();
  assert.equal(fetchImpl.calls, 2, "stale serve must trigger a background revalidation");
});

await test("expired beyond grace is a miss (origin re-fetched)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  await prime("/catalog/c", { ir: IR, cache, fetchImpl, originBase: "http://o" });
  clock.t += 25 * 3600 * 1000; // > ttl(2s)+grace(24h)
  const r = await handle(req("/catalog/c"), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.headers.get("X-Cache"), "MISS");
  assert.equal(fetchImpl.calls, 2);
});

// Fix #7: the freshness/max_stale boundaries are STRICT `<` to mirror the Go server
// (freshness.go: now.Before(expires)/Before(graceUntil)/Before(maxStaleUntil)). At
// EXACTLY age==ttl the Go server is already stale (not fresh); at age==ttl+grace it is a
// miss; at age==ttl+grace+max_stale the salvage marker is gone. The edge must agree on the
// instantaneous boundary tick. We drive EdgeCache._state / _withinMaxStale directly with a
// controllable clock for deterministic boundary checks.
await test("Fix #7: freshness + max_stale boundaries are strict (< not <=), matching Go", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const meta = { storedAt: clock.t, ttlMs: 10, graceMs: 20, maxStaleMs: 30 }; // expires +10, grace +30, maxStale +60
  // age 0..9 fresh; age 10 (==ttl) is STALE (Go is past expires); age 9 still fresh.
  assert.equal(cache._state({ ...meta }), "fresh", "age 0 is fresh");
  clock.t = 1_000_000 + 9;
  assert.equal(cache._state(meta), "fresh", "age 9 (<ttl) is fresh");
  clock.t = 1_000_000 + 10;
  assert.equal(cache._state(meta), "stale", "age==ttl is STALE (strict <, matching Go)");
  clock.t = 1_000_000 + 29;
  assert.equal(cache._state(meta), "stale", "age 29 (<ttl+grace) is stale");
  clock.t = 1_000_000 + 30;
  assert.equal(cache._state(meta), "miss", "age==ttl+grace is MISS (strict <, matching Go)");
  // _withinMaxStale: salvageable while age < ttl+grace+maxStale (==60); at exactly 60 it is gone.
  clock.t = 1_000_000 + 59;
  assert.equal(cache._withinMaxStale(meta), true, "age 59 (<ceiling) is salvageable");
  clock.t = 1_000_000 + 60;
  assert.equal(cache._withinMaxStale(meta), false, "age==ttl+grace+maxStale is NOT salvageable (strict <, matching Go)");
});

// Fix #2: an origin that RETURNS a hard-failure status (5xx) — the common
// flapping/maintenance shape, where fetch RESOLVES with a Response rather than throwing —
// must be treated by the worker as an origin FAILURE and run the SAME precedence the Go
// server's handleOriginError applies (max_stale salvage > negative cache > on_error > bare
// status), NOT forwarded raw. These drive the real handle() path with OUTAGE_IR.
function shopReq(path, init = {}) {
  return new Request("https://shop.example.com" + path, init);
}

await test("Fix #2: returned 503 on a matching scope serves the on_error synthetic (not raw 503)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(503, {}, "upstream boom");
  const r = await handle(shopReq("/api/users"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 503, "on_error @api status");
  assert.equal(await r.text(), "api maintenance", "served the configured maintenance page, not the raw upstream body");
});

await test("Fix #2: returned 500 with no on_error match forwards the bare upstream status (not 502)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(500, {}, "boom");
  const r = await handle(shopReq("/home"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 500, "the bare RETURNED status is forwarded (Go writeStatus(code)), not a synthetic 502");
});

await test("Fix #2: returned 503 is salvaged from a within-max_stale cached copy (HIT-STALE-ERROR)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  // Prime a good 200 copy at /api/users (under the shop host so the cache key matches the
  // salvage request), then advance past grace but within max_stale.
  const ok = originStub(200, { "Content-Type": "text/html" }, "GOOD");
  const pctx = mockCtx();
  await handle(shopReq("/api/users"), {}, pctx, { ir: OUTAGE_IR, cache, fetchImpl: ok, originBase: "http://o" });
  await pctx.drain();
  clock.t += 10 * 3600 * 1000; // ttl 1m + grace 5m < age < +24h max_stale
  const boom = originStub(503, {}, "boom");
  const r = await handle(shopReq("/api/users"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 200, "salvaged the last-good copy");
  assert.equal(await r.text(), "GOOD", "served the stale body, not the 503");
  // max_stale salvage OUTRANKS the on_error synthetic (the whole point of D60/D76).
});

await test("Fix #2: returned 404 is negatively cached + served (not on_error, not 502)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(404, {}, "not here");
  const r = await handle(shopReq("/api/users"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 404, "a returned 404 is served as 404 (negative cache), never the on_error synthetic");
  assert.equal(await r.text(), "not here", "served the origin's 404 body");
});

// A RETURNED 4xx that is NOT 404/410 (403/429/405/401) is a *StatusError in Go
// (httporigin.negativeStatus is ONLY 404||410), so it MUST take handleOriginError's
// hard-failure chain — NOT a Negative response and NOT a normal MISS. Pinned against the
// real Go server in internal/server TestOnErrorReturned4xx*; the edge must mirror it.
await test("Fix A: returned 403 on a matching scope serves the on_error synthetic (not raw 403)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(403, {}, "forbidden page");
  const r = await handle(shopReq("/api/users"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 503, "a returned 403 takes the StatusError chain → on_error fires");
  assert.equal(await r.text(), "api maintenance", "served the maintenance page, not the raw 403 body");
});

await test("Fix A: returned 429 with no on_error match forwards the bare upstream status (not 502)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(429, {}, "rate limited");
  const r = await handle(shopReq("/home"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 429, "the bare RETURNED status is forwarded (Go writeStatus(code)), not 502 and not normal MISS");
});

await test("Fix A: returned 403 is salvaged from a within-max_stale cached copy (HIT-STALE-ERROR)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ok = originStub(200, { "Content-Type": "text/html" }, "GOOD");
  const pctx = mockCtx();
  await handle(shopReq("/api/users"), {}, pctx, { ir: OUTAGE_IR, cache, fetchImpl: ok, originBase: "http://o" });
  await pctx.drain();
  clock.t += 10 * 3600 * 1000; // past grace, within 24h max_stale
  const boom = originStub(403, {}, "forbidden");
  const r = await handle(shopReq("/api/users"), {}, mockCtx(), { ir: OUTAGE_IR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 200, "max_stale salvage of the last-good copy beats on_error on a returned 403");
  assert.equal(await r.text(), "GOOD", "served the stale body, not the 403");
});

await test("security invariant: a Set-Cookie response is NEVER cached", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html", "Set-Cookie": "sid=secret; Path=/" });
  await prime("/catalog/d", { ir: IR, cache, fetchImpl, originBase: "http://o" });
  const r2 = await handle(req("/catalog/d"), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "MISS", "Set-Cookie responses must not be stored");
  assert.equal(fetchImpl.calls, 2);
});

await test("strip_cookies makes a Set-Cookie response cacheable (stored without the cookie)", async () => {
  // 01-storefront strips cookies on `path_regex \.(css|js|png)$`. A .css response that
  // carries Set-Cookie is the Varnish `unset beresp.http.Set-Cookie` case: the cookie is
  // dropped before store, so the response caches AND the served copy carries no cookie.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/css", "Set-Cookie": "sid=secret; Path=/" });
  const r1 = await prime("/assets/app.css", { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r1.headers.get("X-Cache"), "MISS", "first .css request is a cacheable MISS");
  assert.equal(r1.headers.get("Set-Cookie"), null, "the stripped cookie must never be delivered");
  const r2 = await handle(req("/assets/app.css"), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "HIT", "the cookie-stripped .css is served from cache");
  assert.equal(r2.headers.get("Set-Cookie"), null, "the cached copy carries no cookie");
  assert.equal(fetchImpl.calls, 1, "the second request is served from cache, origin hit once");
});

await test("edge forwards the CANONICAL Host to origin (key↔forward agree; no Host poison)", async () => {
  // The edge cache key normalizes the host (strip :port, trailing FQDN dot), so the Host
  // forwarded to origin MUST be normalized too — else example.com / example.com:1337 /
  // example.com. collapse onto one key while the origin sees three Hosts (poison).
  clock.t = 1_000_000;
  const cache = freshCache();
  const seenHosts = [];
  const fetchImpl = async (_url, init) => {
    seenHosts.push((init && init.headers && init.headers.get("Host")) || "");
    return new Response("body", { status: 200, headers: { "Content-Type": "text/html" } });
  };
  const deps = { ir: IR, cache, fetchImpl, originBase: "http://o" };

  // A trailing-dot Host (trivially injectable) must forward the canonical host.
  const ctxA = mockCtx();
  await handle(new Request("https://example.com./catalog/a"), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(seenHosts[seenHosts.length - 1], "example.com", "trailing-dot host must forward canonical example.com");
  assert.equal(seenHosts.length, 1, "exactly one origin fetch so far");

  // The bare host shares the (same normalized) entry — a HIT, origin never re-hit.
  const r2 = await handle(req("/catalog/a"), {}, mockCtx(), deps);
  assert.equal(r2.headers.get("X-Cache"), "HIT", "bare host shares the canonical key");
  assert.equal(seenHosts.length, 1, "no second origin fetch under a divergent Host");

  // A :port variant also forwards the canonical host (no fork).
  const r3 = await handle(new Request("https://example.com:1337/catalog/a"), {}, mockCtx(), deps);
  assert.equal(r3.headers.get("X-Cache"), "HIT", ":port host shares the canonical key");
  assert.equal(seenHosts.length, 1, ":port host did not fork the cache / re-hit origin");
});

await test("pass bypasses the cache (POST)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  await handle(req("/cart", { method: "POST" }), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  await handle(req("/cart", { method: "POST" }), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(fetchImpl.calls, 2, "pass must always reach the origin");
});

await test("synthetic respond short-circuits", async () => {
  const cache = freshCache();
  const fetchImpl = originStub(500, {});
  const r = await handle(req("/health-check"), {}, mockCtx(), { ir: IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 200);
  assert.equal(await r.text(), "OK");
  assert.equal(fetchImpl.calls, 0, "a synthetic response must not touch the origin");
});

await test("stale-within-grace serves HIT-STALE without touching the origin", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ok = originStub(200, { "Content-Type": "text/html" }, "CACHED");
  await prime("/catalog/e", { ir: IR, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 5 * 3600 * 1000; // expired past ttl(2s) but within the 24h grace
  const boom = async () => {
    throw new Error("origin down");
  };
  // Within grace, the lookup is "stale" → served HIT-STALE directly (SWR revalidates in
  // the background); origin health is irrelevant here.
  const r = await handle(req("/catalog/e"), {}, mockCtx(), { ir: IR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 200);
  assert.equal(await r.text(), "CACHED");
  assert.equal(r.headers.get("X-Cache"), "HIT-STALE");
});

await test("stale-on-error is BOUNDED by max_stale: no salvage past ttl+grace when max_stale is unset (D70)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ok = originStub(200, { "Content-Type": "text/html" }, "CACHED");
  await prime("/catalog/e", { ir: IR, cache, fetchImpl: ok, originBase: "http://o" });
  // storefront's default rule is ttl 2s + grace 24h + NO max_stale. Advance past grace:
  // the edge must NOT serve an unboundedly-old copy on origin failure (it used to).
  clock.t += 25 * 3600 * 1000; // beyond ttl+grace, no max_stale window
  const boom = async () => {
    throw new Error("origin down");
  };
  const r = await handle(req("/catalog/e"), {}, mockCtx(), { ir: IR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 502, "a copy older than ttl+grace with no max_stale must NOT be salvaged");
});

await test("stale-on-error within max_stale salvages a past-grace copy (D70)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  // A small synthetic IR: ttl 1s, grace 1s, max_stale 24h — so a copy past grace but
  // within max_stale is salvageable, while one past max_stale is not.
  const msIR = {
    irVersion: 4,
    site: { hosts: ["example.com"] },
    upstream: {},
    matchers: {},
    recv: {},
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "1s", grace: "1s", maxStale: "24h" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const ok = originStub(200, { "Content-Type": "text/html" }, "CACHED");
  await prime("/ms", { ir: msIR, cache, fetchImpl: ok, originBase: "http://o" });
  const boom = async () => {
    throw new Error("origin down");
  };
  // Past grace (2s) but within max_stale (24h): salvageable.
  clock.t += 3 * 3600 * 1000;
  const within = await handle(req("/ms"), {}, mockCtx(), { ir: msIR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(within.status, 200, "a past-grace copy within max_stale must be salvaged");
  assert.equal(within.headers.get("X-Cache"), null); // msIR has no +cache_status header
  // Beyond max_stale: refused.
  clock.t += 30 * 3600 * 1000; // now well past ttl+grace+max_stale
  const beyond = await handle(req("/ms"), {}, mockCtx(), { ir: msIR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(beyond.status, 502, "a copy older than ttl+grace+max_stale must NOT be salvaged");
});

await test("origin failure with no cached copy returns 502", async () => {
  const cache = freshCache();
  const boom = async () => {
    throw new Error("origin down");
  };
  const r = await handle(req("/catalog/never-seen"), {}, mockCtx(), { ir: IR, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 502);
});

// --- D76: respond on_error edge-native outage path -------------------------

// A small IR with a scoped + a catch-all-less on_error so we can exercise match,
// no-match (bare 502), and precedence (salvage wins).
function onErrorIR() {
  return {
    irVersion: 4,
    site: { hosts: ["example.com"] },
    upstream: {},
    matchers: { api: { kind: "path", patterns: ["/api/*"] } },
    recv: {},
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: {
      ttl: [{ selKind: "default", ttl: "1s", grace: "1s", maxStale: "24h" }],
      onError: [{ scope: { names: ["api"] }, status: 503, body: "api down for maintenance", contentType: "text/html; charset=utf-8" }],
    },
    deliver: {},
    edge: { default: "local" },
  };
}

await test("D76: origin failure on a matching scope serves the on_error synthetic (not 502)", async () => {
  const cache = freshCache();
  const boom = async () => {
    throw new Error("origin down");
  };
  const r = await handle(req("/api/users"), {}, mockCtx(), { ir: onErrorIR(), cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 503, "a matching respond on_error must serve its synthetic, not a bare 502");
  assert.equal(await r.text(), "api down for maintenance");
  assert.equal(r.headers.get("Content-Type"), "text/html; charset=utf-8");
});

await test("D76: origin failure on a non-matching scope falls back to a bare 502", async () => {
  const cache = freshCache();
  const boom = async () => {
    throw new Error("origin down");
  };
  const r = await handle(req("/home"), {}, mockCtx(), { ir: onErrorIR(), cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 502, "no matching on_error rule → bare 502");
});

await test("D76: a salvageable stale copy WINS over respond on_error (precedence)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = onErrorIR();
  const ok = originStub(200, { "Content-Type": "text/html" }, "STALE-BUT-REAL");
  await prime("/api/users", { ir, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 3 * 3600 * 1000; // past grace(1s), within max_stale(24h) → salvageable
  const boom = async () => {
    throw new Error("origin down");
  };
  const r = await handle(req("/api/users"), {}, mockCtx(), { ir, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 200, "a real (if stale) copy within max_stale must beat the on_error synthetic");
  assert.equal(await r.text(), "STALE-BUT-REAL");
});

// --- D75: edge-native bounded `replace` body transform ----------------------

function replaceIR() {
  return {
    irVersion: 4,
    site: { hosts: ["example.com"] },
    upstream: {},
    matchers: { html: { kind: "content_type", contentTypes: ["text/html"], responsePhase: true } },
    recv: {},
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: {
      ttl: [{ selKind: "default", ttl: "60s" }],
      transforms: [{ scope: { names: ["html"] }, old: "__TITLE__", new: "Welcome" }],
      transformMaxBytes: 1 << 20,
    },
    deliver: {},
    edge: { default: "local" },
  };
}

await test("D75: replace transforms a within-cap HTML body on delivery", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" }, "<h1>__TITLE__</h1> and __TITLE__");
  const r = await handle(req("/p"), {}, mockCtx(), { ir: replaceIR(), cache, fetchImpl, originBase: "http://o" });
  assert.equal(await r.text(), "<h1>Welcome</h1> and Welcome");
});

await test("D75: replace is skipped for an already-encoded body (passes through)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" }, "__TITLE__ stays raw");
  const r = await handle(req("/enc"), {}, mockCtx(), { ir: replaceIR(), cache, fetchImpl, originBase: "http://o" });
  assert.equal(await r.text(), "__TITLE__ stays raw", "an encoded body must not be transformed");
});

await test("D75: an over-cap body passes through UNTRANSFORMED (server-only non-goal)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = replaceIR();
  ir.response.transformMaxBytes = 32; // tiny cap so a small body is "over cap"
  const big = "__TITLE__ " + "x".repeat(64) + " __TITLE__";
  const fetchImpl = originStub(200, { "Content-Type": "text/html" }, big);
  const r = await handle(req("/big"), {}, mockCtx(), { ir, cache, fetchImpl, originBase: "http://o" });
  assert.equal(await r.text(), big, "a body over transformMaxBytes must stream untransformed");
});

await test("edge tier: distribute @html stores in L2 (KV) + L1", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true); // distribute enabled (kv present)
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const r = await prime("/page", { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.headers.get("X-Cache"), "MISS");
  assert.ok(cache.cache.map.size >= 1, "html should be in L1");
  assert.ok(cache.kv.m.size >= 1, "distribute @html should also populate L2 (KV)");
  const r2 = await handle(req("/page"), {}, mockCtx(), { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "HIT");
  assert.equal(fetchImpl.calls, 1);
});

await test("edge tier: skip @assets does not cache (any tier)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true);
  const fetchImpl = originStub(200, { "Content-Type": "application/javascript" });
  await prime("/assets/app.js", { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(cache.cache.map.size, 0, "skip must not write L1");
  assert.equal(cache.kv.m.size, 0, "skip must not write L2");
  const r2 = await handle(req("/assets/app.js"), {}, mockCtx(), { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "MISS");
  assert.equal(fetchImpl.calls, 2);
});

await test("Range request bypasses the cache (a cached 200 is never served to a Range)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const okFull = originStub(200, { "Content-Type": "text/html" }, "FULLBODY");
  await prime("/catalog/r1", { ir: IR, cache, fetchImpl: okFull, originBase: "http://o" });
  assert.equal(okFull.calls, 1);
  // A Range request must reach the origin (bypass), not get the cached full 200.
  const partial = originStub(206, { "Content-Type": "text/html" }, "PART");
  const r = await handle(req("/catalog/r1", { headers: { Range: "bytes=0-3" } }), {}, mockCtx(), {
    ir: IR,
    cache,
    fetchImpl: partial,
    originBase: "http://o",
  });
  assert.equal(partial.calls, 1, "Range must reach origin, not serve the cached 200");
  assert.equal(r.status, 206);
});

await test("Range response is not stored (no 206 poisoning under the full key)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const partial = originStub(206, { "Content-Type": "text/html" }, "PART");
  await handle(req("/catalog/r2", { headers: { Range: "bytes=0-3" } }), {}, mockCtx(), {
    ir: IR,
    cache,
    fetchImpl: partial,
    originBase: "http://o",
  });
  assert.equal(cache.cache.map.size, 0, "a 206 from a Range request must never be cached");
});

await test("HEAD bypasses the cache (no empty-body poisoning of a later GET)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const head = originStub(200, { "Content-Type": "text/html" }, "");
  await handle(req("/catalog/h1", { method: "HEAD" }), {}, mockCtx(), { ir: IR, cache, fetchImpl: head, originBase: "http://o" });
  assert.equal(cache.cache.map.size, 0, "a HEAD response must not be cached");
  // cache_key is `url host` (no method), so HEAD and GET share a key — the GET must
  // still reach origin and get the real body, not a cached empty HEAD body.
  const get = originStub(200, { "Content-Type": "text/html" }, "REALBODY");
  const r = await handle(req("/catalog/h1"), {}, mockCtx(), { ir: IR, cache, fetchImpl: get, originBase: "http://o" });
  assert.equal(get.calls, 1, "GET after HEAD must reach origin, not a cached empty body");
  assert.equal(await r.text(), "REALBODY");
});

// cacheKeyHash must equal the known sha256 prefix (the same value Go's
// crypto/sha256 and `printf … | shasum -a 256` produce) — Go↔shell↔JS parity for
// the pure-JS digest, independent of the IR conformance harness.
await test("cacheKeyHash matches the canonical sha256 prefix (Go/shell parity)", async () => {
  const { cacheKeyHash, cacheKeyHeaderValue } = await import("./interpreter.js");
  assert.equal(cacheKeyHash("hello"), "2cf24dba5fb0");
  assert.equal(cacheKeyHash(""), "", "empty key hashes to empty (header omitted)");
  // The composed cache key for GET ck.example.com /page ?a=1 (US-1f separated).
  assert.equal(cacheKeyHash("GET\x1fck.example.com\x1f/page\x1fa=1"), "a8d707140198");
  assert.equal(cacheKeyHeaderValue("GET\x1fx", true), "GET\x1fx", "raw form returns the key");
  assert.equal(cacheKeyHeaderValue("GET\x1fx", false), cacheKeyHash("GET\x1fx"));
  assert.equal(cacheKeyHeaderValue("", false), "");
});

// End-to-end through the worker: `header +cache_key X-Cache-Key` emits the 12-hex
// hash of the key the worker builds, on both MISS and HIT (stable), and omits it on
// a pass. Uses a small inline IR so the header marker is present.
await test("worker emits X-Cache-Key (hash) on MISS+HIT, omits on pass", async () => {
  const ir = {
    irVersion: 4,
    site: { hosts: ["ck.local"] },
    upstream: { to: "backend" },
    matchers: { dyn: { kind: "path", patterns: ["/api/*"] } },
    recv: { pass: [{ names: ["dyn"] }] },
    key: { tokens: [{ kind: "method" }, { kind: "host" }, { kind: "path" }] },
    response: {
      ttl: [{ selKind: "default", ttl: "60s" }],
      headerResp: [{ scope: { always: true }, ops: [{ op: "cache_key", name: "X-Cache-Key" }] }],
    },
    deliver: { cacheKeyHeader: "X-Cache-Key" },
    edge: { default: "local" },
  };
  const { cacheKeyHash } = await import("./interpreter.js");
  const want = cacheKeyHash("GET\x1fck.local\x1f/page");

  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const mkReq = (path, host = "ck.local") =>
    new Request("http://" + host + path, { method: "GET", headers: {} });

  const ctx1 = mockCtx();
  const r1 = await handle(mkReq("/page"), {}, ctx1, { ir, cache, fetchImpl, originBase: "http://o" });
  await ctx1.drain();
  assert.equal(r1.headers.get("X-Cache-Key"), want, "MISS hash");

  const r2 = await handle(mkReq("/page"), {}, mockCtx(), { ir, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache-Key"), want, "HIT hash stable");

  // pass path → no key → header omitted.
  const r3 = await handle(mkReq("/api/x"), {}, mockCtx(), { ir, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r3.headers.get("X-Cache-Key"), null, "pass omits the cache-key header");
});

// --- KV guardrail tests (W2: kv_ttl, kv_max_bytes, cross-POP, TTL-only) ------

// store-level: expirationTtl = clamp(ttl+grace, 60s, kv_ttl). The EDGE_IR (06)
// has ttl 30s + grace 10m = 630s; with no kv_ttl cap that is the expirationTtl.
await test("write-through expirationTtl = clamp(ttl+grace, 60s, kv_ttl) — no cap", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true);
  await cache.store("k1", new Response("hi", { headers: { "Content-Type": "text/html" } }), {
    ttlMs: 30_000,
    graceMs: 600_000,
    tier: "distribute",
  });
  assert.equal(cache.kv.puts.length, 1);
  assert.equal(cache.kv.puts[0].expirationTtl, 630, "ceil((30s+600s)/1000)");
});

await test("write-through expirationTtl is capped by kv_ttl", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true, { kvTtlSeconds: 300 }); // 5m cap
  await cache.store("k2", new Response("hi", { headers: { "Content-Type": "text/html" } }), {
    ttlMs: 30_000,
    graceMs: 600_000, // 630s uncapped, but kv_ttl caps to 300
    tier: "distribute",
  });
  assert.equal(cache.kv.puts[0].expirationTtl, 300, "kv_ttl caps retention");
});

await test("write-through expirationTtl is floored at KV's 60s minimum", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true, { kvTtlSeconds: 5 }); // would be < 60
  await cache.store("k3", new Response("hi", { headers: { "Content-Type": "text/html" } }), {
    ttlMs: 1_000,
    graceMs: 1_000,
    tier: "distribute",
  });
  assert.equal(cache.kv.puts[0].expirationTtl, 60, "KV's 60s floor wins over a tiny cap");
});

await test("size bound: a body > kv_max_bytes goes to L1 ONLY, never KV", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true, { kvMaxBytes: 8 });
  const big = "X".repeat(64); // 64 bytes > 8
  await cache.store("kbig", new Response(big, { headers: { "Content-Type": "text/html" } }), {
    ttlMs: 30_000,
    graceMs: 600_000,
    tier: "distribute",
  });
  assert.equal(cache.kv.puts.length, 0, "oversize body must NOT be written to KV");
  assert.equal(cache.cache.map.size, 1, "oversize body still cached in L1");
});

await test("size bound: a small body goes to BOTH L1 and KV", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true, { kvMaxBytes: 1024 });
  await cache.store("ksmall", new Response("tiny", { headers: { "Content-Type": "text/html" } }), {
    ttlMs: 30_000,
    graceMs: 600_000,
    tier: "distribute",
  });
  assert.equal(cache.kv.puts.length, 1, "small body written to KV");
  assert.equal(cache.cache.map.size, 1, "small body written to L1");
});

await test("size bound ignores a lying Content-Length (buffered length is authoritative)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true, { kvMaxBytes: 8 });
  // Claims 1 byte but the real body is 64 bytes — must still stay out of KV.
  const big = "Y".repeat(64);
  await cache.store("klie", new Response(big, { headers: { "Content-Type": "text/html", "Content-Length": "1" } }), {
    ttlMs: 30_000,
    graceMs: 600_000,
    tier: "distribute",
  });
  assert.equal(cache.kv.puts.length, 0, "a wrong Content-Length must not let an oversize body into KV");
});

// Cross-POP: the heart of W2. A second "POP" (fresh caches.default, SHARED KV)
// must serve from KV, not the origin — one origin fill warms the planet.
await test("cross-POP read-through: second POP hits shared KV, not origin", async () => {
  clock.t = 1_000_000;
  const sharedKV = new MockKV();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  // POP A: fresh local cache + shared KV. Fill from origin → write-through KV.
  const popA = new EdgeCache({ cache: new MockCache(), kv: sharedKV, distribute: true, now: () => clock.t });
  const ctxA = mockCtx();
  const rA = await handle(req("/page"), {}, ctxA, { ir: EDGE_IR, cache: popA, fetchImpl, originBase: "http://o" });
  await ctxA.drain();
  assert.equal(rA.headers.get("X-Cache"), "MISS");
  assert.equal(fetchImpl.calls, 1);
  assert.ok(sharedKV.m.size >= 1, "POP A wrote through to the global KV");

  // POP B: a DIFFERENT local cache (cold), SAME global KV. Must hit KV, not origin.
  const popB = new EdgeCache({ cache: new MockCache(), kv: sharedKV, distribute: true, now: () => clock.t });
  const rB = await handle(req("/page"), {}, mockCtx(), { ir: EDGE_IR, cache: popB, fetchImpl, originBase: "http://o" });
  assert.equal(rB.headers.get("X-Cache"), "HIT", "cold POP B serves from the shared KV");
  assert.equal(fetchImpl.calls, 1, "POP B must NOT re-hit the origin (cross-POP warm)");
});

// TTL-only invalidation: a KV entry past its expirationTtl is simply gone — there
// is no purge/epoch path. A later request re-fills from origin.
await test("TTL-only: a KV entry past expirationTtl is gone (re-fill from origin)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true);
  await cache.store("kexp", new Response("v1", { headers: { "Content-Type": "text/html" } }), {
    ttlMs: 30_000,
    graceMs: 30_000, // expirationTtl = 60s
    tier: "distribute",
  });
  assert.equal(cache.kv.puts[0].expirationTtl, 60);
  // Within retention: still present.
  let g = await cache.kv.getWithMetadata("kexp", {}, clock.t + 30_000);
  assert.ok(g.value, "still retained within 60s");
  // Past retention: KV auto-deletes — TTL-only invalidation, no purge needed.
  g = await cache.kv.getWithMetadata("kexp", {}, clock.t + 61_000);
  assert.equal(g.value, null, "past expirationTtl the KV blob is gone");
  assert.equal(cache.kv.m.has("kexp"), false, "entry evicted by TTL, not by a purge/epoch");
});

// Degrade-to-origin: a KV get/put that THROWS must fall through to origin and the
// request must still succeed (KV is never a SPOF).
await test("degrade-to-origin: KV get throwing falls through to origin", async () => {
  clock.t = 1_000_000;
  const throwingKV = {
    async getWithMetadata() {
      throw new Error("KV unavailable");
    },
    async put() {
      throw new Error("KV unavailable");
    },
  };
  const cache = new EdgeCache({ cache: new MockCache(), kv: throwingKV, distribute: true, now: () => clock.t });
  const fetchImpl = originStub(200, { "Content-Type": "text/html" }, "FROM-ORIGIN");
  // store() defers the KV put; a throw inside must not break the response. Then the
  // lookup's KV get throws → treated as miss → origin. Request still succeeds.
  const r = await handle(req("/page"), {}, null, { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r.status, 200);
  assert.equal(await r.text(), "FROM-ORIGIN");
  assert.equal(fetchImpl.calls, 1, "KV failure must degrade to origin");
});

// Security invariant across L2: a Set-Cookie response is never written to KV.
await test("security invariant: a Set-Cookie response is NEVER written to KV (L2)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache(true);
  await cache.store("ksc", new Response("secret", { headers: { "Content-Type": "text/html", "Set-Cookie": "sid=x; Path=/" } }), {
    ttlMs: 30_000,
    graceMs: 600_000,
    tier: "distribute",
  });
  assert.equal(cache.kv.puts.length, 0, "Set-Cookie must never reach KV");
  assert.equal(cache.cache.map.size, 0, "Set-Cookie must never reach L1 either");
});

// --- security invariant tests -----------------------------------------------
// Fix A: client-supplied X-Cadish-Device must NOT influence the edge cache key.
// The edge is the first hop; any X-Cadish-Device on the inbound request is
// attacker-controlled and must be ignored. device is always "" at the edge.
await test("security fix A: client X-Cadish-Device is not used in the cache key", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" }, "BODY");

  // Build a minimal IR that uses {device} as a cache key token so any
  // device leakage would produce distinct keys and a cache miss.
  const deviceIR = {
    irVersion: 4,
    site: { hosts: ["dev.local"] },
    upstream: { to: "backend" },
    matchers: {},
    recv: {},
    key: { tokens: [{ kind: "method" }, { kind: "host" }, { kind: "path" }, { kind: "device" }] },
    response: {
      ttl: [{ selKind: "default", ttl: "60s", grace: "10m" }],
      headerResp: [{ scope: { always: true }, ops: [{ op: "cache_status", name: "X-Cache" }] }],
    },
    deliver: { cacheStatusHeader: "X-Cache" },
    edge: { default: "local" },
  };

  const mkReq = (deviceHeader) =>
    new Request("https://dev.local/page", {
      headers: deviceHeader ? { "X-Cadish-Device": deviceHeader } : {},
    });

  // First request sets the cache key. The IR has device token but the edge
  // ignores X-Cadish-Device, so device="" always → the key is the same for
  // all requests regardless of what X-Cadish-Device the client sends.
  const ctx1 = mockCtx();
  const r1 = await handle(mkReq("mobile"), {}, ctx1, { ir: deviceIR, cache, fetchImpl, originBase: "http://o" });
  await ctx1.drain();
  assert.equal(r1.headers.get("X-Cache"), "MISS", "first request is a miss");
  assert.equal(fetchImpl.calls, 1);

  // A second request with a DIFFERENT spoofed device value must still be a HIT
  // (same key — device is "" in both, so they share the cache entry).
  const r2 = await handle(mkReq("tablet"), {}, mockCtx(), { ir: deviceIR, cache, fetchImpl, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "HIT", "spoofed X-Cadish-Device must not create a distinct cache bucket");
  assert.equal(fetchImpl.calls, 1, "attacker-forged X-Cadish-Device must not cause an origin re-fetch");
});

// Fix B: client-supplied X-Cadish-* trust headers must be stripped before the
// request is forwarded to the origin. The edge is the first hop; a client that
// injects X-Cadish-Geo-Region (or X-Cadish-Device, X-Cadish-Geo-Continent)
// must NOT have those values relayed to the server behind.
await test("security fix B: client X-Cadish-Geo-Region is stripped and not forwarded to origin", async () => {
  let capturedHeaders = null;
  const spyFetch = async (url, init) => {
    capturedHeaders = init.headers instanceof Headers ? init.headers : new Headers(init.headers);
    return new Response("BODY", { status: 200, headers: { "Content-Type": "text/html" } });
  };

  // A geo object that resolves to empty (edge has no CF data in this test).
  const emptyGeo = { geo: "", geoContinent: "", geoRegion: "" };
  const request = new Request("https://example.com/page", {
    headers: {
      "X-Cadish-Device": "mobile",
      "X-Cadish-Geo-Region": "US-TX",
      "X-Cadish-Geo-Continent": "NA",
      // Normal headers that MUST be preserved.
      "Accept-Language": "en-US",
      "Cookie": "sid=abc",
    },
  });

  await fetchOrigin(request, { originBase: "http://backend", reqHeaderOps: [], geo: emptyGeo, fetchImpl: spyFetch });

  assert.ok(capturedHeaders !== null, "spy fetch must have been called");
  // Trust headers from the client must be absent — edge resolved empty geo,
  // so no geo header is set at all. The client's forged values must be gone.
  assert.equal(capturedHeaders.get("X-Cadish-Device"), null, "X-Cadish-Device must be stripped");
  assert.equal(capturedHeaders.get("X-Cadish-Geo-Region"), null, "X-Cadish-Geo-Region must be stripped");
  assert.equal(capturedHeaders.get("X-Cadish-Geo-Continent"), null, "X-Cadish-Geo-Continent must be stripped");
  // The hop-guard header is stamped by the edge itself.
  assert.equal(capturedHeaders.get("X-Cadish-Peer"), "1", "X-Cadish-Peer hop-guard must be set");
  // Ordinary client headers must still be forwarded.
  assert.equal(capturedHeaders.get("Accept-Language"), "en-US", "ordinary headers must be preserved");
  assert.equal(capturedHeaders.get("Cookie"), "sid=abc", "Cookie must be preserved");
});

await test("security fix B: edge-resolved geo headers ARE forwarded (only edge-controlled values)", async () => {
  let capturedHeaders = null;
  const spyFetch = async (url, init) => {
    capturedHeaders = init.headers instanceof Headers ? init.headers : new Headers(init.headers);
    return new Response("BODY", { status: 200, headers: { "Content-Type": "text/html" } });
  };

  // Edge resolves real geo (as if from request.cf).
  const resolvedGeo = { geo: "DE", geoContinent: "EU", geoRegion: "DE-BE" };
  const request = new Request("https://example.com/page", {
    headers: {
      // Client tries to spoof geo — these must be overwritten/stripped.
      "X-Cadish-Geo-Region": "US-TX",
      "X-Cadish-Geo-Continent": "NA",
    },
  });

  await fetchOrigin(request, { originBase: "http://backend", reqHeaderOps: [], geo: resolvedGeo, fetchImpl: spyFetch });

  assert.ok(capturedHeaders !== null, "spy fetch must have been called");
  // Client's forged geo gone; edge-resolved values must be present.
  assert.equal(capturedHeaders.get("X-Cadish-Geo-Region"), "DE-BE", "edge-resolved geo region must be forwarded");
  assert.equal(capturedHeaders.get("X-Cadish-Geo-Continent"), "EU", "edge-resolved geo continent must be forwarded");
  assert.equal(capturedHeaders.get("CF-IPCountry"), "DE", "edge-resolved country must be forwarded");
});

await test("security fix B: EDGE_TRUST_HEADERS list covers all X-Cadish-Device and geo variants", () => {
  // Validate the trust header list is complete and correct — this is a
  // read-only-verified guard that documents the expected coverage.
  assert.ok(EDGE_TRUST_HEADERS.includes("X-Cadish-Device"), "list must include X-Cadish-Device");
  assert.ok(EDGE_TRUST_HEADERS.includes("X-Cadish-Geo-Continent"), "list must include X-Cadish-Geo-Continent");
  assert.ok(EDGE_TRUST_HEADERS.includes("X-Cadish-Geo-Region"), "list must include X-Cadish-Geo-Region");
  // X-Cadish-Peer must NOT be in the strip list (the edge sets it itself).
  assert.ok(!EDGE_TRUST_HEADERS.includes("X-Cadish-Peer"), "X-Cadish-Peer must not be stripped");
});

// Security fix C: client-supplied CF-IPCountry must be stripped and NEVER
// forwarded to the origin. The edge resolves country from request.cf; a
// client-supplied value must be dropped (same trust-strip invariant as the
// X-Cadish-Geo-* headers). When the edge resolves no country the header must
// be absent on the origin request; when the edge resolves a country the
// forwarded value is the edge's, not the client's.
await test("security fix C: client CF-IPCountry is stripped when edge resolves no country", async () => {
  let capturedHeaders = null;
  const spyFetch = async (url, init) => {
    capturedHeaders = init.headers instanceof Headers ? init.headers : new Headers(init.headers);
    return new Response("BODY", { status: 200, headers: { "Content-Type": "text/html" } });
  };

  // Edge resolves no country (T1 / anonymizer / absent cf.country).
  const emptyGeo = { geo: "", geoContinent: "", geoRegion: "" };
  const request = new Request("https://example.com/page", {
    headers: {
      // Client supplies a fake CF-IPCountry — must be stripped.
      "CF-IPCountry": "ZZ",
    },
  });

  await fetchOrigin(request, { originBase: "http://backend", reqHeaderOps: [], geo: emptyGeo, fetchImpl: spyFetch });

  assert.ok(capturedHeaders !== null, "spy fetch must have been called");
  // Client's spoofed CF-IPCountry must be absent — edge resolved no country.
  assert.equal(capturedHeaders.get("CF-IPCountry"), null,
    "client-supplied CF-IPCountry must be stripped when edge resolves no country");
});

await test("security fix C: when edge resolves a country, forwarded CF-IPCountry is the edge value, not the client's", async () => {
  let capturedHeaders = null;
  const spyFetch = async (url, init) => {
    capturedHeaders = init.headers instanceof Headers ? init.headers : new Headers(init.headers);
    return new Response("BODY", { status: 200, headers: { "Content-Type": "text/html" } });
  };

  // Edge resolves country=DE; client tries to spoof it as ZZ.
  const resolvedGeo = { geo: "DE", geoContinent: "EU", geoRegion: "DE-BE" };
  const request = new Request("https://example.com/page", {
    headers: { "CF-IPCountry": "ZZ" },
  });

  await fetchOrigin(request, { originBase: "http://backend", reqHeaderOps: [], geo: resolvedGeo, fetchImpl: spyFetch });

  assert.ok(capturedHeaders !== null, "spy fetch must have been called");
  // The forwarded CF-IPCountry must be the edge-resolved value (DE), not the client's (ZZ).
  assert.equal(capturedHeaders.get("CF-IPCountry"), "DE",
    "forwarded CF-IPCountry must be the edge-resolved value, not the client's spoofed value");
});

await test("security fix C: EDGE_TRUST_HEADERS includes CF-IPCountry", () => {
  assert.ok(EDGE_TRUST_HEADERS.includes("CF-IPCountry"),
    "EDGE_TRUST_HEADERS must include CF-IPCountry to ensure it is stripped before geo re-application");
});

// BUG-1: a path_regex / redirect carrying a lifted RE2 inline flag ({regex, regexFlags})
// must compile via `new RegExp(regex, flags)` WITHOUT throwing, and match
// case-insensitively. (Before the fix the worker compiled `new RegExp("(?i)…")` and
// threw SyntaxError on every such request → 500 on essentially all traffic.)
await test("BUG-1: lifted (?i) regex compiles + matches case-insensitively, no throw", async () => {
  const { decide } = await import("./interpreter.js");
  const ir = {
    irVersion: 4,
    site: { hosts: ["example.com"] },
    upstream: { to: "backend" },
    matchers: { bypass: { kind: "path_regex", regex: "^/(atvpanel|admin)", regexFlags: "i" } },
    recv: {
      pass: [{ names: ["bypass"] }],
      redirect: [{ regex: "^/cams/?$", regexFlags: "i", status: 301, target: "https://example.com/broadcast" }],
    },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "60s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const mk = (path) => ({ method: "GET", host: "example.com", path, origin: { status: 0 }, cacheStatus: "MISS" });
  // /CAMS (uppercase) must redirect via the (?i) regex — proves both compile + ci.
  const d1 = decide(ir, mk("/CAMS"));
  assert.ok(d1.request.redirect, "/CAMS must redirect (case-insensitive)");
  assert.equal(d1.request.redirect.location, "https://example.com/broadcast");
  // /ATVpanel/x (mixed case) must pass via the (?i) path_regex.
  const d2 = decide(ir, mk("/ATVpanel/x"));
  assert.equal(d2.request.pass, true, "/ATVpanel/x must pass (case-insensitive)");
  // a non-matching path neither passes nor redirects.
  const d3 = decide(ir, mk("/broadcast"));
  assert.equal(d3.request.pass, false);
  assert.equal(d3.request.redirect, null);
});

// BUG-1 negative: an untranslatable regex matcher (marked regexUntranslatable, source
// stripped by the projector) must FAIL CLOSED at the edge — no compile, no throw, no
// match — so the worker never 500s and never silently mis-matches a delegated rule.
await test("BUG-1: untranslatable regex matcher fails closed (no throw, no match)", async () => {
  const { decide } = await import("./interpreter.js");
  const ir = {
    irVersion: 4,
    site: { hosts: ["x"] },
    upstream: { to: "backend" },
    matchers: { bad: { kind: "path_regex", regexUntranslatable: true } },
    recv: { pass: [{ names: ["bad"] }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "60s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const d = decide(ir, { method: "GET", host: "x", path: "/aaab", origin: { status: 0 }, cacheStatus: "MISS" });
  assert.equal(d.request.pass, false, "untranslatable regex must fail closed (not match)");
});

// Fix #1/#4 negative: a serverOnly matcher (an `all`/`query` slice-2 Gateway matcher the
// projector delegates) must FAIL CLOSED in matchOne — never silently match — even if one
// slipped into the IR. The worker would otherwise mis-select a scoped recipe / directive.
await test("Fix #1: serverOnly matcher fails closed (never matches)", async () => {
  const { decide } = await import("./interpreter.js");
  const ir = {
    irVersion: 4,
    site: { hosts: ["x"] },
    upstream: { to: "backend" },
    // A serverOnly matcher whose underlying shape WOULD match if it were evaluated
    // (kind "all" with no constraints): the serverOnly guard must short-circuit to
    // non-match before any kind dispatch.
    matchers: { gw: { kind: "all", serverOnly: true } },
    recv: { pass: [{ names: ["gw"] }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "60s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const d = decide(ir, { method: "GET", host: "x", path: "/anything", origin: { status: 0 }, cacheStatus: "MISS" });
  assert.equal(d.request.pass, false, "serverOnly matcher must fail closed (not match)");
});

// --- report -----------------------------------------------------------------

if (failures.length) {
  console.error(`\nFAIL: ${failures.length} failed, ${passed} passed`);
  process.exit(1);
}
console.log(`PASS: ${passed} runtime IO test(s)`);
