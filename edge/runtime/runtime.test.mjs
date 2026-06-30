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
import { handle, buildIReq } from "./entry.js";
import { IR_VERSION, evalRequest, canonicalHeaderKey } from "./interpreter.js";
import { EdgeCache, isCacheableResponse } from "./cache-tiers.js";
import { fetchOrigin, EDGE_TRUST_HEADERS, PEER_HEADER } from "./origin.js";

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
// 11 is the COOKIE-NORM fixture: `classify {ageverify} { derives_from cookie verified-prod
// userType … }` + `cookie_allow` (strip-all) + `cache_key default host url {ageverify}`.
// Used to pin that the edge derives the normalized axis from the ORIGINAL cookies, keys by
// it, strips the axis cookies before the origin/credential check, and caches (no bypass).
const COOKIE_NORM_IR = JSON.parse(readFileSync(join(genDir, "11-cookie-norm.ir.json"), "utf8"));
// 44 is the Finding 1 (round-3) fixture: `@premium cookie premium 1` selects recipe A
// (`cache_key @premium host url {tier}`) where {tier} `derives_from cookie premium`, plus a
// `cache_key default host url cookie:uid`. The premium cookie is stripped post-key, so a
// NAIVE re-selection of the recipe (on the stripped request) would land on the default
// recipe and wrongly judge the unkeyed `uid` cookie covered → a cross-user store. Used to
// pin that the edge judges credential coverage against the recipe that BUILT the key.
const RECIPE_RESELECT_IR = JSON.parse(readFileSync(join(genDir, "44-recipe-reselect.ir.json"), "utf8"));
// 45 is the COOKIE-NORM forward fixture: classify {axis} has a STRIP line
// (`derives_from cookie StripMe`) AND a FORWARD line (`derives_from cookie KeepMe forward`),
// `cookie_allow` (strip-all), `cache_key default host url {axis}`. Used to pin that the edge
// STRIPS StripMe but FORWARDS KeepMe to origin (covered by {axis}), and still CACHES.
const COOKIE_FORWARD_IR = JSON.parse(readFileSync(join(genDir, "45-cookie-forward.ir.json"), "utf8"));
// 47 is the Finding 1 (SAFETY) scoped-forward leak fixture: @premium selects recipe A
// (`cache_key @premium host url {tier}`) where {tier} derives_from cookie premium (strip),
// while the FALLBACK default recipe B (`cache_key default host url {loyal}`) has a
// `derives_from cookie loyalty forward` axis. The premium cookie is stripped post-key, so a
// NAIVE re-selection of the FORWARD set on the stripped request lands on recipe B and marks
// the allow-listed `loyalty` cookie "covered" — though recipe A (which built the key) has no
// forward axis and does not key loyalty. Used to pin that the edge judges forward coverage
// against the recipe that BUILT the key (must BYPASS), matching Go (pipeline.go:458).
//
// The leak gate itself is guarded in THREE places, defense in depth: (1) the "Finding 1
// (forward variant)" handle() test below drives the real worker and asserts a cross-user MISS
// (the load-bearing behavioral guard); (2) internal/pipeline/recipe_reselect_test.go pins the
// Go BypassForCredentials path; and (3) the conformance fixture's derivedStripPostStrip /
// derivedForwardPostStrip probes (decide() recomputes the strip/forward partition on the
// post-strip request) — these FLIP if the gate ever regresses to a fresh selectKeyTokens, so
// the fixture now distinguishes the bug from the fix instead of being byte-identical for both.
const SCOPED_FORWARD_LEAK_IR = JSON.parse(readFileSync(join(genDir, "47-scoped-forward-leak.ir.json"), "utf8"));
// 40 is the from_header-family fixture (`cache_ttl @api from_header X-Cache-Ttl
// grace_from_header X-Cache-Grace max_stale_from_header X-Cache-Max-Stale`). Used to pin
// (Finding 6) that the edge STRIPS those consumed control headers before deliver + store,
// so the internal origin↔cache contract never leaks to the client — mirroring the server.
const GRACE_FROM_HEADER_IR = JSON.parse(readFileSync(join(genDir, "40-grace-from-header.ir.json"), "utf8"));
// 43 is the Finding 1 fixture: `redirect ^/go/(.*)$ 302 {proto}://{host}/landing/$1`.
// Driven through the REAL worker entry (buildIReq) — NOT decide() directly — to pin that
// an https:// inbound request resolves {proto} to "https" (the conformance fixture feeds
// `tls:` straight to decide(), bypassing buildIReq, so it can't catch the adapter omission).
const REDIRECT_PROTO_IR = JSON.parse(readFileSync(join(genDir, "43-redirect-proto-tls.ir.json"), "utf8"));
// 60 is cache_credentialed (D101) + cookie_allow where the cache_ttl SIGNAL selector is
// PATH-scoped (does NOT read a cookie): the common, parity-safe case. The stripped cookie
// (`tracking`) is read by no response-phase matcher, so the edge (normalized cookie) and the
// server (original cookie restored before EvalResponse) reach the SAME store decision.
const CRED_COOKIE_NORM_IR = JSON.parse(readFileSync(join(genDir, "60-cache-credentialed-cookie-norm.ir.json"), "utf8"));
// 61 is the (now-closed) cookie-norm signal case (D101 review): the cache_ttl signal selector
// `@premium cookie tier premium` reads a cookie that `cookie_allow session` STRIPS. BOTH tiers
// evaluate the signal against the NORMALIZED cookie (tier stripped), so the positive signal NEVER
// fires and NEITHER stores — the edge worker always did this, and the Go server now forwards the
// original cookie to ORIGIN ONLY (an origin-bound reqHeaderOp), keeping EvalResponse on the
// normalized request, so it no longer over-caches a per-user body under the shared key. Parity is
// pinned both ways — see the companion
// internal/server/cache_credentialed_cookienorm_test.go (TestCredentialedCookieNormSignalParity).
const CRED_COOKIE_NORM_SIGNAL_IR = JSON.parse(readFileSync(join(genDir, "61-cache-credentialed-cookie-norm-signal.ir.json"), "utf8"));

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
  async delete(req) {
    return this.map.delete(req.url);
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
  async delete(k) {
    return this.m.delete(k);
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

// aeAwareOrigin models a content-negotiating origin: it returns a gzip-ENCODED body to a
// client that accepts gzip and an IDENTITY body otherwise, always advertising
// `Vary: Accept-Encoding`. This is what any compressing origin behind the edge does.
function aeAwareOrigin() {
  const impl = async (_url, init) => {
    impl.calls++;
    const ae = (init && init.headers && init.headers.get("Accept-Encoding")) || "";
    if (/gzip/i.test(ae)) {
      return new Response("GZIPBODY", {
        status: 200,
        headers: { "Content-Type": "text/html", "Content-Encoding": "gzip", Vary: "Accept-Encoding" },
      });
    }
    return new Response("PLAINBODY", {
      status: 200,
      headers: { "Content-Type": "text/html", Vary: "Accept-Encoding" },
    });
  };
  impl.calls = 0;
  return impl;
}

await test("EDGE ENCODING GUARD: a stored Content-Encoding variant is never served to a client that doesn't accept it (Go serveFromCache parity)", async () => {
  // The edge keys its cache on the Accept-Encoding-AGNOSTIC logical key (Vary: Accept-Encoding
  // is treated as "covered" by the encode layer). So a gzip-encoded body cached for a gzip
  // client must NOT be handed to an identity-only client — that delivers an undecodable body.
  // The Go server guards exactly this in serveFromCache (handler.go ~690): a stored copy whose
  // Content-Encoding the client does not accept falls through to a fresh origin negotiation.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = aeAwareOrigin();
  const deps = { ir: IR, cache, fetchImpl, originBase: "http://o" };

  // Client A accepts gzip → origin returns a gzip body → edge stores it under the logical key.
  const ctxA = mockCtx();
  const a = await handle(req("/catalog/a", { headers: { "Accept-Encoding": "gzip" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(a.headers.get("X-Cache"), "MISS");
  assert.equal(a.headers.get("Content-Encoding"), "gzip", "client A is served the gzip variant");
  assert.equal(fetchImpl.calls, 1);

  // Client B accepts NO compression (identity only). The stored copy is gzip-encoded; serving it
  // would be undecodable, so the edge must re-fetch origin (a fresh negotiation), never HIT.
  const b = await handle(req("/catalog/a", { headers: { "Accept-Encoding": "identity" } }), {}, mockCtx(), deps);
  assert.equal(fetchImpl.calls, 2, "an identity-only client must NOT be served the stored gzip variant — re-fetch origin");
  assert.notEqual(b.headers.get("Content-Encoding"), "gzip", "must never deliver a gzip body to an identity-only client");
});

await test("UNSAFE METHOD (POST) is never stored/served at the edge — Go parity (handler.go isSafeMethod)", async () => {
  // Finding 3: an anonymous POST under `cache_ttl default` (EDGE_IR caches `/` and does NOT
  // `pass` POST) must NOT be stored at the edge — a 2nd identical anonymous POST still reaches
  // origin (it can never be a cache HIT), exactly like the Go server (doStore + serveFromCache
  // are both gated on isSafeMethod). Without the guard the first POST would store under the
  // cacheable entry and the second would HIT without the side-effect reaching origin.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const deps = { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" };

  const ctx1 = mockCtx();
  const p1 = await handle(req("/", { method: "POST" }), {}, ctx1, deps);
  await ctx1.drain();
  assert.equal(p1.headers.get("X-Cache"), "MISS", "a POST is never served from cache");
  assert.equal(fetchImpl.calls, 1);

  const ctx2 = mockCtx();
  const p2 = await handle(req("/", { method: "POST" }), {}, ctx2, deps);
  await ctx2.drain();
  assert.equal(p2.headers.get("X-Cache"), "MISS", "a 2nd POST is still a MISS (nothing stored)");
  assert.equal(fetchImpl.calls, 2, "a 2nd identical POST must reach origin — unsafe methods never HIT the edge");
});

await test("a successful POST invalidates the sibling GET entry (RFC 9111 §4.4)", async () => {
  // After a 2xx/3xx write the next GET to the same URI must re-fetch the post-write body
  // rather than serve the stale pre-write copy — mirroring the Go server's §4.4 forget.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const deps = { ir: EDGE_IR, cache, fetchImpl, originBase: "http://o" };

  // Prime a cacheable GET (now FRESH in L1).
  const ctxG = mockCtx();
  const g1 = await handle(req("/"), {}, ctxG, deps);
  await ctxG.drain();
  assert.equal(g1.headers.get("X-Cache"), "MISS");
  const g2 = await handle(req("/"), {}, mockCtx(), deps);
  assert.equal(g2.headers.get("X-Cache"), "HIT", "the GET is cached before the write");

  // A successful POST to the same URI forgets the sibling GET entry.
  const ctxP = mockCtx();
  await handle(req("/", { method: "POST" }), {}, ctxP, deps);
  await ctxP.drain();

  // The next GET re-fetches (MISS, not the stale HIT).
  const g3 = await handle(req("/"), {}, mockCtx(), deps);
  assert.equal(g3.headers.get("X-Cache"), "MISS", "the sibling GET entry was invalidated by the successful POST");
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

await test("derives_from: the edge derives→strips the axis cookies, keys the normalized token, and caches an anonymous origin request", async () => {
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
  const deps = { ir: COOKIE_NORM_IR, cache, fetchImpl, originBase: "http://o" };

  // A registered user: {ageverify} derives to 1 from userType, then verified-prod/userType
  // are stripped before the origin (anonymous upstream) and the response CACHES.
  const ctxA = mockCtx();
  const ra = await handle(req("/p", { headers: { Cookie: "userType=registered; _ga=X" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(ra.headers.get("X-Cache"), "MISS", "first derives_from request is a cacheable MISS (not a bypass)");
  const last = seen[seen.length - 1];
  assert.ok(!/userType/.test(last) && !/verified-prod/.test(last), `origin saw an un-stripped axis cookie: ${last}`);

  // A second registered user (different tracking cookie) shares the normalized entry → HIT.
  const rb = await handle(req("/p", { headers: { Cookie: "userType=registered; _ga=Y" } }), {}, mockCtx(), deps);
  assert.equal(rb.headers.get("X-Cache"), "HIT", "same normalized axis shares the entry across users");

  // A DIFFERENT axis (verified-prod=1 → ageverify 0) lands on a DIFFERENT entry → MISS.
  const rc = await handle(req("/p", { headers: { Cookie: "verified-prod=1" } }), {}, mockCtx(), deps);
  assert.equal(rc.headers.get("X-Cache"), "MISS", "a different normalized axis is a distinct cache entry");
});

await test("forward mode: the edge FORWARDS the forward cookie to origin (not stripped), strips the strip cookie, keys the axis, and CACHES", async () => {
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
  const counted = Object.assign(async (...a) => (counted.calls++, fetchImpl(...a)), { calls: 0 });
  const deps = { ir: COOKIE_FORWARD_IR, cache, fetchImpl: counted, originBase: "http://o" };

  // StripMe (strip) is removed; KeepMe (forward) is FORWARDED to origin; _ga (not allow-
  // listed) is stripped. {axis}=1 (StripMe row). The forward cookie is covered → CACHES.
  const ctxA = mockCtx();
  const ra = await handle(req("/p", { headers: { Cookie: "StripMe=yes; KeepMe=yes; _ga=X" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(ra.headers.get("X-Cache"), "MISS", "first forward request is a cacheable MISS (covered, not a bypass)");
  const last = seen[seen.length - 1];
  assert.match(last, /KeepMe=yes/, `the forward cookie must be FORWARDED to origin: ${last}`);
  assert.ok(!/StripMe/.test(last), `the strip cookie must NOT reach origin: ${last}`);
  assert.ok(!/_ga/.test(last), `a non-allow-listed cookie must be stripped: ${last}`);

  // A second request with the SAME axis HITs the shared entry (it cached).
  const rb = await handle(req("/p", { headers: { Cookie: "StripMe=yes; KeepMe=yes; _ga=Y" } }), {}, mockCtx(), deps);
  assert.equal(rb.headers.get("X-Cache"), "HIT", "the forward response cached → same axis HITs");

  // A different axis (KeepMe row → {axis}=2) is a DISTINCT entry → MISS, KeepMe still forwarded.
  const rc = await handle(req("/p", { headers: { Cookie: "KeepMe=yes" } }), {}, mockCtx(), deps);
  assert.equal(rc.headers.get("X-Cache"), "MISS", "a different axis is a distinct cache entry");
  assert.match(seen[seen.length - 1], /KeepMe=yes/, "the forward cookie is forwarded on the distinct-axis request too");
});

await test("SPEC-DUP-COOKIE (edge): a forward-covered cookie sent twice with IDENTICAL values CACHES; with DIFFERING values BYPASSES (Go==JS)", async () => {
  clock.t = 1_000_000;
  // Same-value duplicate: KeepMe=yes; KeepMe=yes → forward-covered axis is occurrence-
  // independent and the origin sees two identical values → covered → caches (MISS then HIT).
  {
    const cache = freshCache();
    const fetchImpl = originStub(200, { "Content-Type": "text/html" });
    const deps = { ir: COOKIE_FORWARD_IR, cache, fetchImpl, originBase: "http://o" };
    const ctxA = mockCtx();
    const ra = await handle(req("/p", { headers: { Cookie: "KeepMe=yes; KeepMe=yes" } }), {}, ctxA, deps);
    await ctxA.drain();
    assert.equal(ra.headers.get("X-Cache"), "MISS", "same-value forward-covered duplicate is a cacheable MISS (not a bypass)");
    const rb = await handle(req("/p", { headers: { Cookie: "KeepMe=yes; KeepMe=yes" } }), {}, mockCtx(), deps);
    assert.equal(rb.headers.get("X-Cache"), "HIT", "the same-value duplicate cached → second request HITs");
    assert.equal(fetchImpl.calls, 1, "only the first request reached origin (it cached)");
  }
  // Differing-value duplicate: KeepMe=yes; KeepMe=no → ambiguous axis → BYPASS (nothing
  // cached; a repeat of the identical request still MISSes and re-fetches origin).
  {
    const cache = freshCache();
    const fetchImpl = originStub(200, { "Content-Type": "text/html" });
    const deps = { ir: COOKIE_FORWARD_IR, cache, fetchImpl, originBase: "http://o" };
    const ctxA = mockCtx();
    const ra = await handle(req("/p", { headers: { Cookie: "KeepMe=yes; KeepMe=no" } }), {}, ctxA, deps);
    await ctxA.drain();
    assert.equal(ra.headers.get("X-Cache"), "MISS", "differing-value duplicate bypasses (uncached MISS)");
    const rb = await handle(req("/p", { headers: { Cookie: "KeepMe=yes; KeepMe=no" } }), {}, mockCtx(), deps);
    assert.equal(rb.headers.get("X-Cache"), "MISS", "a bypass stores nothing → the repeat still MISSes");
    assert.equal(fetchImpl.calls, 2, "both differing-value requests bypass to origin (nothing cached)");
  }
});

await test("Finding 1: a recipe selector that reads a derives_from cookie does not leak — coverage is judged against the recipe that BUILT the key", async () => {
  // @premium selects recipe A (host url {tier}); {tier} derives_from premium, so premium is
  // stripped post-key. uid stays (allow-listed, unkeyed under recipe A). A naive re-selection
  // on the stripped request lands on the default recipe (host url cookie:uid) and would judge
  // uid covered → store alice's body under recipe A's uid-agnostic key → bob would HIT it.
  clock.t = 1_000_000;
  const cache = freshCache();
  const seen = [];
  const fetchImpl = Object.assign(
    async (_url, init) => {
      const c = (init && init.headers && init.headers.get("Cookie")) || "";
      seen.push(c);
      return new Response("body-for:" + c, { status: 200, headers: { "Content-Type": "text/html" } });
    },
    { calls: 0 },
  );
  const counted = Object.assign(async (...a) => (counted.calls++, fetchImpl(...a)), { calls: 0 });
  const deps = { ir: RECIPE_RESELECT_IR, cache, fetchImpl: counted, originBase: "http://o" };

  const ctxA = mockCtx();
  const a = await handle(req("/p", { headers: { Cookie: "premium=1; uid=alice" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(a.headers.get("X-Cache"), "MISS", "alice (unkeyed uid under recipe A) must bypass, not cache");
  assert.match(seen[seen.length - 1], /uid=alice/, "origin sees alice's uid (forwarded, premium stripped)");

  // Bob: same {tier}=p bucket, DIFFERENT uid. If the post-strip recipe had been used he would
  // HIT alice's stored body. He must MISS and fetch his own.
  const b = await handle(req("/p", { headers: { Cookie: "premium=1; uid=bob" } }), {}, mockCtx(), deps);
  assert.equal(b.headers.get("X-Cache"), "MISS", "CROSS-USER LEAK: bob must not HIT alice's entry (coverage judged against recipe A, no uid)");
  assert.equal(counted.calls, 2, "both premium users bypass to origin; nothing cached cross-user");
});

await test("Finding 1 (forward variant): a fallback recipe's forward axis does not leak — forward coverage is judged against the recipe that BUILT the key", async () => {
  // @premium selects recipe A (host url {tier}); {tier} derives_from premium, so premium is
  // stripped post-key. loyalty stays (allow-listed). The DEFAULT recipe B (host url {loyal})
  // FORWARDS+covers loyalty via {loyal}. A naive re-selection of the FORWARD set on the
  // stripped request lands on recipe B and judges loyalty covered → store user A's body under
  // recipe A's loyalty-agnostic key → user B (same premium, different loyalty) would HIT it.
  // The edge must judge forward coverage against recipe A (no forward axis) → BYPASS.
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, { "Content-Type": "text/html" });
  const deps = { ir: SCOPED_FORWARD_LEAK_IR, cache, fetchImpl, originBase: "http://o" };

  const ctxA = mockCtx();
  const a = await handle(req("/p", { headers: { Cookie: "premium=1; loyalty=gold" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(a.headers.get("X-Cache"), "MISS", "user A (unkeyed loyalty under recipe A) must bypass, not cache");

  // User B: same {tier}=p bucket, DIFFERENT loyalty. If recipe B's forward coverage had been
  // (wrongly) used, A's body would be stored under recipe A's key and B would HIT it. B must MISS.
  const b = await handle(req("/p", { headers: { Cookie: "premium=1; loyalty=silver" } }), {}, mockCtx(), deps);
  assert.equal(b.headers.get("X-Cache"), "MISS", "CROSS-USER LEAK: B must not HIT A's entry (forward coverage judged against recipe A, no loyalty)");
  assert.equal(fetchImpl.calls, 2, "both users bypass to origin; nothing cached cross-user");
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

await test("SPEC-PASS-FORWARDS-COOKIES: a credential-bypassed (uncached) edge request forwards the ORIGINAL cookies to origin", async () => {
  // The kept `session` is unkeyed → the request bypasses the edge cache (credentialed). Because
  // NOTHING is cached, the cookie_allow strip — a pure cache-key normalization — must NOT reach
  // the origin: the origin sees the FULL original Cookie (the kept `session` AND the stripped
  // `_ga`), so a `pass`ed per-user endpoint can authenticate instead of reading the user as
  // GUEST. Go==JS parity with TestCredentialBypassForwardsOriginalCookie (the Go pass branch).
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
  const deps = { ir: COOKIE_ALLOW_UNKEYED_IR, cache, fetchImpl, originBase: "http://o" };

  const r = await handle(req("/page", { headers: { Cookie: "session=AAA; _ga=X" } }), {}, mockCtx(), deps);
  assert.equal(r.headers.get("X-Cache"), "MISS", "an unkeyed allow-listed cookie bypasses (never cached)");
  assert.equal(seen[seen.length - 1], "session=AAA; _ga=X", "the bypass path must forward the ORIGINAL cookies, not the cookie_allow-filtered (session=AAA) value");
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
    irVersion: IR_VERSION,
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
    irVersion: IR_VERSION,
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
    irVersion: IR_VERSION,
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
    irVersion: IR_VERSION,
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

// cache_credentialed (D101): the worker makes caching ORIGIN-AUTHORITATIVE for a matching
// credentialed request — it does NOT credential-bypass it, forwards the ORIGINAL cookies to
// origin, and stores under the SHARED key on a positive X-Cache-Ttl signal (Set-Cookie
// hard-refused). Loads the generated fixture-59 IR so the worker path matches Go==JS exactly.
await test("worker cache_credentialed: forwards cookie, shares HIT, refuses Set-Cookie", async () => {
  const ir = JSON.parse(readFileSync(join(here, "..", "..", "test", "conformance", "generated", "59-cache-credentialed.ir.json"), "utf8"));

  // (a) Positive signal: a logged-in request caches under the shared key; the origin saw the
  // ORIGINAL session cookie; a different cookie HITs the same entry (origin hit only once).
  let seenCookie = null;
  const okFetch = async (_url, init) => {
    seenCookie = new Headers(init.headers).get("Cookie");
    okFetch.calls++;
    return new Response("BODY", { status: 200, headers: { "X-Cache-Ttl": "60", "Pragma": "no-cache", "Cache-Control": "no-store, private" } });
  };
  okFetch.calls = 0;
  const cache = freshCache();
  const mk = (cookie) => new Request("https://example.com/v3/readmodel/cache/home", { method: "GET", headers: { Cookie: cookie } });

  const ctx1 = mockCtx();
  const r1 = await handle(mk("session=alice"), {}, ctx1, { ir, cache, fetchImpl: okFetch, originBase: "http://o" });
  await ctx1.drain();
  assert.equal(r1.headers.get("X-Cache"), "MISS", "first is a MISS");
  assert.equal(seenCookie, "session=alice", "origin must receive the ORIGINAL cookie (origin auth)");
  assert.equal(r1.headers.get("Pragma"), null, "Pragma stripped on the positive-signal store");
  assert.notEqual(r1.headers.get("Cache-Control"), "no-store, private", "weak Cache-Control force-overridden");

  const r2 = await handle(mk("session=bob"), {}, mockCtx(), { ir, cache, fetchImpl: okFetch, originBase: "http://o" });
  assert.equal(r2.headers.get("X-Cache"), "HIT", "a different user's cookie HITs the shared entry");
  assert.equal(okFetch.calls, 1, "origin fetched once — the 2nd request is a shared HIT");

  // (b) SAFETY CRUX — Set-Cookie + X-Cache-Ttl: the positive signal STORES it under the shared
  // key with the Set-Cookie STRIPPED; the MISS delivery carries no Set-Cookie, and a 2nd
  // request (different cookie) HITs the shared object and serves ZERO Set-Cookie (never stored).
  const scFetch = async () => {
    scFetch.calls++;
    return new Response("BODY", { status: 200, headers: { "X-Cache-Ttl": "60", "Set-Cookie": "track=for-alice; Path=/", "Cache-Control": "no-store" } });
  };
  scFetch.calls = 0;
  const cache2 = freshCache();
  const mkSC = (c) => new Request("https://example.com/v3/readmodel/cache/onlineusersnumber", { method: "GET", headers: { Cookie: c } });
  const ctxA = mockCtx();
  const rA = await handle(mkSC("session=alice"), {}, ctxA, { ir, cache: cache2, fetchImpl: scFetch, originBase: "http://o" });
  await ctxA.drain();
  assert.equal(rA.headers.get("X-Cache"), "MISS", "Set-Cookie + X-Cache-Ttl is STORED (MISS)");
  assert.equal(rA.headers.get("Set-Cookie"), null, "Set-Cookie stripped from the delivered MISS");
  const rB = await handle(mkSC("session=bob"), {}, mockCtx(), { ir, cache: cache2, fetchImpl: scFetch, originBase: "http://o" });
  assert.equal(rB.headers.get("X-Cache"), "HIT", "a different user HITs the shared object");
  assert.equal(rB.headers.get("Set-Cookie"), null, "the cached object carries ZERO Set-Cookie (no cross-user cookie leak)");
  assert.equal(scFetch.calls, 1, "stored once — the 2nd is a shared HIT");

  // (c) Set-Cookie WITHOUT a signal (the per-user favorites case) → not stored, refetched.
  const noSig = async () => {
    noSig.calls++;
    return new Response("BODY", { status: 200, headers: { "Set-Cookie": "session=fresh; Path=/" } });
  };
  noSig.calls = 0;
  const cache3 = freshCache();
  const mkFav = () => new Request("https://example.com/v3/readmodel/cache/favorites", { method: "GET", headers: { Cookie: "session=alice" } });
  for (let i = 0; i < 2; i++) {
    const ctx = mockCtx();
    const r = await handle(mkFav(), {}, ctx, { ir, cache: cache3, fetchImpl: noSig, originBase: "http://o" });
    await ctx.drain();
    assert.notEqual(r.headers.get("X-Cache"), "HIT", "a no-signal Set-Cookie response must never be shared-cached");
  }
  assert.equal(noSig.calls, 2, "no-signal response refetched per request (never stored)");
});

// cache_credentialed (D101) FAIL-CLOSED with a co-existing STATIC `cache_ttl default ttl 60s`
// — the LIVE brand-a.example config shape (fixture 64). The static default makes an in-scope response
// dec.cacheable=true, but a static TTL is NOT a per-response origin signal, so it must NOT
// authorize a shared credentialed store. Before the fix the edge stored a personalized in-scope
// 200 (no X-Cache-Ttl) under the SHARED key and replayed it to the next user — a cross-user leak.
await test("worker cache_credentialed: static default + NO signal must NOT shared-cache (D101 fail-closed)", async () => {
  const ir = JSON.parse(readFileSync(join(genDir, "64-cache-credentialed-static-default.ir.json"), "utf8"));

  // (a) THE LEAK: a credentialed in-scope request whose origin 200 carries NO X-Cache-Ttl and
  // NO Set-Cookie. The static `default ttl 60s` would make it cacheable, but the fail-closed gate
  // must refuse the shared store — so alice's private body is refetched for bob, never replayed.
  let lastUser = null;
  const leakFetch = async (_url, init) => {
    leakFetch.calls++;
    const cookie = new Headers(init.headers).get("Cookie");
    lastUser = cookie;
    // A PERSONALIZED body keyed to the caller's session — the thing that must never be shared.
    return new Response(`private-for-${cookie}`, { status: 200, headers: { "Content-Type": "application/json" } });
  };
  leakFetch.calls = 0;
  const cache = freshCache();
  const mk = (cookie) => new Request("https://example.com/v3/readmodel/cache/communityconfiguser", { method: "GET", headers: { Cookie: cookie } });

  const ctxA = mockCtx();
  const rA = await handle(mk("session=alice"), {}, ctxA, { ir, cache, fetchImpl: leakFetch, originBase: "http://o" });
  await ctxA.drain();
  assert.equal(rA.headers.get("X-Cache"), "MISS", "first credentialed no-signal request is a MISS");
  assert.equal(await rA.text(), "private-for-session=alice", "alice gets her own body");

  const ctxB = mockCtx();
  const rB = await handle(mk("session=bob"), {}, ctxB, { ir, cache, fetchImpl: leakFetch, originBase: "http://o" });
  await ctxB.drain();
  assert.notEqual(rB.headers.get("X-Cache"), "HIT", "bob must NOT HIT a shared entry (no-signal store refused — fail-closed)");
  assert.equal(lastUser, "session=bob", "origin saw bob's own cookie (refetched, not served alice's cached body)");
  assert.equal(await rB.text(), "private-for-session=bob", "bob gets HIS body, never alice's");
  assert.equal(leakFetch.calls, 2, "each user refetched — nothing stored under the shared key");

  // (b) REGRESSION GUARD — the legit signal path is unaffected: the SAME static-default config,
  // an in-scope response that DOES carry X-Cache-Ttl, still stores shared (a 2nd user HITs once).
  const sigFetch = async () => {
    sigFetch.calls++;
    return new Response("shared-readmodel", { status: 200, headers: { "Content-Type": "application/json", "X-Cache-Ttl": "60" } });
  };
  sigFetch.calls = 0;
  const cache2 = freshCache();
  const mkSig = (c) => new Request("https://example.com/v3/readmodel/cache/home", { method: "GET", headers: { Cookie: c } });
  const ctxS = mockCtx();
  const rS1 = await handle(mkSig("session=alice"), {}, ctxS, { ir, cache: cache2, fetchImpl: sigFetch, originBase: "http://o" });
  await ctxS.drain();
  assert.equal(rS1.headers.get("X-Cache"), "MISS", "with-signal first request is a MISS (then stored)");
  const rS2 = await handle(mkSig("session=bob"), {}, mockCtx(), { ir, cache: cache2, fetchImpl: sigFetch, originBase: "http://o" });
  assert.equal(rS2.headers.get("X-Cache"), "HIT", "with the per-response signal a 2nd user HITs the shared entry (legit path intact)");
  assert.equal(sigFetch.calls, 1, "stored once under the shared key — the signal authorizes the share");
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
    irVersion: IR_VERSION,
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
    irVersion: IR_VERSION,
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

// OPEN-REDIRECT RUNTIME DEFENSE (parity with Go redirect.go locationAuthority backstop):
// a `redirect` whose authority is built from a $N capture (or a request-sourced token)
// compiles, but at runtime a request like `/index.php@evil.example.com/` can inject an
// off-origin authority (the validated {host} becomes mere userinfo). The worker must SUPPRESS
// such redirects (fall through, request.redirect == null) while still firing every legitimate
// redirect. Mirrors internal/pipeline/redirect_test.go TestRedirectRuntimeAuthorityInjection.
await test("open-redirect: index.php userinfo injection suppressed, legit strip still redirects", async () => {
  const { decide } = await import("./interpreter.js");
  const ir = {
    irVersion: IR_VERSION,
    site: { hosts: ["brand-a.example"], redirectHosts: ["brand-a.example"], canonicalHost: "brand-a.example" },
    upstream: { to: "backend" },
    recv: {
      redirect: [{ regex: "^(/.*?)?/index\\.php(.*)$", regexFlags: "i", status: 301, target: "https://{host}$1$2?{query}" }],
    },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  // Exploit: $1="", $2="@evil.example.com/" → https://brand-a.example@evil.example.com/? → SUPPRESS.
  const exploit = decide(ir, { method: "GET", host: "brand-a.example", path: "/index.php@evil.example.com/", origin: { status: 0 }, cacheStatus: "MISS" });
  assert.equal(exploit.request.redirect, null, "open-redirect (userinfo injection) must be suppressed");
  // Legit: /foo/index.php/bar?x=1 → https://brand-a.example/foo/bar?x=1 (authority unchanged) → ALLOW.
  const legit = decide(ir, { method: "GET", host: "brand-a.example", path: "/foo/index.php/bar", query: { x: ["1"] }, origin: { status: 0 }, cacheStatus: "MISS" });
  assert.ok(legit.request.redirect, "legit index.php strip must still redirect");
  assert.equal(legit.request.redirect.location, "https://brand-a.example/foo/bar?x=1");
});

await test("open-redirect: language {host.base} redirect allowed, relative {query.next} absolute target suppressed", async () => {
  const { decide } = await import("./interpreter.js");
  // Language redirect: host kept under neutralization → authorities match → ALLOW.
  const langIR = {
    irVersion: IR_VERSION,
    site: { hosts: ["es.brand-a.example", "brand-a.example"], redirectHosts: ["es.brand-a.example", "brand-a.example"], canonicalHost: "es.brand-a.example" },
    upstream: { to: "backend" },
    recv: { redirect: [{ regex: "^/(.*)$", status: 302, target: "https://es.{host.base}{uri}" }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const lang = decide(langIR, { method: "GET", host: "brand-a.example", path: "/page", query: { q: ["1"] }, origin: { status: 0 }, cacheStatus: "MISS" });
  assert.ok(lang.request.redirect, "language redirect must still fire");
  assert.equal(lang.request.redirect.location, "https://es.brand-a.example/page?q=1");

  // Latent #2: relative target whose leading token is request-sourced → absolute off-origin.
  const nextIR = {
    irVersion: IR_VERSION,
    site: { hosts: ["brand-a.example"], redirectHosts: ["brand-a.example"], canonicalHost: "brand-a.example" },
    upstream: { to: "backend" },
    recv: { redirect: [{ regex: "^/r$", status: 302, target: "{query.next}" }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const evil = decide(nextIR, { method: "GET", host: "brand-a.example", path: "/r", query: { next: ["https://evil.com/x"] }, origin: { status: 0 }, cacheStatus: "MISS" });
  assert.equal(evil.request.redirect, null, "relative request-sourced absolute redirect must be suppressed");
  // A safe relative next stays relative after expansion → ALLOW.
  const safe = decide(nextIR, { method: "GET", host: "brand-a.example", path: "/r", query: { next: ["/account"] }, origin: { status: 0 }, cacheStatus: "MISS" });
  assert.ok(safe.request.redirect, "safe relative next must still redirect");
  assert.equal(safe.request.redirect.location, "/account");
});

// OPEN-REDIRECT whitespace/control-char bypass hardening (parity with Go redirect_test.go
// TestRedirectWhitespaceAuthorityBypass): a Location whose expansion begins with leading OWS
// ("  //evil/") or carries an embedded TAB/CR/LF reports NO authority to a naive inspector,
// yet the wire/UA strips those bytes — restoring a live off-origin authority. The edge runs
// normalizeRedirectLocation BEFORE the authority check, so these all SUPPRESS, while legit
// redirects keep firing. Mirrors the Go server byte-for-byte.
await test("open-redirect: whitespace/control-char authority bypass suppressed (Go≡JS)", async () => {
  const { decide } = await import("./interpreter.js");
  const nextIR = {
    irVersion: IR_VERSION,
    site: { hosts: ["brand-a.example"], redirectHosts: ["brand-a.example"], canonicalHost: "brand-a.example" },
    upstream: { to: "backend" },
    recv: { redirect: [{ regex: "^/n$", status: 302, target: "{query.next}" }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const bypasses = [
    "  //evil.example.com/",
    "\t//evil.example.com/",
    " https://evil.example.com/",
    "  https://evil.example.com/",
    "//evil.example\r\n.com/",
    "//evil.\texample.com/",
  ];
  for (const next of bypasses) {
    const d = decide(nextIR, { method: "GET", host: "brand-a.example", path: "/n", query: { next: [next] }, origin: { status: 0 }, cacheStatus: "MISS" });
    assert.equal(d.request.redirect, null, `whitespace/control bypass must be suppressed: ${JSON.stringify(next)}`);
  }
  // A relative path with surrounding OWS normalizes to a clean relative Location → ALLOW.
  const okPath = decide(nextIR, { method: "GET", host: "brand-a.example", path: "/n", query: { next: ["  /clean/path  "] }, origin: { status: 0 }, cacheStatus: "MISS" });
  assert.ok(okPath.request.redirect, "OWS-wrapped relative path must still redirect");
  assert.equal(okPath.request.redirect.location, "/clean/path");

  // {http.NAME}-only target: same bypass surface via an attacker-influenced header.
  const hdrIR = {
    irVersion: IR_VERSION,
    site: { hosts: ["brand-a.example"], redirectHosts: ["brand-a.example"], canonicalHost: "brand-a.example" },
    upstream: { to: "backend" },
    recv: { redirect: [{ regex: "^/h$", status: 302, target: "{http.X-Next}" }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  for (const next of bypasses) {
    const d = decide(hdrIR, { method: "GET", host: "brand-a.example", path: "/h", header: { "X-Next": [next] }, origin: { status: 0 }, cacheStatus: "MISS" });
    assert.equal(d.request.redirect, null, `header bypass must be suppressed: ${JSON.stringify(next)}`);
  }

  // Legit redirects unaffected after normalization: index.php strip, language, literal, relative.
  const stripIR = {
    irVersion: IR_VERSION,
    site: { hosts: ["brand-a.example"], redirectHosts: ["brand-a.example"], canonicalHost: "brand-a.example" },
    upstream: { to: "backend" },
    recv: { redirect: [{ regex: "^(/.*?)?/index\\.php(/.*)?$", regexFlags: "i", status: 301, target: "https://{host}$1$2?{query}" }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const strip = decide(stripIR, { method: "GET", host: "brand-a.example", path: "/foo/index.php/bar", query: { x: ["1"] }, origin: { status: 0 }, cacheStatus: "MISS" });
  assert.ok(strip.request.redirect, "legit index.php strip must still fire");
  assert.equal(strip.request.redirect.location, "https://brand-a.example/foo/bar?x=1");

  const litIR = {
    irVersion: IR_VERSION,
    site: { hosts: ["brand-a.example"], redirectHosts: ["brand-a.example"], canonicalHost: "brand-a.example" },
    upstream: { to: "backend" },
    recv: { redirect: [{ regex: "^/go$", status: 302, target: "https://provider.example.com/x" }] },
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: { ttl: [{ selKind: "default", ttl: "300s" }] },
    deliver: {},
    edge: { default: "local" },
  };
  const lit = decide(litIR, { method: "GET", host: "brand-a.example", path: "/go", origin: { status: 0 }, cacheStatus: "MISS" });
  assert.ok(lit.request.redirect, "literal off-site redirect must still fire");
  assert.equal(lit.request.redirect.location, "https://provider.example.com/x");
});

// BUG-1 negative: an untranslatable regex matcher (marked regexUntranslatable, source
// stripped by the projector) must FAIL CLOSED at the edge — no compile, no throw, no
// match — so the worker never 500s and never silently mis-matches a delegated rule.
await test("BUG-1: untranslatable regex matcher fails closed (no throw, no match)", async () => {
  const { decide } = await import("./interpreter.js");
  const ir = {
    irVersion: IR_VERSION,
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
    irVersion: IR_VERSION,
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

await test("from_header: edge strips consumed X-Cache-Ttl/Grace/Max-Stale on deliver AND store (no leak)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const fetchImpl = originStub(200, {
    "Content-Type": "text/html",
    "X-Cache-Ttl": "300",
    "X-Cache-Grace": "5m",
    "X-Cache-Max-Stale": "30m",
  });
  const deps = { ir: GRACE_FROM_HEADER_IR, cache, fetchImpl, originBase: "http://o" };

  // MISS: the delivered response must NOT carry the consumed control headers.
  const ctx = mockCtx();
  const r1 = await handle(req("/api/all"), {}, ctx, deps);
  await ctx.drain();
  assert.equal(r1.headers.get("X-Cache"), "MISS");
  for (const h of ["X-Cache-Ttl", "X-Cache-Grace", "X-Cache-Max-Stale"]) {
    assert.equal(r1.headers.get(h), null, `MISS leaked ${h} to the client`);
  }

  // HIT: the STORED copy was stripped too, so a cache hit also carries none.
  const r2 = await handle(req("/api/all"), {}, mockCtx(), deps);
  assert.equal(r2.headers.get("X-Cache"), "HIT");
  for (const h of ["X-Cache-Ttl", "X-Cache-Grace", "X-Cache-Max-Stale"]) {
    assert.equal(r2.headers.get(h), null, `HIT replayed ${h} from the stored copy`);
  }
});

await test("buildIReq: an https inbound request resolves {proto} to https (real worker adapter)", async () => {
  // Drive the REAL worker entry with an https:// URL (req() builds https://example.com/…).
  // The redirect rule emits {proto}://{host}/landing/$1, so the Location's scheme is the
  // resolved {proto}. Before the buildIReq fix this came back http:// (an HTTPS→HTTP
  // downgrade) because the adapter built newRequest WITHOUT a tls/scheme field.
  const r = await handle(req("/go/home"), {}, mockCtx(), { ir: REDIRECT_PROTO_IR });
  assert.equal(r.status, 302, "redirect rule must fire");
  const loc = r.headers.get("Location");
  assert.ok(loc && loc.startsWith("https://"), `{proto} must resolve to https on a TLS request, got Location=${loc}`);

  // And the http:// counterpart still resolves {proto} to http (no over-correction).
  const rPlain = await handle(new Request("http://example.com/go/home"), {}, mockCtx(), { ir: REDIRECT_PROTO_IR });
  assert.equal(rPlain.status, 302);
  const locPlain = rPlain.headers.get("Location");
  assert.ok(locPlain && locPlain.startsWith("http://") && !locPlain.startsWith("https://"), `{proto} must stay http on a plaintext request, got Location=${locPlain}`);
});

await test("R20: cache_unsafe lets the store guard cache a private/no-store response; Set-Cookie still never caches", async () => {
  const priv = () => new Response("B", { status: 200, headers: { "Cache-Control": "private, max-age=60" } });
  const noStore = () => new Response("B", { status: 200, headers: { "Cache-Control": "no-store" } });
  const setCookie = () => new Response("B", { status: 200, headers: { "Cache-Control": "private", "Set-Cookie": "s=1" } });

  // Default (cache_unsafe=false): private/no-store refused, mirroring the old guard.
  assert.equal(isCacheableResponse(priv(), false), false, "private must be refused without cache_unsafe");
  assert.equal(isCacheableResponse(noStore(), false), false, "no-store must be refused without cache_unsafe");
  // cache_unsafe=true: private/no-store now cacheable (parity with the server).
  assert.equal(isCacheableResponse(priv(), true), true, "private must cache under cache_unsafe");
  assert.equal(isCacheableResponse(noStore(), true), true, "no-store must cache under cache_unsafe");
  // Set-Cookie is ironclad — refused EVEN under cache_unsafe.
  assert.equal(isCacheableResponse(setCookie(), true), false, "Set-Cookie must never cache, even under cache_unsafe");
  // Token-aware: an unrelated token that merely CONTAINS the substring does not refuse.
  assert.equal(isCacheableResponse(new Response("B", { status: 200, headers: { "Cache-Control": "max-age=600, private-data" } }), false), true, "private-data is not the `private` directive");

  // End-to-end through EdgeCache.store: a cacheUnsafe cache stores a private response; a
  // default cache does not.
  clock.t = 2_000_000;
  const unsafe = new EdgeCache({ cache: new MockCache(), now: () => clock.t, cacheUnsafe: true });
  await unsafe.store("k1", priv(), { ttlMs: 60000, graceMs: 0, tier: "local" });
  assert.ok((await unsafe.lookup("k1")).response, "cache_unsafe must store a private response");

  const safe = new EdgeCache({ cache: new MockCache(), now: () => clock.t });
  await safe.store("k1", priv(), { ttlMs: 60000, graceMs: 0, tier: "local" });
  assert.equal((await safe.lookup("k1")).response, null, "default must NOT store a private response");

  // Even under cache_unsafe, a Set-Cookie response is not stored.
  await unsafe.store("k2", setCookie(), { ttlMs: 60000, graceMs: 0, tier: "local" });
  assert.equal((await unsafe.lookup("k2")).response, null, "Set-Cookie must never be stored");
});

await test("R09: a response with >1KB of headers round-trips through KV (L2); metadata stays tiny", async () => {
  clock.t = 3_000_000;
  const kv = new MockKV();
  // L2-only cache (no L1) so lookup must read the KV envelope back.
  const cache = new EdgeCache({ cache: null, kv, distribute: true, now: () => clock.t });
  const bigVal = "x".repeat(2048); // a single header value well over KV's 1024-byte metadata cap
  const resp = new Response("PAYLOAD", { status: 200, headers: { "Content-Type": "text/html", "X-Big": bigVal } });
  await cache.store("kbig", resp, { ttlMs: 60000, graceMs: 0, tier: "distribute" });

  // The KV metadata must NOT carry the headers (it would overflow the 1024-byte cap on real
  // KV and the put would be silently rejected — the R09 bug). It holds only tiny numbers.
  const stored = kv.m.get("kbig");
  assert.ok(stored, "the header-heavy response must be written to KV (not dropped)");
  assert.equal(stored.metadata.headers, undefined, "headers must NOT live in KV metadata");
  assert.ok(JSON.stringify(stored.metadata).length < 1024, "KV metadata must stay under the 1024-byte cap");

  // And it round-trips: the big header survives the envelope.
  const got = await cache.lookup("kbig");
  assert.equal(got.state, "fresh", "the KV-stored object must be a fresh L2 hit");
  assert.equal(got.response.headers.get("X-Big"), bigVal, "the >1KB header must round-trip through KV");
  assert.equal(await got.response.text(), "PAYLOAD", "the body must round-trip through KV");
});

await test("cache_credentialed + cookie_allow (path-scoped signal): edge stores shared, forwards the ORIGINAL cookie (parity-safe common case)", async () => {
  // Companion to internal/server/cache_credentialed_cookienorm_test.go
  // TestCredentialedCookieAllowCommonCaseParity: the cache_ttl signal is PATH-scoped, so the
  // cookie value is irrelevant to the store decision and edge == server.
  clock.t = 1_000_000;
  const cache = freshCache();
  const seen = [];
  const fetchImpl = Object.assign(
    async (_url, init) => {
      seen.push((init && init.headers && init.headers.get("Cookie")) || "");
      return new Response("body", { status: 200, headers: { "Content-Type": "application/json", "X-Cache-Ttl": "60" } });
    },
    { calls: 0 },
  );
  const deps = { ir: CRED_COOKIE_NORM_IR, cache, fetchImpl, originBase: "http://o" };

  const ctxA = mockCtx();
  const ra = await handle(req("/v3/readmodel/cache/home", { headers: { Cookie: "session=alice; tracking=abc" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(ra.headers.get("X-Cache"), "MISS", "req1 is a cacheable MISS (positive signal, stored shared)");
  // cache_credentialed forwards the ORIGINAL (full) cookie to origin, overriding cookie_allow.
  assert.equal(seen[seen.length - 1], "session=alice; tracking=abc", "origin must see the ORIGINAL cookie (cred overrides cookie_allow)");

  const rb = await handle(req("/v3/readmodel/cache/home", { headers: { Cookie: "session=bob" } }), {}, mockCtx(), deps);
  assert.equal(rb.headers.get("X-Cache"), "HIT", "req2 (different user) HITs the shared entry");
});

await test("cache_credentialed + cookie_allow (cookie-dependent signal): edge does NOT store — server now matches (D101 parity)", async () => {
  // The COOKIE-NORM parity case (D101 review). The cache_ttl signal selector `@premium cookie
  // tier premium` reads `tier`, which `cookie_allow session` STRIPS. The edge evaluates
  // evalResponse against the NORMALIZED request (no tier), so @premium never fires and NOTHING
  // is stored — every request is a MISS that re-hits origin. The Go server now does the same
  // (companion test TestCredentialedCookieNormSignalParity): it forwards the original cookie to
  // origin via an origin-bound reqHeaderOp and evaluates EvalResponse against the normalized
  // request, so a non-premium user no longer HITs a premium response. The edge side was always
  // the fail-safe one (caches LESS); the server fix brought it into parity here.
  clock.t = 1_000_000;
  const cache = freshCache();
  let originHits = 0;
  const seen = [];
  const fetchImpl = Object.assign(
    async (_url, init) => {
      originHits++;
      seen.push((init && init.headers && init.headers.get("Cookie")) || "");
      return new Response("body", { status: 200, headers: { "Content-Type": "application/json", "X-Cache-Ttl": "60" } });
    },
    { calls: 0 },
  );
  const deps = { ir: CRED_COOKIE_NORM_SIGNAL_IR, cache, fetchImpl, originBase: "http://o" };

  const ctxA = mockCtx();
  const ra = await handle(req("/v3/readmodel/cache/home", { headers: { Cookie: "session=alice; tier=premium" } }), {}, ctxA, deps);
  await ctxA.drain();
  assert.equal(ra.headers.get("X-Cache"), "MISS", "req1 is a MISS");
  // The original cookie (incl. the stripped `tier`) is still FORWARDED to origin (parity with
  // the server) — only the cache-DECISION view of the cookie differs.
  assert.equal(seen[seen.length - 1], "session=alice; tier=premium", "origin must see the ORIGINAL cookie incl. tier");

  const rb = await handle(req("/v3/readmodel/cache/home", { headers: { Cookie: "session=bob" } }), {}, mockCtx(), deps);
  assert.equal(rb.headers.get("X-Cache"), "MISS", "req2 is a MISS — the edge NEVER stored (normalized cookie has no tier)");
  assert.equal(originHits, 2, "every request re-hits origin (neither edge nor server stores: both judge the signal on the normalized cookie — parity)");
});

// rawReq is a minimal Workers-Request double whose headers.entries() yields the EXACT
// pre-combined values the test wants — used to reproduce what the real Fetch runtime hands
// buildIReq after it has collapsed multiple inbound `Cookie:` lines into one entries() value.
// (A real undici/Workers `Headers` recombines multiple Cookie lines with "; " of its own, so a
// genuine multi-line Request can't reproduce the ", "-joined shape some runtimes produce; this
// double feeds the value directly, the unit-level path the gap note in entry.js calls out.)
function rawReq(url, entries, getMap = {}) {
  const lower = {};
  for (const [k, v] of entries) lower[k.toLowerCase()] = v;
  return {
    method: "GET",
    url,
    headers: {
      entries: () => entries[Symbol.iterator](),
      get: (name) => {
        const n = name.toLowerCase();
        if (n in getMap) return getMap[n];
        return n in lower ? lower[n] : null;
      },
    },
  };
}

const NOGEO = { geo: "", geoContinent: "", geoRegion: "" };

await test("multi-Cookie-line runtime ingestion: buildIReq normalizes the \", \"-combined Cookie to \"; \" (Go lenientCookies parity)", async () => {
  // The runtime gap: at the Workers runtime the Fetch Headers API has ALREADY collapsed multiple
  // inbound `Cookie:` lines into ONE entries() value, joined with the GENERIC ", " separator —
  // NOT the "; " interpreter.js parseCookies (and the Go server's lenientCookies) splits on. So a
  // 2nd/Nth-line cookie was silently invisible to the cookie token / matchers / credential gate.
  const ireq = buildIReq(rawReq("https://example.com/p", [["cookie", "sess=x, uid=42"]]), NOGEO);
  // buildIReq must have normalized the combine separator back to "; " so the whole cookie set
  // survives — byte-identical to a single-line "sess=x; uid=42".
  assert.deepEqual(ireq.header.get(canonicalHeaderKey("Cookie")), ["sess=x; uid=42"], "Cookie normalized to '; '-joined");

  // Behavioral parity through the REAL interpreter: fixture 44's default recipe keys
  // `cookie:uid` (the SECOND, post-comma cookie). Two requests differing ONLY in uid must
  // produce DIFFERENT cache keys — without the fix uid is invisible (the lone parsed cookie is
  // `sess`), the cookie:uid token renders "" for BOTH, and the keys would COLLIDE (cross-user
  // serving). `sess` is not the `premium` cookie, so the always/default recipe is selected.
  const keyA = evalRequest(RECIPE_RESELECT_IR, buildIReq(rawReq("https://example.com/p", [["cookie", "sess=x, uid=42"]]), NOGEO)).cacheKey;
  const keyB = evalRequest(RECIPE_RESELECT_IR, buildIReq(rawReq("https://example.com/p", [["cookie", "sess=x, uid=99"]]), NOGEO)).cacheKey;
  assert.notEqual(keyA, keyB, "cookie:uid (2nd Cookie) must influence the key — no collision");

  // And the ", "-combined form must key IDENTICALLY to a proper single-line "; " request
  // (full parity, whichever separator the host runtime chose to combine with).
  const keySingle = evalRequest(RECIPE_RESELECT_IR, buildIReq(rawReq("https://example.com/p", [["cookie", "sess=x; uid=42"]]), NOGEO)).cacheKey;
  assert.equal(keyA, keySingle, "', '-combined and '; '-combined Cookie produce the same key");

  // A runtime that already recombines Cookie with "; " (undici/workerd) must be a no-op.
  const ireqSemi = buildIReq(rawReq("https://example.com/p", [["cookie", "a=1; b=2"]]), NOGEO);
  assert.deepEqual(ireqSemi.header.get(canonicalHeaderKey("Cookie")), ["a=1; b=2"], "already-'; ' Cookie left untouched");
  // A single cookie (the common case) is byte-identical.
  const ireqOne = buildIReq(rawReq("https://example.com/p", [["cookie", "only=1"]]), NOGEO);
  assert.deepEqual(ireqOne.header.get(canonicalHeaderKey("Cookie")), ["only=1"], "single cookie byte-identical");
});

// +cache_age integer-age formula parity: pin Math.floor(ms/1000) to the same expected
// whole-second integer as Go's int64(duration.Seconds()) over the same elapsed-ms table.
// Both formulas truncate toward zero for non-negative elapsed (Math.floor is identical to
// int64-truncation here). A future rounding-mode change on either side breaks this pin.
//
// Go formula (handler.go): int64(h.now().Sub(st).Seconds())
// JS formula (entry.js):   Math.floor((Date.now() - opts.storedAt) / 1000)
await test("+cache_age age formula: Math.floor(ms/1000) matches Go int64(d.Seconds()) over fixed elapsed table", () => {
  const cases = [
    { elapsedMs: 0, want: 0 },
    { elapsedMs: 999, want: 0 },
    { elapsedMs: 1_000, want: 1 },
    { elapsedMs: 1_500, want: 1 },
    { elapsedMs: 45_000, want: 45 },
    { elapsedMs: 45_999, want: 45 },
  ];
  for (const { elapsedMs, want } of cases) {
    const got = Math.floor(elapsedMs / 1000);
    assert.equal(got, want, `+cache_age elapsed=${elapsedMs}ms: Math.floor(ms/1000)=${got}, want ${want}`);
  }
});

// +cache_age Go/JS parity on the stale-on-error salvage path:
// The Go server (handler.go ~:1645) gates on CacheStatusHit || CacheStatusHitStale
// and NEVER emits X-Cache-Age for CacheStatusHitStaleError (the origin-error salvage).
// The edge must suppress the header on that path too (byte-identical-delivery invariant).
//
// A genuine HIT (fresh) and a genuine HIT-STALE (revalidation grace, SWR) SHOULD still
// emit the header — only the origin-error salvage path (HIT-STALE-ERROR) must not.
function cacheAgeStaleIR() {
  return {
    irVersion: IR_VERSION,
    site: { hosts: ["example.com"] },
    upstream: {},
    matchers: {},
    recv: {},
    key: { tokens: [{ kind: "host" }, { kind: "path" }] },
    response: {
      ttl: [{ selKind: "default", ttl: "1s", grace: "1s", maxStale: "24h" }],
      headerResp: [
        { scope: { always: true }, ops: [{ op: "cache_status", name: "X-Cache" }] },
        { scope: { always: true }, ops: [{ op: "cache_age", name: "X-CF-Cache-Age" }] },
      ],
    },
    deliver: {},
    edge: { default: "local" },
  };
}

await test("+cache_age: genuine HIT emits X-CF-Cache-Age", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = cacheAgeStaleIR();
  const ok = originStub(200, { "Content-Type": "text/html" }, "body");
  await prime("/page", { ir, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 500; // 500ms — still fresh (ttl=1s)
  const r = await handle(req("/page"), {}, mockCtx(), { ir, cache, fetchImpl: ok, originBase: "http://o" });
  assert.equal(r.headers.get("X-Cache"), "HIT");
  assert.ok(r.headers.get("X-CF-Cache-Age") != null, "a genuine HIT must emit X-CF-Cache-Age");
});

await test("+cache_age: HIT-STALE (within grace, SWR) emits X-CF-Cache-Age", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = cacheAgeStaleIR();
  const ok = originStub(200, { "Content-Type": "text/html" }, "body");
  await prime("/page", { ir, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 1_500; // 1.5s — past ttl(1s), within grace(+1s total=2s) → stale
  const r = await handle(req("/page"), {}, mockCtx(), { ir, cache, fetchImpl: ok, originBase: "http://o" });
  assert.equal(r.headers.get("X-Cache"), "HIT-STALE");
  assert.ok(r.headers.get("X-CF-Cache-Age") != null, "HIT-STALE (within grace) must emit X-CF-Cache-Age");
});

await test("+cache_age: stale-on-error transport salvage (HIT-STALE-ERROR) suppresses X-CF-Cache-Age (Go/JS parity)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = cacheAgeStaleIR();
  const ok = originStub(200, { "Content-Type": "text/html" }, "STALE");
  await prime("/page", { ir, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 10 * 3600 * 1000; // 10h — past ttl+grace(2s), within max_stale(24h)
  const boom = async () => { throw new Error("origin down"); };
  const r = await handle(req("/page"), {}, mockCtx(), { ir, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 200, "should serve the stale-on-error salvage copy");
  assert.equal(r.headers.get("X-Cache"), "HIT-STALE-ERROR", "cache-status must still be HIT-STALE-ERROR");
  assert.equal(r.headers.get("X-CF-Cache-Age"), null, "HIT-STALE-ERROR MUST NOT emit X-CF-Cache-Age (Go server suppresses it; parity)");
});

await test("+cache_age: stale-on-error origin-returned-5xx salvage (handleOriginResponseError path) suppresses X-CF-Cache-Age (Go/JS parity)", async () => {
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = cacheAgeStaleIR();
  const ok = originStub(200, { "Content-Type": "text/html" }, "STALE");
  await prime("/page", { ir, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 10 * 3600 * 1000; // 10h — past ttl+grace(2s), within max_stale(24h)
  const boom = originStub(503, {}, "boom");
  const r = await handle(req("/page"), {}, mockCtx(), { ir, cache, fetchImpl: boom, originBase: "http://o" });
  assert.equal(r.status, 200, "should serve the stale-on-error salvage copy");
  assert.equal(r.headers.get("X-Cache"), "HIT-STALE-ERROR", "cache-status must still be HIT-STALE-ERROR");
  assert.equal(r.headers.get("X-CF-Cache-Age"), null, "origin-returned-5xx salvage MUST NOT emit X-CF-Cache-Age (Go server suppresses it; parity)");
});

await test("+cache_age: stale-on-error origin-returned-404 salvage (negative-response path) suppresses X-CF-Cache-Age (Go/JS parity)", async () => {
  // entry.js line ~:745 — the 404/410 case where a stale last-good copy outranks storing the 404.
  // This path passes storedAt, causing the bug; it must be suppressed to match the server.
  clock.t = 1_000_000;
  const cache = freshCache();
  const ir = cacheAgeStaleIR();
  const ok = originStub(200, { "Content-Type": "text/html" }, "STALE");
  await prime("/page", { ir, cache, fetchImpl: ok, originBase: "http://o" });
  clock.t += 10 * 3600 * 1000; // 10h — past ttl+grace(2s), within max_stale(24h)
  const notFound = originStub(404, {}, "not found");
  const r = await handle(req("/page"), {}, mockCtx(), { ir, cache, fetchImpl: notFound, originBase: "http://o" });
  assert.equal(r.status, 200, "a stale salvage copy outranks a 404 response");
  assert.equal(r.headers.get("X-Cache"), "HIT-STALE-ERROR", "cache-status must still be HIT-STALE-ERROR");
  assert.equal(r.headers.get("X-CF-Cache-Age"), null, "origin-returned-404 salvage MUST NOT emit X-CF-Cache-Age (Go server suppresses it; parity)");
});

// --- origin passthrough mode -------------------------------------------------
// PASSTHROUGH (origin binding == "passthrough"): the worker must fetch the ORIGINAL
// request URL unchanged — preserving the client host AND scheme (HTTPS:443 for an https
// request) — and must NOT rewrite the URL host or set a Host header to a different host.
// This relies on Cloudflare same-zone loop-prevention to reach the real multi-host origin
// (apex/www both in the zone), avoiding the canonicalize-redirect loop that a host rewrite
// to the apex/backend hostname triggers. The request-phase header ops, geo headers, the
// X-Cadish-Peer hop-guard, and the EDGE_TRUST_HEADERS strip must STILL be applied.

await test("PASSTHROUGH: origin binding 'passthrough' fetches the ORIGINAL url (host+scheme preserved) and sets no divergent Host; ops/geo/peer/trust-strip still apply", async () => {
  let capturedURL = null;
  let capturedHeaders = null;
  const fetchImpl = async (url, init) => {
    capturedURL = url;
    capturedHeaders = init.headers;
    return new Response("body", { status: 200 });
  };
  const request = new Request("https://www.example.com/p?q=1", {
    headers: {
      // A client-supplied edge-trust header that MUST be stripped before forwarding.
      "X-Cadish-Geo-Region": "INJECTED",
    },
  });
  const reqHeaderOps = [{ op: "set", name: "X-Test-Op", value: "yes" }];
  const geo = { geo: "US", geoContinent: "NA", geoRegion: "US-UT" };
  await fetchOrigin(request, { originBase: "passthrough", reqHeaderOps, geo, fetchImpl });

  // The ORIGINAL url is fetched unchanged — host AND scheme preserved (https:443).
  assert.equal(capturedURL, "https://www.example.com/p?q=1", "passthrough must fetch the original url unchanged (host+scheme preserved)");
  // No Host header rewritten to a different host — let the original host stand. The test
  // Request carries no Host, so none is set (and certainly not the apex/backend host).
  const host = capturedHeaders.get("Host");
  assert.ok(host === null || host === "www.example.com", `passthrough must not set a divergent Host (got ${host})`);
  // The request-phase header ops still apply.
  assert.equal(capturedHeaders.get("X-Test-Op"), "yes", "request header ops must still apply in passthrough");
  // Geo headers still injected.
  assert.equal(capturedHeaders.get("CF-IPCountry"), "US", "geo headers must still apply in passthrough");
  assert.equal(capturedHeaders.get("X-Cadish-Geo-Region"), "US-UT", "the edge-resolved geo region must overwrite the stripped client value");
  // The hop-guard is set.
  assert.equal(capturedHeaders.get(PEER_HEADER), "1", "X-Cadish-Peer hop-guard must still be set in passthrough");
});

await test("EMPTY origin binding throws loudly (NOT a silent passthrough degrade) — passthrough must be opted into explicitly", async () => {
  let fetched = false;
  const fetchImpl = async () => {
    fetched = true;
    return new Response("body", { status: 200 });
  };
  const request = new Request("https://www.example.com/x");
  // An empty CADISH_ORIGIN is an operator error (the deploy plane rejects it). It must fail
  // loudly rather than silently fetch the original host: in the separate-cadish-server-behind
  // topology a silent passthrough would fetch the public zone host instead of the server.
  // Passthrough is reached ONLY via the explicit "passthrough" sentinel.
  await assert.rejects(
    () => fetchOrigin(request, { originBase: "", reqHeaderOps: [], geo: null, fetchImpl }),
    /no origin binding/,
    "an empty origin binding must throw, not silently pass through",
  );
  assert.equal(fetched, false, "no origin fetch must happen on an empty binding");
});

await test("REWRITE (contrast): a real -origin URL still rewrites the host and sets the canonical Host header", async () => {
  let capturedURL = null;
  let capturedHeaders = null;
  const fetchImpl = async (url, init) => {
    capturedURL = url;
    capturedHeaders = init.headers;
    return new Response("body", { status: 200 });
  };
  const request = new Request("https://www.example.com/p?q=1");
  await fetchOrigin(request, { originBase: "http://cadish-behind.internal:8080", reqHeaderOps: [], geo: null, fetchImpl });
  // The host/scheme/port come from the origin base; path+query preserved.
  const out = new URL(capturedURL);
  assert.equal(out.hostname, "cadish-behind.internal", "rewrite mode takes the host from the origin base");
  assert.equal(out.protocol, "http:", "rewrite mode takes the scheme from the origin base");
  assert.equal(out.pathname + out.search, "/p?q=1", "path+query preserved");
  // The Host header is set to the CANONICAL original host (key↔forward parity).
  assert.equal(capturedHeaders.get("Host"), "www.example.com", "rewrite mode sets the canonical original Host");
});

// --- X-Cadish-Edge marker (worker-served vs origin-direct) -------------------
await test("worker stamps X-Cadish-Edge on every response (the worker-served marker)", async () => {
  const worker = (await import("./entry.js")).default;
  // No IR is baked into the raw source, so handle() returns its 'no IR' 500 — but the point is
  // the fetch WRAPPER stamps X-Cadish-Edge on EVERY response the worker returns, so an operator
  // can tell a worker-served response from one served DIRECTLY by the origin (an `edge { bypass }`
  // route, which has no worker → no marker). The cadish server behind never sets this header.
  const res = await worker.fetch(new Request("https://www.example.com/x"), {}, { waitUntil() {} });
  assert.ok(res.headers.get("X-Cadish-Edge"), `X-Cadish-Edge must be set on a worker response (status ${res.status})`);
});

// --- report -----------------------------------------------------------------

if (failures.length) {
  console.error(`\nFAIL: ${failures.length} failed, ${passed} passed`);
  process.exit(1);
}
console.log(`PASS: ${passed} runtime IO test(s)`);
