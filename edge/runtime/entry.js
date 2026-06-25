// entry.js — the worker entrypoint. Orchestrates the IR interpreter + the cache
// tiers + geo injection + origin fetch into the request flow of design §6:
//
//   1. geo: request.cf -> geo classes (+ inject as origin headers)
//   2. interpreter RECV+KEY -> pass / synthetic / redirect / cache key / req headers
//   3. edge cache lookup (L1 -> L2)
//        fresh hit            -> deliver HIT
//        stale-within-grace   -> deliver HIT-STALE, revalidate via waitUntil (SWR)
//   4. miss -> fetch the `to` (cadish behind) with the X-Cadish-Peer hop-guard
//   5. interpreter ORIGIN -> ttl/grace/cacheable; store by edge policy
//   6. interpreter DELIVER -> response headers / strip_cookies / cors / cache-status
//   7. origin failure -> serve stale-on-error if any copy exists, else 502
//
// The worker is small, generic, and best-effort: anything it cannot do faithfully
// is delegated to the Cadish server behind. The brain is 100% in the IR.

import { evalRequest, evalResponse, evalDeliver, newRequest, resolveEdgeTier, cacheKeyHeaderValue, applyTransforms, resolveOnError, canonicalHeaderKey, selectedKeyCoversAllCookies } from "./interpreter.js";
import { resolveGeo } from "./geo.js";
import { fetchOrigin, originURLFor } from "./origin.js";
import { EdgeCache } from "./cache-tiers.js";

// buildIReq builds the interpreter's request from the inbound fetch Request +
// the edge-resolved geo. Device is left "" here: the interpreter classifies the
// {device} bucket NATIVELY from the request's own User-Agent header against the IR's
// device ruleset (D70) — so the edge resolves {device} on its own, no longer relying
// on a server pre-pass nor the legacy X-Cadish-Device header crutch. We deliberately
// do NOT read any client-supplied X-Cadish-Device header: the edge is the first hop,
// so such a header is attacker-controlled; the User-Agent the classifier reads is the
// real client's, the same input the Go server's classify pre-pass uses.
function buildIReq(request, geo) {
  const url = new URL(request.url);
  const query = {};
  for (const [k, v] of url.searchParams.entries()) (query[k] ||= []).push(v);
  const header = {};
  for (const [k, v] of request.headers.entries()) header[k] = v;
  let path = url.pathname;
  try {
    path = decodeURIComponent(url.pathname);
  } catch {
    /* keep the raw pathname on a bad %-sequence */
  }
  return newRequest({
    method: request.method,
    host: url.host,
    path,
    query,
    header,
    clientIP: request.headers.get("CF-Connecting-IP") || "",
    // device is left "" so the interpreter self-classifies from the request's
    // User-Agent against the IR device ruleset (D70). Never taken from a client-
    // supplied X-Cadish-Device header (attacker-controlled at the first hop).
    device: "",
    geo: geo.geo,
    geoContinent: geo.geoContinent,
    geoRegion: geo.geoRegion,
  });
}

// respHeaderToObj extracts the response headers into the {name: value|[values]}
// shape the interpreter's response-phase matchers expect, keeping Set-Cookie as a
// distinct array (so the set_cookie matcher reads real cookie names).
function respHeaderToObj(headers) {
  const obj = {};
  for (const [k, v] of headers.entries()) {
    if (k.toLowerCase() === "set-cookie") continue;
    obj[k] = v;
  }
  const sc = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  if (sc.length) obj["Set-Cookie"] = sc;
  return obj;
}

function applyHeaderOps(headers, ops) {
  for (const op of ops || []) {
    switch (op.op) {
      case "set":
        headers.set(op.name, op.value);
        break;
      case "append":
        headers.append(op.name, op.value);
        break;
      case "remove":
        headers.delete(op.name);
        break;
    }
  }
}

function applyCORS(headers, cors, ireq) {
  if (cors.allowAllOrigins) {
    headers.set("Access-Control-Allow-Origin", "*");
  } else if (cors.origins && cors.origins.length) {
    const origin = ireqHeader(ireq, "Origin");
    if (origin && cors.origins.includes(origin)) {
      headers.set("Access-Control-Allow-Origin", origin);
      headers.append("Vary", "Origin");
    }
  }
  if (cors.methods && cors.methods.length) headers.set("Access-Control-Allow-Methods", cors.methods.join(", "));
  if (cors.headers && cors.headers.length) headers.set("Access-Control-Allow-Headers", cors.headers.join(", "));
}

function ireqHeader(ireq, name) {
  const v = ireq.header.get(name);
  return v && v.length ? v[0] : "";
}

// deliver runs the DELIVER phase and applies it to a response, returning a fresh
// Response. statusOverride forces the cache-status token (e.g. HIT-STALE-ERROR).
// opts.isHead / opts.isRange flip the `replace` transform-skip gating (a HEAD/Range
// response is never body-transformed, mirroring the server).
async function deliver(ir, ireq, resp, cacheStatus, statusOverride, key, opts = {}) {
  const respHeader = respHeaderToObj(resp.headers);
  const dd = evalDeliver(ir, ireq, respHeader, cacheStatus);
  const headers = new Headers(resp.headers);
  applyHeaderOps(headers, dd.respHeaderOps);
  if (dd.stripCookies) headers.delete("Set-Cookie");
  if (dd.cors) applyCORS(headers, dd.cors, ireq);
  if (statusOverride && dd.cacheStatusHeader) headers.set(dd.cacheStatusHeader, statusOverride);
  // `header +cache_key NAME [raw]` (debug): emit the request's computed cache key
  // — the same 12-hex sha256 prefix the Go server emits (or the raw key under
  // `raw`). Omitted when the request has no key (a pass/HEAD/Range path: key
  // undefined). Identical to pipeline.CacheKeyHeaderValue by construction.
  if (dd.cacheKeyHeader && key) {
    const v = cacheKeyHeaderValue(key, dd.cacheKeyRaw);
    if (v) headers.set(dd.cacheKeyHeader, v);
  }
  // `replace` body transform (D75): a SIZE-BOUNDED literal substitution applied
  // post-cache on delivery. Skipped for HEAD/Range/already-encoded responses, and for
  // a body over the IR cap (passed through untransformed — the over-cap/streaming case
  // stays a server-only non-goal). We buffer up to cap+1 bytes; only when the whole
  // body fits do we transform, otherwise we stream the original body unchanged so a
  // huge body is never fully materialized at the edge.
  const out = await applyBodyTransform(ir, dd.transforms, resp, headers, opts);
  return new Response(out.body, { status: resp.status, headers: out.headers });
}

// applyBodyTransform reads the response body up to the IR transform cap and applies the
// matched `replace` rules when (a) the response is transformable (not HEAD/Range/
// encoded) and (b) the whole body fits within the cap. An over-cap or non-transformable
// body is returned UNCHANGED (the original stream/body), so a large body is never fully
// buffered. Returns { body, headers } (headers may be adjusted: a transformed body
// drops the stored ETag, mirroring the server, and resets Content-Length).
async function applyBodyTransform(ir, transforms, resp, headers, opts) {
  const transformsList = transforms || [];
  const contentEncoding = headers.get("Content-Encoding") || "";
  const isHead = !!opts.isHead;
  const isRange = !!opts.isRange;
  if (transformsList.length === 0 || isHead || isRange || contentEncoding !== "" || resp.body == null) {
    return { body: resp.body, headers };
  }
  const cap = (ir.response && ir.response.transformMaxBytes) || 0;
  if (cap <= 0) return { body: resp.body, headers };
  // Buffer up to cap+1 bytes to detect an over-cap body without fully reading it.
  const reader = resp.body.getReader();
  const chunks = [];
  let total = 0;
  let overCap = false;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
    if (total > cap) {
      overCap = true;
      break;
    }
  }
  if (overCap) {
    // Reconstruct the original stream: the buffered prefix followed by the remainder.
    reader.releaseLock();
    const prefix = concatChunks(chunks);
    const rest = resp.body; // the reader was released; the underlying stream resumes
    const combined = new ReadableStream({
      start(controller) {
        controller.enqueue(prefix);
      },
      async pull(controller) {
        const r = rest.getReader();
        for (;;) {
          const { value, done } = await r.read();
          if (done) {
            controller.close();
            return;
          }
          controller.enqueue(value);
        }
      },
    });
    return { body: combined, headers };
  }
  reader.releaseLock();
  const bodyText = new TextDecoder().decode(concatChunks(chunks));
  const tres = applyTransforms(ir, transformsList, bodyText, { isHead, isRange, contentEncoding });
  if (!tres.transformed) return { body: bodyText, headers };
  headers.delete("ETag"); // body changed; the stored ETag no longer matches (server parity)
  const outBytes = new TextEncoder().encode(tres.body);
  headers.set("Content-Length", String(outBytes.byteLength));
  return { body: outBytes, headers };
}

function concatChunks(chunks) {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

// storeResponse returns the Response to PERSIST in the edge cache. When a `strip_cookies`
// rule fires for this response (the same decision evalDeliver makes on delivery), the
// Set-Cookie header is physically removed BEFORE storing — mirroring the server, and the
// only way past the cache-tiers Set-Cookie store guard. This is what lets a cookie-stamping
// origin be cached safely at the edge: the cookie is controlled (stripped) per the operator's
// explicit opt-in, so the stored object — and every HIT served from it — carries no cookie.
// Without a matching strip rule the Set-Cookie response is left intact and the store guard
// refuses it (the ironclad default). resp is cloned so the caller's copy stays readable.
function storeResponse(ir, ireq, resp, respHeader) {
  const dd = evalDeliver(ir, ireq, respHeader, "MISS");
  if (!dd.stripCookies || !resp.headers.has("Set-Cookie")) return resp.clone();
  const headers = new Headers(resp.headers);
  headers.delete("Set-Cookie");
  return new Response(resp.clone().body, { status: resp.status, headers });
}

async function revalidate(ir, ireq, request, geo, cookieAllowActive, originBase, fetchImpl, cache, key, ctx) {
  try {
    const resp = await fetchOrigin(request, { originBase, reqHeaderOps: ireq._reqHeaderOps, geo, fetchImpl });
    const respHeader = respHeaderToObj(resp.headers);
    const rdec = evalResponse(ir, ireq, resp.status, respHeader);
    // Defense in depth: never (re)store a credentialed request's response. This MUST match
    // the main store guard (handle()): a Cookie only forces a bypass when it is NOT exempted
    // by cookie_allow — otherwise a cookie_allow entry would store on its first MISS but never
    // refresh on revalidation, so every post-grace request becomes a MISS (a server↔edge
    // divergence, since the Go server re-stores). Authorization always bypasses.
    if (rdec.cacheable && !request.headers.has("Authorization") && !(request.headers.has("Cookie") && !cookieAllowActive)) {
      await cache.store(
        key,
        storeResponse(ir, ireq, resp, respHeader),
        {
          ttlMs: rdec.ttlNs / 1e6,
          graceMs: rdec.graceNs / 1e6,
          maxStaleMs: rdec.maxStaleNs / 1e6,
          tier: resolveEdgeTier(ir, ireq, respHeader),
        },
        null,
      );
    }
  } catch {
    /* best-effort SWR: a failed revalidation keeps the stale copy until grace ends */
  }
}

// cookieNameAllowed reports whether a cookie name matches any `cookie_allow` pattern
// (exact, or a `*` glob). Mirrors the Go nameGlobSet semantics for cookie names.
function cookieNameAllowed(name, patterns) {
  for (const p of patterns) {
    if (p === "*") return true;
    if (p.indexOf("*") >= 0) {
      const re = new RegExp("^" + p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
      if (re.test(name)) return true;
    } else if (p === name) {
      return true;
    }
  }
  return false;
}

// filterCookieHeader keeps only the cookies whose name is allow-listed, returning the
// rebuilt Cookie header value (empty when none survive). Mirrors the Go server's
// FilterRequestCookies so the edge caches the same controlled cookie traffic.
function filterCookieHeader(raw, patterns) {
  if (!raw) return "";
  const out = [];
  for (const pair of raw.split(";")) {
    const s = pair.trim();
    if (!s) continue;
    const eq = s.indexOf("=");
    const name = eq >= 0 ? s.slice(0, eq) : s;
    if (cookieNameAllowed(name, patterns)) out.push(s);
  }
  return out.join("; ");
}

// handle is the testable core. deps lets tests inject { ir, cache, fetchImpl, now }.
export async function handle(request, env, ctx, deps = {}) {
  const ir = deps.ir || globalThis.__CADISH_IR__;
  if (!ir) return new Response("cadish edge: no IR baked into the bundle", { status: 500 });

  const geo = resolveGeo(request);
  const ireq = buildIReq(request, geo);

  // cookie_allow: strip every request cookie not on the operator's allowlist BEFORE the
  // cache key, the credential bypass, and the origin fetch — so the edge caches the same
  // controlled cookie traffic the server does, and the origin (like the cache) never sees
  // the stripped cookies (incl. any session). An empty allowlist strips ALL cookies.
  const cookieAllowActive = !!ir.cookieAllowSet;
  // Compute the filtered Cookie ONCE and rewrite it on the interpreter's request BEFORE
  // evalRequest, exactly as the server filters r.Header before EvalRequest. This makes the
  // cache key match the server for EVERY cookie key token — including `header:Cookie`, which
  // reads the whole Cookie header (not just `cookie:NAME`). Without this, the edge would key
  // on the unfiltered header while the server keys on the filtered one (a Go↔JS divergence).
  let cookieFiltered = "";
  if (cookieAllowActive) {
    cookieFiltered = filterCookieHeader(request.headers.get("Cookie") || "", ir.cookieAllow || []);
    const ck = canonicalHeaderKey("Cookie");
    if (cookieFiltered) ireq.header.set(ck, [cookieFiltered]);
    else ireq.header.delete(ck);
  }

  const dec = evalRequest(ir, ireq);

  // cookie_allow: the controlled cookies are exempt from the bypass (set below), and we
  // forward only the ALLOW-LISTED cookies to the origin (a Cookie header op the fetch
  // applies) so a stripped session can never reach the backend and produce per-user
  // content. fetchOrigin builds its headers from the ORIGINAL Fetch Request, so the filtered
  // value must be (re)applied there as an explicit op even though ireq is already filtered.
  if (cookieAllowActive) {
    dec.reqHeaderOps = [cookieFiltered ? { op: "set", name: "Cookie", value: cookieFiltered } : { op: "remove", name: "Cookie" }, ...(dec.reqHeaderOps || [])];
  }
  ireq._reqHeaderOps = dec.reqHeaderOps; // carried for SWR revalidation

  if (dec.synthetic) return new Response(dec.synthetic.body, { status: dec.synthetic.status });
  if (dec.redirect) {
    return new Response(null, { status: dec.redirect.status, headers: { Location: dec.redirect.location } });
  }

  const originBase = deps.originBase || originURLFor(env, dec.upstream);
  const fetchImpl = deps.fetchImpl;
  const cache =
    deps.cache ||
    new EdgeCache({
      cache: caches.default,
      kv: env && env.CADISH_KV,
      // The two-tier cache is active whenever an L2 KV binding exists; the per-
      // response edge tier (resolveEdgeTier) decides which objects actually go to
      // L2 (only tier "distribute"). So a bound namespace + any distribute policy
      // works, without needing the default tier to be "distribute".
      distribute: !!(env && env.CADISH_KV),
      now: deps.now,
      // KV guardrails from the IR `edge {}` block: kv_ttl caps KV retention, and
      // kv_max_bytes keeps large bodies out of KV (L1-only). Both default safely
      // in EdgeCache when the IR omits them.
      kvTtlSeconds: (ir.edge && ir.edge.kvTtlSeconds) || 0,
      kvMaxBytes: (ir.edge && ir.edge.kvMaxBytes) || 0,
    });

  // SAFE BY DEFAULT (security, AUTH-LEAK/COOKIE-LEAK): a request carrying credentials
  // (Authorization or Cookie) bypasses the edge shared cache entirely — never served
  // from / stored to it — so one user's private response can't leak to another. The
  // edge enforces this conservatively (it does NOT do per-user keyed caching; the Go
  // server behind it caches keyed credentialed traffic when the cache_key captures the
  // credential — see Pipeline.BypassForCredentials).
  // With cookie_allow the surviving (filtered) cookies are operator-controlled, but they are
  // NOT blanket-exempt: a kept cookie still forces the bypass UNLESS the selected cache key
  // ISOLATES every kept cookie (a cookie:NAME token for each, or header:Cookie). Otherwise an
  // allow-listed-but-unkeyed cookie (a second identity cookie like `uid`, or any kept cookie
  // under an unkeyed config) would let the edge store a per-user body under a shared key — the
  // same name-aware rule the server enforces (Pipeline.BypassForCredentials). Without
  // cookie_allow, any Cookie bypasses (the conservative edge default). Authorization always
  // bypasses (never cookie-exempt).
  let credentialed = request.headers.has("Authorization");
  if (!credentialed && request.headers.has("Cookie")) {
    credentialed = !cookieAllowActive || !selectedKeyCoversAllCookies(ir, ireq);
  }

  // Bypass the cache entirely for `pass`, a credentialed request, and for HEAD / Range
  // requests. A HEAD (bodyless) or a Range (206 partial) response must NEVER be stored
  // under the method/range-agnostic cache key, where it would later satisfy a full GET
  // with an empty or truncated body. The Cadish server behind handles Range/HEAD
  // correctly (it slices a cached 200 — see D35); the edge just passes them.
  if (dec.pass || credentialed || request.method === "HEAD" || request.headers.has("Range")) {
    try {
      const resp = await fetchOrigin(request, { originBase, reqHeaderOps: dec.reqHeaderOps, geo, fetchImpl });
      // HEAD/Range never body-transform (mirrors the server's transform skip).
      return await deliver(ir, ireq, resp, "MISS", undefined, undefined, {
        isHead: request.method === "HEAD",
        isRange: request.headers.has("Range"),
      });
    } catch {
      // Outage on a pass/HEAD/Range: no cached object to salvage (these never store),
      // so serve the configured on_error synthetic if one matches, else a bare 502.
      return onErrorOr502(ir, ireq);
    }
  }

  const key = dec.cacheKey;
  const lookup = await cache.lookup(key);
  if (lookup.state === "fresh") {
    if (lookup.fromL2) await cache.populateL1(key, lookup.response.clone(), lookup.meta, ctx);
    return await deliver(ir, ireq, lookup.response, "HIT", undefined, key);
  }
  if (lookup.state === "stale") {
    if (ctx) ctx.waitUntil(revalidate(ir, ireq, request, geo, cookieAllowActive, originBase, fetchImpl, cache, key, ctx));
    return await deliver(ir, ireq, lookup.response, "HIT-STALE", undefined, key);
  }

  // miss → origin.
  let originResp;
  try {
    originResp = await fetchOrigin(request, { originBase, reqHeaderOps: dec.reqHeaderOps, geo, fetchImpl });
  } catch {
    // TRANSPORT failure (fetch threw — no response, status 0). This is Go's
    // transport-error branch (origin.StatusOf == 0): no status to negatively cache, so
    // the precedence is serve-stale-within-max_stale > respond on_error > bare 502.
    const salvage = await cache.peek(key);
    if (salvage) return await deliver(ir, ireq, salvage.response, "HIT-STALE", "HIT-STALE-ERROR", key);
    return onErrorOr502(ir, ireq);
  }

  // ORIGIN-RETURNED failure (parity with the Go server). fetch only throws on a
  // TRANSPORT error; an origin that RESPONDS 5xx (the common flapping/maintenance
  // shape) returns a Response. The Go server maps such a returned status to an origin
  // FAILURE and routes it through handleOriginError — so the edge must too, instead of
  // forwarding the raw 5xx and consulting none of max_stale / negative-cache / on_error.
  //
  // Go's status→failure mapping (internal/origin/httporigin.go Fetch):
  //   200/206  -> success (handled below, normal flow)
  //   3xx      -> passed through to the client verbatim (NOT a failure)
  //   404/410  -> Negative *Response WITH its body: max_stale salvage wins, else the
  //               normal store/serve flow (negative caching when cache_ttl makes it
  //               cacheable). on_error does NOT fire for a returned 404/410.
  //   ANY OTHER non-success >= 400 (403, 405, 429, 5xx, …) -> *StatusError ->
  //               handleOriginError hard-failure chain: max_stale salvage > negative
  //               cache > on_error > bare status. httporigin's negativeStatus is ONLY
  //               404||410, so a returned 403/429/405 is a StatusError, NOT a Negative
  //               response and NOT a normal MISS — it MUST take the chain (else on_error
  //               and max_stale are silently skipped; verified against the real Go
  //               server in internal/server TestOnErrorReturned4xx*).
  //
  // We mirror exactly which statuses trigger the chain (>=400 && !=404 && !=410), so a
  // normal cacheable 404 is NOT salvaged the way a 5xx is — it follows Go's Negative path.
  const status = originResp.status;
  if (status >= 400 && status !== 404 && status !== 410) {
    return await handleOriginResponseError(ir, ireq, request, cache, key, originResp, ctx);
  }
  if (status === 404 || status === 410) {
    // Negative response (Go's Negative *Response). max_stale salvage of a last-good
    // copy OUTRANKS storing/serving the 404 (handler.go ~728). When no salvageable copy
    // exists, fall through to the normal flow, which negatively caches + serves the 404
    // when cache_ttl marks the status cacheable.
    const salvage = await cache.peek(key);
    if (salvage) return await deliver(ir, ireq, salvage.response, "HIT-STALE", "HIT-STALE-ERROR", key);
  }

  const respHeader = respHeaderToObj(originResp.headers);
  const rdec = evalResponse(ir, ireq, originResp.status, respHeader);
  if (rdec.cacheable && !request.headers.has("Authorization")) {
    await cache.store(
      key,
      storeResponse(ir, ireq, originResp, respHeader),
      {
        ttlMs: rdec.ttlNs / 1e6,
        graceMs: rdec.graceNs / 1e6,
        maxStaleMs: rdec.maxStaleNs / 1e6,
        tier: resolveEdgeTier(ir, ireq, respHeader),
      },
      ctx,
    );
  }
  return await deliver(ir, ireq, originResp, "MISS", undefined, key);
}

// handleOriginResponseError mirrors the Go server's handleOriginError precedence for an
// origin that RETURNED a hard-failure status (>=400 except 404/410, Go's *StatusError path):
//   1. serve-stale-within-max_stale (cache.peek, bounded to the window) — a real (if old)
//      representation beats a synthetic error or a cached failure.
//   2. negative cache: when cache_ttl marks the status cacheable, STORE the negative
//      response and serve it (so subsequent requests are served from cache, not re-hit).
//   3. respond on_error synthetic (the configured maintenance page).
//   4. bare origin status (forward the 5xx the origin returned), Go's writeStatus(code).
// This is the same ordering handleOriginError uses; only the inputs differ (a returned
// Response carries a status + body, where the Go path saw a *StatusError).
async function handleOriginResponseError(ir, ireq, request, cache, key, originResp, ctx) {
  // 1. max_stale salvage.
  const salvage = await cache.peek(key);
  if (salvage) return await deliver(ir, ireq, salvage.response, "HIT-STALE", "HIT-STALE-ERROR", key);

  // 2. negative caching of the returned status (only when cache_ttl status <5xx> opts in).
  const respHeader = respHeaderToObj(originResp.headers);
  const rdec = evalResponse(ir, ireq, originResp.status, respHeader);
  if (rdec.cacheable && !request.headers.has("Authorization")) {
    await cache.store(
      key,
      storeResponse(ir, ireq, originResp, respHeader),
      {
        ttlMs: rdec.ttlNs / 1e6,
        graceMs: rdec.graceNs / 1e6,
        maxStaleMs: rdec.maxStaleNs / 1e6,
        tier: resolveEdgeTier(ir, ireq, respHeader),
      },
      ctx,
    );
    return await deliver(ir, ireq, originResp, "MISS", undefined, key);
  }

  // 3. respond on_error synthetic, else 4. forward the bare origin status (NOT 502 —
  // mirror Go's writeStatus(code) which forwards the actual upstream code).
  const oe = resolveOnError(ir, ireq);
  if (oe) {
    return new Response(oe.body, {
      status: oe.status,
      headers: { "Content-Type": oe.contentType || "text/html; charset=utf-8" },
    });
  }
  return await deliver(ir, ireq, originResp, "MISS", undefined, key);
}

// onErrorOr502 serves the configured `respond on_error` synthetic (D76) when one
// matches the request, else a bare 502 — the worker's outage fallback when there is no
// servable cached object. The synthetic body is operator config (never reflected
// request data), so there is no injection surface; it is written straight to the client
// and is NOT cached (an availability stopgap, mirroring the server's writeOnError).
function onErrorOr502(ir, ireq) {
  const oe = resolveOnError(ir, ireq);
  if (oe) {
    return new Response(oe.body, {
      status: oe.status,
      headers: { "Content-Type": oe.contentType || "text/html; charset=utf-8" },
    });
  }
  return new Response("origin unavailable", { status: 502 });
}

export default {
  fetch(request, env, ctx) {
    return handle(request, env, ctx);
  },
};
