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

import { evalRequest, evalResponse, evalDeliver, newRequest, resolveEdgeTier, cacheKeyHeaderValue, applyTransforms, resolveOnError, canonicalHeaderKey, selectedKeyCoversAllCookies, selectedDerivedStripCookies, selectedDerivedForwardCookies, cacheCredentialedMatchesReq } from "./interpreter.js";
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
export function buildIReq(request, geo) {
  const url = new URL(request.url);
  const query = {};
  for (const [k, v] of url.searchParams.entries()) (query[k] ||= []).push(v);
  const header = {};
  for (const [k, v] of request.headers.entries()) {
    // MULTI-COOKIE-LINE PARITY: the Go server's lenientCookies joins ALL inbound `Cookie:`
    // request lines with "; " before splitting on ';' (request.go), so a cookie carried on a
    // 2nd/Nth line is still seen by the cookie / cookie_json matchers, the cache-key cookie
    // token and the credential-coverage gate. At the Workers runtime the Fetch Headers API has
    // ALREADY collapsed multiple inbound `Cookie:` lines into ONE entries() value — and the
    // GENERIC header-combine separator is ", " (0x2C 0x20), NOT the "; " the cookie grammar
    // (and interpreter.js parseCookies' ';' split) expects. A bare ", " can never appear INSIDE
    // a cookie-pair: comma is not a valid cookie-octet nor a name char (RFC 6265 §4.1.1), so a
    // ", " in a combined Cookie value is unambiguously a cross-line combine boundary. Normalize
    // it back to "; " so parseCookies sees every cookie, byte-identical to the Go server. The
    // common single-line case ("a=1; b=2" or "a=1") carries no ", " and is left untouched. Some
    // runtimes/undici already recombine Cookie with "; " (then this is a no-op), so we match the
    // server WHICHEVER separator the host runtime chose — fail-closed parity, not a guess.
    header[k] = k.toLowerCase() === "cookie" ? v.split(", ").join("; ") : v;
  }
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
    // scheme backs the {proto}/{scheme} token. On the REAL worker the inbound URL
    // already carries the client-facing scheme (Cloudflare terminates TLS at the
    // edge), so derive it from the URL — otherwise newRequest defaults to "http" and
    // every HTTPS request would resolve {proto} to "http" (downgrading a
    // `redirect … {proto}://…` and sending X-Forwarded-Proto: http on TLS traffic).
    tls: url.protocol === "https:",
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
  // Strip the from_header-family control headers a cache_ttl rule CONSUMED
  // (X-Cache-Ttl/X-Cache-Grace/X-Cache-Max-Stale): an internal origin↔cache contract,
  // not for the client — mirroring the Go server (handler.go). The evalResponse walk runs
  // ONLY when (a) the IR declares a from_header rule (ir.response.hasStripHeaders) AND (b)
  // this is a fresh-from-origin MISS: a HIT/HIT-STALE serves the STORED copy, which was
  // already stripped at store time (storeResponse), so re-stripping it is redundant. The
  // common config has no from_header rule, so it skips the walk entirely (Finding 5).
  if (ir.response.hasStripHeaders && cacheStatus === "MISS") {
    for (const n of evalResponse(ir, ireq, resp.status, respHeader).stripHeaders || []) headers.delete(n);
  }
  // cache_credentialed (D101): on a positive-signal MISS, strip the weak refusals (no-store/
  // private/no-cache Cache-Control, Pragma, Expires) the in-scope signal force-overrode, so the
  // client never sees a no-store cadish is caching anyway — mirroring the Go server. Only on a
  // MISS: a HIT/STALE serves the STORED copy, already stripped at store time (storeResponse).
  if (cacheStatus === "MISS" && credentialedStore(ir, ireq, resp, respHeader)) {
    stripCredentialedWeakHeaders(headers);
  }
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

// clientAcceptsEncoding reports whether a client's Accept-Encoding header accepts the given
// content-coding — a faithful port of the Go server's clientAcceptsEncoding (handler.go).
// identity (or an empty coding) is always acceptable. A coding is accepted when listed with a
// non-zero q, or when `*` is listed with a non-zero q. An empty Accept-Encoding means the
// client expressed no preference, which per RFC 9110 §12.5.3 means identity only — so a
// non-identity coding is NOT accepted. Token matching is case-insensitive. The whole stored
// Content-Encoding string is passed as `coding` (mirroring the server), so a multi-coding value
// only matches a `*` and otherwise fails closed to a fresh origin negotiation.
function clientAcceptsEncoding(acceptEncoding, coding) {
  if (coding === "" || coding.toLowerCase() === "identity") return true;
  let star = false;
  for (const part of acceptEncoding.split(",")) {
    let tok = part.trim();
    let q = "1";
    const i = tok.indexOf(";");
    if (i >= 0) {
      const params = tok.slice(i + 1);
      tok = tok.slice(0, i).trim();
      const j = params.toLowerCase().indexOf("q=");
      if (j >= 0) q = params.slice(j + 2).trim();
    }
    const accepted = q !== "0" && q !== "0.0" && q !== "0.00" && q !== "0.000";
    if (tok.toLowerCase() === coding.toLowerCase()) return accepted;
    if (tok === "*") star = accepted;
  }
  return star;
}

// storeResponse returns the Response to PERSIST in the edge cache. When a `strip_cookies`
// rule fires for this response (the same decision evalDeliver makes on delivery), the
// Set-Cookie header is physically removed BEFORE storing — mirroring the server, and the
// only way past the cache-tiers Set-Cookie store guard. This is what lets a cookie-stamping
// origin be cached safely at the edge: the cookie is controlled (stripped) per the operator's
// explicit opt-in, so the stored object — and every HIT served from it — carries no cookie.
// Without a matching strip rule the Set-Cookie response is left intact and the store guard
// refuses it (the ironclad default). resp is cloned so the caller's copy stays readable.
// stripCredentialedWeakHeaders implements the cache_credentialed (D101) force-override of the
// response's per-user markers (the custom-VCL `if (X-Cache-Ttl) { unset set-cookie; unset
// Cache-Control; set ttl }`, and the old `strip_cookies @v3_readmodel`): on a positive-signal
// store the in-scope cache_ttl signal force-stores under the SHARED key, so:
//   - Set-Cookie is ALWAYS removed — the absolute "a Set-Cookie VALUE is NEVER written into a
//     cached object" invariant stays intact (the STORED object and every HIT carry none), and
//     the MISS delivery matches. This bounds the operator-bug case: a per-user route that
//     erroneously emits X-Cache-Ttl never leaks its session/tracking cookie into the shared
//     entry. Stripping it before store is ALSO what lets the edge store guard
//     (isCacheableResponse) persist the object (it otherwise refuses a Set-Cookie response).
//   - no-store/private/no-cache Cache-Control, `Pragma: no-cache`, and any `Expires` are
//     removed too (mirrors the Go server's setSharedFreshness + Pragma delete). Removing the
//     weak Cache-Control also lets the store guard persist the object. A positive `max-age=…`
//     (without a weak directive) is left intact.
function stripCredentialedWeakHeaders(headers) {
  headers.delete("Set-Cookie");
  const cc = headers.get("Cache-Control");
  if (cc != null) {
    const kept = cc
      .split(",")
      .map((p) => p.trim())
      .filter((p) => {
        if (p === "") return false;
        const eq = p.indexOf("=");
        const name = (eq >= 0 ? p.slice(0, eq) : p).trim().toLowerCase();
        return name !== "no-store" && name !== "private" && name !== "no-cache";
      });
    if (kept.length) headers.set("Cache-Control", kept.join(", "));
    else headers.delete("Cache-Control");
  }
  headers.delete("Pragma");
  headers.delete("Expires");
}

// credentialedStore reports whether THIS response is a cache_credentialed (D101) positive-
// signal store: the request is in an origin-authoritative scope AND evalResponse marked the
// response cacheable (a positive in-scope cache_ttl signal fired — the sole storage gate). On
// such a store the worker strips Set-Cookie + the weak controls before caching. Returns false
// instantly on a site without the directive.
function credentialedStore(ir, ireq, resp, respHeader) {
  if (!cacheCredentialedMatchesReq(ir, ireq)) return false;
  return !!evalResponse(ir, ireq, resp.status, respHeader).cacheable;
}

function storeResponse(ir, ireq, resp, respHeader) {
  const dd = evalDeliver(ir, ireq, respHeader, "MISS");
  // The from_header-family control headers a cache_ttl rule CONSUMED must also be removed
  // from the STORED copy, so a later HIT does not replay them to the client — mirroring the
  // server, which strips before both store and deliver. The evalResponse walk runs ONLY
  // when the IR declares a from_header rule (ir.response.hasStripHeaders); the common
  // config skips it (Finding 5).
  const strip = ir.response.hasStripHeaders ? evalResponse(ir, ireq, resp.status, respHeader).stripHeaders || [] : [];
  // cache_credentialed (D101): on a positive-signal store, force-override the weak refusals so
  // the object actually persists and a later HIT never replays a no-store cadish itself cached.
  const credStore = credentialedStore(ir, ireq, resp, respHeader);
  if (!credStore && (!dd.stripCookies || !resp.headers.has("Set-Cookie")) && strip.length === 0) return resp.clone();
  const headers = new Headers(resp.headers);
  if (dd.stripCookies) headers.delete("Set-Cookie");
  for (const n of strip) headers.delete(n);
  if (credStore) stripCredentialedWeakHeaders(headers);
  return new Response(resp.clone().body, { status: resp.status, headers });
}

async function revalidate(ir, ireq, request, geo, credentialed, originBase, fetchImpl, cache, key, ctx) {
  try {
    const resp = await fetchOrigin(request, { originBase, reqHeaderOps: ireq._reqHeaderOps, geo, fetchImpl });
    const respHeader = respHeaderToObj(resp.headers);
    const rdec = evalResponse(ir, ireq, resp.status, respHeader);
    // Defense in depth: never (re)store a credentialed request's response. `credentialed` is
    // the SAME decision the main store guard (handle()) computed AFTER cookie_allow filtering
    // and the COOKIE-NORM derive→strip — so a controlled/normalized request re-stores on
    // revalidation (matching the Go server) while a genuinely credentialed one never does.
    if (rdec.cacheable && !credentialed) {
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
function filterCookieHeader(raw, patterns, keep) {
  if (!raw) return "";
  const out = [];
  for (const pair of raw.split(";")) {
    const s = pair.trim();
    if (!s) continue;
    const eq = s.indexOf("=");
    const name = eq >= 0 ? s.slice(0, eq) : s;
    // A `derives_from` axis input is KEPT through cookie_allow (even when not allow-
    // listed) so the classifier can read it and the key is built from it; it is stripped
    // later, post-key, by the COOKIE-NORM strip below — mirroring the server.
    if (cookieNameAllowed(name, patterns) || (keep && keep.has(name))) out.push(s);
  }
  return out.join("; ");
}

// stripCookieNames removes the named cookies from a raw Cookie header value, returning
// the rebuilt value (empty when none remain). The COOKIE-NORM derive→strip: after the
// cache key (incl. {TOKEN}) is built from the originals, the declared axis cookies leave
// the request so the origin is anonymous and the credential check sees no per-user cookie.
function stripCookieNames(raw, stripSet) {
  if (!raw) return "";
  const out = [];
  for (const pair of raw.split(";")) {
    const s = pair.trim();
    if (!s) continue;
    const eq = s.indexOf("=");
    const name = eq >= 0 ? s.slice(0, eq) : s;
    if (stripSet.has(name)) continue;
    out.push(s);
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
  // COOKIE-NORM: the cookies the ACTIVE `derives_from` axes consume for this request,
  // computed on the ORIGINAL (unfiltered) request. ALL of them (strip + forward) are KEPT
  // through cookie_allow so the classifier reads the original value and the key (incl.
  // {TOKEN}) is built from it. After the key is built, the STRIP-mode cookies are removed
  // (below) while the FORWARD-mode cookies stay in the request (forwarded to origin, covered
  // by {TOKEN}) — the same derive→strip/forward the server performs.
  const derivedStripList = selectedDerivedStripCookies(ir, ireq);
  const derivedForwardList = selectedDerivedForwardCookies(ir, ireq);
  const derivedKeep = new Set([...derivedStripList, ...derivedForwardList]);
  const derivedStripSet = new Set(derivedStripList);
  const origCookie = request.headers.get("Cookie") || "";

  // Compute the filtered Cookie ONCE and rewrite it on the interpreter's request BEFORE
  // evalRequest, exactly as the server filters r.Header before EvalRequest. This makes the
  // cache key match the server for EVERY cookie key token — including `header:Cookie`, which
  // reads the whole Cookie header (not just `cookie:NAME`). The derived-axis inputs are KEPT
  // here (derivedKeep) so the classifier can read them; they are stripped just below.
  let cookieFiltered = "";
  if (cookieAllowActive) {
    cookieFiltered = filterCookieHeader(origCookie, ir.cookieAllow || [], derivedKeep);
    const ck = canonicalHeaderKey("Cookie");
    if (cookieFiltered) ireq.header.set(ck, [cookieFiltered]);
    else ireq.header.delete(ck);
  }

  const dec = evalRequest(ir, ireq);

  // COOKIE-NORM strip: now that the key (incl. {TOKEN}) was built from the ORIGINAL cookies,
  // remove the active STRIP-mode derives_from cookies from the interpreter request AND from
  // the value forwarded to origin. FORWARD-mode cookies are deliberately NOT stripped — they
  // stay so the origin reads them (covered by {TOKEN}). Because the strip cookies are then
  // absent, the credential bypass (below) sees no per-user strip cookie and the origin gets an
  // anonymous-w.r.t.-the-axis request (Varnish `unset Cookie` for the static paths).
  let forwardedCookie = cookieAllowActive ? cookieFiltered : origCookie;
  if (derivedStripList.length) {
    forwardedCookie = stripCookieNames(forwardedCookie, derivedStripSet);
    const ck = canonicalHeaderKey("Cookie");
    if (forwardedCookie) ireq.header.set(ck, [forwardedCookie]);
    else ireq.header.delete(ck);
  }

  // cookie_allow / derive-strip: we forward only the controlled (and de-derived) cookies to
  // the origin (a Cookie header op the fetch applies) so a stripped session or axis cookie can
  // never reach the backend and produce per-user content. fetchOrigin builds its headers from
  // the ORIGINAL Fetch Request, so the final value must be (re)applied there as an explicit op.
  // A forward-mode cookie survives in forwardedCookie, so this op also (re)applies it to origin.
  // The base ops (pre cookie normalization) are kept so the PASS path can swap the cookie op for
  // one that forwards the ORIGINAL cookie (SPEC-PASS-FORWARDS-COOKIES), below.
  const baseReqHeaderOps = dec.reqHeaderOps || [];
  const cookieNormActive = cookieAllowActive || derivedStripList.length > 0;
  if (cookieNormActive) {
    dec.reqHeaderOps = [forwardedCookie ? { op: "set", name: "Cookie", value: forwardedCookie } : { op: "remove", name: "Cookie" }, ...baseReqHeaderOps];
  }
  ireq._reqHeaderOps = dec.reqHeaderOps; // carried for SWR revalidation (cacheable: keeps the filtered cookie)

  // cache_credentialed (D101): a request matching a `cache_credentialed @scope` makes caching
  // ORIGIN-AUTHORITATIVE — the worker (a) does NOT credential-bypass it (caches under the
  // SHARED key) and (b) forwards the ORIGINAL cookies to origin so the per-user routes
  // authenticate, mirroring the Go server restoring the original Cookie before the origin
  // fetch on the cacheable path. The cache key is already built (shared, credential-free), so
  // the restored cookie reaches only the origin, never the key. When cookieNormActive the
  // default reqHeaderOps forward the FILTERED cookie — swap them for the original; otherwise
  // fetchOrigin already forwards the original request cookies (no op). Zero cost without the
  // directive (cacheCredentialedMatchesReq short-circuits on an empty set).
  const originAuthoritative = cacheCredentialedMatchesReq(ir, ireq);
  if (originAuthoritative && cookieNormActive) {
    const credOps = [origCookie ? { op: "set", name: "Cookie", value: origCookie } : { op: "remove", name: "Cookie" }, ...baseReqHeaderOps];
    dec.reqHeaderOps = credOps;
    ireq._reqHeaderOps = credOps;
  }

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
      // cache_unsafe: let the store guard cache private/no-store responses the same way the
      // interpreter's evalResponse does under cache_unsafe (Set-Cookie stays ironclad, R20).
      cacheUnsafe: !!ir.cacheUnsafe,
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
  // Presence is judged on the interpreter request AFTER cookie_allow filtering and the
  // COOKIE-NORM strip (ireq), NOT the original Fetch request — so a request whose only
  // cookies were derives_from axis inputs (now stripped) is anonymous and caches, while a
  // remaining uncontrolled/unkeyed cookie still forces the bypass. selectedKeyCoversAllCookies
  // reads the same stripped ireq, so the coverage check matches.
  //
  // AUTHORIZATION (R23, DELIBERATE — see ADR D92): the edge ALWAYS bypasses a request carrying
  // Authorization, even when the cache key covers it (`cache_key … header:Authorization`), where
  // the server WOULD cache it (Pipeline.keyCoversAuthorization). This is a conscious conservative
  // policy, NOT an oversight: the edge cache key is stored RAW in the Cache API request URL
  // (_l1Request → encodeURIComponent(key)) and as the KV key NAME, so keying by Authorization
  // would write raw bearer tokens into Cloudflare's cache-key namespace — a broader exposure than
  // the server's in-memory keys. The server behind STILL caches keyed-Authorization traffic, so no
  // capability is lost globally; the edge tier simply declines that one case. (Cookies ARE keyed
  // at the edge — selectedKeyCoversAllCookies — because cookie-keyed personalization is common; a
  // raw-token edge key is the narrower, riskier surface we keep server-only.)
  // cache_credentialed (D101): in an ORIGIN-AUTHORITATIVE scope the credential bypass is
  // SKIPPED entirely — neither Authorization NOR a Cookie forces a bypass (the response rules
  // decide cacheability, and the cookies were forwarded to origin above). v1 covers BOTH
  // Cookie and Authorization (owner decision); the entry stores under the SHARED key (never
  // keyed by the credential), so the ADR-D92 "raw token in the edge cache key" concern does
  // not apply here. Outside such a scope the conservative edge default is unchanged.
  let credentialed = !originAuthoritative && request.headers.has("Authorization");
  const remainingCookie = ireq.header.get(canonicalHeaderKey("Cookie"));
  const hasRemainingCookie = Array.isArray(remainingCookie) && remainingCookie.some((v) => v && v.length);
  if (!originAuthoritative && !credentialed && hasRemainingCookie) {
    credentialed = !cookieAllowActive || !selectedKeyCoversAllCookies(ir, ireq);
  }

  // UNSAFE METHOD (RFC 9111 §3 / §4): a shared cache serves stored responses only to safe
  // methods and stores only their responses. The Go server never serves/stores an unsafe
  // method (handler.go isSafeMethod gates both serveFromCache and doStore) — without the
  // same guard here a POST/PUT/… under a broad `cache_ttl` would be STORED (rdec.cacheable
  // is method-independent) and a 2nd identical anonymous POST would HIT the edge without
  // ever reaching origin, silently dropping its side-effect. Safe methods are GET and HEAD;
  // HEAD already bypasses below, so the unsafe set is "anything but GET/HEAD". Route every
  // unsafe method through the bypass branch (never cache.lookup/store) — Go parity.
  const isUnsafeMethod = request.method !== "GET" && request.method !== "HEAD";

  // Bypass the cache entirely for `pass`, a credentialed request, an UNSAFE method, and for
  // HEAD / Range requests. A HEAD (bodyless) or a Range (206 partial) response must NEVER be
  // stored under the method/range-agnostic cache key, where it would later satisfy a full GET
  // with an empty or truncated body. The Cadish server behind handles Range/HEAD correctly
  // (it slices a cached 200 — see D35); the edge just passes them.
  if (dec.pass || credentialed || isUnsafeMethod || request.method === "HEAD" || request.headers.has("Range")) {
    // SPEC-PASS-FORWARDS-COOKIES: a passed / credential-bypassed (uncached) request forwards the
    // ORIGINAL, pre-filter Cookie to the origin — cookie_allow / derives_from normalization is a
    // pure cache-key concern with no benefit (and breaks auth: a `pass`ed /me reads a logged-in
    // user as GUEST) when nothing is cached. SAFE: a passed response is never stored, so the
    // per-user cookie cannot contaminate a shared entry. Mirrors the Go server's pass branch and
    // the edge upgrade/tunnel intent. The cacheable path below keeps dec.reqHeaderOps (filtered).
    let passReqHeaderOps = dec.reqHeaderOps;
    if (cookieNormActive) {
      passReqHeaderOps = [origCookie ? { op: "set", name: "Cookie", value: origCookie } : { op: "remove", name: "Cookie" }, ...baseReqHeaderOps];
    }
    try {
      const resp = await fetchOrigin(request, { originBase, reqHeaderOps: passReqHeaderOps, geo, fetchImpl });
      // RFC 9111 §4.4 INVALIDATION: a SUCCESSFUL (2xx/3xx) response to an unsafe method on a
      // URI invalidates any cached entry for that URI. Forget the SIBLING GET entry — the key
      // a GET to this same URI would produce — so the next GET re-fetches the post-write body
      // instead of serving the stale pre-write copy (mirrors the Go server's §4.4 single-key
      // forget). The sibling key is re-derived from a GET-forced clone of the ORIGINAL request
      // (its unfiltered Cookie restored implicitly — buildIReq reads request.headers directly,
      // exactly as Go's siblingGetKey restores origCookie); a method-less custom `cache_key`
      // yields the same key as the POST (the GET and POST share one entry — the very case §4.4
      // protects). Best-effort: a delete failure never blocks the write response.
      if (isUnsafeMethod && resp.status >= 200 && resp.status < 400) {
        try {
          const getReq = buildIReq({ method: "GET", url: request.url, headers: request.headers }, geo);
          const getKey = evalRequest(ir, getReq).cacheKey || dec.cacheKey;
          if (getKey) await cache.invalidate(getKey, ctx);
        } catch {
          /* §4.4 invalidation is best-effort — never fail the unsafe-method response on it */
        }
      }
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
  // ENCODING GUARD (parity with the Go server's serveFromCache, handler.go ~690): the cache key
  // does NOT partition by Accept-Encoding (Vary: Accept-Encoding is treated as covered), so a
  // stored copy may carry a Content-Encoding the origin negotiated for a DIFFERENT client.
  // Serving it to a client that does not accept that coding hands back an undecodable body (gzip
  // to an identity-only client, br to a gzip-only client). When the stored coding is not
  // acceptable, treat the lookup as a MISS so this client gets a fresh origin negotiation —
  // never a cross-encoding serve. (identity / no Content-Encoding is always acceptable, so the
  // common case pays one header read and nothing else.)
  if (lookup.response) {
    const ce = lookup.response.headers.get("Content-Encoding") || "";
    if (ce && !clientAcceptsEncoding(request.headers.get("Accept-Encoding") || "", ce)) {
      lookup.state = "miss";
      lookup.response = null;
    }
  }
  // CLIENT-FORCED REVALIDATION (client_cache_control) — DELIBERATE edge/server difference,
  // documented, NOT an oversight. The Go server, by default, honors a request `Cache-Control:
  // no-cache` / `max-age=0` / `Pragma: no-cache` (RFC 9111 §5.2.1.4) and revalidates with origin
  // before serving a fresh HIT; `client_cache_control ignore` opts out (handler.go
  // clientForcesRevalidate). The edge worker intentionally does NOT scan request Cache-Control
  // and serves the operator-TTL-fresh copy UNCONDITIONALLY: a CDN-style additive tier must not
  // let a client `no-cache` punch through the shared edge cache to origin (the cache-bust / DoS
  // vector). This is the by-design `client_cache_control` posture for the edge — equivalent to a
  // permanent `ignore` at this tier — and Cloudflare's own cache layer ahead of the worker
  // applies whatever request-Cache-Control handling the zone is configured for. Spec:
  // developer-docs/specs/done/2026-06-26-client-cache-control-ignore.md ("Edge: N/A — the worker
  // doesn't scan request Cache-Control; CF cache handles it"). Reference doc: the
  // client_cache_control entry in docs/cadishfile-reference.md (edge-tier note). So there is no
  // ignoreClientRevalidation flag in the EdgeIR and nothing to fail closed on here.
  if (lookup.state === "fresh") {
    if (lookup.fromL2) await cache.populateL1(key, lookup.response.clone(), lookup.meta, ctx);
    return await deliver(ir, ireq, lookup.response, "HIT", undefined, key);
  }
  if (lookup.state === "stale") {
    if (ctx) ctx.waitUntil(revalidate(ir, ireq, request, geo, credentialed, originBase, fetchImpl, cache, key, ctx));
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
  // cache_credentialed (D101) stores under the SHARED key, so the ADR-D92 "never key the edge
  // cache by a raw Authorization token" refusal does NOT apply — the token never enters the
  // key. In an origin-authoritative scope an Authorization-bearing request's response is stored
  // when evalResponse marks it cacheable (a positive in-scope signal — the sole storage gate;
  // storeResponse strips Set-Cookie before caching). Outside such a scope the edge still declines
  // to store any Authorization-bearing response (the conservative default).
  if (rdec.cacheable && (originAuthoritative || !request.headers.has("Authorization"))) {
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
