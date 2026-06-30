// origin.js — fetch the upstream `to` (a Cadish server behind, recommended; or
// the origin directly, degraded). Adds the X-Cadish-Peer hop-guard so the server
// behind knows the request arrived via the edge, applies the request-phase header
// ops + the injected geo headers, and leaves stale-on-error handling to the
// caller (it just throws on a network failure). Minimal I/O.

import { applyGeoHeaders } from "./geo.js";
import { normalizeHost } from "./interpreter.js";

// PEER_HEADER marks a request as coming from a Cadish Edge peer (loop-guard +
// lets the server behind trust the injected geo headers).
export const PEER_HEADER = "X-Cadish-Peer";

// EDGE_TRUST_HEADERS is the exhaustive list of headers that the edge owns and
// the server behind elevates trust in when X-Cadish-Peer is set. These MUST be
// unconditionally stripped from the client request before forwarding (see
// security fix B and fix C). Only edge-resolved values are then applied.
// Never add X-Cadish-Peer itself here — it is set by the edge after stripping.
//
// CF-IPCountry is included (fix C): applyGeoHeaders in geo.js sets it only when
// the edge resolves a non-empty country; when absent (T1/anonymizer/no cf.country)
// the header would otherwise survive from the client request. Stripping it here
// before applyGeoHeaders re-applies the edge value ensures the client can never
// inject a country code (mirrors the same invariant as X-Cadish-Geo-Continent /
// X-Cadish-Geo-Region).
export const EDGE_TRUST_HEADERS = [
  "X-Cadish-Device",
  "X-Cadish-Geo-Continent",
  "X-Cadish-Geo-Region",
  "CF-IPCountry",
];

// applyRequestHeaderOps applies the RECV-phase header edits (set/append/remove)
// to an outgoing Headers object. cache_status never appears here (it is a
// delivery-only op the interpreter drops in the request phase).
export function applyRequestHeaderOps(headers, ops) {
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

// originURLFor resolves the concrete upstream base URL the worker fetches. v1:
// a single default binding (env.CADISH_ORIGIN); an optional env.CADISH_UPSTREAMS
// JSON map ({name: url}) lets a `route`d upstream name pick a different base. The
// IR carries upstream NAMES only (never URLs — D34/§2.8); the mapping to a URL
// lives in the deploy bindings, here.
export function originURLFor(env, upstreamName) {
  if (upstreamName && env.CADISH_UPSTREAMS) {
    try {
      const m = JSON.parse(env.CADISH_UPSTREAMS);
      if (m && m[upstreamName]) return m[upstreamName];
    } catch {
      /* fall through to the default */
    }
  }
  return env.CADISH_ORIGIN || "";
}

// PASSTHROUGH_ORIGIN is the sentinel origin binding (set via `-origin passthrough` /
// CADISH_ORIGIN=passthrough) that selects PASSTHROUGH (fetch-through) mode: the worker
// fetches the ORIGINAL request URL unchanged — preserving the client host AND scheme —
// instead of rewriting the authority to a backend URL. Passthrough must be opted into
// EXPLICITLY with this sentinel: an empty binding is an operator error and throws loudly
// (see fetchOrigin), never a silent degrade — in the separate-cadish-server-behind topology
// a silent passthrough would fetch the public zone host instead of the intended server.
export const PASSTHROUGH_ORIGIN = "passthrough";

// isPassthrough reports whether the resolved origin base selects passthrough mode: ONLY the
// explicit sentinel literal "passthrough". An empty binding is NOT passthrough — it is an
// error handled (loudly) by fetchOrigin.
export function isPassthrough(originBase) {
  return originBase === PASSTHROUGH_ORIGIN;
}

// fetchOrigin builds and sends the origin request. It preserves the method, body, path and
// query of the inbound request; applies the request-phase header ops and the edge-resolved
// geo headers; and sets the hop-guard. fetchImpl defaults to the global fetch (so tests can
// inject a stub). It throws on a transport error — the caller decides whether to serve stale.
//
// Two origin modes, selected by the origin binding:
//   - REWRITE (default): originBase is a real URL (the separate cadish-server-behind
//     topology). The authority is rewritten to the origin base's scheme/host/port and the
//     CANONICAL original Host is forwarded as a header (key↔forward parity).
//   - PASSTHROUGH (originBase == "passthrough"): the ORIGINAL request URL is fetched
//     unchanged — host AND scheme preserved (so HTTPS:443 for a client HTTPS request) — and NO
//     Host header is set (the original host stands). This fronts a multi-host origin in the
//     SAME Cloudflare zone, relying on CF same-zone loop-prevention to reach the real origin.
//     Rewriting the host to a `-origin` apex/backend hostname makes a canonicalizing origin
//     redirect (apex→www, http→https) into an infinite loop, because CF `fetch()` IGNORES a
//     Host-header override (the URL host wins); preserving the original URL is exactly what the
//     original hand-written `fetch(request)` worker did.
export async function fetchOrigin(request, { originBase, reqHeaderOps, geo, fetchImpl, usesGeo }) {
  const doFetch = fetchImpl || fetch;
  // An empty binding is an operator error — fail loudly rather than silently passing through
  // to the original host (which in a rewrite topology would be the public zone, not the server).
  // Passthrough mode must be selected explicitly via the "passthrough" sentinel.
  if (!originBase) throw new Error("no origin binding (set CADISH_ORIGIN, or -origin passthrough for same-zone fetch-through)");

  const inURL = new URL(request.url);
  const passthrough = isPassthrough(originBase);
  // PASSTHROUGH: fetch the ORIGINAL url unchanged (host+scheme preserved). REWRITE: take
  // scheme/host/port from the origin binding, preserving only the path + query.
  let outURL;
  if (passthrough) {
    outURL = inURL;
  } else {
    const base = new URL(originBase);
    outURL = new URL(inURL.pathname + inURL.search, base);
    outURL.protocol = base.protocol;
  }

  const headers = new Headers(request.headers);
  // Security fix B: unconditionally remove every client-supplied edge-trust
  // header before forwarding. Because X-Cadish-Peer is set below, the server
  // behind will trust the *edge-resolved* values applied afterwards. Without
  // this strip, a client that supplies X-Cadish-Geo-Region (or any other trust
  // header) in its request would have it forwarded and trusted by the server.
  // (Applied in BOTH modes — passthrough still talks to a trusting cadish origin.)
  for (const name of EDGE_TRUST_HEADERS) headers.delete(name);
  applyRequestHeaderOps(headers, reqHeaderOps);
  // Inject the CF geo headers to the cadish server behind ONLY when the deploy uses geo
  // (F-B): a site that never keys on or reflects geo must not forward an unkeyed geo
  // signal an origin could vary on under a geo-independent edge key. usesGeo===false
  // (explicitly projected) suppresses; undefined (direct callers/tests) preserves the
  // prior always-inject behaviour.
  if (geo && usesGeo !== false) applyGeoHeaders(headers, geo);
  headers.set(PEER_HEADER, "1");
  // REWRITE mode only: forward the CANONICAL host (normalizeHost: lower-case, strip :port +
  // trailing FQDN dot) — the SAME normalization the edge cache key uses (interpreter.js
  // renderToken host token) and the Go server's NormalizeHost origin-forward. Forwarding the
  // raw inURL.host instead let `example.com`, `example.com:1337`, and `example.com.` collapse
  // onto ONE edge cache key while the origin saw three different Hosts — a Host-reflecting
  // origin then poisons the shared entry (trailing-dot is injectable straight through). One
  // reader = key and forward agree. In PASSTHROUGH mode we deliberately do NOT set Host: the
  // original URL host already stands, and CF `fetch()` ignores a Host override anyway — setting
  // a divergent one would only mislead the server behind (and break the same-zone reach).
  if (!passthrough) {
    headers.set("Host", normalizeHost(inURL.host) || inURL.host);
  }

  const init = {
    method: request.method,
    headers,
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
    // Required by the Fetch spec (and undici) when sending a streaming body;
    // without it a spec-compliant fetch rejects the request, breaking POST/PUT
    // passthrough. workerd tolerates its absence, but setting it is correct
    // everywhere.
    init.duplex = "half";
  }
  // In passthrough mode outURL === inURL; toString() yields the original url verbatim.
  return doFetch(outURL.toString(), init);
}
