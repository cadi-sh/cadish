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

// fetchOrigin builds and sends the origin request. It preserves the method, body,
// path and query of the inbound request; rewrites the authority to the resolved
// origin base; applies the request-phase header ops and the edge-resolved geo
// headers; and sets the hop-guard. fetchImpl defaults to the global fetch (so
// tests can inject a stub). It throws on a transport error — the caller decides
// whether to serve stale.
export async function fetchOrigin(request, { originBase, reqHeaderOps, geo, fetchImpl }) {
  const doFetch = fetchImpl || fetch;
  if (!originBase) throw new Error("no origin binding (set CADISH_ORIGIN)");

  const inURL = new URL(request.url);
  const base = new URL(originBase);
  // Preserve the path + query; take scheme/host/port from the origin binding.
  const outURL = new URL(inURL.pathname + inURL.search, base);
  outURL.protocol = base.protocol;

  const headers = new Headers(request.headers);
  // Security fix B: unconditionally remove every client-supplied edge-trust
  // header before forwarding. Because X-Cadish-Peer is set below, the server
  // behind will trust the *edge-resolved* values applied afterwards. Without
  // this strip, a client that supplies X-Cadish-Geo-Region (or any other trust
  // header) in its request would have it forwarded and trusted by the server.
  for (const name of EDGE_TRUST_HEADERS) headers.delete(name);
  applyRequestHeaderOps(headers, reqHeaderOps);
  if (geo) applyGeoHeaders(headers, geo);
  headers.set(PEER_HEADER, "1");
  // Forward the CANONICAL host (normalizeHost: lower-case, strip :port + trailing FQDN dot) —
  // the SAME normalization the edge cache key uses (interpreter.js renderToken host token) and
  // the Go server's NormalizeHost origin-forward. Forwarding the raw inURL.host instead let
  // `example.com`, `example.com:1337`, and `example.com.` collapse onto ONE edge cache key while
  // the origin saw three different Hosts — a Host-reflecting origin then poisons the shared
  // entry (trailing-dot is injectable straight through). One reader = key and forward agree.
  headers.set("Host", normalizeHost(inURL.host) || inURL.host);

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
  return doFetch(outURL.toString(), init);
}
