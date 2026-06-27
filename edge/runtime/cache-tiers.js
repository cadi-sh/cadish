// cache-tiers.js — L1 (per-POP Cache API) + L2 (global KV) as ONE logical edge
// cache with read-through (design §2.7, §6). The IR decides cacheability/TTL; this
// module only stores and serves by the edge policy (local / distribute / skip)
// and classifies freshness (fresh / stale-within-grace / expired) so the entry
// can do SWR. KV (distribute) is opt-in and OFF by default.
//
// Security invariant (HARD, never skipped — §6): a response carrying Set-Cookie,
// or marked private/no-store, is NEVER written to L1 or L2. The entry additionally
// refuses to cache responses to Authorization-bearing requests.

// Internal metadata header names on an L1-stored Response.
const H_STORED_AT = "X-Cadish-Stored-At";
const H_TTL_MS = "X-Cadish-Ttl-Ms";
const H_GRACE_MS = "X-Cadish-Grace-Ms";
// H_MAX_STALE_MS records the max_stale (D60) window so a salvaged copy carries its own
// stale-on-error bound: peek() refuses a copy older than storedAt+ttl+grace+maxStale
// (D70). 0 / absent => no error-fallback window (the edge must not serve past grace).
const H_MAX_STALE_MS = "X-Cadish-Max-Stale-Ms";
const INTERNAL_HEADERS = [H_STORED_AT, H_TTL_MS, H_GRACE_MS, H_MAX_STALE_MS];

// isCacheableResponse enforces the edge security invariant: a response carrying
// Set-Cookie is NEVER cached (ironclad — even under cache_unsafe; a strip_cookies rule
// removes it BEFORE store, so a stored copy never carries one). A private/no-store
// response is refused UNLESS cacheUnsafe is set, mirroring the server: the interpreter's
// evalResponse caches private/no-store under cache_unsafe (the operator accepted the
// risk), but this store-tier guard previously refused them unconditionally — a permanent
// MISS + origin amplification that diverged from the server (R20). The Cache-Control test
// is WHOLE-TOKEN and case-insensitive (so `private-data` / `max-age=600` are safe), not a
// substring match.
export function isCacheableResponse(response, cacheUnsafe = false) {
  if (response.headers.has("Set-Cookie")) return false;
  if (cacheUnsafe) return true; // operator opted out of the private/no-store refusal
  return !ccHasNoStoreOrPrivate(response.headers.get("Cache-Control") || "");
}

// ccHasNoStoreOrPrivate token-matches a Cache-Control value for a no-store or private
// directive, whole-name and case-insensitive (mirrors the server's hasUncacheableCC token
// comparison), so an unrelated token that merely CONTAINS the substring does not falsely
// refuse caching (R20).
function ccHasNoStoreOrPrivate(value) {
  for (const part of value.split(",")) {
    const p = part.trim();
    const eq = p.indexOf("=");
    const name = (eq >= 0 ? p.slice(0, eq) : p).trim().toLowerCase();
    if (name === "no-store" || name === "private") return true;
  }
  return false;
}

// --- KV (L2) value envelope (R09) -------------------------------------------
//
// Cloudflare Workers KV caps per-entry METADATA at 1024 bytes. The L2 tier used to pack
// ALL response headers into the KV metadata, so a header-heavy response (many/large
// headers) exceeded the cap → the put was REJECTED and swallowed by _safe() → the object
// silently never reached KV, defeating cross-POP sharing with no signal (R09). Instead we
// persist a self-describing ENVELOPE as the KV VALUE ({status, headers, body}) and keep the
// metadata to a handful of tiny numeric freshness fields, which can never overflow.
//
// Wire format: [4-byte big-endian meta length][meta JSON (utf-8)][body bytes]. meta JSON is
// {status, headers:[[name,value]…]}. The body follows verbatim (binary-safe, no base64).
const _kvTextEncoder = new TextEncoder();
const _kvTextDecoder = new TextDecoder();

function encodeKVEnvelope(status, headerPairs, bodyBytes) {
  const meta = _kvTextEncoder.encode(JSON.stringify({ status, headers: headerPairs }));
  const out = new Uint8Array(4 + meta.length + bodyBytes.length);
  new DataView(out.buffer).setUint32(0, meta.length, false); // big-endian meta length
  out.set(meta, 4);
  out.set(bodyBytes, 4 + meta.length);
  return out;
}

function decodeKVEnvelope(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  const metaLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false);
  const meta = JSON.parse(_kvTextDecoder.decode(bytes.subarray(4, 4 + metaLen)));
  return { status: meta.status, headers: meta.headers || [], body: bytes.subarray(4 + metaLen) };
}

// KV's expirationTtl has a hard 60s floor (a put below it is rejected); the edge
// always clamps up to it. DEFAULT_KV_MAX_BYTES (1 MiB) is the size bound when the
// IR omits one — objects larger than it are written to L1 only, never KV.
const KV_MIN_EXPIRATION_SECONDS = 60;
const DEFAULT_KV_MAX_BYTES = 1 << 20;

// EdgeCache wraps the L1 Cache API and the optional L2 KV namespace. now() is
// injectable for tests. kvTtlSeconds caps KV retention (the `kv_ttl` guardrail; 0
// => no cap, use the object's ttl+grace); kvMaxBytes is the `kv_max_bytes` size
// bound (a larger body never enters KV).
export class EdgeCache {
  constructor({ cache, kv, distribute = false, now, kvTtlSeconds = 0, kvMaxBytes = 0, cacheUnsafe = false } = {}) {
    this.cache = cache || null;
    this.kv = kv || null;
    this.distribute = !!distribute && !!kv;
    this.now = now || (() => Date.now());
    this.kvTtlSeconds = kvTtlSeconds > 0 ? kvTtlSeconds : 0;
    this.kvMaxBytes = kvMaxBytes > 0 ? kvMaxBytes : DEFAULT_KV_MAX_BYTES;
    // cacheUnsafe mirrors the site's `cache_unsafe` opt-out: when set, the store guard
    // stops refusing private/no-store responses (parity with the server / the interpreter's
    // evalResponse), keeping the Set-Cookie refusal ironclad (R20).
    this.cacheUnsafe = !!cacheUnsafe;
  }

  // _kvExpirationTtl computes the KV retention in whole seconds:
  // clamp(ttl+grace+max_stale, 60s, kv_ttl). The 60s is KV's hard floor; kv_ttl (when
  // set) caps it so cold POPs fall back to origin sooner. max_stale extends retention
  // so a past-grace copy survives in KV long enough to be salvaged on origin error
  // within the configured window (D70).
  _kvExpirationTtl(ttlMs, graceMs, maxStaleMs = 0) {
    let secs = Math.ceil((ttlMs + graceMs + maxStaleMs) / 1000);
    if (this.kvTtlSeconds > 0 && secs > this.kvTtlSeconds) secs = this.kvTtlSeconds;
    if (secs < KV_MIN_EXPIRATION_SECONDS) secs = KV_MIN_EXPIRATION_SECONDS;
    return secs;
  }

  // _l1Request maps a cache key to a synthetic Cache-API request URL. The key is
  // URL-encoded into a path so two distinct keys never collide.
  _l1Request(key) {
    return new Request("https://cadish-edge.internal/" + encodeURIComponent(key));
  }

  _state(meta) {
    // Strict `<` to mirror the Go server (freshness.go: now.Before(expires) => fresh,
    // now.Before(graceUntil) => stale). At exactly age==ttl Go is already stale, at
    // age==ttl+grace Go is already a miss; matching the strict bound keeps the two
    // runtimes from diverging on the instantaneous boundary tick.
    const age = this.now() - meta.storedAt;
    if (age < meta.ttlMs) return "fresh";
    if (age < meta.ttlMs + meta.graceMs) return "stale";
    return "miss";
  }

  _readMetaFromResponse(res) {
    const storedAt = Number(res.headers.get(H_STORED_AT));
    const ttlMs = Number(res.headers.get(H_TTL_MS));
    const graceMs = Number(res.headers.get(H_GRACE_MS));
    const maxStaleMs = Number(res.headers.get(H_MAX_STALE_MS)) || 0;
    if (!Number.isFinite(storedAt)) return null;
    return { storedAt, ttlMs, graceMs, maxStaleMs };
  }

  _strip(res) {
    const headers = new Headers(res.headers);
    for (const h of INTERNAL_HEADERS) headers.delete(h);
    return new Response(res.body, { status: res.status, headers });
  }

  // lookup returns { state, response, meta, fromL2 }. state is fresh | stale |
  // miss. A miss returns response null. On an L2 hit it returns the rebuilt
  // response and flags fromL2 so the caller can populate L1 read-through.
  async lookup(key) {
    if (this.cache) {
      const res = await this.cache.match(this._l1Request(key));
      if (res) {
        const meta = this._readMetaFromResponse(res);
        if (meta) {
          const state = this._state(meta);
          if (state !== "miss") return { state, response: this._strip(res), meta, fromL2: false };
        }
      }
    }
    if (this.distribute) {
      // Degrade-to-origin (HARD invariant): a KV read error/timeout is treated as an
      // L2 miss so the caller falls through to origin. KV is additive, never a SPOF.
      try {
        const { value, metadata } = await this.kv.getWithMetadata(key, { type: "arrayBuffer" });
        if (value && metadata) {
          const state = this._state(metadata);
          if (state !== "miss") {
            const env = decodeKVEnvelope(value);
            const response = new Response(env.body, { status: env.status, headers: env.headers });
            return { state, response, meta: metadata, fromL2: true };
          }
        }
      } catch {
        /* KV down/slow → treat as L2 miss → origin */
      }
    }
    return { state: "miss", response: null, meta: null, fromL2: false };
  }

  // store writes the response into the tiers selected by `tier` (local → L1;
  // distribute → L1 + L2; skip → nothing), honoring the security invariant. Writes
  // are deferred via ctx.waitUntil when a ctx is given (so they never block the
  // response), else awaited.
  async store(key, response, { ttlMs, graceMs, maxStaleMs = 0, tier }, ctx) {
    if (tier === "skip") return;
    if (!isCacheableResponse(response, this.cacheUnsafe)) return;
    const storedAt = this.now();

    // Buffer the body once: L1 always stores it, and the L2 size bound needs its
    // length. The buffered length is the authoritative size for the size bound (a
    // missing/wrong Content-Length must never let an oversize body into KV).
    const wantsKV = this.distribute && tier === "distribute";
    let body = null;
    if (this.cache || wantsKV) body = await response.clone().arrayBuffer();

    // writes is awaited when no ctx is given (so a caller without waitUntil — and the
    // tests — observe a settled store); with a ctx each is deferred via waitUntil.
    const writes = [];

    if (this.cache) {
      const headers = new Headers(response.headers);
      headers.set(H_STORED_AT, String(storedAt));
      headers.set(H_TTL_MS, String(ttlMs));
      headers.set(H_GRACE_MS, String(graceMs));
      if (maxStaleMs > 0) headers.set(H_MAX_STALE_MS, String(maxStaleMs));
      // The real Workers Cache API only persists a response with positive freshness
      // headers; without this it silently drops the entry (a fidelity gap miniflare
      // surfaced). The edge's own metadata drives HIT/STALE; Cache-Control just keeps
      // the object retained for at least the ttl+grace(+max_stale) window so a
      // past-grace copy is still salvageable for stale-on-error within max_stale (D70).
      setRetention(headers, ttlMs, graceMs, maxStaleMs);
      const stored = new Response(body, { status: response.status, headers });
      writes.push(defer(ctx, this.cache.put(this._l1Request(key), stored)));
    }

    if (wantsKV) {
      // Size bound (HARD): a body larger than kv_max_bytes is written to L1 only,
      // NEVER KV — regardless of the distribute tier. This protects the KV write
      // rate / storage and keeps below KV's 25 MB hard ceiling. The buffered length
      // is authoritative (Content-Length can be absent or wrong).
      if (body.byteLength <= this.kvMaxBytes) {
        // Tiny metadata (numeric freshness fields only) + the full {status, headers, body}
        // in the VALUE envelope, so a header-heavy response can never overflow KV's 1024-byte
        // metadata cap and be silently dropped from L2 (R09).
        const metadata = { storedAt, ttlMs, graceMs, maxStaleMs };
        const envelope = encodeKVEnvelope(response.status, [...response.headers], new Uint8Array(body));
        const expirationTtl = this._kvExpirationTtl(ttlMs, graceMs, maxStaleMs);
        // Degrade-to-origin: a KV write failure is swallowed — the object still lives
        // in L1 at this POP, so the request is unaffected (KV is never a SPOF).
        writes.push(defer(ctx, this._safe(this.kv.put(key, envelope, { metadata, expirationTtl }))));
      }
    }

    if (!ctx) await Promise.all(writes);
  }

  // invalidate removes any stored entry for `key` from BOTH tiers (L1 Cache API + L2 KV).
  // RFC 9111 §4.4: a SUCCESSFUL unsafe-method (POST/PUT/PATCH/DELETE) write invalidates the
  // cached representation of the URI, so the next GET re-fetches the post-write body rather
  // than serving the stale pre-write copy — the same observable mechanism as the Go server's
  // single-key forget (handler.go §4.4). Best-effort and degrade-safe: a delete failure is
  // swallowed (never blocks the response), and the KV delete is attempted whenever a KV
  // binding exists (the object may have been distributed under any tier). Deferred via
  // ctx.waitUntil when a ctx is given, else awaited (so tests observe a settled delete).
  async invalidate(key, ctx) {
    const dels = [];
    if (this.cache) dels.push(defer(ctx, this._safe(this.cache.delete(this._l1Request(key)))));
    if (this.kv) dels.push(defer(ctx, this._safe(this.kv.delete(key))));
    if (!ctx) await Promise.all(dels);
  }

  // _safe absorbs a rejected KV write so it never surfaces as an unhandled
  // rejection (degrade-to-origin: a KV put error is logged-and-ignored).
  _safe(promise) {
    return Promise.resolve(promise).catch(() => {});
  }

  // _withinMaxStale reports whether a stored copy is still salvageable for
  // stale-on-error: its age must not exceed ttl+grace+max_stale (D70). A copy with no
  // max_stale window (maxStaleMs falsy) is NOT salvageable past grace — the edge then
  // bounds stale-on-error to the configured window instead of serving unboundedly-old
  // content (the v1 behavior was unbounded). A copy still within grace is always
  // salvageable (age <= ttl+grace).
  _withinMaxStale(meta) {
    if (!meta) return false;
    // Strict `<` to mirror the Go server (freshness.go staleWithin: now.Before(
    // maxStaleUntil)). At exactly age==ttl+grace+max_stale Go has already dropped the
    // marker, so the edge must too.
    const age = this.now() - meta.storedAt;
    const ceiling = meta.ttlMs + meta.graceMs + (meta.maxStaleMs || 0);
    return age < ceiling;
  }

  // peek returns a stored copy (L1 then L2) for stale-on-error salvage, but ONLY when
  // it is still within its ttl+grace+max_stale window (D70 — the edge no longer serves
  // an unboundedly-old copy on origin failure; max_stale bounds it). Returns
  // { response, meta } or null when no copy exists or the copy is past max_stale.
  async peek(key) {
    if (this.cache) {
      const res = await this.cache.match(this._l1Request(key));
      if (res) {
        const meta = this._readMetaFromResponse(res);
        if (meta && this._withinMaxStale(meta)) return { response: this._strip(res), meta };
      }
    }
    if (this.kv) {
      // Degrade-to-origin: a KV read error during salvage is treated as no L2 copy.
      try {
        const { value, metadata } = await this.kv.getWithMetadata(key, { type: "arrayBuffer" });
        if (value && metadata && this._withinMaxStale(metadata)) {
          const env = decodeKVEnvelope(value);
          return { response: new Response(env.body, { status: env.status, headers: env.headers }), meta: metadata };
        }
      } catch {
        /* KV down → no salvageable L2 copy */
      }
    }
    return null;
  }

  // populateL1 writes an L2-sourced response into L1 read-through.
  async populateL1(key, response, meta, ctx) {
    if (!this.cache) return;
    const body = await response.clone().arrayBuffer();
    const headers = new Headers(response.headers);
    headers.set(H_STORED_AT, String(meta.storedAt));
    headers.set(H_TTL_MS, String(meta.ttlMs));
    headers.set(H_GRACE_MS, String(meta.graceMs));
    if (meta.maxStaleMs > 0) headers.set(H_MAX_STALE_MS, String(meta.maxStaleMs));
    setRetention(headers, meta.ttlMs, meta.graceMs, meta.maxStaleMs || 0);
    defer(ctx, this.cache.put(this._l1Request(key), new Response(body, { status: response.status, headers })));
  }
}

// setRetention sets a Cache-Control max-age so the Workers Cache API retains the
// stored object for at least the edge's ttl+grace(+max_stale) window (the edge's own
// metadata, not this header, decides freshness). max_stale extends retention so a
// past-grace copy survives for stale-on-error salvage within its window (D70). Min 1s
// so a tiny ttl still persists.
function setRetention(headers, ttlMs, graceMs, maxStaleMs = 0) {
  const secs = Math.max(1, Math.ceil((ttlMs + graceMs + maxStaleMs) / 1000));
  headers.set("Cache-Control", "max-age=" + secs);
}

function defer(ctx, promise) {
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(promise);
  return promise;
}
