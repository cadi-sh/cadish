package pipeline

import "time"

// RequestDecision is the outcome of the RECV + KEY phases (EvalRequest). The
// server applies it before consulting the cache.
type RequestDecision struct {
	// Pass is true when the request must bypass the cache entirely: fetch from the
	// upstream and stream to the client, never storing. Decided in RECV from `pass`
	// rules. When Pass is true the server skips LOOKUP and storage.
	Pass bool
	// Synthetic, when non-nil, is a canned response to return immediately without
	// touching cache or origin (from a matching `respond` rule). When set, all
	// other fields except CacheStatus-style delivery are moot.
	Synthetic *Synthetic
	// Redirect, when non-nil, is a computed 3xx to return immediately without
	// touching cache or origin (from a matching `redirect` rule). Like Synthetic it
	// short-circuits the lifecycle in RECV; the server writes the status + Location.
	// At most one of Synthetic/Redirect is set per request (first matching RECV
	// terminal wins).
	Redirect *Redirect
	// Upstream is the name of the upstream/cluster the request was routed to (from
	// `route`), or "" for the site default. The `upstream` matcher in later phases
	// matches against this value.
	Upstream string
	// CacheKey is the composed cache key (from `cache_key`, or the default
	// "method host path"). Empty only if the request is Synthetic.
	CacheKey string
	// Purge, when non-nil, indicates the request matched a `purge` guard and is a
	// cache-invalidation request the server should honor.
	Purge *PurgeDecision
	// ReqHeaderOps are request-header edits to apply before forwarding to origin
	// (from RECV-phase `header` directives). Applied in order.
	ReqHeaderOps []HeaderOp
	// Rewrite, when non-nil, carries the path/query rewrite to apply to the ORIGIN
	// request line (from RECV-phase `rewrite` directives), composed first-to-last.
	// It affects ONLY the bytes cadish dials upstream — the cache key (CacheKey
	// above) is always computed from the CLIENT-facing request, never the rewrite,
	// so two clients hitting the same client URL share one cache entry regardless of
	// a deterministic rewrite. nil when no `rewrite` rule matched (the common case;
	// the server then forwards the client path/query unchanged).
	Rewrite *RewriteDecision
}

// RewriteDecision is the resolved origin-request rewrite: the final path and the
// final raw query string cadish should send upstream, already computed from the
// matching `rewrite` rules. The server applies it to the origin request only; it
// never feeds the cache key. Path is the rewritten path; RawQuery is the rewritten,
// already-encoded query (without a leading '?'), or "" for no query.
type RewriteDecision struct {
	Path     string
	RawQuery string
}

// Synthetic is a canned response produced by a `respond` directive.
type Synthetic struct {
	Status int
	Body   string
}

// OnError is the resolved origin-error-phase synthetic produced by a matching
// `respond on_error [@scope] STATUS BODY` directive (D57). It is consulted ONLY on
// the handler's origin-error path, after serve-stale-within-grace and the cacheable
// negative-cache (D15) checks have been exhausted — i.e. for an UNCACHEABLE hard
// failure with no servable object. The body is decided at compile (held as []byte
// so the error path does one Write, no streaming, no tee); ContentType defaults to
// "text/html; charset=utf-8". The synthetic is NOT cached by default — it is an
// availability stopgap, not an origin answer; caching it would mask recovery.
type OnError struct {
	Status      int
	Body        []byte
	ContentType string
}

// Redirect is a computed 3xx produced by a `redirect` directive: a status code
// (301/302/307/308) and a fully-resolved Location built from the request (host +
// path) via template substitution (regex capture groups and {host}/{path}/{query}/
// {uri} placeholders). The server writes Status with a Location header.
type Redirect struct {
	Status   int
	Location string
}

// PurgeDecision describes a matched `purge` request. The guard condition (e.g. a
// secret token header) already matched, so Authorized is true; the server still
// owns the actual invalidation.
type PurgeDecision struct {
	// Authorized is true when the purge guard matched (always true when the
	// PurgeDecision is non-nil — a non-matching guard yields a nil PurgeDecision).
	Authorized bool
	// Regex, when non-empty, is a key-pattern the purge should ban (from the
	// directive's `regex EXPR`, with {http.HEADER} placeholders resolved against
	// the request). For the `regex-path EXPR` form the operator-written path
	// pattern has already been rewritten to anchor against the PATH component of
	// the key (so a Varnish-style `^/foo` matches the path token, not the whole
	// `host path …` key). Empty means "purge this request's own cache key".
	Regex string
}

// ResponseDecision is the outcome of the ORIGIN/store phase (EvalResponse). It is
// split from EvalRequest because cache_ttl selectors can branch on the response
// status, which is only known after the origin replies.
type ResponseDecision struct {
	// TTL is how long a fresh object stays servable without revalidation. Zero
	// means "not cacheable from a positive TTL rule" (see HitForMiss).
	TTL time.Duration
	// Grace is the stale-while-revalidate window after TTL during which a stale
	// object may be served while an async revalidation runs. Zero means no grace.
	Grace time.Duration
	// MaxStale (D60) is the additional window after grace during which a past-grace
	// object may still be served, but ONLY as a fallback when the origin fetch fails
	// (cache-status HIT-STALE-ERROR). Zero means no error-fallback window — the entry
	// behaves exactly as today once grace elapses. Server-only in v1 (not projected
	// to the edge IR). Measured from storedAt like TTL/Grace; the servable ceiling is
	// storedAt + TTL + Grace + MaxStale.
	MaxStale time.Duration
	// HitForMiss, when > 0, records a "do not cache this key" decision for the
	// given duration (Varnish hit-for-miss): the body is not stored but the
	// negative decision is, to avoid stampeding the origin on a transient error.
	// When HitForMiss > 0, TTL/Grace are zero and the object is not cached.
	HitForMiss time.Duration
	// StoreTier is the cache tier the object should be stored in: "ram" or "disk"
	// (from `storage`). Empty means the server's default tier routing applies.
	StoreTier string
	// Cacheable reports whether a positive cache_ttl rule matched (TTL set). It is
	// false for hit-for-miss and for the (unusual) case of no matching rule.
	Cacheable bool
}

// CacheStatus is the cache-lookup outcome the server feeds into EvalDeliver so the
// `header +cache_status` special can emit the right token.
type CacheStatus int

const (
	// CacheStatusUnknown is the zero value (renders as "MISS").
	CacheStatusUnknown CacheStatus = iota
	// CacheStatusHit: a fresh object served from cache.
	CacheStatusHit
	// CacheStatusMiss: not in cache (or pass); fetched from origin.
	CacheStatusMiss
	// CacheStatusHitStale: a stale object served from grace while revalidating.
	CacheStatusHitStale
	// CacheStatusHitStaleError (D60): a past-grace object served as a last resort
	// because the origin fetch FAILED and the object is still within its max_stale
	// window. Distinct from CacheStatusHitStale (live grace, origin health
	// irrelevant) so operators can tell "served stale to hide latency" from "served
	// stale because the origin is down."
	CacheStatusHitStaleError
)

// String renders the cache status as the header token emitted by
// `header +cache_status`.
func (c CacheStatus) String() string {
	switch c {
	case CacheStatusHit:
		return "HIT"
	case CacheStatusHitStale:
		return "HIT-STALE"
	case CacheStatusHitStaleError:
		return "HIT-STALE-ERROR"
	default:
		return "MISS"
	}
}

// DeliverDecision is the outcome of the DELIVER phase (EvalDeliver), applied to
// the response just before it is written to the client.
type DeliverDecision struct {
	// RespHeaderOps are response-header edits to apply, in order. A matched
	// `header +cache_status NAME` is materialized here as a concrete set op writing
	// the CacheStatus token into NAME, so the server can apply every op uniformly.
	RespHeaderOps []HeaderOp
	// StripCookies is true when a matching `strip_cookies` rule fired: the server
	// drops Set-Cookie (and request Cookie) for this response.
	StripCookies bool
	// CORS, when non-nil, carries the CORS headers a `cors` directive requests.
	CORS *CORSDecision
	// CacheStatusHeader is the header name a `header +cache_status` directive
	// targets (e.g. "X-Cache"), or "" if none. Provided in addition to the
	// materialized RespHeaderOps entry for servers that handle it specially.
	CacheStatusHeader string
	// CacheKeyHeader is the header name a `header +cache_key` directive targets
	// (e.g. "X-Cache-Key"), or "" if none. Unlike +cache_status the value is NOT in
	// this decision — the cache key is the server-held RECV key — so the server's
	// deliver path sets the header from the key it already holds, hashing it
	// (CacheKeyHash) unless CacheKeyRaw. The header is omitted when the request has
	// no key (pass/synthetic/redirect). See CacheKeyHeaderValue.
	CacheKeyHeader string
	// CacheKeyRaw selects the raw key string (the `raw` modifier) instead of the
	// default 12-hex hash for CacheKeyHeader. Meaningful only when CacheKeyHeader is
	// set.
	CacheKeyRaw bool
	// Transforms are ordered literal body substitutions (`replace OLD NEW`) whose
	// scope matched this response. The server applies them POST-cache, on delivery,
	// to a size-bounded body — the cache always stores the canonical origin body,
	// so transforms run per-delivery on both HIT and MISS. Empty when none apply.
	Transforms []Replacement
	// Encode, when non-nil, requests on-the-fly response-body compression
	// (`encode`) at deliver. It carries the configured codec preference order,
	// the Content-Type include list, and the minimum body size. The server
	// negotiates against the client's Accept-Encoding and compresses POST-cache,
	// AFTER any Transforms. The cache stores the uncompressed origin body, so
	// compression runs per-delivery. nil when the site declares no `encode`.
	Encode *EncodeDecision
}

// EncodeDecision carries the compiled `encode` policy surfaced on the deliver
// decision. It is the immutable plan the server negotiates and applies at
// delivery; it does not itself decide whether to compress a given response (the
// server gates on Accept-Encoding, Range/HEAD, existing Content-Encoding,
// Content-Type, and MinLength — see the server's encodeApplies).
type EncodeDecision struct {
	// Codecs is the configured codec preference order (e.g. ["zstd","br","gzip"]).
	// The server picks the first one the client accepts. Each token is a wire
	// Content-Encoding name ("gzip", "br", "zstd").
	Codecs []string
	// Types is the Content-Type include list (lower-cased media types; a trailing
	// "/*" matches a whole top-level type, e.g. "text/*"). A response whose
	// Content-Type is not in this list is served uncompressed.
	Types []string
	// MinLength is the body-size floor (bytes): bodies shorter than this are not
	// worth compressing and are served uncompressed.
	MinLength int
}

// Replacement is one literal body substitution from a `replace OLD NEW`
// directive: every occurrence of Old becomes New. Applied in order.
type Replacement struct {
	Old string
	New string
}

// CORSDecision carries the values for the CORS response headers requested by a
// `cors` directive.
type CORSDecision struct {
	// AllowAllOrigins is true for `cors *` (Access-Control-Allow-Origin: *).
	AllowAllOrigins bool
	// Origins is the explicit allowed-origin list (when not AllowAllOrigins).
	Origins []string
	// Methods is the Access-Control-Allow-Methods list, if specified.
	Methods []string
	// Headers is the Access-Control-Allow-Headers list, if specified.
	Headers []string
}
