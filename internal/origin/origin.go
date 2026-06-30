// Package origin is cadish's upstream-fetch layer. An Origin fetches an object
// from some backend (a generic HTTP/HTTPS server, an S3-compatible store, …) and
// returns it as a STREAMING response so the server can tee the body into the
// cache while simultaneously serving it to the client — without ever buffering
// the whole object in memory.
//
// # Composition over baked-in policy
//
// The core knows exactly one thing: "given this Request, give me this object"
// (the Origin interface). Strategies that combine multiple backends — fallback,
// A/B, mirror, shadow — are NOT special-cased inside any concrete origin. They
// are COMPOSITION at this layer: a chain.Chain is itself an Origin that wraps an
// ordered list of origins and falls through on configurable statuses. This is
// how `origin chain s3 -> cloudfront` from the Cadishfile is realized — fallback
// is config-driven composition, never hardcoded in s3origin or httporigin.
//
// # Streaming / ownership contract (the server MUST honor this)
//
// Fetch returns a *Response whose Body is a live, working io.ReadCloser still
// connected to the upstream socket. The contract is:
//
//   - OWNERSHIP. On a nil error, the caller OWNS Response.Body and MUST Close it
//     exactly once, even if it reads none or only part of the body. Failing to
//     Close leaks the upstream connection (and, for pooled transports, prevents
//     connection reuse). On a NON-nil error, Body is nil and there is nothing to
//     close — concrete origins drain+close the upstream body themselves before
//     returning an error.
//
//   - NO BUFFERING. The body is NOT read into memory by the origin. The caller
//     streams it. This is what lets the server wire an io.TeeReader(Body, cache)
//     so the bytes flowing to the client are written to the cache in the same
//     pass (serve-and-cache). The origin only guarantees a reader; the TeeReader
//     wiring lives in the server.
//
//   - PARTIAL READS / EARLY CLOSE. The caller may Close before EOF (client
//     disconnected, range satisfied, cache write failed). Close MUST be safe at
//     any point and aborts the upstream transfer. A partial body that the caller
//     chose to stop reading is NOT an origin error.
//
//   - ERRORS MID-STREAM. A read error after Fetch returned (the upstream dropped
//     the connection, the context was cancelled) surfaces from Body.Read, NOT
//     from Fetch. The caller MUST treat a mid-stream read error as a truncated
//     response and MUST NOT commit a truncated body to the cache. Such a body was
//     already partially streamed to the client; recovery is the server's policy.
//
//   - CONTEXT. The ctx passed to Fetch governs the WHOLE lifetime of the
//     response, including the streaming body read. Cancelling ctx (client went
//     away, deadline) unblocks an in-flight Body.Read with a context error. Bound
//     CONNECTION-ESTABLISHMENT phases (dial, TLS, response headers) with
//     transport timeouts; do NOT cap the body transfer with a timeout (large
//     media stream for minutes) — rely on ctx for body cancellation.
//
//   - RANGE / 206 PASSTHROUGH. If Request carries a Range header, it is forwarded
//     verbatim and a 206 upstream response is passed through unchanged:
//     Response.StatusCode is 206 and Response.Header carries Content-Range. The
//     origin does NOT synthesize ranges from a full body; it asks the upstream.
//
//   - STATUS PASSTHROUGH. Origins return the upstream's real status (200, 206,
//     304, …) with a streaming body. A 404 / 410 is returned as a NEGATIVE
//     *Response (Response.Negative true) carrying its real body+headers, so a
//     chain can fall through on it AND the server can negatively cache the actual
//     error page (full-body negative caching, backlog #21). A backend that
//     reports not-found with no usable body (S3 NoSuchKey) still maps to the
//     bodyless ErrNotFound sentinel. Other non-2xx statuses (e.g. 401/403/5xx) are
//     returned as a *StatusError so a chain can fall through on a configurable
//     status set; an HTTP origin attaches the LIVE error body + headers to the
//     *StatusError (the holder MUST Close it) so the server can stream the origin's
//     real error response verbatim instead of a synthetic placeholder.
package origin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ErrNotFound is the shared sentinel for "the upstream does not have this
// object" (HTTP 404, S3 NoSuchKey/NotFound, and — for buckets fronted by an OAI
// without ListBucket — 403 AccessDenied for a missing key). Concrete origins map
// their backend's not-found signal to this error and close any upstream body
// before returning it. A chain.Chain falls through to the next origin on it.
var ErrNotFound = errors.New("origin: object not found")

// ErrSkip is returned by an origin that DECLINED to handle a request WITHOUT reading
// its body — a pure no-op skip (e.g. PeerOrigin's cache-bypass / write / loop / self
// guards, which return before touching req.Body). A chain.Chain falls through to the
// next origin on ErrSkip EVEN when req.Body != nil, because the body is provably still
// intact and replayable. This is distinct from ErrNotFound (a real lookup miss that may
// have consumed the body), which the chain treats as terminal for a body request to
// avoid re-issuing a non-idempotent, non-replayable write to a second origin.
var ErrSkip = errors.New("origin: skipped (request not handled, body untouched)")

// StatusError reports that an origin received an HTTP response whose status is
// neither a success (200/206) nor a plain not-found (which maps to ErrNotFound).
// A chain.Chain consults its fall-through status set against StatusError.Status
// to decide whether to try the next origin.
//
// BODY OWNERSHIP. An HTTP origin attaches the LIVE upstream non-2xx body + headers
// (Body, Header, ContentLength) so the server can stream the real error response
// (an auth challenge, a JSON error envelope, a maintenance page) to the client
// VERBATIM instead of a synthetic placeholder — a passed/uncached error is never
// stored, so there is no cache-poisoning risk. When Body is non-nil the holder OWNS
// it and MUST Close it exactly once (use CloseBody): a chain.Chain that falls
// through closes the abandoned body; the server streams then closes it. Body is nil
// for origins that obtained no streamable body (s3origin, a transport-level status),
// in which case the caller has nothing to close and serves a synthetic status.
type StatusError struct {
	// Status is the upstream HTTP status code (e.g. 500, 502, 403).
	Status int
	// Origin is a short identifier of the origin that produced it (for logs),
	// e.g. "httporigin" or "s3origin". Optional.
	Origin string
	// Header is the upstream response header set (Content-Type, WWW-Authenticate,
	// Retry-After, …) so the server delivers the origin's real error headers. May
	// be nil (no headers captured).
	Header http.Header
	// Body is the LIVE upstream error body. When non-nil the holder MUST Close it
	// exactly once (see CloseBody). nil when no streamable body was captured.
	Body io.ReadCloser
	// ContentLength is the length of Body (-1 when unknown/chunked). Meaningful only
	// when Body is non-nil.
	ContentLength int64
}

func (e *StatusError) Error() string {
	if e.Origin != "" {
		return fmt.Sprintf("origin: %s upstream status %d", e.Origin, e.Status)
	}
	return fmt.Sprintf("origin: upstream status %d", e.Status)
}

// CloseBody closes the captured upstream body if this StatusError carries one and
// clears it, so it is safe to call more than once (and a no-op when Body is nil).
func (e *StatusError) CloseBody() {
	if e != nil && e.Body != nil {
		_ = e.Body.Close()
		e.Body = nil
	}
}

// CloseStatusErrBody closes the captured upstream body of a *StatusError wrapped
// anywhere in err's chain (a no-op for any other error). A chain.Chain uses it to
// release the body of a fall-through error it is abandoning.
func CloseStatusErrBody(err error) {
	var se *StatusError
	if errors.As(err, &se) {
		se.CloseBody()
	}
}

// StatusOf extracts the HTTP status an error represents for fall-through
// decisions: ErrNotFound counts as 404, a *StatusError reports its Status, and
// any other error (a connection/transport error, a context cancellation) reports
// 0 — meaning "no HTTP response was obtained". This is the classification a
// chain.Chain uses to decide whether to fall through.
func StatusOf(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrNotFound) {
		return http.StatusNotFound
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// Request is an origin fetch request. It is backend-agnostic: an HTTP origin maps
// Key onto a URL path under its base URL, an S3 origin maps Key onto an object
// key in its bucket.
type Request struct {
	// Method is the HTTP method. Empty means GET. Origins that only support reads
	// (s3origin) honor GET/HEAD and reject others.
	Method string

	// Key is the object key / URL path (e.g. "videos/clip.mp4" or
	// "$6/default_profile.png"). It is the RAW key; per-backend encoding (S3 key
	// escaping, URL path escaping) is the concrete origin's job. A leading slash
	// is tolerated.
	Key string

	// Header carries request headers to forward to the upstream. The Range header,
	// if present, is forwarded verbatim for partial/seek requests (=> 206). Header
	// may be nil.
	Header http.Header

	// ClientHost is the ORIGINAL client request authority (e.g.
	// "www.example.com" or "shop.example.com:8443"), carried so an origin can
	// forward it as the upstream Host header (backlog #11). Go builds the upstream
	// request Host from the base URL, so without this an origin sends
	// Host: <upstream> (e.g. "wordpress:80") and a name-based vhost / multi-tenant
	// origin canonical-301s. httporigin's host_header policy decides whether this
	// is forwarded (preserve), replaced by the upstream host (origin), or overridden
	// by a fixed value. May be "" (e.g. a background revalidation after the client
	// headers are gone), in which case a preserve policy falls back to the upstream
	// host. Backends that don't model a Host (s3origin) ignore it.
	ClientHost string

	// RawQuery is the original, already-encoded request query string (no leading
	// "?"), forwarded to HTTP origins so an origin that varies its response by query
	// (search, pagination, API params, WP `?preview=`) receives the parameters the
	// client sent. Key carries only the path, so without this the query is lost and
	// every distinct-query cache key would fetch the same path-only origin body.
	// Backends whose object identity has no query component (s3origin: an S3 object
	// key) ignore it. May be "".
	RawQuery string

	// Body is the CLIENT request body to forward to the upstream for a write method
	// (POST/PUT/PATCH/DELETE-with-body). It is nil for a GET/HEAD (and for a
	// background revalidation, which is a bodyless GET). It is streamed straight
	// through — the origin does NOT buffer it.
	//
	// OWNERSHIP: the origin layer does NOT close Body itself. The server owns the
	// CLIENT body lifecycle (http.Server closes the inbound r.Body after the handler
	// returns). When an HTTP origin hands Body to net/http's Client, the Client
	// closes the request Body as part of sending the request (per net/http
	// semantics), so httporigin must NOT close it a second time — passing r.Body
	// through and letting the http.Server close it is safe (the Client's close of
	// r.Body and the server's close are idempotent for a real *http.Request body).
	// Backends that don't accept writes (s3origin) reject a write method outright and
	// never touch Body.
	Body io.ReadCloser

	// ContentLength is the length of Body as the client declared it (the client
	// request's Content-Length), or -1 when unknown (chunked client upload). It is 0
	// when there is no body. HTTP origins set it on the upstream request so a known
	// length is sent as Content-Length rather than chunked.
	ContentLength int64

	// Bypass marks a request that must NOT read-through to a peer cadish node: it is a
	// cache-bypass (an explicit `pass`, or a credential bypass) whose response is never
	// stored, so asking the owning peer is pure wasted latency — the peer would only
	// pass to origin too. A read-through PeerOrigin honors this by surfacing
	// origin.ErrNotFound so the chain falls through to the real origin, giving a `pass`
	// the same straight-to-origin path in read_through mode that owner mode already
	// gives it (owner mode skips the owner-route seam because a `pass` returns before
	// it). It is set ONLY for a clear bypass — a "possibly cacheable" request (incl.
	// cache_credentialed) leaves it false and follows the full path to the owner.
	// Backends that are not a peer pool (httporigin, s3origin) ignore it.
	Bypass bool
}

// RangeHeader returns the raw Range header value (e.g. "bytes=0-1023"), or "" if
// none was set.
func (r *Request) RangeHeader() string {
	if r.Header == nil {
		return ""
	}
	return r.Header.Get("Range")
}

// method returns the effective HTTP method (GET when unset).
func (r *Request) method() string {
	if r.Method == "" {
		return http.MethodGet
	}
	return r.Method
}

// Response is a streamed origin response. See the package doc for the full
// ownership/streaming contract: on a nil error from Fetch the caller OWNS Body
// and MUST Close it exactly once.
type Response struct {
	// StatusCode is the upstream status: 200/206 for a positive body, or a
	// negatively-cacheable status (404 / 410) when Negative is set (full-body
	// negative caching, backlog #21).
	StatusCode int

	// Header is the upstream response header set (Content-Type, ETag,
	// Last-Modified, Accept-Ranges, and — for 206 — Content-Range). Never nil.
	Header http.Header

	// ContentLength is the length of THIS response body (full size for 200, range
	// length for 206), or -1 if unknown (chunked transfer). The server only sets a
	// Content-Length downstream when this is >= 0.
	ContentLength int64

	// Body is the live, streaming response body. The caller MUST Close it exactly
	// once (see the package/streaming contract). Never nil on a Response returned
	// with a nil error.
	Body io.ReadCloser

	// Negative marks a NEGATIVE full-body response: a not-found / gone status
	// (404 / 410) returned WITH its real error-page body and headers, rather than
	// collapsed to the bodyless ErrNotFound sentinel. It is the full-body-negative-
	// caching contract (backlog #21): a chain.Chain treats a Negative response as a
	// miss and falls through to the next origin (closing the abandoned body), while
	// the server — when the response pipeline marks the status cacheable — stores
	// the actual body+headers so a cached error page is served verbatim on a HIT.
	// On a positive 200/206 response this is false.
	Negative bool

	// BetweenBytes, when > 0, is the per-upstream body-stall budget configured by
	// `upstream { timeout … between_bytes D }` (gap G5). It is advisory metadata the
	// origin attaches so the SERVER can enforce it as a between-bytes deadline on the
	// streaming body (the origin layer must return Body unchanged — it never wraps
	// it). Zero ⇒ no per-upstream budget; the server falls back to its global
	// -idle-timeout. See the server's idle-timeout reader.
	BetweenBytes time.Duration
}

// ContentRange returns the Content-Range header (set only for 206 responses), or
// "".
func (r *Response) ContentRange() string { return r.Header.Get("Content-Range") }

// Origin fetches a single object from one backend and returns it as a streaming
// Response. Implementations MUST honor the streaming/ownership contract in the
// package doc.
//
// Fetch returns:
//   - (*Response, nil) on a 200 or 206 — caller owns and MUST Close Response.Body.
//   - (*Response, nil) with Response.Negative set on a 404 / 410 — the real
//     error-page body+headers are streamed (full-body negative caching, backlog
//     #21); caller owns and MUST Close Response.Body. A chain falls through on it.
//   - (nil, ErrNotFound) when a backend reports not-found WITHOUT a usable body
//     (e.g. S3 NoSuchKey / 403 for OAI buckets) — no body to close.
//   - (nil, *StatusError) for any other non-success HTTP status. An HTTP origin
//     attaches the live error body + headers to the *StatusError (holder MUST
//     Close it) so the server can stream it verbatim; origins with no streamable
//     body (s3origin, a transport-level status) leave it nil.
//   - (nil, err) for a connection/transport error or a context cancellation
//     BEFORE the response headers arrived. (A failure AFTER headers — mid-stream —
//     surfaces from Response.Body.Read, not here.)
type Origin interface {
	Fetch(ctx context.Context, req *Request) (*Response, error)
}

// UpgradeTarget describes ONE backend an upgrade tunnel should dial: a base URL
// (scheme + host [+ base path]) plus the per-upstream RoundTripper that already
// carries the configured transport knobs (connect/TLS timeouts, `sni`,
// `http_reuse`, `tls_insecure`/`ca_file`/`alpn`). It is the seam the server uses to
// aim an httputil.ReverseProxy at the routed upstream for a WebSocket /
// `Connection: Upgrade` passthrough — REUSING the existing per-upstream transport
// (never a second independent dialer) so lb pick + transport policy stay honored.
type UpgradeTarget struct {
	// URL is the backend base URL to dial (scheme + host, plus any base path).
	URL *url.URL
	// Transport is the per-upstream round-tripper. nil is allowed (the caller then
	// falls back to a default transport), but a configured origin always supplies its
	// own so the upgrade dial honors the same TLS/keepalive policy as a normal fetch.
	Transport http.RoundTripper
	// Host is the Host header to send upstream per the upstream's `host_header`
	// policy. "" means "preserve the client Host" (the cadish default), which the
	// ReverseProxy honors by leaving the outbound Host as the inbound request's.
	Host string
}

// Upgrader is the OPTIONAL capability an Origin implements to support a
// connection-upgrade (WebSocket / `Connection: Upgrade`) passthrough tunnel. The
// server type-asserts the routed Origin to this interface; an origin that does not
// implement it cannot tunnel (the server answers a clean error instead of dialing).
// ResolveUpgrade returns ONE backend to dial for req, honoring lb health/sticky for
// a pool. It returns ErrNoUpgradeBackend when no backend is currently eligible. ctx
// carries the lb routing key (lb.WithRoutingKey) so a sticky / shard-by-key pool pins
// the tunnel to the SAME backend the Fetch path would pick (Finding 3); pools that do
// not consult a routing key ignore it.
type Upgrader interface {
	ResolveUpgrade(ctx context.Context, req *Request) (UpgradeTarget, error)
}

// ErrNoUpgradeBackend is returned by Upgrader.ResolveUpgrade when no backend is
// currently eligible to host the tunnel (e.g. an lb pool with no live backend).
var ErrNoUpgradeBackend = errors.New("origin: no eligible backend for upgrade tunnel")
