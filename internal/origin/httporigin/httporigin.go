// Package httporigin is cadish's generic HTTP/HTTPS upstream origin: given a base
// URL, it fetches an object by joining the request Key onto that base, forwards
// the Range header for partial/seek requests, and streams the response body so
// the server can tee it into the cache while serving the client. This is the
// bread-and-butter origin — most users point cadish at a plain HTTP origin.
//
// It uses a shared, connection-pooling http.Client. CONNECTION-ESTABLISHMENT
// phases (dial, TLS, response headers) are bounded with timeouts so a black-holed
// or slow upstream can't pin goroutines/sockets; the body transfer itself is
// intentionally NOT capped (large media stream for minutes) and relies on the
// per-request context for cancellation. See the origin package doc for the full
// streaming/ownership contract.
package httporigin

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

// originName identifies this origin in StatusError / logs.
const originName = "httporigin"

// HostPolicy selects which Host header httporigin sends upstream (backlog #11).
// Go builds the request Host from the base URL, so unless we set req.Host the
// upstream sees Host: <upstream> (e.g. "wordpress:80") — which makes name-based
// vhosts and multi-tenant SaaS origins canonical-301 (the staging-POC WordPress
// homepage break). A `Host` entry in the header map is IGNORED by net/http; the
// authoritative field is req.Host, which this policy drives.
type HostPolicy int

const (
	// HostPreserve forwards the original client Host (origin.Request.ClientHost).
	// This is the cadish DEFAULT and what real CDNs do. When the client Host is
	// unknown (e.g. a background revalidation), it falls back to HostOrigin.
	HostPreserve HostPolicy = iota
	// HostOrigin sends the upstream base URL's host — the historical Go-default
	// behavior (`host_header origin`), for origins that key on their own hostname.
	HostOrigin
	// HostFixed sends a fixed operator-supplied value (`host_header <value>`).
	HostFixed
)

// Origin fetches objects from one HTTP/HTTPS base URL.
type Origin struct {
	// base is the parsed base URL (scheme + host + optional base path). A request
	// Key is resolved against it (see urlFor).
	base *url.URL
	hc   *http.Client

	// hostPolicy decides the upstream Host header; hostValue is the fixed Host for
	// HostFixed. The zero value is HostPreserve (the default), so a freshly
	// constructed Origin forwards the client Host with no extra wiring.
	hostPolicy HostPolicy
	hostValue  string

	// sni is the TLS ClientHello server name to advertise for HTTPS backends (gap
	// H6, `sni <server-name>`). Empty ⇒ leave Go's default (the dialed host).
	sni string
	// disableKeepAlives, when true, forces a fresh backend connection per request
	// (gap H6, `http_reuse never`) — the Go equivalent of HAProxy's http-reuse never.
	disableKeepAlives bool

	// betweenBytes is the per-upstream body-stall budget (gap G5,
	// `timeout … between_bytes D`). The origin does NOT wrap the body (the streaming
	// contract forbids it); it only stamps the value onto each Response so the server
	// enforces it as a between-bytes deadline. Zero ⇒ unset.
	betweenBytes time.Duration
}

// Option configures an Origin.
type Option func(*Origin)

// WithHTTPClient overrides the internal http.Client (tests / advanced wiring).
// The supplied client should bound establishment phases; a body-transfer timeout
// MUST NOT be set (it would truncate large streams).
func WithHTTPClient(hc *http.Client) Option { return func(o *Origin) { o.hc = hc } }

// WithHostPolicy sets the upstream Host-header policy (backlog #11). value is the
// fixed Host used only by HostFixed and ignored otherwise. The default (no option)
// is HostPreserve.
func WithHostPolicy(p HostPolicy, value string) Option {
	return func(o *Origin) {
		o.hostPolicy = p
		o.hostValue = value
	}
}

// WithSNI sets the TLS ClientHello server name advertised to an HTTPS backend
// (gap H6, `sni <server-name>`). When name is non-empty the origin gets its OWN
// http.Transport whose TLSClientConfig.ServerName is name, so an IP-fronted vhost
// origin presents the right certificate / routes to the right vhost instead of
// 421-ing. Empty name is a no-op (Go derives SNI from the dialed host, as today).
func WithSNI(name string) Option { return func(o *Origin) { o.sni = name } }

// WithDisableKeepAlives disables backend connection reuse for this origin (gap H6,
// `http_reuse never`). When true the origin gets its OWN http.Transport with
// DisableKeepAlives set, so a fresh connection is dialed per request — the Go
// equivalent of HAProxy's http-reuse never (eliminates the multi-vhost 421). False
// is a no-op (the shared pooled, keep-alive client is used, as today).
func WithDisableKeepAlives(disable bool) Option {
	return func(o *Origin) { o.disableKeepAlives = disable }
}

// WithBetweenBytes sets the per-upstream body-stall budget (gap G5,
// `timeout … between_bytes D`). The origin attaches it to each Response as advisory
// metadata; the server enforces it as a between-bytes deadline on the streaming
// body. A non-positive value is a no-op (the server uses its global -idle-timeout).
func WithBetweenBytes(d time.Duration) Option {
	return func(o *Origin) { o.betweenBytes = d }
}

// New builds an HTTP origin rooted at baseURL (e.g. "https://origin.example.com"
// or "https://host/prefix"). The base path, if any, is preserved and request
// keys are appended under it. It returns an error if baseURL is unparseable or
// lacks a scheme/host.
func New(baseURL string, opts ...Option) (*Origin, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, fmt.Errorf("httporigin: parse base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("httporigin: base URL must be http or https, got %q", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("httporigin: base URL missing host: %q", baseURL)
	}
	o := &Origin{base: u}
	for _, opt := range opts {
		opt(o)
	}
	// Transport selection (gap H6). When NO explicit client was supplied
	// (WithHTTPClient), this origin gets its OWN fresh pooled client — the default
	// path is byte-for-byte the legacy one (Go-default SNI, keep-alive on). When a
	// transport knob (sni / disable-keep-alives) is set we apply it to THIS origin's
	// transport only; clients are per-origin, so a knob never touches another
	// origin's pool or keep-alive. WithHTTPClient (the lb per-timeouts path) supplies
	// its own per-backend client; the knobs are applied to its transport too.
	if o.hc == nil {
		o.hc = pooledHTTPClient()
	}
	applyTransportKnobs(o.hc, o.sni, o.disableKeepAlives)
	return o, nil
}

// applyTransportKnobs sets the gap-H6 transport knobs on hc's *http.Transport in
// place. A non-empty sni sets TLSClientConfig.ServerName; disable sets
// DisableKeepAlives. When NEITHER is set it is a no-op (the default path leaves the
// transport untouched — the zero-datapath-change invariant). It only touches the
// transport when hc.Transport is an *http.Transport (the shape this package and lb
// both build).
func applyTransportKnobs(hc *http.Client, sni string, disable bool) {
	if sni == "" && !disable {
		return
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		return
	}
	if sni != "" {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{ServerName: sni} //nolint:gosec // ServerName only; default MinVersion applies
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
			tr.TLSClientConfig.ServerName = sni
		}
	}
	if disable {
		tr.DisableKeepAlives = true
	}
}

// pooledHTTPClient builds an http.Client tuned for high-throughput streaming with
// generous keep-alive pools. Establishment phases (dial, TLS, headers) are
// bounded; the body transfer is uncapped (governed by the request context). This
// is tuned for high-throughput origin fetches.
func pooledHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// No ambient proxy (security): origin fetches are explicit upstream
		// connections, so honouring HTTP_PROXY/HTTPS_PROXY from the environment would
		// let a misconfigured or attacker-influenced proxy silently divert origin
		// traffic — an SSRF-adjacent footgun. Pairs with the redirect SSRF guard below.
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		// Bound time to the FIRST byte (headers); the body then streams uncapped and
		// a slow body is handled by the request context.
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		// SSRF guard (security review #1): never FOLLOW redirects. Go's default
		// follows up to 10, so a malicious/compromised origin replying
		// `302 Location: http://169.254.169.254/…` (cloud metadata) or an RFC1918/
		// loopback target would be transparently fetched and streamed/cached. With
		// ErrUseLastResponse the 30x is returned as-is and surfaced to the client as
		// a passthrough response (Fetch's 3xx case) — cadish never dials the target.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// urlFor resolves a request Key against the base URL, appending the key under the
// base path. The key is treated as a raw path segment sequence; url.URL escaping
// is applied so keys with reserved characters are encoded correctly.
//
// Security: dot-segments (../) in the key are collapsed with path.Clean BEFORE
// the fetch so that an HTTP origin (which DOES interpret .. as traversal) cannot
// be used to escape a configured base-path prefix. If the cleaned path would land
// outside the base path the call returns an error and no fetch is performed.
// NOTE: this cleaning is intentionally applied ONLY to the origin fetch path and
// never to the cache key; the cache key is built from the raw client path upstream
// of this function. Two raw keys that clean to the same origin path is benign;
// the dangerous direction (attacker choosing origin content via a single key) is
// not introduced by this change.
func (o *Origin) urlFor(key string) (string, error) {
	key = strings.TrimPrefix(key, "/")
	// Join base path and key with a single slash. We build the target by cloning
	// the base and setting its (unescaped) Path; url.URL.String() re-escapes it.
	u := *o.base
	basePath := strings.TrimSuffix(u.Path, "/")

	var joined string
	if basePath == "" {
		joined = "/" + key
	} else {
		joined = basePath + "/" + key
	}

	// Collapse dot-segments so an HTTP origin (which interprets ".." as traversal)
	// cannot be coaxed into serving content outside the configured base path.
	cleaned := path.Clean(joined)

	// Preserve a trailing slash: HTTP trailing slashes are semantically meaningful
	// (directory listing vs. file). path.Clean strips them, so we re-append one
	// when the pre-clean joined path ended with "/" and the cleaned result is not
	// already "/" (the root — path.Clean leaves "/" alone). This matches the
	// approach used by net/http's path normalisation.
	if strings.HasSuffix(joined, "/") && cleaned != "/" {
		cleaned += "/"
	}

	// Confinement check: the cleaned path must be either:
	//   (a) equal to basePath or basePath+"/" — a legitimate fetch of the base
	//       directory itself (e.g. a trailing-slash listing request), or
	//   (b) a proper child of basePath (cleaned starts with basePath+"/").
	// Anything that resolves outside basePath (e.g. /tenant-a/../tenant-b →
	// /tenant-b) is refused. We derive confinePrefix from the trailing-slash-
	// stripped basePath; an empty basePath means everything under "/" is allowed.
	var confinePrefix string
	if basePath == "" {
		confinePrefix = "/"
	} else {
		confinePrefix = basePath + "/"
	}

	// Allow the cleaned path when it equals basePath (without slash) or
	// basePath+"/" (with slash restored), or is a child of basePath.
	isBaseDir := cleaned == basePath || cleaned == basePath+"/"
	isChild := strings.HasPrefix(cleaned, confinePrefix)
	if !isBaseDir && !isChild {
		return "", fmt.Errorf("httporigin: key %q escapes configured base path %q (cleaned: %q)", key, u.Path, cleaned)
	}

	u.Path = cleaned
	// Reset RawPath so String() recomputes the escaped form from Path.
	u.RawPath = ""
	return u.String(), nil
}

// hostFor resolves the upstream Host header to send for this request per the
// origin's HostPolicy (backlog #11). It returns "" to mean "leave req.Host as the
// Go default" (the base URL host) — which happens for HostOrigin and for
// HostPreserve when the client Host is unknown (e.g. a background revalidation
// after the client headers are gone). Returning "" rather than the base host keeps
// the zero-config legacy path byte-for-byte identical.
func (o *Origin) hostFor(clientHost string) string {
	switch o.hostPolicy {
	case HostFixed:
		return o.hostValue
	case HostPreserve:
		return clientHost // "" falls back to the base host (req.Host left as-is)
	default: // HostOrigin
		return ""
	}
}

// negativeStatus reports whether an upstream status is a not-found / gone status
// that cadish returns as a full-body NEGATIVE *Response (so it can be negatively
// cached with its real error-page body), rather than collapsed to the bodyless
// ErrNotFound sentinel. Other non-success statuses (5xx, 401, 403…) are not
// negatively cacheable and surface as a *StatusError with the body drained.
func negativeStatus(code int) bool {
	return code == http.StatusNotFound || code == http.StatusGone
}

// Fetch implements origin.Origin. It forwards the Range header verbatim, streams
// the body (no buffering), returns a 404/410 as a full-body NEGATIVE *Response
// (Negative true), and returns a *origin.StatusError for any other non-success
// status (body closed). See the origin package doc for the ownership/streaming
// contract.
func (o *Origin) Fetch(ctx context.Context, in *origin.Request) (*origin.Response, error) {
	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	targetURL, err := o.urlFor(in.Key)
	if err != nil {
		return nil, err
	}
	// Forward the client request body for write methods (POST/PUT/…). in.Body is nil
	// for GET/HEAD and background revalidations, in which case the upstream request
	// is bodyless. net/http's Client closes the request Body when it sends the
	// request, so we do NOT close in.Body here (the server owns the client body
	// lifecycle; see origin.Request.Body).
	req, err := http.NewRequestWithContext(ctx, method, targetURL, in.Body)
	if err != nil {
		return nil, fmt.Errorf("httporigin: build request: %w", err)
	}
	// Carry the client-declared body length so a known length is sent as
	// Content-Length rather than chunked. NewRequestWithContext only infers
	// ContentLength for a few well-known reader types; an arbitrary io.ReadCloser
	// leaves it 0, so set it explicitly. <= 0 (unknown/none) leaves Go's default.
	if in.Body != nil && in.ContentLength > 0 {
		req.ContentLength = in.ContentLength
	}
	// Forward the original (already-encoded) query string. urlFor builds only the
	// path; without this the origin never sees the query and a query-varying backend
	// returns the wrong body for every distinct-query cache key.
	req.URL.RawQuery = in.RawQuery
	// Forward request headers (incl. Range) verbatim.
	for k, vs := range in.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// Host header policy (backlog #11). net/http IGNORES a "Host" entry in the
	// header map; req.Host is the authoritative field. By default we PRESERVE the
	// client's Host so name-based vhosts / multi-tenant origins answer for the
	// public hostname instead of canonical-301'ing to the internal upstream host.
	if h := o.hostFor(in.ClientHost); h != "" {
		req.Host = h
	}

	resp, err := o.hc.Do(req)
	if err != nil {
		// Transport/timeout error BEFORE headers; no body to close.
		return nil, fmt.Errorf("httporigin: fetch %q: %w", in.Key, err)
	}

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent:
		// Success: hand the live body to the caller (who MUST Close it).
		return &origin.Response{
			StatusCode:    resp.StatusCode,
			Header:        resp.Header,
			ContentLength: resp.ContentLength, // -1 when unknown (chunked)
			Body:          resp.Body,
			BetweenBytes:  o.betweenBytes,
		}, nil
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		// Redirect / 304: we do NOT follow it (SSRF guard, security review #1).
		// Instead we PASS IT THROUGH as a streaming response so the client (browser)
		// sees the real 30x + Location and follows it itself — cadish never dials the
		// redirect target. This also means a 3xx reaches the client as a 3xx rather
		// than being mistranslated to 502 (closes the "3xx → 502" issue). The server
		// caches only 200s, so a redirect is never stored.
		return &origin.Response{
			StatusCode:    resp.StatusCode,
			Header:        resp.Header,
			ContentLength: resp.ContentLength,
			Body:          resp.Body,
		}, nil
	case negativeStatus(resp.StatusCode):
		// 404 / 410: hand the live error-page body to the caller (who MUST Close it)
		// as a NEGATIVE response. A chain falls through on it; the server negatively
		// caches the real body+headers when the pipeline marks the status cacheable.
		return &origin.Response{
			StatusCode:    resp.StatusCode,
			Header:        resp.Header,
			ContentLength: resp.ContentLength, // -1 when unknown (chunked)
			Body:          resp.Body,
			Negative:      true,
			BetweenBytes:  o.betweenBytes,
		}, nil
	default:
		// Any other status (4xx, 5xx): drain+close and surface a StatusError so a
		// chain can fall through without us ever streaming an error page to the
		// client.
		status := resp.StatusCode
		drainClose(resp.Body)
		return nil, &origin.StatusError{Status: status, Origin: originName}
	}
}

// drainClose discards a small amount of the body then closes it, so the
// underlying keep-alive connection can be returned to the pool for reuse instead
// of being torn down. We cap the drain so a huge error page can't block us.
func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, 4<<10)
	_ = body.Close()
}
