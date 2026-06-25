package cfsign

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

// originName identifies this origin in StatusError / logs.
const originName = "cfsign"

// Origin is an origin.Origin that CloudFront-signs each request URL before
// fetching it. It wraps a Signer (the distribution + key) and a freshness window:
// every Fetch mints a canned-policy URL valid for ttl, then streams a plain HTTPS
// GET of that signed URL. It is the composable building block behind a
// `sign cloudfront …` upstream — just an origin.Origin, so it drops into an
// `origin chain` like any other backend.
//
// The streaming / status contract mirrors httporigin exactly: 200/206 stream the
// live body (caller closes), 3xx pass through (we never follow — SSRF guard), 404
// → origin.ErrNotFound, any other status → *origin.StatusError so a chain can fall
// through.
type Origin struct {
	signer *Signer
	ttl    time.Duration
	hc     *http.Client
	now    func() time.Time
}

// OriginOption configures an Origin.
type OriginOption func(*Origin)

// WithHTTPClient overrides the internal http.Client (tests / advanced wiring). The
// client MUST NOT set a body-transfer timeout (it would truncate large streams)
// and SHOULD NOT follow redirects.
func WithHTTPClient(hc *http.Client) OriginOption { return func(o *Origin) { o.hc = hc } }

// WithClock overrides the clock used to compute the signed URL's expiry (tests).
func WithClock(now func() time.Time) OriginOption { return func(o *Origin) { o.now = now } }

// NewOrigin builds a signing origin. ttl is the validity window minted into each
// signed URL (clamped to a small positive default when non-positive).
func NewOrigin(signer *Signer, ttl time.Duration, opts ...OriginOption) *Origin {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	o := &Origin{signer: signer, ttl: ttl, hc: pooledHTTPClient(), now: time.Now}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Fetch signs in.Key for the configured distribution and streams a GET of the
// signed URL.
func (o *Origin) Fetch(ctx context.Context, in *origin.Request) (*origin.Response, error) {
	signed, err := o.signer.SignedURL(in.Key, o.now().Add(o.ttl))
	if err != nil {
		return nil, fmt.Errorf("cfsign: sign %q: %w", in.Key, err)
	}
	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, signed, nil)
	if err != nil {
		return nil, fmt.Errorf("cfsign: build request: %w", err)
	}
	for k, vs := range in.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := o.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cfsign: fetch %q: %w", in.Key, err)
	}

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent:
		return &origin.Response{
			StatusCode:    resp.StatusCode,
			Header:        resp.Header,
			ContentLength: resp.ContentLength,
			Body:          resp.Body,
		}, nil
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		// Pass the redirect through (never followed — SSRF guard, as in httporigin).
		return &origin.Response{
			StatusCode:    resp.StatusCode,
			Header:        resp.Header,
			ContentLength: resp.ContentLength,
			Body:          resp.Body,
		}, nil
	case resp.StatusCode == http.StatusNotFound:
		drainClose(resp.Body)
		return nil, origin.ErrNotFound
	default:
		status := resp.StatusCode
		drainClose(resp.Body)
		return nil, &origin.StatusError{Status: status, Origin: originName}
	}
}

// pooledHTTPClient mirrors httporigin's SSRF-safe, streaming-tuned client:
// establishment phases are bounded, the body is uncapped (context-governed), and
// redirects are never followed.
func pooledHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// No ambient proxy (security): origin dials are explicit; an env-configured
		// HTTP(S)_PROXY diverting them is an SSRF-adjacent footgun. Mirrors httporigin.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// drainClose discards a little of the body then closes it so the keep-alive
// connection returns to the pool.
func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, 4<<10)
	_ = body.Close()
}
