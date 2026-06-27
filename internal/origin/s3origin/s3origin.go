// Package s3origin is cadish's S3-compatible upstream origin (e.g. AWS S3, OVH
// Object Storage, MinIO). Given an endpoint + bucket (+ static
// credentials), it fetches an object via the AWS SDK for Go v2's S3 GetObject,
// forwards the Range header for partial/seek requests (=> 206), and streams the
// response body so the server can tee it into the cache while serving the client.
//
// It uses a shared, connection-pooling HTTP client so cadish can sustain heavy
// throughput without leaking sockets. CONNECTION-ESTABLISHMENT phases (dial, TLS,
// response headers) are bounded with timeouts so a black-holed or slow origin
// can't pin goroutines; the body transfer itself is NOT capped (large media) and
// relies on the per-request context for cancellation. See the origin package doc
// for the full streaming/ownership contract.
package s3origin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/cadi-sh/cadish/internal/origin"
)

// originName identifies this origin in StatusError / logs.
const originName = "s3origin"

// Config configures an S3-compatible origin. It is a plain value type (no
// dependency on cadish's Cadishfile config package) so the origin layer stays
// self-contained.
type Config struct {
	// Endpoint is the S3-compatible endpoint URL (e.g.
	// "https://s3.gra.io.cloud.ovh.net"). Required.
	Endpoint string
	// Region is the S3 region (e.g. "gra"). Required by the SDK; for many
	// S3-compatible stores any non-empty value works.
	Region string
	// Bucket is the bucket to fetch from. Required.
	Bucket string
	// AccessKey / SecretKey are static credentials. Required for private buckets.
	// When BOTH are empty the origin fetches ANONYMOUSLY (see Anonymous) — signing a
	// request with empty static credentials is rejected by S3/MinIO, so empty creds
	// must mean "no signing", not "sign with an empty key".
	AccessKey string
	SecretKey string
	// Anonymous forces unsigned (public-bucket) requests. It is also implied when
	// AccessKey and SecretKey are both empty.
	Anonymous bool
	// UsePathStyle forces path-style addressing (/<bucket>/<key>) instead of
	// virtual-host style. Most S3-compatible stores (OVH, MinIO) need this true.
	UsePathStyle bool
}

// Origin fetches objects from one S3 bucket.
type Origin struct {
	s3     *s3.Client
	bucket string
}

// Option configures an Origin.
type Option func(*s3.Options)

// New builds an S3-compatible origin from cfg. It wires a connection-pooling HTTP
// client with bounded establishment timeouts (body transfer uncapped). Additional
// raw s3.Options can be tweaked via opts (tests inject a custom HTTP client this
// way).
func New(cfg Config, opts ...Option) *Origin {
	o := s3.Options{
		Region:       cfg.Region,
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: cfg.UsePathStyle,
		HTTPClient:   pooledHTTPClient(),
	}
	// Anonymous (no creds) → unsigned requests; the SDK detects aws.AnonymousCredentials
	// and skips signing. With static creds present, sign normally. Signing with EMPTY
	// static creds (the old behavior) is rejected by S3/MinIO, so empty ⇒ anonymous.
	if cfg.Anonymous || (cfg.AccessKey == "" && cfg.SecretKey == "") {
		o.Credentials = aws.AnonymousCredentials{}
	} else {
		o.Credentials = credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")
	}
	for _, opt := range opts {
		opt(&o)
	}
	return &Origin{s3: s3.New(o), bucket: cfg.Bucket}
}

// WithHTTPClient overrides the S3 client's HTTP client (tests point this at an
// httptest server).
func WithHTTPClient(hc aws.HTTPClient) Option {
	return func(o *s3.Options) { o.HTTPClient = hc }
}

// pooledHTTPClient is tuned for high-throughput origin fetches: large keep-alive pools,
// bounded establishment phases, uncapped body transfer (per-request context
// governs cancellation).
func pooledHTTPClient() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().
		WithDialerOptions(func(d *net.Dialer) {
			d.Timeout = 5 * time.Second
			d.KeepAlive = 30 * time.Second
		}).
		WithTransportOptions(func(t *http.Transport) {
			t.MaxIdleConns = 512
			t.MaxIdleConnsPerHost = 128
			t.IdleConnTimeout = 90 * time.Second
			t.TLSHandshakeTimeout = 5 * time.Second
			t.ExpectContinueTimeout = 1 * time.Second
			// Bound time to the FIRST byte (headers); the body then streams uncapped.
			t.ResponseHeaderTimeout = 30 * time.Second
			t.ForceAttemptHTTP2 = true
		})
}

// Fetch implements origin.Origin. It forwards the Range header (=> 206), streams
// the body (no buffering), maps NoSuchKey/404 to origin.ErrNotFound, and surfaces
// any other non-success status as a *origin.StatusError. The returned
// Response.Body MUST be closed by the caller. See the origin package doc.
func (o *Origin) Fetch(ctx context.Context, in *origin.Request) (*origin.Response, error) {
	// s3origin is a READ-ONLY origin: it only maps GET/HEAD onto S3 GetObject. A write
	// method (POST/PUT/PATCH/DELETE) has no read semantics here, so reject it
	// explicitly rather than silently doing a GetObject (which would drop the client
	// body and return the wrong object). "" means GET.
	if m := in.Method; m != "" && m != http.MethodGet && m != http.MethodHead {
		return nil, fmt.Errorf("s3origin: method %s not supported (read-only origin)", m)
	}
	// in.RawQuery is intentionally ignored: an S3 object's identity is its key, which
	// has no query component (unlike an HTTP origin, where the query selects content).
	in.Key = strings.TrimPrefix(in.Key, "/")
	gi := &s3.GetObjectInput{
		Bucket: aws.String(o.bucket),
		Key:    aws.String(in.Key),
	}
	if r := in.RangeHeader(); r != "" {
		gi.Range = aws.String(r)
	}

	out, err := o.s3.GetObject(ctx, gi)
	if err != nil {
		if isNotFound(err) {
			return nil, origin.ErrNotFound
		}
		// Map a real non-404 HTTP status to a StatusError so a chain can fall
		// through on 5xx, etc. A status of 0 means the SDK wrapped a transport /
		// context error (no HTTP response was obtained) — surface it as-is so the
		// caller's timeout/cancellation classification (and a chain's connection-
		// error fall-through) still works.
		if st, ok := httpStatus(err); ok && st > 0 {
			return nil, &origin.StatusError{Status: st, Origin: originName}
		}
		return nil, err
	}

	status := http.StatusOK
	hdr := make(http.Header)
	setIf(hdr, "Content-Type", aws.ToString(out.ContentType))
	setIf(hdr, "ETag", aws.ToString(out.ETag))
	setIf(hdr, "Accept-Ranges", aws.ToString(out.AcceptRanges))
	if lm := out.LastModified; lm != nil {
		hdr.Set("Last-Modified", lm.UTC().Format(http.TimeFormat))
	}
	if cr := aws.ToString(out.ContentRange); cr != "" {
		hdr.Set("Content-Range", cr)
		status = http.StatusPartialContent
	}
	// S3 always returns Content-Length on a GetObject 200/206, so a non-nil pointer
	// is the authoritative length — INCLUDING a 0-byte object. Collapsing 0 to -1
	// ("unknown") would drop the downstream Content-Length: 0 and cache the empty
	// object with an unknown Size; only a missing length (nil) is -1. Use the pointer
	// presence, not the value sign, to discriminate known-zero from unknown.
	clen := int64(-1)
	if out.ContentLength != nil && *out.ContentLength >= 0 {
		clen = *out.ContentLength
		hdr.Set("Content-Length", strconv.FormatInt(clen, 10))
	}

	return &origin.Response{
		StatusCode:    status,
		Header:        hdr,
		ContentLength: clen,
		Body:          out.Body, // live io.ReadCloser; caller MUST Close.
	}, nil
}

// setIf sets header k to v only when v is non-empty.
func setIf(h http.Header, k, v string) {
	if v != "" {
		h.Set(k, v)
	}
}

// httpStatus extracts the HTTP status code from a smithy/SDK response error, if
// the error carries one.
func httpStatus(err error) (int, bool) {
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode(), true
	}
	return 0, false
}

// isNotFound reports whether err is an S3 NoSuchKey / 404 / NotFound. We check the
// structured response status first, then fall back to message matching for smithy
// NoSuchKey errors from S3-compatible stores that don't surface a clean 404.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := httpStatus(err); ok && st == http.StatusNotFound {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "NoSuchKey") ||
		strings.Contains(msg, "NotFound") ||
		strings.Contains(msg, "status code: 404")
}
