package s3origin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

const (
	testBucket = "media"
	testKey    = "videos/clip.mp4"
	testBody   = "0123456789ABCDEF"
	testCT     = "video/mp4"
	testETag   = `"d41d8cd98f00b204e9800998ecf8427e"`
	testLM     = "Wed, 21 Oct 2015 07:28:00 GMT"
)

// fakeS3 is an httptest-backed S3-compatible endpoint. With path-style
// addressing, requests arrive at /<bucket>/<key>.
type fakeS3 struct {
	mu        sync.Mutex
	lastRange string
	lastPath  string
	calls     int
	h         http.HandlerFunc
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastRange = r.Header.Get("Range")
	f.lastPath = r.URL.Path
	f.calls++
	f.mu.Unlock()
	f.h(w, r)
}

func (f *fakeS3) capturedRange() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRange
}

func newOrigin(t *testing.T, h http.HandlerFunc) (*Origin, *fakeS3) {
	t.Helper()
	fs := &fakeS3{h: h}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	o := New(Config{
		Endpoint:     srv.URL,
		Region:       "us-east-1",
		Bucket:       testBucket,
		AccessKey:    "test-access",
		SecretKey:    "test-secret",
		UsePathStyle: true,
	})
	return o, fs
}

func req(key, rng string) *origin.Request {
	r := &origin.Request{Key: key}
	if rng != "" {
		r.Header = http.Header{"Range": {rng}}
	}
	return r
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", testCT)
	w.Header().Set("ETag", testETag)
	w.Header().Set("Last-Modified", testLM)
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, testBody)
}

// TestNew_AnonymousVsStaticSigning guards the credential fix: empty creds (or explicit
// Anonymous) must produce UNSIGNED requests (no Authorization header) so public buckets
// work — signing with empty static creds is what made S3 origins 502. Static creds must
// still sign.
func TestNew_AnonymousVsStaticSigning(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		wantAuth bool
	}{
		{"static creds sign", Config{AccessKey: "AK", SecretKey: "SK"}, true},
		{"empty creds => anonymous unsigned", Config{}, false},
		{"explicit anonymous skips signing", Config{AccessKey: "AK", SecretKey: "SK", Anonymous: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, testBody)
			}))
			defer srv.Close()

			cfg := tc.cfg
			cfg.Endpoint, cfg.Region, cfg.Bucket, cfg.UsePathStyle = srv.URL, "us-east-1", testBucket, true
			resp, err := New(cfg).Fetch(context.Background(), req(testKey, ""))
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			resp.Body.Close()

			if tc.wantAuth && gotAuth == "" {
				t.Errorf("expected a signed request (Authorization header), got none")
			}
			if !tc.wantAuth && gotAuth != "" {
				t.Errorf("expected an anonymous (unsigned) request, got Authorization %q", gotAuth)
			}
		})
	}
}

func TestFetch_200OK_BodyAndHeaders(t *testing.T) {
	o, fs := newOrigin(t, okHandler)

	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != testBody {
		t.Fatalf("body = %q want %q", body, testBody)
	}
	if resp.Header.Get("Content-Type") != testCT {
		t.Fatalf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("ETag") != testETag {
		t.Fatalf("ETag = %q", resp.Header.Get("ETag"))
	}
	if resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("Accept-Ranges = %q", resp.Header.Get("Accept-Ranges"))
	}
	if resp.ContentRange() != "" {
		t.Fatalf("ContentRange = %q want empty for 200", resp.ContentRange())
	}
	if resp.ContentLength != int64(len(testBody)) {
		t.Fatalf("ContentLength = %d want %d", resp.ContentLength, len(testBody))
	}
	// Path-style request hits /<bucket>/<key> with no Range.
	if !strings.Contains(fs.lastPath, testBucket) || !strings.Contains(fs.lastPath, "clip.mp4") {
		t.Fatalf("upstream path = %q want bucket+key", fs.lastPath)
	}
	if got := fs.capturedRange(); got != "" {
		t.Fatalf("upstream Range = %q want empty", got)
	}
}

// TestFetch_EmptyObject_ContentLengthZero guards that a 0-byte S3 object is
// surfaced as a KNOWN length of 0 — not -1 ("unknown"). The server only emits a
// downstream Content-Length and records a definite cache Size when
// Response.ContentLength >= 0 (handler.go), so a 0 collapsed to -1 drops the
// Content-Length: 0 header and caches the empty object with an unknown size.
func TestFetch_EmptyObject_ContentLengthZero(t *testing.T) {
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", testCT)
		w.Header().Set("ETag", testETag)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		// no body
	})

	resp, err := o.Fetch(context.Background(), req("empty.bin", ""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want 200", resp.StatusCode)
	}
	if resp.ContentLength != 0 {
		t.Fatalf("ContentLength = %d want 0 (known empty object, not -1/unknown)", resp.ContentLength)
	}
	if got := resp.Header.Get("Content-Length"); got != "0" {
		t.Fatalf("Content-Length header = %q want \"0\"", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("body len = %d want 0", len(body))
	}
}

func TestFetch_206PartialContent_RangeForwarded(t *testing.T) {
	const (
		part       = "4567"
		contentRng = "bytes 4-7/16"
		wantRange  = "bytes=4-7"
	)
	o, fs := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != wantRange {
			t.Errorf("upstream Range = %q want %q", got, wantRange)
		}
		w.Header().Set("Content-Type", testCT)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Range", contentRng)
		w.WriteHeader(http.StatusPartialContent)
		io.WriteString(w, part)
	})

	resp, err := o.Fetch(context.Background(), req(testKey, wantRange))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d want 206", resp.StatusCode)
	}
	if resp.ContentRange() != contentRng {
		t.Fatalf("Content-Range = %q want %q", resp.ContentRange(), contentRng)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != part {
		t.Fatalf("body = %q want %q", body, part)
	}
	if got := fs.capturedRange(); got != wantRange {
		t.Fatalf("captured upstream Range = %q want %q", got, wantRange)
	}
}

func TestFetch_404_ReturnsErrNotFound(t *testing.T) {
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
	})

	resp, err := o.Fetch(context.Background(), req("missing/key.mp4", ""))
	if resp != nil {
		resp.Body.Close()
		t.Fatalf("resp = %v want nil on 404", resp)
	}
	if !errors.Is(err, origin.ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestFetch_5xx_IsStatusErrorNotNotFound(t *testing.T) {
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `<?xml version="1.0"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`)
	})

	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if resp != nil {
		resp.Body.Close()
		t.Fatalf("resp = %v want nil on 5xx", resp)
	}
	if err == nil {
		t.Fatal("err = nil want a 5xx error")
	}
	if errors.Is(err, origin.ErrNotFound) {
		t.Fatalf("err = %v must NOT be ErrNotFound for 5xx", err)
	}
	if origin.StatusOf(err) != http.StatusInternalServerError {
		t.Fatalf("StatusOf = %d want 500 (err=%v)", origin.StatusOf(err), err)
	}
}

func TestFetch_ContextDeadline_Timeout(t *testing.T) {
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := o.Fetch(ctx, req(testKey, ""))
	if resp != nil {
		resp.Body.Close()
		t.Fatalf("resp = %v want nil on timeout", resp)
	}
	if err == nil {
		t.Fatal("err = nil want a deadline error")
	}
	if errors.Is(err, origin.ErrNotFound) {
		t.Fatalf("err = %v must NOT be ErrNotFound for timeout", err)
	}
	if !isTimeout(err) {
		t.Fatalf("err = %v (%T) not classifiable as timeout", err, err)
	}
}

func TestFetch_BodyIsWorkingReadCloser(t *testing.T) {
	o, _ := newOrigin(t, okHandler)
	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	buf := make([]byte, 4)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("partial read: %v", err)
	}
	if n != 4 || string(buf) != testBody[:4] {
		t.Fatalf("read %d %q want first 4", n, buf[:n])
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestFetch_RealEndpoint exercises a real S3-compatible endpoint when credentials
// are present in the environment, otherwise it skips. Set S3_ENDPOINT, S3_BUCKET,
// S3_KEY, S3_REGION (optional), S3_ACCESS_KEY, S3_SECRET_KEY.
func TestFetch_RealEndpoint(t *testing.T) {
	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	key := os.Getenv("S3_KEY")
	access := os.Getenv("S3_ACCESS_KEY")
	secret := os.Getenv("S3_SECRET_KEY")
	if endpoint == "" || bucket == "" || key == "" || access == "" || secret == "" {
		t.Skip("set S3_ENDPOINT/S3_BUCKET/S3_KEY/S3_ACCESS_KEY/S3_SECRET_KEY to run the real-endpoint test")
	}
	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	o := New(Config{
		Endpoint:     endpoint,
		Region:       region,
		Bucket:       bucket,
		AccessKey:    access,
		SecretKey:    secret,
		UsePathStyle: true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := o.Fetch(ctx, req(key, ""))
	if err != nil {
		t.Fatalf("Fetch real endpoint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d want 200", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("stream body: %v", err)
	}
}

// isTimeout mirrors the server-side timeout classification: an error counts as a
// timeout if it wraps context.DeadlineExceeded or satisfies net.Error.Timeout().
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

// TestFetch_RejectsWrite guards the P0 fix: s3origin is a READ-ONLY origin. It used
// to ignore in.Method and always do GetObject, so a POST/PUT silently became a GET.
// A write method must now return a clear not-supported error.
func TestFetch_RejectsWrite(t *testing.T) {
	o, fs := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should not be called for a write method (got %s %s)", r.Method, r.URL.Path)
	})

	_, err := o.Fetch(context.Background(), &origin.Request{Method: http.MethodPost, Key: testKey})
	if err == nil {
		t.Fatal("Fetch(POST) returned nil error, want a not-supported error")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("Fetch(POST) error = %q, want a 'not supported' message", err.Error())
	}
	if fs.calls != 0 {
		t.Fatalf("upstream was called %d times for a rejected write, want 0", fs.calls)
	}
}
