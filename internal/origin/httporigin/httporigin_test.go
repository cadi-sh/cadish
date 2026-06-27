package httporigin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

const (
	testKey  = "videos/clip.mp4"
	testBody = "0123456789ABCDEF"
	testCT   = "video/mp4"
	testETag = `"d41d8cd98f00b204e9800998ecf8427e"`
)

// recordingHandler captures the last request and delegates to h.
type recordingHandler struct {
	mu        sync.Mutex
	lastPath  string
	lastQuery string
	lastRange string
	calls     int
	h         http.HandlerFunc
}

func (r *recordingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.lastPath = req.URL.Path
	r.lastQuery = req.URL.RawQuery
	r.lastRange = req.Header.Get("Range")
	r.calls++
	r.mu.Unlock()
	r.h(w, req)
}

func newOrigin(t *testing.T, h http.HandlerFunc) (*Origin, *recordingHandler) {
	t.Helper()
	rec := &recordingHandler{h: h}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	o, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, rec
}

func req(key, rng string) *origin.Request {
	r := &origin.Request{Key: key}
	if rng != "" {
		r.Header = http.Header{"Range": {rng}}
	}
	return r
}

func TestFetch_200FullBody(t *testing.T) {
	o, rec := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", testCT)
		w.Header().Set("ETag", testETag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, testBody)
	})

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
	if resp.ContentRange() != "" {
		t.Fatalf("ContentRange = %q want empty for 200", resp.ContentRange())
	}
	if !strings.HasSuffix(rec.lastPath, "clip.mp4") {
		t.Fatalf("upstream path = %q want .../clip.mp4", rec.lastPath)
	}
	if rec.lastRange != "" {
		t.Fatalf("upstream Range = %q want empty", rec.lastRange)
	}
}

func TestFetch_ForwardsQuery(t *testing.T) {
	o, rec := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testBody)
	})

	r := &origin.Request{Key: testKey, RawQuery: "size=4096&q=hello%20world"}
	resp, err := o.Fetch(context.Background(), r)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()

	if rec.lastQuery != "size=4096&q=hello%20world" {
		t.Fatalf("upstream query = %q, want the forwarded query string", rec.lastQuery)
	}
	if !strings.HasSuffix(rec.lastPath, "clip.mp4") {
		t.Fatalf("upstream path = %q, want .../clip.mp4 (query must not corrupt the path)", rec.lastPath)
	}
}

func TestFetch_NoQueryWhenEmpty(t *testing.T) {
	o, rec := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testBody)
	})

	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()

	if rec.lastQuery != "" {
		t.Fatalf("upstream query = %q, want empty when no RawQuery set", rec.lastQuery)
	}
}

func TestFetch_206Range(t *testing.T) {
	const (
		part       = "4567"
		contentRng = "bytes 4-7/16"
		wantRange  = "bytes=4-7"
	)
	o, rec := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != wantRange {
			t.Errorf("upstream Range = %q want %q", got, wantRange)
		}
		w.Header().Set("Content-Type", testCT)
		w.Header().Set("Content-Range", contentRng)
		w.Header().Set("Accept-Ranges", "bytes")
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
	if rec.lastRange != wantRange {
		t.Fatalf("captured upstream Range = %q want %q", rec.lastRange, wantRange)
	}
}

// TestFetch_404IsNegativeResponse pins the full-body-negative-caching contract
// (backlog #21): a 404 is returned as a streaming *Response carrying the real
// status, headers, and body — flagged Negative so a chain can fall through on it
// and the server can negatively cache the actual error page.
func TestFetch_404IsNegativeResponse(t *testing.T) {
	const errBody = "custom not-found page"
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Origin-Mark", "404page")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, errBody)
	})

	resp, err := o.Fetch(context.Background(), req("missing.mp4", ""))
	if err != nil {
		t.Fatalf("Fetch err = %v, want a *Response on 404", err)
	}
	if resp == nil {
		t.Fatal("resp = nil, want a negative *Response on 404")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d want 404", resp.StatusCode)
	}
	if !resp.Negative {
		t.Fatalf("resp.Negative = false, want true for a 404")
	}
	if resp.Header.Get("X-Origin-Mark") != "404page" {
		t.Fatalf("header X-Origin-Mark = %q want 404page", resp.Header.Get("X-Origin-Mark"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != errBody {
		t.Fatalf("body = %q want %q", body, errBody)
	}
}

// TestFetch_410IsNegativeResponse: a 410 Gone is likewise a negative *Response.
func TestFetch_410IsNegativeResponse(t *testing.T) {
	const errBody = "gone for good"
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		io.WriteString(w, errBody)
	})

	resp, err := o.Fetch(context.Background(), req("gone.mp4", ""))
	if err != nil {
		t.Fatalf("Fetch err = %v, want a *Response on 410", err)
	}
	if resp == nil {
		t.Fatal("resp = nil, want a negative *Response on 410")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone || !resp.Negative {
		t.Fatalf("status=%d negative=%v want 410/true", resp.StatusCode, resp.Negative)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != errBody {
		t.Fatalf("body = %q want %q", body, errBody)
	}
}

func TestFetch_5xxIsStatusError(t *testing.T) {
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if resp != nil {
		resp.Body.Close()
		t.Fatalf("resp = %v want nil on 5xx", resp)
	}
	if errors.Is(err, origin.ErrNotFound) {
		t.Fatalf("err = %v must not be ErrNotFound for 5xx", err)
	}
	var se *origin.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T) want *origin.StatusError", err, err)
	}
	if se.Status != http.StatusInternalServerError {
		t.Fatalf("StatusError.Status = %d want 500", se.Status)
	}
	if origin.StatusOf(err) != 500 {
		t.Fatalf("StatusOf = %d want 500", origin.StatusOf(err))
	}
	// PRESERVE-ORIGIN-ERROR-BODY: the non-2xx StatusError now CARRIES the live body +
	// headers (not drained) so the server can stream the origin's real error response
	// verbatim. The holder MUST Close it.
	if se.Body == nil {
		t.Fatal("StatusError.Body = nil, want the live upstream error body (not drained)")
	}
	if got := se.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("StatusError.Header Content-Type = %q, want the upstream error header", got)
	}
	got, rerr := io.ReadAll(se.Body)
	se.CloseBody()
	if rerr != nil {
		t.Fatalf("read StatusError.Body: %v", rerr)
	}
	if string(got) != "boom\n" {
		t.Fatalf("StatusError.Body = %q, want the upstream error body %q", got, "boom\n")
	}
	se.CloseBody() // idempotent: safe to call again
}

func TestFetch_ConnectionError(t *testing.T) {
	// Point at a server, then close it so the dial fails.
	rec := &recordingHandler{h: func(w http.ResponseWriter, r *http.Request) {}}
	srv := httptest.NewServer(rec)
	url := srv.URL
	srv.Close()

	o, err := New(url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if resp != nil {
		resp.Body.Close()
		t.Fatalf("resp = %v want nil on connection error", resp)
	}
	if err == nil {
		t.Fatal("err = nil want a connection error")
	}
	if errors.Is(err, origin.ErrNotFound) {
		t.Fatalf("err = %v must not be ErrNotFound", err)
	}
	// A connection error carries no HTTP status => StatusOf == 0 (falls through in a chain).
	if origin.StatusOf(err) != 0 {
		t.Fatalf("StatusOf = %d want 0 for connection error", origin.StatusOf(err))
	}
}

func TestFetch_ContextCancelMidStream(t *testing.T) {
	// The handler writes a few bytes, flushes, then blocks until the request
	// context is cancelled — so the client's Read blocks mid-stream and unblocks
	// with a context error when we cancel.
	released := make(chan struct{})
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", testCT)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "head")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(released)
	})

	ctx, cancel := context.WithCancel(context.Background())
	resp, err := o.Fetch(ctx, req(testKey, ""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	// Read the first flushed chunk.
	buf := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("read head: %v", err)
	}
	if string(buf) != "head" {
		t.Fatalf("head = %q", buf)
	}

	// Cancel mid-stream; the next Read must surface an error (NOT EOF).
	cancel()
	_, rerr := io.ReadAll(resp.Body)
	if rerr == nil {
		t.Fatal("mid-stream read after cancel returned nil error, want a context error")
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("handler not released after cancel")
	}
}

func TestFetch_BodyOwnershipPartialReadThenClose(t *testing.T) {
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, testBody)
	})
	resp, err := o.Fetch(context.Background(), req(testKey, ""))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Read part, then Close early — must be safe and not error.
	buf := make([]byte, 4)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("partial read: %v", err)
	}
	if n != 4 || string(buf) != testBody[:4] {
		t.Fatalf("read %d %q want first 4", n, buf[:n])
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("early Close: %v", err)
	}
}

func TestNew_RejectsBadBaseURL(t *testing.T) {
	for _, bad := range []string{"", "ftp://x", "no-scheme.com", "https://"} {
		if _, err := New(bad); err == nil {
			t.Errorf("New(%q) = nil err, want error", bad)
		}
	}
}

func TestURLFor_JoinsBasePathAndKey(t *testing.T) {
	o, err := New("https://h.example.com/prefix")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := o.urlFor("/a/b.mp4")
	if err != nil {
		t.Fatalf("urlFor err = %v", err)
	}
	want := "https://h.example.com/prefix/a/b.mp4"
	if got != want {
		t.Fatalf("urlFor = %q want %q", got, want)
	}
}

// TestURLFor_DotSegmentEscapeRefused tests the path-traversal security fix:
// a key containing ../ that would escape the base path must be rejected.
func TestURLFor_DotSegmentEscapeRefused(t *testing.T) {
	// Origin confined to /tenant-a/; key attempts to escape to /tenant-b/.
	o, err := New("https://backend.example.com/tenant-a/")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// These keys all attempt to escape /tenant-a/.
	escapingKeys := []string{
		"../tenant-b/private",
		"../../etc/passwd",
		"foo/../../tenant-b/secret",
		"../",
	}
	for _, key := range escapingKeys {
		_, err := o.urlFor(key)
		if err == nil {
			t.Errorf("urlFor(%q) returned no error; want error for path-prefix escape", key)
		}
	}
}

// TestURLFor_NormalKeyUnaffected confirms normal keys still work after the fix.
func TestURLFor_NormalKeyUnaffected(t *testing.T) {
	o, err := New("https://backend.example.com/tenant-a/")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := o.urlFor("images/logo.png")
	if err != nil {
		t.Fatalf("urlFor err = %v", err)
	}
	want := "https://backend.example.com/tenant-a/images/logo.png"
	if got != want {
		t.Fatalf("urlFor = %q want %q", got, want)
	}
}

// TestURLFor_DotSegmentWithinPrefixCleaned confirms that a key with embedded ..
// that stays within the base path is cleaned and fetched (not rejected).
func TestURLFor_DotSegmentWithinPrefixCleaned(t *testing.T) {
	o, err := New("https://backend.example.com/tenant-a/")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// a/b/../c stays within /tenant-a/ — should resolve to /tenant-a/a/c.
	got, err := o.urlFor("a/b/../c")
	if err != nil {
		t.Fatalf("urlFor err = %v (want nil; path stays in prefix)", err)
	}
	want := "https://backend.example.com/tenant-a/a/c"
	if got != want {
		t.Fatalf("urlFor = %q want %q", got, want)
	}
}

// TestFetch_PathTraversalReturnsError is an integration test: Fetch itself must
// return an error (not fetch upstream) when the key escapes the base path.
func TestFetch_PathTraversalReturnsError(t *testing.T) {
	// This server should never be reached; if it is, we want a clear signal.
	fetched := false
	o, _ := newOriginWithBase(t, "/tenant-a/", func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.WriteHeader(http.StatusOK)
	})

	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "../tenant-b/private"})
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("Fetch returned nil error; want error for path-traversal key")
	}
	if fetched {
		t.Fatal("upstream was reached; traversal was not blocked")
	}
}

// TestURLFor_TrailingSlashPreserved asserts that a trailing slash in the key is
// preserved after dot-segment cleaning. HTTP trailing slashes are semantically
// meaningful (directory listing vs. file), so path.Clean must not silently strip them.
func TestURLFor_TrailingSlashPreserved(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		key     string
		want    string
	}{
		{
			name:    "trailing slash on listing under base",
			baseURL: "https://backend.example.com/catalog/",
			key:     "",
			want:    "https://backend.example.com/catalog/",
		},
		{
			name:    "trailing slash on subdirectory listing",
			baseURL: "https://backend.example.com/",
			key:     "dir/",
			want:    "https://backend.example.com/dir/",
		},
		{
			name:    "trailing slash preserved under prefixed base",
			baseURL: "https://backend.example.com/tenant-a/",
			key:     "images/",
			want:    "https://backend.example.com/tenant-a/images/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := New(tc.baseURL)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := o.urlFor(tc.key)
			if err != nil {
				t.Fatalf("urlFor(%q) err = %v, want nil", tc.key, err)
			}
			if got != tc.want {
				t.Fatalf("urlFor(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// TestURLFor_BaseDirectoryRequestAllowed asserts that a request resolving exactly
// to the base directory (cleaned == basePath) is allowed and not refused as an escape.
func TestURLFor_BaseDirectoryRequestAllowed(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		key     string
		want    string
	}{
		{
			name:    "empty key under trailing-slash base",
			baseURL: "https://backend.example.com/catalog/",
			key:     "",
			want:    "https://backend.example.com/catalog/",
		},
		{
			name:    "dot key resolves to base dir (no trailing slash, still allowed)",
			baseURL: "https://backend.example.com/catalog/",
			key:     ".",
			want:    "https://backend.example.com/catalog",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := New(tc.baseURL)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := o.urlFor(tc.key)
			if err != nil {
				t.Fatalf("urlFor(%q) err = %v, want nil (base-dir request is legitimate)", tc.key, err)
			}
			if got != tc.want {
				t.Fatalf("urlFor(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

// newOriginWithBase creates an Origin whose base URL is srv.URL + basePath.
func newOriginWithBase(t *testing.T, basePath string, h http.HandlerFunc) (*Origin, *recordingHandler) {
	t.Helper()
	rec := &recordingHandler{h: h}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	o, err := New(srv.URL + basePath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, rec
}

// TestFetch_ForwardsRequestBody guards the P0 correctness fix: a non-GET request
// (POST/PUT/…) carrying a body must forward the EXACT body bytes — and a correct
// Content-Length — to the upstream. cadish used to build the upstream request with
// a nil body, so a proxied/`pass`'d write reached the origin with the right method
// and Content-Length header but an EMPTY body (data loss / origin hang).
func TestFetch_ForwardsRequestBody(t *testing.T) {
	const payload = "the quick brown fox jumps over the lazy dog"
	var (
		gotBody   string
		gotLen    int64
		gotMethod string
	)
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotLen = r.ContentLength
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	})

	in := &origin.Request{
		Method:        http.MethodPost,
		Key:           "submit",
		Body:          io.NopCloser(strings.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
	resp, err := o.Fetch(context.Background(), in)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if gotMethod != http.MethodPost {
		t.Fatalf("upstream method = %q, want POST", gotMethod)
	}
	if gotBody != payload {
		t.Fatalf("upstream body = %q, want %q", gotBody, payload)
	}
	if gotLen != int64(len(payload)) {
		t.Fatalf("upstream Content-Length = %d, want %d", gotLen, len(payload))
	}
}

// TestFetch_GETNoBody confirms a GET (nil Body) still works — no regression.
func TestFetch_GETNoBody(t *testing.T) {
	var gotLen int64
	o, _ := newOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) != 0 {
			t.Errorf("GET upstream body = %q, want empty", b)
		}
		gotLen = r.ContentLength
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, testBody)
	})

	resp, err := o.Fetch(context.Background(), &origin.Request{Method: http.MethodGet, Key: testKey})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if gotLen > 0 {
		t.Fatalf("GET upstream Content-Length = %d, want 0", gotLen)
	}
}
