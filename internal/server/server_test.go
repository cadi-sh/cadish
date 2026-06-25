package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// discardLogger is a no-op slog logger for tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testCtx returns a context with a short deadline for shutdown calls.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// fakeClock is an injectable, advanceable clock for freshness/TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countingOrigin is an httptest origin server that counts requests and serves a
// body keyed by path.
type countingOrigin struct {
	srv     *httptest.Server
	hits    atomic.Int64
	handler func(w http.ResponseWriter, r *http.Request)
}

func newCountingOrigin(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *countingOrigin {
	t.Helper()
	co := &countingOrigin{handler: h}
	co.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		co.hits.Add(1)
		co.handler(w, r)
	}))
	t.Cleanup(co.srv.Close)
	return co
}

// buildHandler writes a Cadishfile (with originURL spliced into the `to` line),
// loads it, and returns a Handler driven by clk.
func buildHandler(t *testing.T, clk *fakeClock, body string, originURL string) (*Handler, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfgText := fmt.Sprintf(body, originURL)
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, cfgText)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	now := time.Now
	if clk != nil {
		now = clk.now
	}
	h := NewHandler(cfg, Options{Logger: discardLogger(), Now: now})
	t.Cleanup(h.Shutdown)
	return h, cfg
}

// do performs one request against the handler and returns the recorder.
func do(h *Handler, method, target string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "test.local"
	if hdr != nil {
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const (
	cfgBasic = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
)

func TestMissThenHit(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/a.txt", nil)
	if rec1.Code != 200 || rec1.Body.String() != "hello /a.txt" {
		t.Fatalf("miss: got %d %q", rec1.Code, rec1.Body.String())
	}
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}

	rec2 := do(h, "GET", "http://test.local/a.txt", nil)
	if rec2.Code != 200 || rec2.Body.String() != "hello /a.txt" {
		t.Fatalf("hit: got %d %q", rec2.Code, rec2.Body.String())
	}
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT", got)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1", origin.hits.Load())
	}
}

// TestForwardsQueryToOrigin guards the correctness fix: a cacheable GET must forward
// its query string to the origin (it used to send the path only, so a query-varying
// origin returned the wrong body for every distinct-query cache key).
func TestForwardsQueryToOrigin(t *testing.T) {
	var gotQuery atomic.Value
	gotQuery.Store("")
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery.Store(r.URL.RawQuery)
		_, _ = io.WriteString(w, "q="+r.URL.RawQuery)
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/search?size=4096&q=hello%20world", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if q := gotQuery.Load().(string); q != "size=4096&q=hello%20world" {
		t.Fatalf("origin received query %q, want the full forwarded query string", q)
	}
	if body := rec.Body.String(); body != "q=size=4096&q=hello%20world" {
		t.Fatalf("body = %q (origin did not see the query)", body)
	}
}

func TestCoalescing(t *testing.T) {
	release := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the winner in origin so waiters pile up behind it
		_, _ = io.WriteString(w, "coalesced")
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	const n = 20
	var wg sync.WaitGroup
	bodies := make([]string, n)
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := do(h, "GET", "http://test.local/hot", nil)
			codes[i] = rec.Code
			bodies[i] = rec.Body.String()
		}(i)
	}
	// Give all goroutines time to enter the coalescer (winner blocks in origin).
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want exactly 1 (coalesced)", origin.hits.Load())
	}
	for i := 0; i < n; i++ {
		if codes[i] != 200 || bodies[i] != "coalesced" {
			t.Fatalf("req %d: got %d %q", i, codes[i], bodies[i])
		}
	}
}

func TestPassBypassesCache(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "v"+r.URL.RawQuery)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@dyn path /api/*
	pass @dyn
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	for i := 0; i < 3; i++ {
		rec := do(h, "GET", "http://test.local/api/x", nil)
		if rec.Code != 200 {
			t.Fatalf("pass req %d: code %d", i, rec.Code)
		}
		if got := rec.Header().Get("X-Cache"); got != "MISS" {
			t.Fatalf("pass X-Cache = %q, want MISS", got)
		}
	}
	if origin.hits.Load() != 3 {
		t.Fatalf("pass origin hits = %d, want 3 (never cached)", origin.hits.Load())
	}
}

func TestRespondSynthetic(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("origin should not be hit for a synthetic response")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	respond /health 200 "OK"
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/health", nil)
	if rec.Code != 200 || rec.Body.String() != "OK" {
		t.Fatalf("synthetic: got %d %q", rec.Code, rec.Body.String())
	}
	if origin.hits.Load() != 0 {
		t.Fatalf("origin hit for synthetic: %d", origin.hits.Load())
	}
}

func TestRedirectComputed(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("origin should not be hit for a redirect")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	redirect (?i)^/es(/.*)?$ 301 https://{host}/espanol$1
	redirect 302 map {
		/registro -> /register
	}
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	// Capture-group substitution (path suffix preserved).
	rec := do(h, "GET", "http://test.local/es/cams", nil)
	if rec.Code != 301 {
		t.Fatalf("es redirect: got status %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://test.local/espanol/cams" {
		t.Fatalf("es redirect: Location = %q", loc)
	}

	// Translation-map form.
	rec = do(h, "GET", "http://test.local/registro", nil)
	if rec.Code != 302 || rec.Header().Get("Location") != "https://test.local/register" {
		t.Fatalf("map redirect: got %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// No match -> not a redirect (origin would be hit, but we asserted it isn't,
	// so a non-matching path must fall through to a normal lookup). Use a path the
	// origin serves.
	if origin.hits.Load() != 0 {
		t.Fatalf("origin hit during redirects: %d", origin.hits.Load())
	}
}

func TestTTLExpiryRefetch(t *testing.T) {
	clk := newFakeClock()
	var v atomic.Int64
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ver%d", v.Load())
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, body, origin.srv.URL)

	if got := do(h, "GET", "http://test.local/x", nil).Body.String(); got != "ver0" {
		t.Fatalf("first: %q", got)
	}
	// Within TTL: served from cache, origin not consulted.
	clk.advance(30 * time.Second)
	v.Store(1)
	r2 := do(h, "GET", "http://test.local/x", nil)
	if r2.Body.String() != "ver0" || r2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("within ttl: %q %q", r2.Body.String(), r2.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("hits within ttl = %d, want 1", origin.hits.Load())
	}
	// Past TTL (no grace): expired -> refetch.
	clk.advance(31 * time.Second)
	r3 := do(h, "GET", "http://test.local/x", nil)
	if r3.Body.String() != "ver1" || r3.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("past ttl: %q %q", r3.Body.String(), r3.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("hits past ttl = %d, want 2", origin.hits.Load())
	}
}

func TestGraceServesStaleAndRevalidates(t *testing.T) {
	clk := newFakeClock()
	var v atomic.Int64
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ver%d", v.Load())
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s grace 1h
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, body, origin.srv.URL)

	if got := do(h, "GET", "http://test.local/x", nil).Body.String(); got != "ver0" {
		t.Fatalf("first: %q", got)
	}
	// Move into the grace window and change the origin content.
	clk.advance(90 * time.Second)
	v.Store(1)
	r2 := do(h, "GET", "http://test.local/x", nil)
	if r2.Body.String() != "ver0" {
		t.Fatalf("stale serve should return old body, got %q", r2.Body.String())
	}
	if r2.Header().Get("X-Cache") != "HIT-STALE" {
		t.Fatalf("stale X-Cache = %q, want HIT-STALE", r2.Header().Get("X-Cache"))
	}

	// A single background revalidation should run and refresh the cache.
	waitFor(t, 2*time.Second, func() bool { return origin.hits.Load() == 2 })

	// The bgfetch stored ver1 as fresh (relative to the advanced clock). Next read
	// is a fresh HIT of the new content.
	r3 := do(h, "GET", "http://test.local/x", nil)
	if r3.Body.String() != "ver1" || r3.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("after revalidate: %q %q", r3.Body.String(), r3.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (one initial + one bg revalidate)", origin.hits.Load())
	}
}

func TestHitForMiss(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@nocache path /nocache
	cache_ttl @nocache hit_for_miss 60s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	// hit_for_miss path: never cached, every request goes to origin.
	for i := 0; i < 3; i++ {
		do(h, "GET", "http://test.local/nocache", nil)
	}
	if origin.hits.Load() != 3 {
		t.Fatalf("hit_for_miss hits = %d, want 3", origin.hits.Load())
	}
	// A normal path is cached after the first fetch.
	do(h, "GET", "http://test.local/normal", nil)
	do(h, "GET", "http://test.local/normal", nil)
	if origin.hits.Load() != 4 {
		t.Fatalf("normal-path hits = %d, want 4 (3 + 1 cached)", origin.hits.Load())
	}
}

// TestFullBodyNegativeCaching pins backlog #21: a 404 carrying a real error-page
// body+headers, made cacheable via `cache_ttl status 404 410`, is stored WITH its
// body. The second request is a cache HIT served verbatim (same status, body, and
// origin headers) without re-hitting origin.
func TestFullBodyNegativeCaching(t *testing.T) {
	const errBody = "<html>custom 404 page</html>"
	const errETag = `"deadbeef"`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", errETag)
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, errBody)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 404 410 ttl 60s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	r1 := do(h, "GET", "http://test.local/missing", nil)
	if r1.Code != http.StatusNotFound {
		t.Fatalf("first code = %d, want 404", r1.Code)
	}
	if r1.Body.String() != errBody {
		t.Fatalf("first body = %q, want %q", r1.Body.String(), errBody)
	}
	if got := r1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}

	r2 := do(h, "GET", "http://test.local/missing", nil)
	if r2.Code != http.StatusNotFound {
		t.Fatalf("second code = %d, want 404 (negative HIT)", r2.Code)
	}
	if r2.Body.String() != errBody {
		t.Fatalf("second body = %q, want the cached %q", r2.Body.String(), errBody)
	}
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (full-body negative hit)", got)
	}
	// The cache contract persists Content-Type / ETag / Last-Modified (the same set
	// it stores for a 200); those are reconstructed on the negative HIT verbatim.
	if got := r2.Header().Get("Content-Type"); got != "text/html" {
		t.Fatalf("second Content-Type = %q, want cached text/html", got)
	}
	if got := r2.Header().Get("ETag"); got != errETag {
		t.Fatalf("second ETag = %q, want cached %q", got, errETag)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (404 body negatively cached)", origin.hits.Load())
	}
}

func TestHeaderOpsAndCacheStatus(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		_, _ = io.WriteString(w, "x")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
	header X-Powered-By cadish
	header -X-Origin
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/x", nil)
	if rec.Header().Get("X-Powered-By") != "cadish" {
		t.Fatalf("X-Powered-By = %q", rec.Header().Get("X-Powered-By"))
	}
	if rec.Header().Get("X-Origin") != "" {
		t.Fatalf("X-Origin should be removed, got %q", rec.Header().Get("X-Origin"))
	}
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
}

func TestRangeFromCache(t *testing.T) {
	const full = "0123456789abcdef"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, full)
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	// Prime the cache with a full GET.
	if rec := do(h, "GET", "http://test.local/f", nil); rec.Body.String() != full {
		t.Fatalf("prime: %q", rec.Body.String())
	}
	// Range request served from cache as 206.
	rec := do(h, "GET", "http://test.local/f", http.Header{"Range": {"bytes=4-7"}})
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range code = %d, want 206", rec.Code)
	}
	if rec.Body.String() != "4567" {
		t.Fatalf("range body = %q, want 4567", rec.Body.String())
	}
	if cr := rec.Header().Get("Content-Range"); cr != "bytes 4-7/16" {
		t.Fatalf("Content-Range = %q", cr)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("range origin hits = %d, want 1 (served from cache)", origin.hits.Load())
	}

	// Unsatisfiable range -> 416.
	rec416 := do(h, "GET", "http://test.local/f", http.Header{"Range": {"bytes=99-"}})
	if rec416.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("unsatisfiable range code = %d, want 416", rec416.Code)
	}
}

func TestOriginChainFallback(t *testing.T) {
	primary := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // always miss
	})
	fallback := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "from-fallback")
	})
	body := fmt.Sprintf(`test.local {
	cache { ram 64MiB }
	upstream s3 { to %s }
	upstream cf { to %s }
	origin chain s3 -> cf
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`, primary.srv.URL, "%s")
	h, _ := buildHandler(t, nil, body, fallback.srv.URL)

	rec := do(h, "GET", "http://test.local/obj", nil)
	if rec.Code != 200 || rec.Body.String() != "from-fallback" {
		t.Fatalf("chain: got %d %q", rec.Code, rec.Body.String())
	}
	if primary.hits.Load() != 1 || fallback.hits.Load() != 1 {
		t.Fatalf("chain hits: primary=%d fallback=%d, want 1/1", primary.hits.Load(), fallback.hits.Load())
	}
	// Cached now: second request hits neither origin.
	rec2 := do(h, "GET", "http://test.local/obj", nil)
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second X-Cache = %q", rec2.Header().Get("X-Cache"))
	}
	if primary.hits.Load() != 1 || fallback.hits.Load() != 1 {
		t.Fatalf("after cache: primary=%d fallback=%d", primary.hits.Load(), fallback.hits.Load())
	}
}

// truncatingOrigin hijacks the connection and sends a Content-Length larger than
// the body it writes, then closes — simulating a truncated upstream response.
func truncatingOrigin(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var hits atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				// Read (and discard) the request line + headers.
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				// Claim 1000 bytes but send only 10, then close (truncation).
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: text/plain\r\n\r\n")
				_, _ = c.Write([]byte("0123456789"))
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String(), &hits
}

func TestTruncatedBodyNotCached(t *testing.T) {
	url, hits := truncatingOrigin(t)
	h, _ := buildHandler(t, nil, cfgBasic, url)

	// First request: truncated stream. The client may see a short/errored body, but
	// crucially nothing must be committed to cache.
	_ = do(h, "GET", "http://test.local/t", nil)
	// Second request must go to origin again (cache empty), proving no cache commit.
	_ = do(h, "GET", "http://test.local/t", nil)
	if hits.Load() < 2 {
		t.Fatalf("truncated body appears cached: origin hits = %d, want >= 2", hits.Load())
	}
}

func TestGracefulShutdown(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	dir := t.TempDir()
	cfgText := fmt.Sprintf(cfgBasic, origin.srv.URL)
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(cfg, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// Hit the live listener.
	resp, err := http.Get("http://" + ln.Addr().String() + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("body = %q", b)
	}

	if err := srv.Shutdown(testCtx(t)); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("serve returned %v, want nil after graceful shutdown", err)
	}
}

// TestServerStartFailsOnK8sSyncError verifies that NewServer surfaces a startup
// error when the k8s informer caches do not sync (fail-fast: never serve k8s://
// pools with an unhealthy/unreachable API).
func TestServerStartFailsOnK8sSyncError(t *testing.T) {
	cfg := config.FailingK8sConfigForTest()
	_, err := NewServer(cfg, ":0", Options{Logger: discardLogger()})
	if err == nil {
		t.Fatal("expected NewServer to fail when k8s caches don't sync")
	}
}

// waitFor polls cond until true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

func TestSizeAndHostSelection(t *testing.T) {
	// parseSize sanity is covered in config; here verify wildcard host selection.
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "z")
	})
	body := `a.example.com, *.cdn.example.com {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	for _, host := range []string{"a.example.com", "img.cdn.example.com"} {
		req := httptest.NewRequest("GET", "http://"+host+"/x", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("host %q: code %d", host, rec.Code)
		}
	}
}

// doBody performs one request against the handler with a request body and returns
// the recorder. It mirrors do but supplies a body io.Reader (and Content-Length).
func doBody(h *Handler, method, target, body string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "test.local"
	if hdr != nil {
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPassForwardsRequestBody guards the P0 correctness fix end-to-end: a `pass`'d
// POST carrying a body must reach the origin with the FULL body intact. cadish used
// to forward a nil body to the origin, so a write proxied through it arrived empty.
func TestPassForwardsRequestBody(t *testing.T) {
	const payload = "name=cadish&kind=reverse-proxy&n=42"
	var (
		gotBody   atomic.Value
		gotMethod atomic.Value
		gotLen    atomic.Int64
	)
	gotBody.Store("")
	gotMethod.Store("")
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody.Store(string(b))
		gotMethod.Store(r.Method)
		gotLen.Store(r.ContentLength)
		_, _ = io.WriteString(w, "stored")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@api path /api/*
	pass @api
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	rec := doBody(h, "POST", "http://test.local/api/submit", payload, nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if m := gotMethod.Load().(string); m != "POST" {
		t.Fatalf("origin method = %q, want POST", m)
	}
	if got := gotBody.Load().(string); got != payload {
		t.Fatalf("origin body = %q, want %q (body was dropped)", got, payload)
	}
	if gotLen.Load() != int64(len(payload)) {
		t.Fatalf("origin Content-Length = %d, want %d", gotLen.Load(), len(payload))
	}
}
