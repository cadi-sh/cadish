// Package e2e drives the storefront migration fixture through the real
// server.Handler (config.Load -> server.NewHandler) against httptest origins,
// asserting the behavioral golden cases from
// test/migration/storefront/golden_cases.md that are observable over HTTP.
//
// It deliberately lives in its own package and only consumes internal/config and
// internal/server through their public APIs — it never edits them.
package e2e

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/server"
)

// fixedNow is a frozen clock so TTL/grace never expire mid-test (everything
// stored stays fresh), making HIT/MISS deterministic.
var fixedNow = time.Unix(1_700_000_000, 0)

// testOrigin is an httptest upstream that counts hits per path and can return
// special statuses for designated paths. It sets a Server header and a Set-Cookie
// so header-removal and cookie-stripping are observable.
type testOrigin struct {
	srv      *httptest.Server
	mu       sync.Mutex
	hits     map[string]int
	lastHost string // the Host header the upstream last received (backlog #11)
}

func newTestOrigin(t *testing.T) *testOrigin {
	t.Helper()
	o := &testOrigin{hits: map[string]int{}}
	o.srv = httptest.NewServer(http.HandlerFunc(o.serve))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *testOrigin) serve(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.hits[r.URL.Path]++
	o.lastHost = r.Host
	o.mu.Unlock()

	w.Header().Set("Server", "test-origin")
	switch r.URL.Path {
	case "/boom":
		w.WriteHeader(http.StatusBadGateway)
		return
	case "/redir":
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusMovedPermanently)
		return
	case "/gone":
		w.WriteHeader(http.StatusNotFound)
		return
	case "/gone410":
		w.WriteHeader(http.StatusGone)
		return
	}

	ct := "text/html; charset=utf-8"
	switch {
	case strings.HasSuffix(r.URL.Path, ".css"):
		ct = "text/css"
	case strings.HasSuffix(r.URL.Path, ".jpg"):
		ct = "image/jpeg"
	}
	body := bodyFor(r.URL.Path)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Set-Cookie", "sess=abc; Path=/")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

func (o *testOrigin) host() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastHost
}

func (o *testOrigin) count(path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hits[path]
}

func (o *testOrigin) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, v := range o.hits {
		n += v
	}
	return n
}

func bodyFor(p string) string {
	if p == "/data" {
		return "abcdefghijklmnopqrstuvwxyz"
	}
	return "BODY:" + p
}

// harness bundles the handler and the two origins.
type harness struct {
	h   *server.Handler
	web *testOrigin
	img *testOrigin
}

func setup(t *testing.T) *harness {
	t.Helper()
	web := newTestOrigin(t)
	img := newTestOrigin(t)
	t.Setenv("TEST_WEB_ORIGIN", web.srv.URL)
	t.Setenv("TEST_IMAGES_ORIGIN", img.srv.URL)
	t.Setenv("PURGE_TOKEN", "topsecret")

	cfg, err := config.Load("testdata/storefront.Cadishfile")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })

	h := server.NewHandler(cfg, server.Options{
		Now:    func() time.Time { return fixedNow },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &harness{h: h, web: web, img: img}
}

// req drives one request through the handler and returns the recorder.
func (hh *harness) req(t *testing.T, method, url string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, url, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	hh.h.ServeHTTP(rec, r)
	return rec
}

func (hh *harness) get(t *testing.T, url string) *httptest.ResponseRecorder {
	return hh.req(t, http.MethodGet, url, nil)
}

const base = "http://example.com"

// ---- golden cases ----

// Case 1, 19: a normal page caches — MISS then HIT, origin hit exactly once.
func TestCacheableMissThenHit(t *testing.T) {
	hh := setup(t)
	r1 := hh.get(t, base+"/article")
	if r1.Code != 200 || r1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first: code=%d X-Cache=%q", r1.Code, r1.Header().Get("X-Cache"))
	}
	if got := r1.Body.String(); got != "BODY:/article" {
		t.Fatalf("body=%q", got)
	}
	r2 := hh.get(t, base+"/article")
	if r2.Code != 200 || r2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second: code=%d X-Cache=%q", r2.Code, r2.Header().Get("X-Cache"))
	}
	if n := hh.web.count("/article"); n != 1 {
		t.Errorf("origin hits=%d, want 1 (second served from cache)", n)
	}
}

// Cases 2-3: /panel/ (and other @nocache paths) bypass the cache on every request.
func TestNocachePathsPass(t *testing.T) {
	hh := setup(t)
	for _, p := range []string{"/panel/x", "/private/secret", "/publish/ad", "/media/image_server.php", "/sitemap.xml"} {
		hh.get(t, base+p)
		hh.get(t, base+p)
		if n := hh.web.count(p); n != 2 {
			t.Errorf("%s origin hits=%d, want 2 (pass = never cached)", p, n)
		}
	}
}

// Case 7: POST bypasses the cache even for an otherwise-cacheable path.
func TestPostPasses(t *testing.T) {
	hh := setup(t)
	hh.get(t, base+"/article") // cache it
	hh.req(t, http.MethodPost, base+"/article", nil)
	hh.req(t, http.MethodPost, base+"/article", nil)
	// 1 GET miss + 2 POSTs all hit origin.
	if n := hh.web.count("/article"); n != 3 {
		t.Errorf("origin hits=%d, want 3 (GET miss + 2 POST pass)", n)
	}
}

// Case 8: an XHR (X-Requested-With) bypasses the cache.
func TestAjaxPasses(t *testing.T) {
	hh := setup(t)
	xhr := map[string]string{"X-Requested-With": "XMLHttpRequest"}
	hh.req(t, http.MethodGet, base+"/feed", xhr)
	hh.req(t, http.MethodGet, base+"/feed", xhr)
	if n := hh.web.count("/feed"); n != 2 {
		t.Errorf("origin hits=%d, want 2 (ajax = pass)", n)
	}
}

// Case 9-10: category listings ARE cached (not in @nocache).
func TestListingCached(t *testing.T) {
	hh := setup(t)
	r1 := hh.get(t, base+"/catalog/")
	r2 := hh.get(t, base+"/catalog/")
	if r1.Header().Get("X-Cache") != "MISS" || r2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("listing X-Cache: first=%q second=%q, want MISS then HIT",
			r1.Header().Get("X-Cache"), r2.Header().Get("X-Cache"))
	}
	if n := hh.web.count("/catalog/"); n != 1 {
		t.Errorf("origin hits=%d, want 1", n)
	}
}

// Case 11: /health-check is a synthetic 200 "OK" — origin is never touched.
func TestHealthCheckSynthetic(t *testing.T) {
	hh := setup(t)
	r := hh.get(t, base+"/health-check")
	if r.Code != 200 || strings.TrimSpace(r.Body.String()) != "OK" {
		t.Errorf("health-check: code=%d body=%q, want 200 OK", r.Code, r.Body.String())
	}
	if n := hh.web.total() + hh.img.total(); n != 0 {
		t.Errorf("origin touched %d times for synthetic route, want 0", n)
	}
}

// Case 16: a static.* host routes to the images origin (not web) and is cached.
func TestStaticRoutesToImages(t *testing.T) {
	hh := setup(t)
	const u = "http://static.example.com/photo.jpg"
	r1 := hh.get(t, u)
	r2 := hh.get(t, u)
	if r1.Code != 200 || r1.Header().Get("X-Cache") != "MISS" || r2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("static: r1=%d/%s r2=%s", r1.Code, r1.Header().Get("X-Cache"), r2.Header().Get("X-Cache"))
	}
	if n := hh.img.count("/photo.jpg"); n != 1 {
		t.Errorf("images origin hits=%d, want 1", n)
	}
	if n := hh.web.count("/photo.jpg"); n != 0 {
		t.Errorf("web origin hits=%d, want 0 (routed to images)", n)
	}
}

// Case 20: a 404 from origin is surfaced to the client.
func TestNotFoundPassthrough(t *testing.T) {
	hh := setup(t)
	r := hh.get(t, base+"/gone")
	if r.Code != http.StatusNotFound {
		t.Errorf("code=%d, want 404", r.Code)
	}
}

// Case 22: a non-200 (502) is surfaced and not cached (subsequent requests still
// reach origin — the bad response never poisons the key).
func TestUpstream5xxNotCached(t *testing.T) {
	hh := setup(t)
	r := hh.get(t, base+"/boom")
	if r.Code != http.StatusBadGateway {
		t.Errorf("code=%d, want 502", r.Code)
	}
	hh.get(t, base+"/boom")
	if n := hh.web.count("/boom"); n < 2 {
		t.Errorf("origin hits=%d, want >=2 (502 not cached)", n)
	}
}

// Case 23: negative caching — a 404/410 with a `cache_ttl status 404 410 ttl 60s
// grace 1h` rule is stored (with its real body+headers, backlog #21) and served
// from cache, so a deleted object's negative status is not re-fetched from origin
// on every request. (These origin responses carry no body; the full-body path is
// pinned in internal/server.TestFullBodyNegativeCaching.)
func TestNegativeCaching(t *testing.T) {
	hh := setup(t)

	// 404 is negatively cached: the second request is a cache HIT, origin seen once.
	r1 := hh.get(t, base+"/gone")
	r2 := hh.get(t, base+"/gone")
	if r1.Code != http.StatusNotFound || r2.Code != http.StatusNotFound {
		t.Errorf("/gone codes: r1=%d r2=%d, want 404/404", r1.Code, r2.Code)
	}
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("/gone second X-Cache=%q, want HIT (negative hit)", got)
	}
	if n := hh.web.count("/gone"); n != 1 {
		t.Errorf("/gone origin hits=%d, want 1 (404 negatively cached)", n)
	}

	// 410 (Gone) is cached the same way.
	g1 := hh.get(t, base+"/gone410")
	g2 := hh.get(t, base+"/gone410")
	if g1.Code != http.StatusGone || g2.Code != http.StatusGone {
		t.Errorf("/gone410 codes: g1=%d g2=%d, want 410/410", g1.Code, g2.Code)
	}
	if n := hh.web.count("/gone410"); n != 1 {
		t.Errorf("/gone410 origin hits=%d, want 1 (410 negatively cached)", n)
	}
}

// Case 26: deliver headers — X-Cache emitted, debug headers removed, CORS +
// X-Frame-Options added.
func TestDeliverHeaders(t *testing.T) {
	hh := setup(t)
	r := hh.get(t, base+"/article")
	if got := r.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache=%q, want MISS", got)
	}
	if got := r.Header().Get("Server"); got != "" {
		t.Errorf("Server=%q, want removed", got)
	}
	if got := r.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO=%q, want *", got)
	}
	if got := r.Header().Get("Access-Control-Allow-Methods"); got != "GET, OPTIONS, POST" {
		t.Errorf("ACAM=%q", got)
	}
	if got := r.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("XFO=%q, want SAMEORIGIN", got)
	}
}

// Cases 27-28: cookie stripping on the CACHED classes (strip_cookies @cacheable); a
// PASS class keeps its cookie. The origin stamps Set-Cookie on every response: a
// cacheable page drops it (controlled → cacheable), a passed page preserves it.
func TestCookieStripping(t *testing.T) {
	hh := setup(t)
	// A static asset is cached -> the origin's Set-Cookie is stripped.
	css := hh.get(t, base+"/style.css")
	if got := css.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("/style.css Set-Cookie=%q, want stripped (cached class)", got)
	}
	// A normal article page is ALSO cached now -> stripped (this is what lets it cache:
	// a Set-Cookie response is never stored unless the cookie is controlled/stripped).
	article := hh.get(t, base+"/article")
	if got := article.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("/article Set-Cookie=%q, want stripped (cached class)", got)
	}
	// A PASS path (@nocache) is NOT cached and keeps its Set-Cookie intact — the cookie
	// is only stripped on the cacheable classes, never on bypassed traffic.
	panel := hh.get(t, base+"/panel/x")
	if got := panel.Header().Get("Set-Cookie"); got == "" {
		t.Errorf("/panel/x Set-Cookie was stripped, want preserved (pass class)")
	}
}

// Case 30 (gap #4): the `header @longcache Cache-Control …` rule scopes on the
// RESPONSE Content-Type via a content_type matcher, so a text/css response gets
// the long immutable Cache-Control while a text/html one does not. (Previously
// the rule matched the request PATH against "image/svg|text/css" and never
// fired.)
func TestContentTypeCacheControl(t *testing.T) {
	hh := setup(t)
	const want = "public, max-age=31536000"

	css := hh.get(t, base+"/style.css") // origin sets Content-Type: text/css
	if got := css.Header().Get("Cache-Control"); got != want {
		t.Errorf("/style.css Cache-Control=%q, want %q (content_type matched)", got, want)
	}

	html := hh.get(t, base+"/article") // text/html
	if got := html.Header().Get("Cache-Control"); got == want {
		t.Errorf("/article Cache-Control=%q, want it unset (content_type should not match text/html)", got)
	}
}

// Range request served from cache returns 206 with the correct slice.
func TestRangeFromCache(t *testing.T) {
	hh := setup(t)
	hh.get(t, base+"/data") // populate cache (26-byte body)
	r := hh.req(t, http.MethodGet, base+"/data", map[string]string{"Range": "bytes=2-5"})
	if r.Code != http.StatusPartialContent {
		t.Fatalf("code=%d, want 206", r.Code)
	}
	if got := r.Header().Get("Content-Range"); got != "bytes 2-5/26" {
		t.Errorf("Content-Range=%q, want bytes 2-5/26", got)
	}
	if got := r.Body.String(); got != "cdef" {
		t.Errorf("body=%q, want cdef", got)
	}
	if n := hh.web.count("/data"); n != 1 {
		t.Errorf("origin hits=%d, want 1 (range served from cache)", n)
	}
}

// Cases 12-13: a correct purge token invalidates (next GET revalidates); a wrong
// token does not.
func TestPurgeTokenGuarded(t *testing.T) {
	hh := setup(t)
	tok := func(v string) map[string]string { return map[string]string{"X-Purge-Token": v} }

	hh.get(t, base+"/purgeme") // miss -> cache (web hits=1)
	if hh.get(t, base+"/purgeme").Header().Get("X-Cache") != "HIT" {
		t.Fatal("expected HIT after caching")
	}

	// Wrong token: the PURGE is NOT authorized as a cadish purge directive, so it is
	// not served from cache (the method-less `cache_key url host` + unsafe-method SERVE
	// guard route it to origin). The test origin answers it with a 200 — and a
	// SUCCESSFUL unsafe-method response invalidates the sibling GET entry per RFC 9111
	// §4.4. So this unauthorized PURGE, treated as a plain unsafe write that the origin
	// accepted, DOES invalidate the cached GET: the FOLLOWING GET re-fetches (MISS).
	// (An origin that rejected the unauthorized write with a 4xx would leave the cache
	// intact — §4.4 invalidates only on success.)
	hh.req(t, "PURGE", base+"/purgeme", tok("wrong"))
	if n := hh.web.count("/purgeme"); n != 2 {
		t.Errorf("origin hits=%d after wrong-token purge, want 2 (unsafe method routed to origin, not served from cache)", n)
	}
	if got := hh.get(t, base+"/purgeme").Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("X-Cache=%q after wrong-token purge, want MISS (§4.4: origin's 200 to the unsafe PURGE invalidated the entry)", got)
	}
	if n := hh.web.count("/purgeme"); n != 3 {
		t.Errorf("origin hits=%d after wrong-token purge + GET, want 3 (§4.4 invalidation re-fetched)", n)
	}

	// Correct token: an AUTHORIZED cadish purge -> next GET revalidates from origin.
	// (The GET above re-warmed the cache to hits=3; the purge forgets it; the GET after
	// re-fetches to hits=4.)
	pr := hh.req(t, "PURGE", base+"/purgeme", tok("topsecret"))
	if pr.Code != http.StatusOK {
		t.Errorf("purge code=%d, want 200", pr.Code)
	}
	hh.get(t, base+"/purgeme")
	if n := hh.web.count("/purgeme"); n != 4 {
		t.Errorf("origin hits=%d after correct-token purge + GET, want 4 (revalidated)", n)
	}
}

// TestHostHeaderForwardedByDefault verifies the staging-POC fix (backlog #11):
// with no host_header directive (default = preserve), the upstream receives the
// CLIENT's Host (example.com), not the internal upstream host:port. This is what
// stops a WordPress / name-based vhost from canonical-301'ing the homepage.
func TestHostHeaderForwardedByDefault(t *testing.T) {
	hh := setup(t)
	if r := hh.get(t, base+"/article"); r.Code != http.StatusOK {
		t.Fatalf("GET /article code=%d, want 200", r.Code)
	}
	if got := hh.web.host(); got != "example.com" {
		t.Fatalf("upstream Host = %q, want client host %q (default host_header = preserve)", got, "example.com")
	}
}
