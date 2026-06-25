package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/metrics"
)

// fakeLive is a stand-in LiveSource so admin tests need no real server.
type fakeLive struct{ sites []SiteState }

func (f fakeLive) LiveState() []SiteState { return f.sites }

// fakeIngress is a stand-in IngressSource so admin tests need no real controller.
type fakeIngress struct {
	stats   IngressStats
	present bool
}

func (f fakeIngress) IngressStats() (IngressStats, bool) { return f.stats, f.present }

func newTestServer(t *testing.T) (*Server, *metrics.Metrics) {
	t.Helper()
	// A minimal Cadishfile on disk for the /api/config view.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Cadishfile")
	src := "example.com {\n  @img path /img/*\n  cache_key url host\n  strip_cookies @img\n}\n"
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret", Metrics: true}
	live := fakeLive{sites: []SiteState{{
		Name: "example.com", Addresses: []string{"example.com"},
		Cache: CacheStats{RAMObjects: 3, RAMBytes: 1024, RAMMaxBytes: 4096},
	}}}
	return New(ac, m, live, nil, nil, cfgPath), m
}

func do(t *testing.T, srv *Server, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

func TestAuthRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/metrics", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", rec.Code)
	}
	rec = do(t, srv, "GET", "/api/metrics", "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d, want 401", rec.Code)
	}
	rec = do(t, srv, "GET", "/api/metrics", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("good token: status %d, want 200", rec.Code)
	}
}

// The admin token must NEVER be accepted via the query string: a ?token= value
// leaks into access logs, browser history and the Referer header. Only the
// Authorization header is honoured.
func TestTokenViaQueryRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/metrics?token=secret", nil) // no Authorization header
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("query-string token must be rejected: status %d, want 401", rec.Code)
	}
}

// The SPA shell at GET / is the login page (no secrets, no live data), so it is
// served without a token — that is what lets a browser load the dashboard without
// ever putting the token in a URL. Data endpoints stay gated (TestAuthRequired).
func TestIndexPublicNoToken(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/", "") // no token
	if rec.Code != http.StatusOK {
		t.Fatalf("index without token: status %d, want 200 (public login shell)", rec.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv, m := newTestServer(t)
	m.IncRequest()
	m.RecordCacheStatus("HIT")
	m.RecordCacheStatus("HIT")
	m.RecordCacheStatus("MISS")

	rec := do(t, srv, "GET", "/api/metrics", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var v metricsView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if v.Snapshot.Hits != 2 {
		t.Errorf("Hits = %d, want 2", v.Snapshot.Hits)
	}
	if v.HitRatio < 0.66 || v.HitRatio > 0.67 {
		t.Errorf("HitRatio = %v, want ~0.666", v.HitRatio)
	}
}

// The /api/metrics JSON carries the WAF v1 security + rate_limit counters so the
// dashboard's Security panel can render them.
func TestMetricsEndpointSecurityCounters(t *testing.T) {
	srv, m := newTestServer(t)
	m.RecordSecurity("allow", "office")
	m.RecordSecurity("deny", "scanners")
	m.RecordSecurity("deny", "scanners")
	m.RecordSecurity("monitor", "ru_cn")
	m.RecordRateLimit("throttle", "api")
	m.RecordRateLimit("monitor", "api")
	m.RecordRateLimit("pass", "api")

	rec := do(t, srv, "GET", "/api/metrics", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var v metricsView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	s := v.Snapshot
	if s.SecurityAllow != 1 || s.SecurityDeny != 2 || s.SecurityMonitor != 1 {
		t.Errorf("security counters = allow %d deny %d monitor %d, want 1/2/1", s.SecurityAllow, s.SecurityDeny, s.SecurityMonitor)
	}
	if s.RateLimitThrottle != 1 || s.RateLimitMonitor != 1 || s.RateLimitPass != 1 {
		t.Errorf("rate_limit counters = throttle %d monitor %d pass %d, want 1/1/1", s.RateLimitThrottle, s.RateLimitMonitor, s.RateLimitPass)
	}
}

// The dashboard HTML embeds the Security panel + its render hook.
func TestIndexHasSecurityPanel(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/", "secret")
	body := rec.Body.String()
	for _, want := range []string{`id="security"`, "renderSecurity", "rate_limit_throttle", "security_deny"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard HTML missing %q", want)
		}
	}
}

func TestConfigEndpointReusesCheck(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/config", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var report struct {
		Sites []struct {
			Addresses      []string `json:"addresses"`
			MatcherCount   int      `json:"matcher_count"`
			DirectiveCount int      `json:"directive_count"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if len(report.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(report.Sites))
	}
	if report.Sites[0].MatcherCount < 1 {
		t.Errorf("matcher_count = %d, want >=1", report.Sites[0].MatcherCount)
	}
}

func TestLiveEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/live", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var v struct {
		Sites []SiteState `json:"sites"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(v.Sites) != 1 || v.Sites[0].Name != "example.com" {
		t.Fatalf("sites = %+v", v.Sites)
	}
	if v.Sites[0].Cache.RAMBytes != 1024 {
		t.Errorf("RAMBytes = %d, want 1024", v.Sites[0].Cache.RAMBytes)
	}
}

// When an IngressSource is wired, /api/ingress carries the controller's reconcile
// stats and the SSE frame includes an "ingress" object.
func TestIngressEndpointPresent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(cfgPath, []byte("example.com {\n  cache_key url\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret"}
	ing := fakeIngress{present: true, stats: IngressStats{
		WatchedIngresses: 7, LastAppliedHash: "deadbeefcafef00d", Rejects: 2,
		LastError: "boom", IsLeader: true,
	}}
	srv := New(ac, metrics.New(), fakeLive{}, ing, nil, cfgPath)

	rec := do(t, srv, "GET", "/api/ingress", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var v struct {
		Present bool         `json:"present"`
		Ingress IngressStats `json:"ingress"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if !v.Present {
		t.Fatal("present = false, want true")
	}
	if v.Ingress.WatchedIngresses != 7 || v.Ingress.LastAppliedHash != "deadbeefcafef00d" ||
		v.Ingress.Rejects != 2 || v.Ingress.LastError != "boom" || !v.Ingress.IsLeader {
		t.Errorf("ingress stats = %+v", v.Ingress)
	}

	// The SSE stream payload carries the same data so the once-a-second tiles refresh.
	pay := srv.streamPayload()
	st, ok := pay["ingress"].(IngressStats)
	if !ok {
		t.Fatalf("stream payload ingress = %T, want IngressStats", pay["ingress"])
	}
	if st.WatchedIngresses != 7 {
		t.Errorf("stream ingress watched = %d, want 7", st.WatchedIngresses)
	}
}

// With no IngressSource (plain `cadish run`), /api/ingress reports present:false and the
// SSE frame omits the "ingress" key, so the dashboard never shows the panel.
func TestIngressEndpointAbsent(t *testing.T) {
	srv, _ := newTestServer(t) // newTestServer wires no IngressSource
	rec := do(t, srv, "GET", "/api/ingress", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var v struct {
		Present bool `json:"present"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Present {
		t.Fatal("present = true, want false (no ingress source)")
	}
	if _, ok := srv.streamPayload()["ingress"]; ok {
		t.Fatal("stream payload includes ingress key with no source")
	}
}

// The controller's last_error can carry attacker-influenced text (a malformed
// cadi.sh/policy fragment or Ingress object surfaced in a render/apply error). The
// JSON API carries it RAW (the SPA escapes at render); guard that the embedded dashboard
// routes both the ingress error and the config error through escapeHtml before innerHTML,
// so a stored-XSS regression in the token-gated admin panel is caught.
func TestIngressErrorEscapedInDashboard(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(cfgPath, []byte("example.com {\n  cache_key url\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret"}
	const raw = `<img src=x onerror=alert(1)>`
	ing := fakeIngress{present: true, stats: IngressStats{LastError: raw}}
	srv := New(ac, metrics.New(), fakeLive{}, ing, nil, cfgPath)

	// (1) the JSON API preserves the error text (decoded value is the original); Go's
	// encoder escapes <>& to \uXXXX in transport, so the raw markup never appears literally
	// in the body — but the SPA must still escape it at render (defense in depth).
	rec := do(t, srv, "GET", "/api/ingress", "secret")
	if strings.Contains(rec.Body.String(), "<img") {
		t.Errorf("JSON body should not carry literal HTML markup (encoder must escape it):\n%s", rec.Body.String())
	}
	var got struct {
		Ingress IngressStats `json:"ingress"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Ingress.LastError != raw {
		t.Errorf("decoded LastError = %q, want %q", got.Ingress.LastError, raw)
	}

	// (2) the embedded SPA routes error text through escapeHtml before innerHTML.
	rec = do(t, srv, "GET", "/", "secret")
	body := rec.Body.String()
	for _, want := range []string{"escapeHtml(ing.last_error", "escapeHtml(report.error"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard must escape error text before innerHTML; missing %q", want)
		}
	}
}

// The dashboard HTML embeds the Kubernetes Ingress panel + its render hook.
func TestIndexHasIngressPanel(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/", "secret")
	body := rec.Body.String()
	for _, want := range []string{`id="ingress"`, "renderIngress", "watched_ingresses", "last_applied_hash"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard HTML missing %q", want)
		}
	}
}

func TestPrometheusEndpoint(t *testing.T) {
	srv, m := newTestServer(t)
	m.IncRequest()
	m.RecordCacheStatus("HIT")
	m.RecordSecurity("deny", "scanners")
	m.RecordRateLimit("throttle", "api")
	rec := do(t, srv, "GET", "/metrics", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"cadish_requests_total 1",
		"cadish_cache_hits_total 1",
		"cadish_security_deny_total 1",
		"cadish_rate_limit_throttle_total 1",
		"# TYPE cadish_request_latency_ms histogram",
		"cadish_request_latency_ms_bucket{le=\"+Inf\"}",
		"cadish_cache_ram_bytes{site=\"example.com\"} 1024",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("prometheus output missing %q\n---\n%s", want, body)
		}
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

// When the admin block does not enable metrics, /metrics is not registered.
func TestPrometheusDisabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Cadishfile")
	_ = os.WriteFile(cfgPath, []byte("example.com {\n  cache_key url\n}\n"), 0o644)
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret", Metrics: false}
	srv := New(ac, metrics.New(), fakeLive{}, nil, nil, cfgPath)
	rec := do(t, srv, "GET", "/metrics", "secret")
	// Without the route, the SPA shell (index) catches it -> 200 HTML, not the
	// prometheus text. Assert it is NOT the prometheus body.
	if strings.Contains(rec.Body.String(), "cadish_requests_total") {
		t.Fatal("/metrics served prometheus output despite metrics disabled")
	}
}

func TestIndexServed(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "command center") {
		t.Errorf("index missing expected content:\n%s", rec.Body.String()[:min(200, len(rec.Body.String()))])
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestXSSEscapeHtmlSinks reads the embedded dashboard source and asserts that every
// server-derived string sink that was previously unescaped is now wrapped in escapeHtml.
// This is a regression guard: if someone removes an escapeHtml wrapper from one of
// the known-dangerous interpolations the test fails immediately at CI time.
func TestXSSEscapeHtmlSinks(t *testing.T) {
	src, err := os.ReadFile("ui/index.html")
	if err != nil {
		t.Fatalf("cannot read ui/index.html: %v", err)
	}
	html := string(src)

	// Each entry is [description, must-contain substring].
	// The must-contain strings are the escaped forms of previously-bare interpolations.
	mustContain := []struct {
		desc, want string
	}{
		// renderSites: site name
		{"renderSites site name escaped", "escapeHtml(s.name"},
		// renderUpstreams: pool name and policy
		{"renderUpstreams pool name escaped", "escapeHtml(u.name)"},
		{"renderUpstreams policy escaped", "escapeHtml(u.policy)"},
		// renderUpstreams: backend base_url
		{"renderUpstreams backend base_url escaped", "escapeHtml(b.base_url)"},
		// renderConfig: site addresses joined string
		{"renderConfig site addresses escaped", "escapeHtml((site.addresses||[]).join(\", \")"},
		// renderConfig: suggestion strings
		{"renderConfig suggestions escaped", "escapeHtml(s)"},
		// renderConfig: phase-count keys
		{"renderConfig phase key escaped", "escapeHtml(p)"},
		// renderIngress: last_applied_hash
		{"renderIngress last_applied_hash escaped", "escapeHtml(ing.last_applied_hash"},
	}

	for _, tc := range mustContain {
		if !strings.Contains(html, tc.want) {
			t.Errorf("XSS regression [%s]: ui/index.html does not contain %q", tc.desc, tc.want)
		}
	}

	// Also assert the previously-bare sinks no longer appear without escapeHtml wrapping.
	// We check that the raw unescaped patterns (as they were before the fix) are absent.
	// mustNotContain checks that the previously-bare server-data sinks are gone.
	// Note: renderPgReport (the playground renderer) operates on user-typed config and
	// legitimately keeps its own phase-key interpolation; we do NOT check for ${p}: here
	// because that would be a false positive against the playground renderer.
	mustNotContain := []struct {
		desc, bad string
	}{
		// renderSites name was: ${s.name||"—"} (bare)
		{"renderSites bare name", "${s.name||\"—\"}"},
		// renderUpstreams pool name was: ${u.name} (bare)
		{"renderUpstreams bare pool name", "${u.name}"},
		// renderUpstreams backend base_url was: ${b.base_url} (bare)
		{"renderUpstreams bare base_url", "${b.base_url}"},
		// renderConfig addresses was: ${(site.addresses||[]).join(", ")||"(top-level)"} (bare)
		{"renderConfig bare addresses", "${(site.addresses||[]).join(\", \")||\"(top-level)\"}"},
		// renderConfig suggestion was: ▸ ${s}</div> (bare — note escapeHtml wraps s now)
		{"renderConfig bare suggestion", "▸ ${s}</div>"},
	}

	for _, tc := range mustNotContain {
		if strings.Contains(html, tc.bad) {
			t.Errorf("XSS regression [%s]: ui/index.html still contains unescaped sink %q", tc.desc, tc.bad)
		}
	}
}

// TestConfigEndpointPathRedacted verifies that the /api/config JSON response
// does NOT expose the absolute on-disk Cadishfile path. The Path field must be
// just the filename (e.g. "Cadishfile"), not an absolute dir. Any Diagnostic
// Position strings must not begin with a "/" directory prefix — they should be
// "Cadishfile:line:col" rather than "/abs/path/Cadishfile:line:col".
// This is the fix for #16: minor host-layout disclosure to any token holder.
func TestConfigEndpointPathRedacted(t *testing.T) {
	// Build a config that generates at least one diagnostic with a position so we
	// can assert Position stripping too.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Cadishfile")
	src := "example.com {\n  cache_key url host\n}\n"
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret"}
	srv := New(ac, metrics.New(), fakeLive{}, nil, nil, cfgPath)

	rec := do(t, srv, "GET", "/api/config", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d\nbody: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// The absolute directory must NOT appear in the response at all.
	if strings.Contains(body, dir) {
		t.Errorf("/api/config response contains absolute directory %q:\n%s", dir, body)
	}

	// The Path field must be just the filename.
	var report struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if report.Path != "Cadishfile" {
		t.Errorf("report.Path = %q, want bare filename %q", report.Path, "Cadishfile")
	}
	if strings.Contains(report.Path, "/") || strings.Contains(report.Path, "\\") {
		t.Errorf("report.Path contains a directory separator: %q", report.Path)
	}
}

// TestConfigEndpointErrorPathStripped verifies that when /api/config fails to load
// (e.g. the Cadishfile is missing or unreadable), the error JSON does NOT disclose
// the absolute on-disk path. The error string must not contain the directory prefix.
func TestConfigEndpointErrorPathStripped(t *testing.T) {
	dir := t.TempDir()
	// Point cfgPath at a non-existent file so check.Check returns an os.ErrNotExist
	// error whose message includes the absolute path — this triggers the error branch.
	cfgPath := filepath.Join(dir, "Cadishfile")
	// Do NOT write the file; check.Check will fail with "open /abs/path/Cadishfile: no such file".

	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret"}
	srv := New(ac, metrics.New(), fakeLive{}, nil, nil, cfgPath)

	rec := do(t, srv, "GET", "/api/config", "secret")
	body := rec.Body.String()

	// The absolute directory must NOT appear in the error message.
	if strings.Contains(body, dir) {
		t.Errorf("/api/config error response contains absolute directory %q:\n%s", dir, body)
	}
	// Must be an error response.
	if !strings.Contains(body, "error") {
		t.Errorf("/api/config error response does not contain 'error' key:\n%s", body)
	}
}

func TestStreamEmitsFrame(t *testing.T) {
	srv, m := newTestServer(t)
	m.IncRequest()

	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	// Read just the first SSE frame (terminated by a blank line).
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	frame := string(buf[:n])
	if !strings.HasPrefix(strings.TrimSpace(frame), "data:") {
		t.Fatalf("stream did not emit an SSE frame: %q", frame)
	}
	if !strings.Contains(frame, "\"metrics\"") {
		t.Errorf("stream frame missing metrics payload: %q", frame)
	}
}
