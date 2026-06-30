package edgedeploy

import (
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockCF is a minimal Cloudflare API stand-in: it records requests and returns
// canned v4 envelopes per (method, path-prefix). Tests inspect recorded.
type mockCF struct {
	t        *testing.T
	requests []recordedReq
	// kvNamespaces is the list returned by GET …/storage/kv/namespaces.
	kvNamespaces []kvNamespace
	// routes is the list returned by GET …/workers/routes.
	routes []workerRoute
}

type recordedReq struct {
	method string
	path   string
	body   []byte
}

func (m *mockCF) ok(w http.ResponseWriter, result any) {
	raw, _ := json.Marshal(result)
	_ = json.NewEncoder(w).Encode(apiResponse{Success: true, Result: raw})
}

func (m *mockCF) fail(w http.ResponseWriter, code int, msg string) {
	_ = json.NewEncoder(w).Encode(apiResponse{Success: false, Errors: []apiError{{Code: code, Message: msg}}})
}

func (m *mockCF) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.requests = append(m.requests, recordedReq{method: r.Method, path: r.URL.Path + queryOf(r), body: body})
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			m.fail(w, 10000, "bad auth: "+got)
			return
		}
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/storage/kv/namespaces") && r.Method == http.MethodGet:
			m.ok(w, m.kvNamespaces)
		case strings.HasSuffix(p, "/storage/kv/namespaces") && r.Method == http.MethodPost:
			m.ok(w, kvNamespace{ID: "ns-created", Title: "EDGE_CACHE"})
		case strings.Contains(p, "/workers/scripts/") && r.Method == http.MethodPut:
			m.ok(w, map[string]string{"id": "cadish-edge-example"})
		case p == "/zones" && r.Method == http.MethodGet:
			m.ok(w, []zone{{ID: "zone-abc", Name: "example.com"}})
		case strings.HasSuffix(p, "/workers/routes") && r.Method == http.MethodGet:
			m.ok(w, m.routes)
		case strings.HasSuffix(p, "/workers/routes") && r.Method == http.MethodPost:
			m.ok(w, workerRoute{ID: "route-new"})
		case strings.Contains(p, "/workers/routes/") && r.Method == http.MethodDelete:
			m.ok(w, map[string]string{"id": "deleted"})
		default:
			m.fail(w, 404, "unhandled "+r.Method+" "+p)
		}
	})
}

func queryOf(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}

func newTestClient(t *testing.T, m *mockCF) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	c := New("test-token")
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()
	return c, srv
}

func (m *mockCF) find(method, pathContains string) *recordedReq {
	for i := range m.requests {
		if m.requests[i].method == method && strings.Contains(m.requests[i].path, pathContains) {
			return &m.requests[i]
		}
	}
	return nil
}

func (m *mockCF) count(method, pathContains string) int {
	n := 0
	for _, r := range m.requests {
		if r.method == method && strings.Contains(r.path, pathContains) {
			n++
		}
	}
	return n
}

func TestDeployUploadsScriptWithBindings(t *testing.T) {
	m := &mockCF{t: t} // empty KV list -> namespace gets created
	c, srv := newTestClient(t, m)
	defer srv.Close()

	cfg := Config{
		AccountID:   "acc-123",
		WorkerName:  "cadish-edge-example",
		KVNamespace: "EDGE_CACHE",
		OriginURL:   "https://cadish-behind.example.com",
		Upstreams:   map[string]string{"images": "https://img.example.com"},
	}
	if err := c.Deploy(context.Background(), cfg, "export default { fetch(){} }"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	// KV namespace was looked up then created (none existed).
	if m.count(http.MethodGet, "/storage/kv/namespaces") != 1 {
		t.Errorf("expected one KV list, got %d", m.count(http.MethodGet, "/storage/kv/namespaces"))
	}
	if m.count(http.MethodPost, "/storage/kv/namespaces") != 1 {
		t.Errorf("expected one KV create, got %d", m.count(http.MethodPost, "/storage/kv/namespaces"))
	}

	put := m.find(http.MethodPut, "/workers/scripts/cadish-edge-example")
	if put == nil {
		t.Fatal("script PUT not issued")
	}
	meta := parseUploadMetadata(t, put.body)
	if meta.MainModule != mainModule {
		t.Errorf("main_module = %q, want %q", meta.MainModule, mainModule)
	}
	got := map[string]binding{}
	for _, b := range meta.Bindings {
		got[b.Name] = b
	}
	if got["CADISH_ORIGIN"].Text != "https://cadish-behind.example.com" {
		t.Errorf("CADISH_ORIGIN binding = %+v", got["CADISH_ORIGIN"])
	}
	if got["CADISH_KV"].Type != "kv_namespace" || got["CADISH_KV"].NamespaceID != "ns-created" {
		t.Errorf("CADISH_KV binding = %+v", got["CADISH_KV"])
	}
	if !strings.Contains(got["CADISH_UPSTREAMS"].Text, "images") {
		t.Errorf("CADISH_UPSTREAMS binding = %+v", got["CADISH_UPSTREAMS"])
	}
}

func TestDeployReusesExistingKVNamespace(t *testing.T) {
	m := &mockCF{t: t, kvNamespaces: []kvNamespace{{ID: "ns-existing", Title: "EDGE_CACHE"}}}
	c, srv := newTestClient(t, m)
	defer srv.Close()

	cfg := Config{AccountID: "acc-123", WorkerName: "w", KVNamespace: "EDGE_CACHE"}
	if err := c.Deploy(context.Background(), cfg, "x"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if m.count(http.MethodPost, "/storage/kv/namespaces") != 0 {
		t.Error("must not create a KV namespace that already exists")
	}
	put := m.find(http.MethodPut, "/workers/scripts/")
	meta := parseUploadMetadata(t, put.body)
	for _, b := range meta.Bindings {
		if b.Name == "CADISH_KV" && b.NamespaceID != "ns-existing" {
			t.Errorf("CADISH_KV should bind the existing namespace id, got %q", b.NamespaceID)
		}
	}
}

func TestDeployNoKVWhenUnset(t *testing.T) {
	m := &mockCF{t: t}
	c, srv := newTestClient(t, m)
	defer srv.Close()
	cfg := Config{AccountID: "acc-123", WorkerName: "w", OriginURL: "https://o"}
	if err := c.Deploy(context.Background(), cfg, "x"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if m.count(http.MethodGet, "/storage/kv/namespaces") != 0 {
		t.Error("no KV configured: must not touch the KV API")
	}
}

func TestEnableAttachesMissingRoutesIdempotently(t *testing.T) {
	m := &mockCF{t: t, routes: []workerRoute{{ID: "r1", Pattern: "example.com/*", Script: "w"}}}
	c, srv := newTestClient(t, m)
	defer srv.Close()

	cfg := Config{Zone: "example.com", WorkerName: "w", Routes: []string{"example.com/*", "www.example.com/*"}}
	if err := c.Enable(context.Background(), cfg); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	// Zone resolved by name.
	if m.find(http.MethodGet, "/zones?name=example.com") == nil {
		t.Error("zone name was not resolved")
	}
	// Only the missing route is created (example.com/* already exists).
	if m.count(http.MethodPost, "/workers/routes") != 1 {
		t.Errorf("expected exactly one route create, got %d", m.count(http.MethodPost, "/workers/routes"))
	}
}

func TestDisableDetachesWorkerRoutes(t *testing.T) {
	m := &mockCF{t: t, routes: []workerRoute{
		{ID: "r1", Pattern: "example.com/*", Script: "w"},
		{ID: "r2", Pattern: "other.com/*", Script: "someone-else"},
	}}
	c, srv := newTestClient(t, m)
	defer srv.Close()

	cfg := Config{Zone: "0123456789abcdef0123456789abcdef", WorkerName: "w"} // 32-hex => used as id
	if err := c.Disable(context.Background(), cfg); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	// A 32-hex zone is used directly (no /zones lookup).
	if m.find(http.MethodGet, "/zones?name=") != nil {
		t.Error("a zone id must not be resolved via /zones")
	}
	// Only our worker's route is deleted.
	if m.count(http.MethodDelete, "/workers/routes/r1") != 1 {
		t.Error("worker route r1 should be deleted")
	}
	if m.count(http.MethodDelete, "/workers/routes/r2") != 0 {
		t.Error("another worker's route r2 must not be touched")
	}
}

// TestEnableCreatesNoScriptExclusionRoutes proves Enable attaches the worker routes
// AND creates a no-script (origin-direct) route per RouteExclusions pattern,
// idempotently (an already-present exclusion route is not recreated).
func TestEnableCreatesNoScriptExclusionRoutes(t *testing.T) {
	m := &mockCF{t: t, routes: []workerRoute{
		{ID: "r1", Pattern: "example.com/*", Script: "w"},        // worker route already present
		{ID: "x1", Pattern: "example.com/transmit*", Script: ""}, // one exclusion already present
	}}
	c, srv := newTestClient(t, m)
	defer srv.Close()

	cfg := Config{
		Zone:            "example.com",
		WorkerName:      "w",
		Routes:          []string{"example.com/*"},
		RouteExclusions: []string{"example.com/transmit*", "example.com/broadcast*"},
	}
	if err := c.Enable(context.Background(), cfg); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	// The worker route already exists → not recreated. The already-present exclusion is
	// left as-is; only the missing exclusion (broadcast) is created.
	if n := m.count(http.MethodPost, "/workers/routes"); n != 1 {
		t.Fatalf("expected exactly one route create (the missing exclusion), got %d", n)
	}
	created := lastRouteCreate(t, m)
	if created["pattern"] != "example.com/broadcast*" {
		t.Errorf("created route pattern = %q, want example.com/broadcast*", created["pattern"])
	}
	// A no-worker route must NOT carry a script field.
	if _, ok := created["script"]; ok {
		t.Errorf("an exclusion route must omit the script field, got %v", created)
	}
}

// TestDisableRemovesNoScriptExclusionRoutes proves Disable removes both the worker's
// routes and the no-script exclusion routes it created, but leaves an unrelated
// no-script route untouched. Idempotent.
func TestDisableRemovesNoScriptExclusionRoutes(t *testing.T) {
	m := &mockCF{t: t, routes: []workerRoute{
		{ID: "r1", Pattern: "example.com/*", Script: "w"},
		{ID: "x1", Pattern: "example.com/transmit*", Script: ""},  // ours (in RouteExclusions)
		{ID: "x2", Pattern: "example.com/unrelated*", Script: ""}, // someone else's no-script route
	}}
	c, srv := newTestClient(t, m)
	defer srv.Close()

	cfg := Config{
		Zone:            "0123456789abcdef0123456789abcdef",
		WorkerName:      "w",
		RouteExclusions: []string{"example.com/transmit*"},
	}
	if err := c.Disable(context.Background(), cfg); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if m.count(http.MethodDelete, "/workers/routes/r1") != 1 {
		t.Error("worker route r1 should be deleted")
	}
	if m.count(http.MethodDelete, "/workers/routes/x1") != 1 {
		t.Error("our exclusion route x1 should be deleted")
	}
	if m.count(http.MethodDelete, "/workers/routes/x2") != 0 {
		t.Error("an unrelated no-script route x2 must not be touched")
	}

	// Idempotent: with the routes already gone, a second Disable deletes nothing.
	m2 := &mockCF{t: t} // empty routes list
	c2, srv2 := newTestClient(t, m2)
	defer srv2.Close()
	if err := c2.Disable(context.Background(), cfg); err != nil {
		t.Fatalf("Disable (idempotent): %v", err)
	}
	if m2.count(http.MethodDelete, "/workers/routes/") != 0 {
		t.Error("second Disable with no routes must delete nothing")
	}
}

// lastRouteCreate returns the decoded body of the last POST /workers/routes request.
func lastRouteCreate(t *testing.T, m *mockCF) map[string]any {
	t.Helper()
	for i := len(m.requests) - 1; i >= 0; i-- {
		r := m.requests[i]
		if r.method == http.MethodPost && strings.HasSuffix(strings.Split(r.path, "?")[0], "/workers/routes") {
			var body map[string]any
			if err := json.Unmarshal(r.body, &body); err != nil {
				t.Fatalf("route create body JSON: %v", err)
			}
			return body
		}
	}
	t.Fatal("no POST /workers/routes recorded")
	return nil
}

func TestDeploySurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(apiResponse{Success: false, Errors: []apiError{{Code: 10001, Message: "bad token"}}})
	}))
	defer srv.Close()
	c := New("test-token")
	c.BaseURL = srv.URL
	c.HTTP = srv.Client()
	err := c.Deploy(context.Background(), Config{AccountID: "a", WorkerName: "w"}, "x")
	if err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Errorf("expected a surfaced API error, got %v", err)
	}
}

// TestDeployRejectsPathInjectingTarget proves a worker name (or account id) that
// would alter the REST path is rejected BEFORE any HTTP call — so a mis-derived
// target cannot clobber an unrelated script.
func TestDeployRejectsPathInjectingTarget(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"worker-slash", Config{AccountID: "acc-123", WorkerName: "../scripts/victim"}},
		{"worker-space", Config{AccountID: "acc-123", WorkerName: "my worker"}},
		{"account-slash", Config{AccountID: "acc/../other", WorkerName: "w"}},
		{"worker-query", Config{AccountID: "acc-123", WorkerName: "w?x=1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockCF{t: t}
			c, srv := newTestClient(t, m)
			defer srv.Close()
			err := c.Deploy(context.Background(), tc.cfg, "x")
			if err == nil {
				t.Fatal("expected Deploy to reject a path-injecting target")
			}
			if len(m.requests) != 0 {
				t.Errorf("no HTTP call must be made for an invalid target, got %d", len(m.requests))
			}
		})
	}
}

// parseUploadMetadata extracts the "metadata" part JSON from a multipart upload body.
func parseUploadMetadata(t *testing.T, body []byte) scriptMetadata {
	t.Helper()
	// The recorded body has no boundary header; re-derive it from the first line.
	// Easier: the test client used multipart.Writer; the boundary is in the body's
	// first delimiter line "--<boundary>". Parse via a reader that sniffs it.
	first := body
	if i := strings.IndexByte(string(body), '\n'); i > 0 {
		first = body[:i]
	}
	boundary := strings.TrimSpace(strings.TrimPrefix(string(first), "--"))
	mr := multipart.NewReader(strings.NewReader(string(body)), boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FormName() == "metadata" {
			data, _ := io.ReadAll(part)
			var meta scriptMetadata
			if err := json.Unmarshal(data, &meta); err != nil {
				t.Fatalf("metadata JSON: %v", err)
			}
			return meta
		}
	}
	t.Fatal("no metadata part in upload body")
	return scriptMetadata{}
}
