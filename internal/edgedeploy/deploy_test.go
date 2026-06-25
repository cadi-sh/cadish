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
