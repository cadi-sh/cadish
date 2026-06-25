package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStrictHostRejectsUndeclaredHost: with the global `strict_host` option a
// single-site config must NOT serve an undeclared Host — it returns 421 Misdirected
// Request instead of 200 (the lenient single-site fallback is disabled).
func TestStrictHostRejectsUndeclaredHost(t *testing.T) {
	co := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	cfg := `
{
	strict_host
}
test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
}
`
	h, _ := buildHandler(t, nil, cfg, co.srv.URL)

	// Declared host: served normally.
	req := httptest.NewRequest("GET", "http://test.local/a", nil)
	req.Host = "test.local"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("declared host: status = %d, want 200", rec.Code)
	}

	// Undeclared host: rejected with 421 under strict_host.
	req = httptest.NewRequest("GET", "http://evil.example/a", nil)
	req.Host = "evil.example"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("undeclared host under strict_host: status = %d, want 421", rec.Code)
	}
}

// TestLenientHostDefaultServesUndeclaredHost: WITHOUT strict_host (the default), a
// single-site config still serves any Host (the lenient fallback) — unchanged
// behavior, the backward-compatibility guard for the new opt-in.
func TestLenientHostDefaultServesUndeclaredHost(t *testing.T) {
	co := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
}
`
	h, _ := buildHandler(t, nil, cfg, co.srv.URL)

	req := httptest.NewRequest("GET", "http://evil.example/a", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("undeclared host (lenient default): status = %d, want 200", rec.Code)
	}
}
