package server

import (
	"net/http"
	"testing"
)

// TestRedirectPassthrough verifies a 3xx from the origin reaches the client as that
// 3xx (with Location) rather than being mistranslated to 502 (closes the "3xx →
// 502" issue) — and that cadish never follows it (SSRF guard, security review #1).
func TestRedirectPassthrough(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/login")
		w.WriteHeader(http.StatusFound) // 302
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/needs-redirect", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (passthrough, not 502)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://elsewhere.example/login" {
		t.Fatalf("Location = %q, want the origin's redirect target", loc)
	}
}
