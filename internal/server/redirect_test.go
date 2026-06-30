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

// TestRedirectNoStoreCacheControl verifies that a `redirect … no_store` directive
// adds Cache-Control: no-store, no-cache, must-revalidate, private to the 3xx
// response, and that a plain redirect (without no_store) does NOT.
func TestRedirectNoStoreCacheControl(t *testing.T) {
	const cfgNoStore = `test.local {
	upstream backend { to %s }
	redirect ^/pers 302 https://test.local/personalized no_store
	redirect ^/fixed 301 https://test.local/static
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfgNoStore, "http://127.0.0.1:1") // origin unreachable — short-circuit fires first

	const wantCC = "no-store, no-cache, must-revalidate, private"

	// A redirect with no_store must carry Cache-Control.
	recNoStore := do(h, "GET", "http://test.local/pers", nil)
	if recNoStore.Code != http.StatusFound {
		t.Fatalf("no_store redirect: status = %d, want 302", recNoStore.Code)
	}
	if cc := recNoStore.Header().Get("Cache-Control"); cc != wantCC {
		t.Errorf("no_store redirect: Cache-Control = %q, want %q", cc, wantCC)
	}

	// A plain redirect must NOT carry Cache-Control.
	recPlain := do(h, "GET", "http://test.local/fixed", nil)
	if recPlain.Code != http.StatusMovedPermanently {
		t.Fatalf("plain redirect: status = %d, want 301", recPlain.Code)
	}
	if cc := recPlain.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("plain redirect: Cache-Control = %q, want empty", cc)
	}
}
