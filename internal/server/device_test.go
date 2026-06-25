package server

import (
	"io"
	"net/http"
	"testing"
)

// TestDeviceKeyVariation: with `cache_key … {device}` (and the built-in
// classifier — no device_detect block), two User-Agents in the SAME device class
// share a cache entry, while a different class is a separate entry. Proves the
// server's UA-classification pre-pass feeds the {device} key token end-to-end.
func TestDeviceKeyVariation(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "body")
	})
	const cfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path {device}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	ua := func(s string) http.Header { return http.Header{"User-Agent": []string{s}} }

	// First mobile request: MISS, origin hit.
	r1 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (iPhone) Mobile/15E148"))
	if r1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("mobile #1 X-Cache=%q, want MISS", r1.Header().Get("X-Cache"))
	}

	// Second request, different UA but SAME class (mobile): HIT, no new origin hit.
	r2 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (Linux; Android 13) Mobile"))
	if r2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("mobile #2 X-Cache=%q, want HIT (same device class shares the entry)", r2.Header().Get("X-Cache"))
	}

	// Desktop UA: different device class → different key → MISS + new origin hit.
	r3 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (Windows NT 10.0) Firefox/120"))
	if r3.Header().Get("X-Cache") != "MISS" {
		t.Errorf("desktop X-Cache=%q, want MISS (distinct device class)", r3.Header().Get("X-Cache"))
	}

	if got := origin.hits.Load(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (one per device class: mobile, desktop)", got)
	}
}

// TestDeviceDetectCustom: a device_detect block overrides the classifier.
func TestDeviceDetectCustom(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "b")
	})
	const cfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	device_detect {
		cli ua_contains curl wget
		default browser
	}
	cache_key host path {device}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	ua := func(s string) http.Header { return http.Header{"User-Agent": []string{s}} }

	do(h, "GET", "http://test.local/p", ua("curl/8.0"))       // class "cli" — MISS
	r := do(h, "GET", "http://test.local/p", ua("wget/1.21")) // also "cli" — HIT
	if r.Header().Get("X-Cache") != "HIT" {
		t.Errorf("wget X-Cache=%q, want HIT (curl+wget both class cli)", r.Header().Get("X-Cache"))
	}
	r2 := do(h, "GET", "http://test.local/p", ua("Mozilla Firefox")) // class "browser" — MISS
	if r2.Header().Get("X-Cache") != "MISS" {
		t.Errorf("firefox X-Cache=%q, want MISS (class browser)", r2.Header().Get("X-Cache"))
	}
	if got := origin.hits.Load(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (cli, browser)", got)
	}
}
