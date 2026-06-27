package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// PRESERVE-ORIGIN-ERROR-BODY: an upstream non-2xx (401/403/422/5xx, …) must reach
// the client as the origin's REAL status + headers + body, not the bare synthetic
// `origin error`. The synthetic is reserved for a transport failure / no-backend,
// where there is no upstream body. These tests pin that contract on the pass,
// hit-for-miss, and transport-failure paths, and the negative-cache regression.

// TestPassDeliversOriginErrorBody: a `pass` (uncached) request whose origin answers
// 401 with a JSON envelope delivers that JSON + Content-Type + WWW-Authenticate +
// status verbatim to the client (the high-value core of the fix).
func TestPassDeliversOriginErrorBody(t *testing.T) {
	const errJSON = `{"result":"KO","message":"UNAUTHORIZED"}`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, errJSON)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/v3/user/me", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (origin status delivered verbatim)", rec.Code)
	}
	if rec.Body.String() != errJSON {
		t.Fatalf("body = %q, want the origin JSON %q (NOT \"origin error\")", rec.Body.String(), errJSON)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json (origin error headers delivered)", got)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="api"` {
		t.Fatalf("WWW-Authenticate = %q, want the upstream challenge header delivered", got)
	}
}

// TestHitForMissDeliversErrorBodyNotStored: a CACHEABLE request whose status is NOT
// negatively cached (it matches `cache_ttl status not 200 hit_for_miss`) delivers
// the upstream 401/403 body to THIS client but stores NOTHING — a second request
// re-hits origin (no negative entry was created, no poisoning).
func TestHitForMissDeliversErrorBodyNotStored(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		const errJSON = `{"result":"KO","message":"DENIED"}`
		origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, errJSON)
		})
		body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 60s
	cache_ttl status not 200 hit_for_miss 5s
	header +cache_status X-Cache
}
`
		h, _ := buildHandler(t, nil, body, origin.srv.URL)

		rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/favorites", nil)
		if rec1.Code != code || rec1.Body.String() != errJSON {
			t.Fatalf("%d first: got %d %q, want %d + origin JSON", code, rec1.Code, rec1.Body.String(), code)
		}
		if got := rec1.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("%d first Content-Type = %q, want application/json", code, got)
		}

		// Second request must ALSO reach origin: nothing was stored (HFM bypass, no
		// negative entry), so there is no HIT serving a stale/poisoned error.
		rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/favorites", nil)
		if rec2.Code != code || rec2.Body.String() != errJSON {
			t.Fatalf("%d second: got %d %q, want %d + origin JSON", code, rec2.Code, rec2.Body.String(), code)
		}
		if got := rec2.Header().Get("X-Cache"); got == "HIT" {
			t.Fatalf("%d second X-Cache = %q, want a non-HIT (error must not be stored)", code, got)
		}
		if origin.hits.Load() != 2 {
			t.Fatalf("%d origin hits = %d, want 2 (both reach origin; nothing cached)", code, origin.hits.Load())
		}
	}
}

// TestTransportErrorBareFallback: a genuine transport failure (origin unreachable,
// no upstream response/body) still produces the bare synthetic — 502 `origin error`
// with no on_error configured. This is the ONLY remaining synthetic-body path.
func TestTransportErrorBareFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	url := srv.URL
	srv.Close() // unreachable: every dial is a transport error

	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 200 ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, url)
	rec := do(h, "GET", "http://test.local/x", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502 (transport failure synthetic)", rec.Code)
	}
	if rec.Body.String() != "origin error" {
		t.Fatalf("body = %q, want the bare \"origin error\" synthetic (no upstream body to deliver)", rec.Body.String())
	}
}

// TestNegative404FullBodyUnchanged is the regression guard: a 404 with a real
// error-page body is still delivered AND negatively cached full-body (the 404/410
// path is unchanged by the preserve-error-body fix). A second request is a HIT
// served from the negative cache with the real body.
func TestNegative404FullBodyUnchanged(t *testing.T) {
	const page = "<html>gone fishing</html>"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, page)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 404 ttl 60s
	cache_ttl status 200 ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/missing", nil)
	if rec1.Code != http.StatusNotFound || rec1.Body.String() != page {
		t.Fatalf("first: got %d %q, want 404 + the real error page", rec1.Code, rec1.Body.String())
	}
	rec2 := do(h, "GET", "http://test.local/missing", nil)
	if rec2.Code != http.StatusNotFound || rec2.Body.String() != page {
		t.Fatalf("second: got %d %q, want 404 + the cached error page", rec2.Code, rec2.Body.String())
	}
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (negative full-body cache unchanged)", got)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (second served from negative cache)", origin.hits.Load())
	}
}

// TestPassLargeErrorBodyStreamed: a large (multi-MiB) 503 error body on the pass
// path is streamed through verbatim and arrives intact — it goes through the same
// io.Copy streaming path as a 2xx (idle-timeout reader), never a bounded synthetic.
func TestPassLargeErrorBodyStreamed(t *testing.T) {
	const n = 3 << 20 // 3 MiB
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("E", n)))
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/big-error", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
	if rec.Body.Len() != n {
		t.Fatalf("body len = %d, want %d (large error body streamed intact, not buffered/truncated)", rec.Body.Len(), n)
	}
}
