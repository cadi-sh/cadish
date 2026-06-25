package server

import (
	"io"
	"net/http"
	"testing"
)

// TestSetCookieNotCached proves the session-safety path end-to-end: a response
// carrying a `Set-Cookie: sessionid=...` is matched by a `@session set_cookie
// sessionid` response-phase matcher driving `cache_ttl @session hit_for_miss 0s`,
// so it is never stored. Two sequential requests both reach origin (no HIT),
// proving one user's session cookie can't be served to another from cache.
func TestSetCookieNotCached(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "sessionid=abc123; HttpOnly; Path=/")
		_, _ = io.WriteString(w, "private page")
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@session set_cookie sessionid
	cache_ttl @session hit_for_miss 0s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/account", nil)
	if rec1.Code != 200 || rec1.Body.String() != "private page" {
		t.Fatalf("first: got %d %q", rec1.Code, rec1.Body.String())
	}
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}

	// Second request must also reach origin: the Set-Cookie response was never
	// stored (hit-for-miss), so there is no HIT.
	rec2 := do(h, "GET", "http://test.local/account", nil)
	if rec2.Code != 200 || rec2.Body.String() != "private page" {
		t.Fatalf("second: got %d %q", rec2.Code, rec2.Body.String())
	}
	if got := rec2.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("second X-Cache = %q, want a non-HIT (Set-Cookie response must not be cached)", got)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (both requests reach origin; Set-Cookie response not cached)", origin.hits.Load())
	}
}

// TestSetCookieUnrelatedStillCached confirms the matcher is scoped: a response
// that sets a DIFFERENT cookie name is not matched by `@session set_cookie
// any Set-Cookie response — even an unrelated, non-session cookie, even under
// cache_unsafe — is NEVER cached (the ironclad confidentiality invariant). A cached
// Set-Cookie would hand one user's freshly-minted cookie to everyone.
func TestSetCookieNeverCachedEvenUnsafe(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "prefs=dark; Path=/")
		_, _ = io.WriteString(w, "public page")
	})
	body := `test.local {
	cache { ram 64MiB }
	cache_unsafe
	upstream backend { to %s }
	@session set_cookie sessionid
	cache_ttl @session hit_for_miss 0s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	if rec := do(h, "GET", "http://test.local/home", nil); rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	rec2 := do(h, "GET", "http://test.local/home", nil)
	if got := rec2.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("second X-Cache = %q, want MISS (a Set-Cookie response is never cached, even with cache_unsafe)", got)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (Set-Cookie response never cached)", origin.hits.Load())
	}
}
