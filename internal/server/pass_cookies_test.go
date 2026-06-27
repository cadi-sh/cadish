package server

import (
	"net/http"
	"testing"
)

// SPEC-PASS-FORWARDS-COOKIES: a passed (uncached) request must reach the origin with the
// ORIGINAL, pre-filter Cookie header — cookie_allow / derives_from stripping is a pure
// cache-key normalization that has no benefit (and only breaks auth) when nothing is cached.
// These mirror cookie_allow_test.go's reflectCookieOrigin probe (origin echoes the Cookie it
// received into the body) and tracer_test.go's `pass @api` config. Pass-ness is asserted via
// the origin being re-hit on a repeat (a passed response is never cached), since the
// `+cache_status` response header renders the deliver status (MISS), not the PASS access-log.

// TestPassForwardsOriginalCookie: an explicit `pass @api` request carrying a session +
// login cookie, under a `cookie_allow selectedLanguage` that would otherwise strip them,
// must reach the origin with the FULL original Cookie (so a `pass`ed /me sees the session
// and does not read a logged-in user as GUEST). FAILS before the fix (origin saw only
// selectedLanguage=en).
func TestPassForwardsOriginalCookie(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@api path /api/*
	pass @api
	cookie_allow selectedLanguage
	cache_key host path cookie:selectedLanguage
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	const cookie = "session=abc; login=xyz; selectedLanguage=en"
	rec := do(h, "GET", "http://test.local/api/me", http.Header{"Cookie": {cookie}})
	if got := rec.Body.String(); got != "got["+cookie+"]" {
		t.Fatalf("origin saw %q, want the FULL original Cookie %q forwarded on the pass path", got, cookie)
	}
	// A passed response is never cached: a repeat re-hits the origin (proves the bypass).
	_ = do(h, "GET", "http://test.local/api/me", http.Header{"Cookie": {cookie}})
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (a `pass`ed request is never cached)", n)
	}
}

// TestPassCacheablePathKeepsFilteredCookie is the regression guard: the SAME config, but a
// CACHEABLE request (not on the `pass` route) must still reach the origin with the
// cookie_allow-FILTERED cookie, so the cache key + cross-user collapse stay intact. Only the
// pass/uncached path restores the original.
func TestPassCacheablePathKeepsFilteredCookie(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@api path /api/*
	pass @api
	cookie_allow selectedLanguage
	cache_key host path cookie:selectedLanguage
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	const cookie = "session=abc; login=xyz; selectedLanguage=en"
	rec := do(h, "GET", "http://test.local/page", http.Header{"Cookie": {cookie}})
	if got := rec.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("X-Cache = %q, want MISS (cacheable page, keyed by selectedLanguage)", got)
	}
	if got := rec.Body.String(); got != "got[selectedLanguage=en]" {
		t.Fatalf("origin saw %q, want only the FILTERED selectedLanguage on the cacheable path (collapse intact)", got)
	}
	// Collapse intact: a different session but same selectedLanguage shares the entry (HIT).
	rec2 := do(h, "GET", "http://test.local/page", http.Header{"Cookie": {"session=ZZZ; selectedLanguage=en"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache = %q, want HIT (the cacheable collapse must still hold)", got)
	}
}

// TestPassWithoutCookieSynthesizesNone: a pass request whose client sent NO Cookie must reach
// the origin WITHOUT any synthesized Cookie header.
func TestPassWithoutCookieSynthesizesNone(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@api path /api/*
	pass @api
	cookie_allow selectedLanguage
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/api/me", nil)
	if got := rec.Body.String(); got != "got[]" {
		t.Fatalf("origin saw %q, want no Cookie synthesized for a cookieless pass request", got)
	}
}

// TestCredentialBypassForwardsOriginalCookie: a request that BYPASSES the cache because it
// carries an allow-listed-but-UNKEYED identity cookie (BypassForCredentials, not an explicit
// `pass`) must ALSO forward the original Cookie — including the `foo` that cookie_allow
// stripped — to the origin. Same uncached path, same restore.
func TestCredentialBypassForwardsOriginalCookie(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cookie_allow session
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	const cookie = "session=abc; foo=bar"
	rec := do(h, "GET", "http://test.local/page", http.Header{"Cookie": {cookie}})
	if got := rec.Body.String(); got != "got["+cookie+"]" {
		t.Fatalf("origin saw %q, want the FULL original Cookie %q forwarded on the credential-bypass path", got, cookie)
	}
	// Credential bypass is never cached: a repeat re-hits the origin.
	_ = do(h, "GET", "http://test.local/page", http.Header{"Cookie": {cookie}})
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (a credential-bypass request is never cached)", n)
	}
}
