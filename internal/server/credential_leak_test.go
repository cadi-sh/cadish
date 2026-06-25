package server

import (
	"io"
	"net/http"
	"testing"
)

// reflectCredsOrigin echoes the request's Cookie + Authorization into the body so a
// test can detect whether one user's private response leaked to another.
func reflectCredsOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "body-for["+r.Header.Get("Cookie")+"|"+r.Header.Get("Authorization")+"]")
	})
}

// cfgDefaultTTL is the canonical "cache everything for a minute" config with NO
// explicit pass for credentials — the exact shape that leaked (COOKIE-LEAK/AUTH-LEAK).
const cfgDefaultTTL = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestCookieRequestNotCachedCrossUser (COOKIE-LEAK) is the security guard: a request
// carrying a session Cookie must be PASSed by default (Varnish builtin-VCL parity,
// RFC 9111), so a private page returned for one user's cookie is never stored in the
// SHARED cache and served to an anonymous (or different) user.
func TestCookieRequestNotCachedCrossUser(t *testing.T) {
	origin := reflectCredsOrigin(t)
	h, _ := buildHandler(t, nil, cfgDefaultTTL, origin.srv.URL)

	// User A (logged in) fetches a private page — twice. A credentialed request must
	// be PASSed (bypass cache), so BOTH hit origin (never served a stored copy).
	a := do(h, "GET", "http://test.local/account", http.Header{"Cookie": {"session=AAA-secret"}})
	if a.Body.String() != "body-for[session=AAA-secret|]" {
		t.Fatalf("user A body = %q", a.Body.String())
	}
	_ = do(h, "GET", "http://test.local/account", http.Header{"Cookie": {"session=AAA-secret"}})
	if origin.hits.Load() != 2 {
		t.Errorf("two cookie requests both hit origin? hits=%d, want 2 (credentialed = never cached)", origin.hits.Load())
	}

	// Anonymous user B must NOT receive A's private body.
	b := do(h, "GET", "http://test.local/account", nil)
	if b.Body.String() == "body-for[session=AAA-secret|]" {
		t.Fatalf("COOKIE-LEAK: anonymous user received user A's private cached body")
	}
	if b.Body.String() != "body-for[|]" {
		t.Errorf("anonymous body = %q, want the anonymous origin response", b.Body.String())
	}
}

// TestAuthorizationRequestNotCachedCrossUser (AUTH-LEAK, RFC 9111 §3.5).
func TestAuthorizationRequestNotCachedCrossUser(t *testing.T) {
	origin := reflectCredsOrigin(t)
	h, _ := buildHandler(t, nil, cfgDefaultTTL, origin.srv.URL)

	a := do(h, "GET", "http://test.local/api/me", http.Header{"Authorization": {"Bearer AAA-secret"}})
	if a.Body.String() != "body-for[|Bearer AAA-secret]" {
		t.Fatalf("user A body = %q", a.Body.String())
	}
	b := do(h, "GET", "http://test.local/api/me", nil)
	if b.Body.String() == "body-for[|Bearer AAA-secret]" {
		t.Fatalf("AUTH-LEAK: anonymous user received user A's authorized cached body")
	}
	c := do(h, "GET", "http://test.local/api/me", http.Header{"Authorization": {"Bearer BBB-other"}})
	if c.Body.String() == "body-for[|Bearer AAA-secret]" {
		t.Fatalf("AUTH-LEAK: user B received user A's authorized cached body")
	}
}

// TestCacheUnsafeDoesNotEnableCookieCaching: cache_unsafe (which governs response
// Set-Cookie shareability) must NOT be a back door for caching credentialed requests —
// the only opt-in is keying by the credential, so an operator cannot accidentally leak
// by reaching for cache_unsafe.
func TestCacheUnsafeDoesNotEnableCookieCaching(t *testing.T) {
	origin := reflectCredsOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_unsafe
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	_ = do(h, "GET", "http://test.local/x", http.Header{"Cookie": {"session=AAA"}})
	_ = do(h, "GET", "http://test.local/x", http.Header{"Cookie": {"session=AAA"}})
	if origin.hits.Load() != 2 {
		t.Errorf("cache_unsafe must NOT cache cookie requests: hits=%d, want 2 (still bypassed)", origin.hits.Load())
	}
	b := do(h, "GET", "http://test.local/x", nil)
	if b.Body.String() == "body-for[session=AAA|]" {
		t.Fatalf("cache_unsafe leaked a cookie response cross-user")
	}
}

// TestCookieKeyEnablesPerUserCaching: keying on `cookie:session` lifts the bypass —
// each session gets its OWN entry (leak-proof), and a repeat with the same session
// HITs while a different session MISSes.
func TestCookieKeyEnablesPerUserCaching(t *testing.T) {
	origin := reflectCredsOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path cookie:session
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	a1 := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"session=AAA"}})
	if got := a1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first AAA request X-Cache=%q, want MISS", got)
	}
	a2 := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"session=AAA"}})
	if got := a2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second AAA request should HIT its own per-session entry, got %q", got)
	}
	if a2.Body.String() != "body-for[session=AAA|]" {
		t.Errorf("AAA HIT body = %q", a2.Body.String())
	}
	// A DIFFERENT session must get its own entry — never AAA's.
	b := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"session=BBB"}})
	if got := b.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("session BBB must MISS (own entry), got %q", got)
	}
	if b.Body.String() == "body-for[session=AAA|]" {
		t.Fatalf("LEAK: session BBB received session AAA's cached body")
	}
}

// TestCookieKeyByWrongCookieStillBypasses (LEAK GUARD a): keying on a NON-identity
// cookie (cart_count) must NOT lift the bypass while the request also carries an
// un-keyed identity cookie (session) — otherwise two users with the same cart_count
// but different sessions collide and one gets the other's private body.
func TestCookieKeyByWrongCookieStillBypasses(t *testing.T) {
	origin := reflectCredsOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path cookie:cart_count
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	// User A: session AAA, cart_count 3.
	a := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"session=AAA; cart_count=3"}})
	// User B: DIFFERENT session, SAME cart_count.
	b := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"session=BBB; cart_count=3"}})
	if b.Body.String() == a.Body.String() {
		t.Fatalf("CACHE LEAK: user B received user A's body %q (session not covered by cookie:cart_count)", a.Body.String())
	}
	if origin.hits.Load() != 2 {
		t.Errorf("an un-keyed identity cookie must bypass: hits=%d, want 2", origin.hits.Load())
	}
}

// TestCookieKeyMissNamedSessionBypasses (LEAK GUARD b): the documented `cookie:session`
// recipe must NOT cache-share an app whose session cookie is named differently
// (PHPSESSID/JSESSIONID/…): the request carries PHPSESSID (un-keyed) so it must bypass,
// not key everyone onto an empty `session` value.
func TestCookieKeyMissNamedSessionBypasses(t *testing.T) {
	origin := reflectCredsOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path cookie:session
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	a := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"PHPSESSID=AAA"}})
	b := do(h, "GET", "http://test.local/acct", http.Header{"Cookie": {"PHPSESSID=BBB"}})
	if b.Body.String() == a.Body.String() {
		t.Fatalf("CACHE LEAK: cookie:session shared a PHPSESSID app's private body across users")
	}
	if origin.hits.Load() != 2 {
		t.Errorf("an un-keyed session cookie must bypass: hits=%d, want 2", origin.hits.Load())
	}
}

// TestAuthorizationKeyEnablesPerTokenCaching: keying on `header:Authorization` lifts
// the bypass per bearer token.
func TestAuthorizationKeyEnablesPerTokenCaching(t *testing.T) {
	origin := reflectCredsOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path header:Authorization
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	_ = do(h, "GET", "http://test.local/me", http.Header{"Authorization": {"Bearer AAA"}})
	a2 := do(h, "GET", "http://test.local/me", http.Header{"Authorization": {"Bearer AAA"}})
	if got := a2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("same bearer token should HIT, got %q", got)
	}
	b := do(h, "GET", "http://test.local/me", http.Header{"Authorization": {"Bearer BBB"}})
	if b.Body.String() == "body-for[|Bearer AAA]" {
		t.Fatalf("LEAK: token BBB received token AAA's cached body")
	}
}

// TestCookieKeyStillBypassesUncoveredAuthorization: keying by cookie:session covers the
// cookie but NOT an Authorization header — a request carrying both must still bypass
// (the uncovered credential wins).
func TestCookieKeyStillBypassesUncoveredAuthorization(t *testing.T) {
	origin := reflectCredsOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path cookie:session
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	hdr := http.Header{"Cookie": {"session=AAA"}, "Authorization": {"Bearer T"}}
	_ = do(h, "GET", "http://test.local/acct", hdr)
	_ = do(h, "GET", "http://test.local/acct", hdr)
	if origin.hits.Load() != 2 {
		t.Errorf("an uncovered Authorization must still bypass: hits=%d, want 2", origin.hits.Load())
	}
}

// TestErrorsNotCachedUnderDefault (NEG-ALL): a transient 5xx must NOT be cached under
// a generic `cache_ttl default` — caching an outage pins it for the whole TTL even
// after the origin recovers.
func TestErrorsNotCachedUnderDefault(t *testing.T) {
	var code int = 503
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, "err-body")
	})
	h, _ := buildHandler(t, nil, cfgDefaultTTL, origin.srv.URL)

	r1 := do(h, "GET", "http://test.local/p", nil)
	if r1.Code != 503 {
		t.Fatalf("req1 code = %d, want 503", r1.Code)
	}
	// Origin recovers.
	code = 200
	r2 := do(h, "GET", "http://test.local/p", nil)
	if r2.Code != 200 {
		t.Fatalf("NEG-ALL: after origin recovery req2 = %d, want 200 (a cached 503 pinned the outage)", r2.Code)
	}
}

// TestExplicitStatusCachesError (NEG-ALL opt-in): an EXPLICIT `cache_ttl status 503`
// still caches the 503 — the operator opted in deliberately.
func TestExplicitStatusCachesError(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "err")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 503 ttl 60s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	_ = do(h, "GET", "http://test.local/p", nil)
	r2 := do(h, "GET", "http://test.local/p", nil)
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("explicit `cache_ttl status 503` should cache the 503 (HIT), got %q", got)
	}
}

// TestNegativeCache404StillWorksUnderDefault: the documented 404/410 negative-caching
// under `cache_ttl default` is preserved (not collateral damage of the NEG-ALL fix).
func TestNegativeCache404StillWorksUnderDefault(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, "nope")
	})
	h, _ := buildHandler(t, nil, cfgDefaultTTL, origin.srv.URL)
	_ = do(h, "GET", "http://test.local/missing", nil)
	r2 := do(h, "GET", "http://test.local/missing", nil)
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("404 negative caching under default should still HIT, got %q (origin hits=%d)", got, origin.hits.Load())
	}
}
