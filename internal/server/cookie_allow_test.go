package server

import (
	"io"
	"net/http"
	"testing"
)

// reflectCookieOrigin echoes the exact Cookie header it received into the body, so a
// test can verify which cookies survived the cookie_allow filter on the way to origin.
func reflectCookieOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "got["+r.Header.Get("Cookie")+"]")
	})
}

// TestCookieAllowStripsAndCaches: `cookie_allow darkMode` keeps darkMode and STRIPS the
// session before the origin + key. darkMode is KEYED (cookie:darkMode), so it caches safely:
// two users with different sessions but the same darkMode share that darkMode's entry (the
// origin never saw a session → never produced per-user content), and the origin sees only the
// allow-listed cookie. (A kept cookie MUST be keyed to cache — an unkeyed one bypasses; see
// TestCookieAllowUnkeyedCookieBypasses.)
func TestCookieAllowStripsAndCaches(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cookie_allow darkMode
	cache_key host path cookie:darkMode
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// User A: session + darkMode. The origin must receive ONLY darkMode (session stripped).
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=AAA; darkMode=1"}})
	if got := a.Body.String(); got != "got[darkMode=1]" {
		t.Fatalf("origin saw %q, want only darkMode (session must be stripped)", got)
	}
	if got := a.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("A X-Cache = %q, want MISS (cookie_allow makes it cacheable)", got)
	}
	// User B: DIFFERENT session, SAME darkMode → shares A's generic entry (HIT), origin not re-hit.
	b := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=BBB; darkMode=1"}})
	if got := b.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("B X-Cache = %q, want HIT (shared generic darkMode entry)", got)
	}
	if origin.hits.Load() != 1 {
		t.Errorf("origin hits = %d, want 1 (B served from the shared entry)", origin.hits.Load())
	}
	// And what B got is the GENERIC darkMode page — never A's session-specific content
	// (there is none, because the origin never received a session).
	if b.Body.String() != "got[darkMode=1]" {
		t.Errorf("B body = %q, want the generic darkMode entry", b.Body.String())
	}
}

// TestCookieAllowDifferentValueDifferentEntry: a different darkMode value keys to its
// own entry (cookie_allow keeps it; the key would need cookie:darkMode/normalize to
// vary — here the page is darkMode-blind so both share, which is the operator's call).
// This test pins that the ALLOW-listed cookie still reaches origin (forwarded).
func TestCookieAllowForwardsAllowedCookie(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cookie_allow lang
	cache_key host path cookie:lang
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"lang=es; _ga=X"}})
	if got := a.Body.String(); got != "got[lang=es]" {
		t.Fatalf("origin saw %q, want only lang=es (_ga stripped)", got)
	}
	// Same lang → HIT; different lang → MISS (keyed by cookie:lang).
	if got := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"lang=es; _ga=Y"}}).Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("same lang should HIT, got %q", got)
	}
	if got := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"lang=fr"}}).Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("different lang should MISS its own entry, got %q", got)
	}
}

// TestCookieAllowUnkeyedCookieBypasses pins the safe behavior for an allow-listed-but-UNKEYED
// cookie: `cookie_allow session` keeps the session (forwarded to origin) but the key does NOT
// capture it, so the request must BYPASS the shared cache — never store A's per-session body
// under a session-agnostic key where B would be served it. Allow-listing controls WHICH
// cookies survive; the key must still ISOLATE a survivor or the request bypasses. (To cache
// it, key it: `cache_key … cookie:session`. `cadish check` flags the unkeyed case with the
// cookie-allow-unkeyed warning.)
func TestCookieAllowUnkeyedCookieBypasses(t *testing.T) {
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
	// User A: the origin sees the (forwarded) session, but with no cookie:session in the key
	// the request bypasses — nothing is stored.
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=AAA"}})
	if got := a.Body.String(); got != "got[session=AAA]" {
		t.Fatalf("origin saw %q, want session forwarded", got)
	}
	// User B with a DIFFERENT session must NOT be served A's body — it bypasses to origin too.
	b := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=BBB"}})
	if b.Body.String() == "got[session=AAA]" {
		t.Fatalf("CROSS-USER LEAK: B served A's session body %q", b.Body.String())
	}
	if b.Body.String() != "got[session=BBB]" {
		t.Errorf("B body = %q, want its own session (fresh bypass fetch)", b.Body.String())
	}
	// Both bypassed to origin (nothing cached): exactly one origin hit per request.
	if n := origin.hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 (both unkeyed-cookie requests bypassed)", n)
	}
}

// TestCookieAllowSecondUnkeyedCookieBypasses is the HIGH-severity multi-cookie case: even
// when the operator KEYS one allow-listed cookie (cookie:session), a SECOND allow-listed but
// UNKEYED identity cookie (uid) must still force a bypass — otherwise two users sharing a
// session but differing on uid collide on one entry and B is served A's body. The exemption
// is name-aware: every surviving cookie must be key-covered.
func TestCookieAllowSecondUnkeyedCookieBypasses(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cookie_allow session uid
	cache_key host path cookie:session
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	// A: session=S, uid=alice → personalized; uid is NOT in the key, so it must bypass.
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=S; uid=alice"}})
	if got := a.Body.String(); got != "got[session=S; uid=alice]" {
		t.Fatalf("origin saw %q, want both cookies forwarded", got)
	}
	// B: SAME session=S but uid=bob → must NOT be served alice's body.
	b := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=S; uid=bob"}})
	if b.Body.String() == "got[session=S; uid=alice]" {
		t.Fatalf("CROSS-USER LEAK: B (uid=bob) served A's uid=alice body %q", b.Body.String())
	}
	if n := origin.hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 (the unkeyed second cookie uid forces a bypass)", n)
	}
}

// TestCookieAllowEmptyStripsAll: bare `cookie_allow` strips EVERY cookie → the request
// reaches origin anonymous and caches as anonymous content.
func TestCookieAllowEmptyStripsAll(t *testing.T) {
	origin := reflectCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cookie_allow
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=AAA; anything=1"}})
	if got := a.Body.String(); got != "got[]" {
		t.Fatalf("origin saw %q, want no cookies (all stripped)", got)
	}
	if got := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"session=BBB"}}).Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("all-stripped requests share the anonymous entry, want HIT, got %q", got)
	}
}
