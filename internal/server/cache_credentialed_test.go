package server

import (
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

// cache_credentialed (D101) end-to-end server tests. The directive makes caching
// ORIGIN-AUTHORITATIVE for matching credentialed requests: skip the credential bypass,
// forward the original cookies to origin, and store under the SHARED key on a positive
// in-scope cache_ttl signal (Set-Cookie / uncovered-Vary hard-refused; no signal ⇒ not
// stored). The origin echoes the Cookie it received so we can prove the forward.

const credCfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl
	cache_ttl default hit_for_miss 0s
	header +cache_status X-Cache
}
`

// credOrigin echoes the received Cookie and emits the headers chosen per-path.
func credOrigin(t *testing.T, hdr func(path string) http.Header) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		for k, vs := range hdr(r.URL.Path) {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		_, _ = io.WriteString(w, "cookie["+r.Header.Get("Cookie")+"]")
	})
}

// TestCredentialedPositiveSignalSharedHit: a logged-in (session cookie) request to a shared
// readmodel endpoint whose origin emits X-Cache-Ttl (even WITH Pragma: no-cache + past
// Expires + no-store) is cached under the SHARED key; a SECOND request with a DIFFERENT cookie
// HITs the same entry, and the cookies were FORWARDED to origin on the store fetch.
func TestCredentialedPositiveSignalSharedHit(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{
			"X-Cache-Ttl":   {"60"},
			"Pragma":        {"no-cache"},
			"Expires":       {"Thu, 01 Jan 1981 00:00:00 GMT"},
			"Cache-Control": {"no-store, private"},
			"Content-Type":  {"application/json"},
		}
	})
	h, _ := buildHandler(t, nil, credCfg, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}
	if got := rec1.Body.String(); got != "cookie[session=alice]" {
		t.Fatalf("origin saw %q, want the ORIGINAL session cookie forwarded on the store fetch", got)
	}
	// The weak control headers force-overridden by the positive signal must not be replayed.
	if cc := rec1.Header().Get("Cache-Control"); cc == "no-store, private" {
		t.Fatalf("delivered Cache-Control = %q, want cadish's freshness (no-store force-overridden)", cc)
	}
	if rec1.Header().Get("Pragma") != "" {
		t.Fatal("Pragma: no-cache must be stripped from a credentialed positive-signal store")
	}
	if rec1.Header().Get("Expires") != "" {
		t.Fatal("a past Expires must be stripped from a credentialed positive-signal store")
	}

	// A DIFFERENT user's cookie HITs the same shared entry — the whole point.
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=bob"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (shared across users)", got)
	}
	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits = %d, want 1 (shared cache hit on the 2nd, different-cookie request)", n)
	}
}

// TestCredentialedNoSignalNotStored: a per-user endpoint that emits NO X-Cache-Ttl and NO
// Set-Cookie is NEVER stored — refetched per request (fail-closed). This is the property that
// makes a forgotten-Set-Cookie per-user route safe.
func TestCredentialedNoSignalNotStored(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{"Content-Type": {"application/json"}}
	})
	h, _ := buildHandler(t, nil, credCfg, origin.srv.URL)

	for i := 0; i < 2; i++ {
		rec := do(h, "GET", "http://test.local/v3/readmodel/cache/communityconfiguser", http.Header{"Cookie": {"session=alice"}})
		if got := rec.Header().Get("X-Cache"); got == "HIT" {
			t.Fatalf("request %d X-Cache = HIT, want a fresh fetch (no positive signal ⇒ never stored)", i)
		}
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (no-signal response must never be shared-cached)", n)
	}
}

// TestCredentialedSetCookieWithSignalStoresStripped is the SAFETY CRUX (live-evidence case):
// a real shared endpoint emits Set-Cookie (a tracking cookie) ALONGSIDE X-Cache-Ttl. The
// positive signal STORES it under the shared key WITH the Set-Cookie STRIPPED from BOTH the
// delivered response AND the stored object; a 2nd request (different cookie) HITs and serves
// ZERO Set-Cookie. This is the absolute invariant: a Set-Cookie VALUE is NEVER in a cached
// object — so no user's session/tracking cookie leaks to another.
func TestCredentialedSetCookieWithSignalStoresStripped(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{
			"X-Cache-Ttl":   {"60"},
			"Set-Cookie":    {"FLYING_SPAGUETTI_MONSTER_PRODUCTION=track-for-alice; Path=/"},
			"Cache-Control": {"no-store, no-cache, must-revalidate"},
			"Pragma":        {"no-cache"},
			"Content-Type":  {"application/json"},
		}
	})
	h, _ := buildHandler(t, nil, credCfg, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/onlineusersnumber", http.Header{"Cookie": {"session=alice"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS (stored under the shared key)", got)
	}
	if got := rec1.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("delivered MISS must carry ZERO Set-Cookie (stripped), got %v", got)
	}
	if got := rec1.Body.String(); got != "cookie[session=alice]" {
		t.Fatalf("origin saw %q, want the ORIGINAL session cookie forwarded to origin", got)
	}

	// 2nd request, DIFFERENT cookie → HIT, and the cached object carries ZERO Set-Cookie
	// (it was never stored): no tracking cookie minted for alice leaks to bob.
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/onlineusersnumber", http.Header{"Cookie": {"session=bob"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (shared)", got)
	}
	if got := rec2.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a HIT served from the shared object must carry ZERO Set-Cookie, got %v (cross-user cookie leak!)", got)
	}
	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits = %d, want 1 (the 2nd request is a shared HIT)", n)
	}
}

// TestCredentialedSetCookieNoSignalNotStored: the per-user `favorites` case — Set-Cookie but
// NO X-Cache-Ttl ⇒ no positive signal ⇒ never stored (fail-closed via the signal gate).
func TestCredentialedSetCookieNoSignalNotStored(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{"Set-Cookie": {"session=fresh-for-alice; Path=/; HttpOnly"}}
	})
	h, _ := buildHandler(t, nil, credCfg, origin.srv.URL)

	for i := 0; i < 2; i++ {
		rec := do(h, "GET", "http://test.local/v3/readmodel/cache/favorites", http.Header{"Cookie": {"session=alice"}})
		if got := rec.Header().Get("X-Cache"); got == "HIT" {
			t.Fatalf("request %d X-Cache = HIT, want never-stored (no positive signal)", i)
		}
		// A Set-Cookie response NOT in a positive-signal store is a pass-through: the cookie is
		// delivered to its OWN user (this is not a shared-cache leak — it is never stored).
		if got := rec.Header().Get("Set-Cookie"); got == "" {
			t.Fatalf("request %d: a non-stored per-user response should pass its Set-Cookie through to its own user", i)
		}
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (a no-signal per-user response must never be shared-cached)", n)
	}
}

// credCfgStaticDefault is the LEAK regression config: a cache_credentialed @rm scope whose
// per-response signal is `from_header X-Cache-Ttl`, but with a co-existing SITE-WIDE POSITIVE
// static `cache_ttl default ttl 60s`. Before the fix, a @rm request whose origin response
// carries NO X-Cache-Ttl still matched the static `default ttl 60s` rule → dec.Cacheable=true →
// entered the credentialed branch → stored the PER-USER body under the SHARED key with Set-Cookie
// stripped → a different user HIT it and received the first user's private body. The static TTL
// is NOT a per-response origin signal, so it must NOT authorize a credentialed share.
const credCfgStaticDefault = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestCredentialedStaticDefaultNoSignalNotShared is the cross-user leak regression (HIGH): with a
// co-existing positive static `cache_ttl default ttl 60s`, a credentialed @rm response that carries
// a PER-USER Set-Cookie but NO X-Cache-Ttl per-response signal must NOT be stored under the shared
// key. Alice GETs /favorites (her private body + Set-Cookie, no signal); Bob (different cookie) must
// MISS and NEVER receive Alice's body. A static operator TTL is not a per-response origin signal, so
// it cannot authorize a credentialed share — the response falls through to the normal Set-Cookie
// shareability refusal. Pre-fix this stored Alice's body shared (origin hits == 1, Bob got Alice's
// body); post-fix origin hits == 2 and Bob gets his own body.
func TestCredentialedStaticDefaultNoSignalNotShared(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{
			"Set-Cookie":   {"session=private-for-this-user; Path=/; HttpOnly"},
			"Content-Type": {"application/json"},
		}
	})
	h, _ := buildHandler(t, nil, credCfgStaticDefault, origin.srv.URL)

	// Alice's private body — must NOT be stored under the shared key (no per-response signal).
	recAlice := do(h, "GET", "http://test.local/v3/readmodel/cache/favorites", http.Header{"Cookie": {"session=alice"}})
	if got := recAlice.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("Alice X-Cache = %q, want MISS", got)
	}
	aliceBody := recAlice.Body.String()
	if aliceBody != "cookie[session=alice]" {
		t.Fatalf("Alice origin saw %q, want her own cookie forwarded", aliceBody)
	}

	// Bob (different cookie) must MISS — a static-TTL-only credentialed response is NEVER shared.
	recBob := do(h, "GET", "http://test.local/v3/readmodel/cache/favorites", http.Header{"Cookie": {"session=bob"}})
	if got := recBob.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("Bob X-Cache = HIT — Alice's per-user body was shared-cached under a static TTL (cross-user leak!)")
	}
	if got := recBob.Body.String(); got == aliceBody {
		t.Fatalf("Bob received Alice's private body %q (cross-user leak!)", got)
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (a static-TTL-only credentialed response must be refetched per user, never shared)", n)
	}
}

// TestCredentialedStaticDefaultWithSignalStillStores confirms the POSITIVE path is unaffected by the
// leak fix: in the SAME static-default config, an @rm response WITH X-Cache-Ttl (the per-response
// origin signal) + a Set-Cookie is still stored shared with Set-Cookie stripped, and Bob HITs.
func TestCredentialedStaticDefaultWithSignalStillStores(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{
			"X-Cache-Ttl":  {"60"},
			"Set-Cookie":   {"track=for-alice; Path=/"},
			"Content-Type": {"application/json"},
		}
	})
	h, _ := buildHandler(t, nil, credCfgStaticDefault, origin.srv.URL)

	recAlice := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice"}})
	if got := recAlice.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("Alice X-Cache = %q, want MISS (stored under the shared key)", got)
	}
	if got := recAlice.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("delivered MISS must carry ZERO Set-Cookie (stripped), got %v", got)
	}

	recBob := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=bob"}})
	if got := recBob.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("Bob X-Cache = %q, want HIT (positive per-response signal shares)", got)
	}
	if got := recBob.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a shared HIT must carry ZERO Set-Cookie, got %v", got)
	}
	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits = %d, want 1 (positive signal stores shared)", n)
	}
}

// TestCredentialedAuthorizationShared: v1 covers Authorization too — an Authorization-bearing
// request with a positive signal + shareable response caches shared; a different Authorization
// HITs. (No Cookie involved.)
func TestCredentialedAuthorizationShared(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{"X-Cache-Ttl": {"60"}, "Content-Type": {"application/json"}}
	})
	h, _ := buildHandler(t, nil, credCfg, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Authorization": {"Bearer alice"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Authorization": {"Bearer bob"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (Authorization shared under the credential-free key)", got)
	}
	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits = %d, want 1", n)
	}
}

// TestCredentialedDefaultStillBypasses: WITHOUT cache_credentialed, the identical credentialed
// request still bypasses (refetched per request) — the default is unchanged.
func TestCredentialedDefaultStillBypasses(t *testing.T) {
	var hits atomic.Int64
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("X-Cache-Ttl", "60")
		_, _ = io.WriteString(w, "ok")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path
	cache_ttl default from_header X-Cache-Ttl
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	for i := 0; i < 2; i++ {
		rec := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice"}})
		if got := rec.Header().Get("X-Cache"); got == "HIT" {
			t.Fatalf("request %d X-Cache = HIT, want a bypass per request (no cache_credentialed directive)", i)
		}
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (credential bypass unchanged without the directive)", n)
	}
}
