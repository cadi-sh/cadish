package server

import (
	"io"
	"net/http"
	"testing"
)

// cfgDerivesFrom reproduces the testing-stack bring-up gap (RUN-26-JUN §A1): a
// classify {ageverify} derives a low-cardinality axis from per-user cookies, declares
// them via `derives_from`, and the cache key varies on the normalized token. With
// auto-strip the per-user cookies are read (to derive + key) then removed before the
// origin fetch, so the response caches under the collapsed key.
const cfgDerivesFrom = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@verified   cookie verified-prod 1
	@registered cookie userType registered
	classify {ageverify} {
		derives_from cookie verified-prod userType
		when @verified   -> 0
		when @registered -> 1
		default          -> 2
	}
	cookie_allow
	cache_key default host url {ageverify}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// reflectAgeOrigin echoes the cookies + derived headers it RECEIVES so the test can
// prove the origin saw an anonymous (stripped) request and the right derived state.
func ageOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// The origin classifies userType itself; here it just reflects what it sees.
		ut := "guest"
		if c, err := r.Cookie("userType"); err == nil {
			ut = c.Value
		}
		_, _ = io.WriteString(w, "userType="+ut+";cookie="+r.Header.Get("Cookie"))
	})
}

// TestDerivesFrom_RegisteredCachesAnonymousOrigin: a `userType=registered` request
// yields the registered classification in the KEY and CACHES, while the origin sees an
// anonymous request (the per-user cookie stripped).
func TestDerivesFrom_RegisteredCachesAnonymousOrigin(t *testing.T) {
	origin := ageOrigin(t)
	h, _ := buildHandler(t, nil, cfgDerivesFrom, origin.srv.URL)

	hdr := http.Header{"Cookie": {"userType=registered; _ga=GA1.2.3"}}
	a := do(h, "GET", "http://test.local/p", hdr)
	if a.Code != 200 {
		t.Fatalf("status = %d, want 200", a.Code)
	}
	// The origin must NOT have seen userType (it was stripped) — anonymous upstream.
	if got := a.Body.String(); got != "userType=guest;cookie=" {
		t.Fatalf("origin saw %q, want an anonymous request (no Cookie forwarded)", got)
	}
	if x := a.Header().Get("X-Cache"); x != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", x)
	}

	// A second identical request must HIT the shared cache (it cached — no bypass).
	b := do(h, "GET", "http://test.local/p", hdr)
	if x := b.Header().Get("X-Cache"); x != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (the registered response cached)", x)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (request cached, second served from cache)", origin.hits.Load())
	}
}

// TestDerivesFrom_AxisVariesButTrackingDoesNot: two requests differing only in the
// derived axis input (verified-prod) land on DIFFERENT cache entries; a third cookie
// (_ga) does not fragment the key.
func TestDerivesFrom_AxisVariesButTrackingDoesNot(t *testing.T) {
	origin := ageOrigin(t)
	h, _ := buildHandler(t, nil, cfgDerivesFrom, origin.srv.URL)

	// verified-prod=1 -> ageverify 0.
	do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"verified-prod=1"}})
	// verified-prod=0 -> default ageverify 2 (different entry → MISS, origin hit again).
	r2 := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"verified-prod=0"}})
	if x := r2.Header().Get("X-Cache"); x != "MISS" {
		t.Fatalf("verified-prod=0 X-Cache = %q, want MISS (distinct axis → distinct key)", x)
	}
	// verified-prod=1 again, plus a tracking cookie that must not fragment: HIT.
	r3 := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"verified-prod=1; _ga=GA9.9"}})
	if x := r3.Header().Get("X-Cache"); x != "HIT" {
		t.Fatalf("verified-prod=1 (+_ga) X-Cache = %q, want HIT (tracking cookie must not fragment)", x)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (one per distinct normalized axis)", origin.hits.Load())
	}
}

// TestDerivesFrom_SiblingInvalidationUsesOriginalCookie is the Finding 4 regression:
// under an UNSCOPED derives_from recipe, an unsafe-method request's §4.4 sibling-GET
// invalidation must forget the key the real GET stored under (the AXIS-derived key),
// not the default-axis key. The bug: the COOKIE-NORM strip removes the axis cookie
// before siblingGetKey re-evaluates as GET, so the sibling key collapsed to the
// classifier default and the WRONG (never-stored) key was forgotten — leaving the real
// entry stale-fresh. We GET to cache under axis 0, PUT with the same cookie, then assert
// the next GET MISSES (the right key was invalidated).
func TestDerivesFrom_SiblingInvalidationUsesOriginalCookie(t *testing.T) {
	origin := ageOrigin(t)
	h, _ := buildHandler(t, nil, cfgDerivesFrom, origin.srv.URL)
	hdr := http.Header{"Cookie": {"verified-prod=1"}} // -> ageverify 0

	if r := do(h, "GET", "http://test.local/p", hdr); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	if r := do(h, "GET", "http://test.local/p", hdr); r.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second GET X-Cache=%q, want HIT (cached under the axis-derived key)", r.Header().Get("X-Cache"))
	}

	// Unsafe method with the SAME cookie: invalidates the sibling GET key.
	if r := do(h, "PUT", "http://test.local/p", hdr); r.Code != 200 {
		t.Fatalf("PUT status=%d, want 200", r.Code)
	}

	// The next GET with the same cookie must MISS — the PUT must have forgotten the
	// axis-derived GET key, not the stripped default-axis key.
	if r := do(h, "GET", "http://test.local/p", hdr); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("post-PUT GET X-Cache=%q, want MISS (sibling invalidation forgot the axis key the GET stored under)", r.Header().Get("X-Cache"))
	}
}

// TestDerivesFrom_UnsafeMethodForwardsOriginalCookie is the Finding 2 regression: a
// PUT/POST carrying the sole credential cookie (a strip-mode derives_from cookie) is
// uncached (unsafe method → never stored) and must reach the origin carrying the
// ORIGINAL cookie, not the COOKIE-NORM-stripped anonymous request. Before the fix the
// strip removed the cookie for every method; BypassForCredentials then saw no
// credential (so the cookie-restoring pass branch was skipped), the request fell to the
// unsafe-method branch, and serveOrigin forwarded the write with the Cookie GONE — a
// normalized identity-cookie write arriving at the backend as anonymous, for zero
// caching benefit.
func TestDerivesFrom_UnsafeMethodForwardsOriginalCookie(t *testing.T) {
	origin := ageOrigin(t)
	h, _ := buildHandler(t, nil, cfgDerivesFrom, origin.srv.URL)
	hdr := http.Header{"Cookie": {"verified-prod=1"}}

	r := do(h, "PUT", "http://test.local/p", hdr)
	if r.Code != 200 {
		t.Fatalf("PUT status=%d, want 200", r.Code)
	}
	if got := r.Body.String(); got != "userType=guest;cookie=verified-prod=1" {
		t.Fatalf("origin saw %q, want the ORIGINAL cookie forwarded (cookie=verified-prod=1) on the unsafe write", got)
	}

	// The unsafe-method response is NEVER stored: a following GET must MISS (origin hit
	// again), proving the cookie restore did not contaminate a shared cache entry.
	g := do(h, "GET", "http://test.local/p", hdr)
	if x := g.Header().Get("X-Cache"); x != "MISS" {
		t.Fatalf("post-PUT GET X-Cache=%q, want MISS (the unsafe response must not be stored)", x)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (PUT + the uncached GET; nothing stored by the PUT)", origin.hits.Load())
	}
}

// TestDerivesFrom_UndeclaredCookieStillBypasses: an identity cookie that is NOT a
// declared axis input and NOT keyed still forces a bypass (fail-closed) — no cross-user
// leak even though derives_from is in play.
func TestDerivesFrom_UndeclaredCookieStillBypasses(t *testing.T) {
	// `sid` is allow-listed (kept) but is neither keyed nor a derives_from input.
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@verified cookie verified-prod 1
	classify {ageverify} {
		derives_from cookie verified-prod
		when @verified -> 0
		default        -> 2
	}
	cookie_allow verified-prod sid
	cache_key default host url {ageverify}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		sid := "anon"
		if c, err := r.Cookie("sid"); err == nil {
			sid = c.Value
		}
		_, _ = io.WriteString(w, "private:"+sid)
	})
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// Alice carries an unkeyed identity cookie sid → must bypass (origin sees sid).
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"verified-prod=1; sid=alice"}})
	if got := a.Body.String(); got != "private:alice" {
		t.Fatalf("origin body = %q, want private:alice (sid forwarded, bypass)", got)
	}
	// A later anonymous request must NOT get Alice's body — proof nothing leaked.
	b := do(h, "GET", "http://test.local/p", nil)
	if b.Body.String() == "private:alice" {
		t.Fatal("CROSS-USER LEAK: anonymous request served Alice's private body")
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (Alice bypassed + anon fetched; nothing cached cross-user)", origin.hits.Load())
	}
}
