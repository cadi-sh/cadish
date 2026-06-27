package pipeline

import (
	"net/http"
	"testing"
	"time"
)

// respWithSetCookie builds a response header carrying the given Set-Cookie lines.
func respWithSetCookie(lines ...string) http.Header {
	h := http.Header{}
	for _, l := range lines {
		h.Add("Set-Cookie", l)
	}
	return h
}

// TestSetCookieMatcherPresence: a bare `set_cookie` matcher fires when the response
// carries ANY Set-Cookie header, and can drive a cache_ttl hit_for_miss so a
// session-bearing response is never cached. Without Set-Cookie the default applies.
func TestSetCookieMatcherPresence(t *testing.T) {
	p := compileSrc(t, `example.com {
    @hascookie set_cookie
    cache_key path
    cache_ttl @hascookie hit_for_miss 0s
    cache_ttl default      ttl 1h
}`)

	req := &Request{Path: "/x"}

	// A response that sets a cookie must NOT be cacheable.
	if d := p.EvalResponse(req, 200, respWithSetCookie("sessionid=abc; Path=/")); d.Cacheable {
		t.Error("a response with Set-Cookie should not be cacheable")
	}

	// A response with no Set-Cookie falls through to the default (cacheable, 1h).
	if d := p.EvalResponse(req, 200, http.Header{}); !d.Cacheable || d.TTL != time.Hour {
		t.Errorf("no Set-Cookie should be cacheable ttl 1h, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}

	// A nil response header (e.g. a bodyless negative entry) does not match and
	// must not panic — it falls through to the default.
	if d := p.EvalResponse(req, 200, nil); !d.Cacheable || d.TTL != time.Hour {
		t.Errorf("nil header should fall through to default, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}
}

// TestSetCookieMatcherByName: `set_cookie NAME` fires only when a cookie of that
// name is set, so an operator can scope the no-cache to just the session cookie.
func TestSetCookieMatcherByName(t *testing.T) {
	p := compileSrc(t, `example.com {
    @session set_cookie sessionid
    cache_key path
    cache_ttl @session hit_for_miss 0s
    cache_ttl default     ttl 1h
}`)

	req := &Request{Path: "/x"}

	// Sets the named cookie -> not cacheable.
	if d := p.EvalResponse(req, 200, respWithSetCookie("sessionid=abc; HttpOnly")); d.Cacheable {
		t.Error("Set-Cookie sessionid should not be cacheable")
	}

	// Sets a different cookie -> @session does not match -> the per-rule guard does
	// not fire. But caching is SAFE BY DEFAULT, so any Set-Cookie still refuses the
	// shared cache (this is the cross-user-leak fix); the operator must opt in with
	// cache_unsafe to cache it. See TestSafeDefaultSetCookieNotCached.
	if d := p.EvalResponse(req, 200, respWithSetCookie("prefs=dark; Path=/")); d.Cacheable {
		t.Error("an unrelated Set-Cookie should NOT be cached by default (safe-by-default)")
	}
	// Even cache_unsafe does NOT cache a Set-Cookie response — the refusal is IRONCLAD
	// (a Set-Cookie is a per-user credential the origin is minting now). cache_unsafe
	// governs the OTHER refusals (private/no-store/Vary), not Set-Cookie.
	pu := compileSrc(t, `example.com {
    cache_unsafe
    @session set_cookie sessionid
    cache_key path
    cache_ttl @session hit_for_miss 0s
    cache_ttl default     ttl 1h
}`)
	if d := pu.EvalResponse(req, 200, respWithSetCookie("prefs=dark; Path=/")); d.Cacheable {
		t.Errorf("a Set-Cookie response must NOT cache even with cache_unsafe (ironclad), got cacheable=%v", d.Cacheable)
	}

	// No Set-Cookie at all -> cacheable default.
	if d := p.EvalResponse(req, 200, http.Header{}); !d.Cacheable {
		t.Error("no Set-Cookie should be cacheable")
	}
}

// TestStripCookiesMakesSetCookieCacheable pins the Varnish `unset beresp.http.Set-Cookie`
// equivalent: a Set-Cookie response is refused by default (ironclad — not even cache_unsafe
// lifts it), but a `strip_cookies` rule covering it removes the cookie before store/deliver,
// so the now-cookieless response becomes cacheable. This is the EXPLICIT, per-class opt-in
// that lets a cookie-stamping origin be cached safely — you can't cache a Set-Cookie by
// accident, only by declaring the cookie controlled.
func TestStripCookiesMakesSetCookieCacheable(t *testing.T) {
	p := compileSrc(t, `example.com {
    @assets path_regex \.(css|js)$
    cache_key path
    cache_ttl default ttl 1h
    strip_cookies @assets
}`)

	cookie := respWithSetCookie("sid=abc; Path=/")

	// A covered class (.css) strips the cookie pre-cache -> cacheable.
	if d := p.EvalResponse(&Request{Path: "/app.css"}, 200, cookie); !d.Cacheable || d.TTL != time.Hour {
		t.Errorf("strip_cookies-covered Set-Cookie response must be cacheable (ttl 1h), got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}

	// An UNcovered class (.html) keeps the cookie -> refused (the ironclad default).
	if d := p.EvalResponse(&Request{Path: "/page.html"}, 200, cookie); d.Cacheable {
		t.Error("an uncovered Set-Cookie response must NOT be cacheable (no strip_cookies => never stored)")
	}
}

// TestStripCookiesSetCookieIroncladEvenCacheUnsafe: even with cache_unsafe, an UNcovered
// Set-Cookie response is never cacheable — only strip_cookies (controlling the cookie) lifts
// the refusal, never the cache_unsafe flag.
func TestStripCookiesSetCookieIroncladEvenCacheUnsafe(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_unsafe
    cache_key path
    cache_ttl default ttl 1h
}`)
	if d := p.EvalResponse(&Request{Path: "/x"}, 200, respWithSetCookie("sid=abc")); d.Cacheable {
		t.Error("cache_unsafe must NOT cache a Set-Cookie response (ironclad); only strip_cookies lifts it")
	}
}

// TestSetCookieNeverCachedUnderRespHeaderTTLRule (Minor 2) pins the safe default against
// a `resp_header`-scoped cache_ttl tier: a response selected by `cache_ttl resp_header
// X-Powered-By Express ttl 1m grace 2w` that ALSO carries Set-Cookie (or Cache-Control:
// private) is STILL refused — the ironclad never-cache-a-credential default wins over the
// TTL tier. Structurally guaranteed (Set-Cookie/private are refused regardless of which
// TTL rule matched); this is the explicit regression guard.
func TestSetCookieNeverCachedUnderRespHeaderTTLRule(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_key path
    cache_ttl resp_header X-Powered-By Express ttl 1m grace 2w
    cache_ttl default ttl 1h
}`)
	req := &Request{Path: "/x"}

	// Sanity: the resp_header tier IS selected for an Express response without a cookie
	// (so the test below actually exercises that tier, not the default).
	plain := http.Header{"X-Powered-By": {"Express"}}
	if d := p.EvalResponse(req, 200, plain); !d.Cacheable || d.TTL != time.Minute {
		t.Fatalf("Express response (no cookie) should hit the resp_header tier (cacheable ttl 1m), got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}

	// Same tier, but the response sets a cookie -> NEVER cached (credential safe default).
	withCookie := http.Header{"X-Powered-By": {"Express"}, "Set-Cookie": {"sid=abc; Path=/"}}
	if d := p.EvalResponse(req, 200, withCookie); d.Cacheable {
		t.Error("a Set-Cookie response must NOT be cached even under a resp_header cache_ttl tier (safe default wins)")
	}

	// And a Cache-Control: private response under the same tier is likewise refused.
	private := http.Header{"X-Powered-By": {"Express"}, "Cache-Control": {"private"}}
	if d := p.EvalResponse(req, 200, private); d.Cacheable {
		t.Error("a Cache-Control: private response must NOT be cached even under a resp_header cache_ttl tier")
	}
}

// TestSetCookieScopesCompile: set_cookie is a response-phase matcher, so it may
// scope the origin-response directives (cache_ttl, storage) AND the deliver
// directives (header, strip_cookies, cors).
func TestSetCookieScopesCompile(t *testing.T) {
	compileSrc(t, `example.com {
    @sc set_cookie
    cache_key path
    cache_ttl @sc hit_for_miss 0s
    storage   @sc -> ram
    header    @sc X-Had-Cookie yes
    strip_cookies @sc
    cors      @sc *
}`)
}

// TestSetCookieRequestPhaseErrors: scoping a request-phase directive with a
// set_cookie matcher is a compile error (the response isn't known in RECV/KEY).
func TestSetCookieRequestPhaseErrors(t *testing.T) {
	cases := map[string]string{
		"pass": `example.com {
    @sc set_cookie
    pass @sc
}`,
		"route": `example.com {
    upstream u { to http://h:80 }
    @sc set_cookie
    route @sc -> u
}`,
		"purge": `example.com {
    @sc set_cookie
    purge when @sc
}`,
		"request_header": `example.com {
    @sc set_cookie
    header @sc X-Foo bar
    cache_key path
}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if err := compileErr(t, src); err == nil {
				t.Fatalf("expected a compile error for set_cookie scoping %s", name)
			}
		})
	}
}
