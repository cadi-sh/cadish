package pipeline

import (
	"net/http"
	"testing"
)

// Finding 1 (round-3, SAFETY): the cache key is built by the recipe SELECTED on the
// PRE-strip request (recipe A). When a `cache_key` recipe's SELECTOR reads a cookie
// that is ALSO a `derives_from` input, StripDerivedCookies removes that cookie after
// the key is built — so RE-running selectKeyTokens on the now-stripped request (as the
// credential-coverage gate and the Vary gate used to) can pick a DIFFERENT recipe B.
// Validating coverage / Vary against recipe B while the body is stored under recipe A's
// key is a cross-user / cross-variant leak. The fix captures recipe A at EvalRequest and
// every later gate reuses it. These tests fail before the fix.

// leakSrc: @premium selects recipe A {host url {tier}} when premium=1; {tier} derives_from
// premium, so the strip removes premium post-key. The default recipe keys cookie:uid. A
// request `premium=1; uid=alice` builds its key under recipe A (which does NOT key uid),
// but after the strip the buggy re-selection lands on the default recipe (which keys uid)
// and wrongly concludes the credential is covered → caches a per-user body under a
// uid-agnostic key → another user with the same premium value reads alice's body.
const leakSrc = `example.com {
    @premium cookie premium 1
    classify {tier} {
        derives_from cookie premium
        when @premium -> p
        default       -> f
    }
    cookie_allow premium uid
    cache_key @premium host url {tier}
    cache_key default host url cookie:uid
    cache_ttl default ttl 60s
}`

func TestRecipeReselectCredentialCoverageUsesBuiltRecipe(t *testing.T) {
	p := compileSrc(t, leakSrc)
	req := &Request{Method: "GET", Host: "example.com", Path: "/p",
		Header: http.Header{"Cookie": {"premium=1; uid=alice"}}}
	key := applyCookieFlow(p, req)

	// Recipe A built the key (host url {tier}); it does NOT key uid, so the request
	// MUST bypass (uid is an unkeyed identity cookie under the recipe that owns the key).
	if !p.BypassForCredentials(req) {
		t.Fatalf("Finding 1 LEAK: must BYPASS — coverage must be judged against the recipe that BUILT the key (host url {tier}, no uid), not the post-strip default recipe that keys cookie:uid; key=%q cookie=%q", key, req.Header.Get("Cookie"))
	}
}

// Finding 1 (forward-axis variant, SAFETY): recipe A (host url {tier}) is selected when
// premium=1; {tier} derives_from premium (strip), so premium is removed post-key. The
// FALLBACK default recipe B (host url {loyal}) carries a `derives_from … forward` axis on
// a DIFFERENT allow-listed cookie `loyalty`. After the strip, a naive re-selection of the
// FORWARD set lands on recipe B and marks `loyalty` "covered" — though recipe A (which
// built the key) has no forward axis and does NOT key loyalty. Coverage must be judged
// against recipe A: loyalty is an unkeyed kept cookie → the request MUST bypass. This is
// the scoped case the single-recipe 45-cookie-forward fixture cannot reach.
const fwdLeakSrc = `example.com {
    @premium cookie premium 1
    classify {tier} {
        derives_from cookie premium
        when @premium -> p
        default       -> f
    }
    classify {loyal} {
        derives_from cookie loyalty forward
        when cookie loyalty gold -> g
        default                  -> z
    }
    cookie_allow premium loyalty
    cache_key @premium host url {tier}
    cache_key default host url {loyal}
    cache_ttl default ttl 60s
}`

func TestRecipeReselectForwardCoverageUsesBuiltRecipe(t *testing.T) {
	p := compileSrc(t, fwdLeakSrc)
	req := &Request{Method: "GET", Host: "example.com", Path: "/p",
		Header: http.Header{"Cookie": {"premium=1; loyalty=gold"}}}
	key := applyCookieFlow(p, req)

	// Recipe A built the key (host url {tier}, no forward axis); loyalty is a kept,
	// unkeyed cookie under that recipe → the request MUST bypass. The post-strip default
	// recipe B (which forwards+covers loyalty via {loyal}) must NOT be consulted.
	if !p.BypassForCredentials(req) {
		t.Fatalf("Finding 1 LEAK (forward variant): must BYPASS — forward coverage must be judged against the recipe that BUILT the key (host url {tier}, no forward axis), not the post-strip default recipe that forwards loyalty via {loyal}; key=%q cookie=%q", key, req.Header.Get("Cookie"))
	}
}

// Symmetric Vary path: recipe A (host url {tier}) does NOT key X-Variant; the default
// recipe keys header:X-Variant. A `Vary: X-Variant` response on a request that selected
// recipe A must be REFUSED — the post-strip re-selection (default, which keys X-Variant)
// must not be used to (wrongly) accept it.
func TestRecipeReselectVaryUsesBuiltRecipe(t *testing.T) {
	src := `example.com {
    @premium cookie premium 1
    classify {tier} {
        derives_from cookie premium
        when @premium -> p
        default       -> f
    }
    cookie_allow premium
    cache_key @premium host url {tier}
    cache_key default host url header:X-Variant
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	req := &Request{Method: "GET", Host: "example.com", Path: "/p",
		Header: http.Header{"Cookie": {"premium=1"}}}
	_ = applyCookieFlow(p, req) // EvalRequest captures recipe A; strip removes premium

	h := http.Header{}
	h.Set("Vary", "X-Variant")
	if d := p.EvalResponse(req, 200, h); d.Cacheable {
		t.Fatal("Finding 1 LEAK: Vary X-Variant must be REFUSED — the recipe that built the key (host url {tier}) does not key X-Variant; the post-strip default recipe must not be consulted")
	}
}

// No cross-user collision: two users with different premium values that both resolve to
// the SAME {tier} bucket but carry DISTINCT identity cookies (uid) must not share a
// cacheable entry — both bypass, so neither stores a per-user body under the shared key.
func TestRecipeReselectNoSharedStore(t *testing.T) {
	p := compileSrc(t, leakSrc)
	alice := &Request{Method: "GET", Host: "example.com", Path: "/p",
		Header: http.Header{"Cookie": {"premium=1; uid=alice"}}}
	bob := &Request{Method: "GET", Host: "example.com", Path: "/p",
		Header: http.Header{"Cookie": {"premium=1; uid=bob"}}}
	_ = applyCookieFlow(p, alice)
	_ = applyCookieFlow(p, bob)
	if !p.BypassForCredentials(alice) || !p.BypassForCredentials(bob) {
		t.Fatal("Finding 1 LEAK: both premium users carry an unkeyed uid under the key-building recipe → both must bypass (no shared store)")
	}
}
