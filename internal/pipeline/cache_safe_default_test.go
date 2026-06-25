package pipeline

import (
	"net/http"
	"testing"
	"time"
)

// safeDefaultSite caches everything for 5m with a broad `default` rule and no
// explicit set_cookie/hit_for_miss guard — the natural config that the safe-by-
// default refusal protects.
const safeDefaultSite = `example.com {
    cache_key path
    cache_ttl default ttl 5m
}`

// unsafeOverrideSite is the same broad config but with the operator opt-out
// (cache_unsafe), which restores the prior "cache whatever the rule matched"
// behavior.
const unsafeOverrideSite = `example.com {
    cache_unsafe
    cache_key path
    cache_ttl default ttl 5m
}`

// TestSafeDefaultSetCookieNotCached: a Set-Cookie response is refused by default
// even though `cache_ttl default ttl 5m` matched; with cache_unsafe it is cached.
func TestSafeDefaultSetCookieNotCached(t *testing.T) {
	req := &Request{Path: "/x"}

	p := compileSrc(t, safeDefaultSite)
	if d := p.EvalResponse(req, 200, respWithSetCookie("session=abc; Path=/")); d.Cacheable {
		t.Error("Set-Cookie response must NOT be cacheable by default")
	}
	// A clean response is still cached.
	if d := p.EvalResponse(req, 200, http.Header{}); !d.Cacheable || d.TTL != 5*time.Minute {
		t.Errorf("clean response should be cacheable 5m, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}

	// A Set-Cookie response is NEVER cacheable — NOT even under cache_unsafe (ironclad,
	// like Vary: *). The cookie is a per-user credential the origin is minting now.
	po := compileSrc(t, unsafeOverrideSite)
	if d := po.EvalResponse(req, 200, respWithSetCookie("session=abc; Path=/")); d.Cacheable {
		t.Error("a Set-Cookie response must NOT be cacheable even with cache_unsafe (ironclad)")
	}
	// cache_unsafe still overrides the OTHER refusals (e.g. a private response).
	hp := http.Header{}
	hp.Set("Cache-Control", "private")
	if d := po.EvalResponse(req, 200, hp); !d.Cacheable {
		t.Error("cache_unsafe should still cache a `private` (non-Set-Cookie) response")
	}
}

// TestSafeDefaultCacheControl: private/no-store/no-cache responses are refused by
// default; max-age=60 is fine; the token parser is not fooled by `private-data`.
func TestSafeDefaultCacheControl(t *testing.T) {
	req := &Request{Path: "/x"}
	p := compileSrc(t, safeDefaultSite)

	refuse := []string{"private", "no-store", "no-cache", "public, no-store", "max-age=60, private",
		"s-maxage=0", "public, s-maxage=0", "max-age=60, s-maxage=0"}
	for _, cc := range refuse {
		h := http.Header{}
		h.Set("Cache-Control", cc)
		if d := p.EvalResponse(req, 200, h); d.Cacheable {
			t.Errorf("Cache-Control %q must NOT be cacheable by default", cc)
		}
	}

	allow := []string{"max-age=60", "public", "public, max-age=300", "private-data", "no-cache-control-here", "s-maxage=10"}
	for _, cc := range allow {
		h := http.Header{}
		h.Set("Cache-Control", cc)
		if d := p.EvalResponse(req, 200, h); !d.Cacheable {
			t.Errorf("Cache-Control %q SHOULD be cacheable (no refusal token)", cc)
		}
	}

	// With cache_unsafe even private / s-maxage=0 is cached (the operator opt-out).
	po := compileSrc(t, unsafeOverrideSite)
	for _, cc := range []string{"private", "s-maxage=0"} {
		h := http.Header{}
		h.Set("Cache-Control", cc)
		if d := po.EvalResponse(req, 200, h); !d.Cacheable {
			t.Errorf("with cache_unsafe a %q response SHOULD be cacheable", cc)
		}
	}
}

// TestSafeDefaultVary: Vary: Cookie is refused; Vary: Accept-Encoding is allowed
// (cadish handles AE variance in its encode layer); Vary: * is never cached even
// with the override; a Vary header covered by the cache key is allowed.
func TestSafeDefaultVary(t *testing.T) {
	req := &Request{Path: "/x"}
	p := compileSrc(t, safeDefaultSite)

	h := http.Header{}
	h.Set("Vary", "Cookie")
	if d := p.EvalResponse(req, 200, h); d.Cacheable {
		t.Error("Vary: Cookie must NOT be cacheable by default")
	}

	h = http.Header{}
	h.Set("Vary", "Accept-Encoding")
	if d := p.EvalResponse(req, 200, h); !d.Cacheable {
		t.Error("Vary: Accept-Encoding SHOULD be cacheable (encode layer handles it)")
	}

	// Mixed: Accept-Encoding plus an uncovered header -> refuse.
	h = http.Header{}
	h.Set("Vary", "Accept-Encoding, Cookie")
	if d := p.EvalResponse(req, 200, h); d.Cacheable {
		t.Error("Vary: Accept-Encoding, Cookie must NOT be cacheable by default")
	}

	// Vary: * is never cacheable, even with the override.
	h = http.Header{}
	h.Set("Vary", "*")
	if d := p.EvalResponse(req, 200, h); d.Cacheable {
		t.Error("Vary: * must NEVER be cacheable")
	}
	po := compileSrc(t, unsafeOverrideSite)
	if d := po.EvalResponse(req, 200, h); d.Cacheable {
		t.Error("Vary: * must NEVER be cacheable even with cache_unsafe")
	}

	// A Vary header that IS part of the cache key is safe (one variant per key).
	pk := compileSrc(t, `example.com {
    cache_key path header:Accept-Language
    cache_ttl default ttl 5m
}`)
	h = http.Header{}
	h.Set("Vary", "Accept-Language")
	if d := pk.EvalResponse(req, 200, h); !d.Cacheable {
		t.Error("Vary header covered by the cache key SHOULD be cacheable")
	}
}

// TestCacheUnsafeCatalogPhase: the override directive is taught to the check catalog.
func TestSafeDefaultExistingHFMStillWorks(t *testing.T) {
	// The explicit set_cookie hit_for_miss path keeps working; the safe default does
	// not change a result the operator already handled.
	p := compileSrc(t, `example.com {
    @sc set_cookie
    cache_key path
    cache_ttl @sc hit_for_miss 30s
    cache_ttl default ttl 1h
}`)
	req := &Request{Path: "/x"}
	d := p.EvalResponse(req, 200, respWithSetCookie("session=abc"))
	if d.Cacheable {
		t.Error("set_cookie hit_for_miss should not be cacheable")
	}
	if d.HitForMiss != 30*time.Second {
		t.Errorf("hit_for_miss window should be 30s, got %v", d.HitForMiss)
	}
}
