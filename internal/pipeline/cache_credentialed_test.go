package pipeline

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// credReq builds a Request carrying a Cookie header (and the given path).
func credReq(path, cookie string) *Request {
	return &Request{Path: path, Header: http.Header{"Cookie": {cookie}}}
}

// markCred runs CacheCredentialedMatches so the request is evaluated exactly as the
// server does at the bypass decision (the scope is path-based here, so EvalResponse
// re-evaluates it identically). Returns the match result.
func markCred(p *Pipeline, req *Request) bool { return p.CacheCredentialedMatches(req) }

const credSrc = `example.com {
    @rm path_regex ^/v3/readmodel/cache/
    cache_credentialed @rm
    cache_key path
    cache_ttl @rm from_header X-Cache-Ttl
    cache_ttl default hit_for_miss 0s
}`

// TestCacheCredentialedPositiveSignalStores: a credentialed request in a cache_credentialed
// scope whose response FIRES the in-scope cache_ttl (X-Cache-Ttl present) is cached under the
// SHARED key, even WITH Pragma: no-cache + a past Expires + a no-store Cache-Control — the
// positive signal force-overrides the weak refusals (the custom-VCL return(hash) analog).
func TestCacheCredentialedPositiveSignalStores(t *testing.T) {
	p := compileSrc(t, credSrc)
	req := credReq("/v3/readmodel/cache/home", "session=abc")
	if !markCred(p, req) {
		t.Fatal("request should match the cache_credentialed scope")
	}
	// The credential bypass must be SKIPPED for this request by the server; the pipeline's
	// BypassForCredentials still reports true (it is the server that consults CacheCredentialed
	// to skip it) — assert the match is what flips it.
	h := http.Header{
		"X-Cache-Ttl":   {"60"},
		"Pragma":        {"no-cache"},
		"Expires":       {"Thu, 01 Jan 1981 00:00:00 GMT"},
		"Cache-Control": {"no-store, private"},
	}
	d := p.EvalResponse(req, 200, h)
	if !d.Cacheable || d.TTL != 60*time.Second {
		t.Fatalf("positive signal must store under the shared key, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}
	if !d.CredentialedStore {
		t.Error("CredentialedStore must be set so the server strips the weak control headers on store+deliver")
	}
	if d.ForcedPrivate {
		t.Error("cache_credentialed is a deliberate opt-in to SHARE; must NOT mark ForcedPrivate")
	}
}

// TestCacheCredentialedFailClosedNoSignal: same scope, a response with NO X-Cache-Ttl and NO
// Set-Cookie is NOT stored (no positive signal) — the fail-closed property that makes a
// forgotten-Set-Cookie per-user route safe.
func TestCacheCredentialedFailClosedNoSignal(t *testing.T) {
	p := compileSrc(t, credSrc)
	req := credReq("/v3/readmodel/cache/favorites", "session=abc")
	markCred(p, req)
	d := p.EvalResponse(req, 200, http.Header{"Content-Type": {"application/json"}})
	if d.Cacheable {
		t.Fatal("no positive in-scope signal ⇒ must NOT store (fail-closed)")
	}
}

// TestCacheCredentialedSetCookieWithSignalStores: the LIVE-EVIDENCE case — a real shared
// endpoint emits Set-Cookie (a tracking cookie) ALONGSIDE X-Cache-Ttl. The positive signal
// FORCE-OVERRIDES and STRIPS the Set-Cookie (the VCL `unset set-cookie`), so the response is
// STORED under the shared key (CredentialedStore=true; the server strips Set-Cookie on
// store+deliver). cadish matches the VCL here — NOT stricter.
func TestCacheCredentialedSetCookieWithSignalStores(t *testing.T) {
	p := compileSrc(t, credSrc)
	req := credReq("/v3/readmodel/cache/onlineusersnumber", "session=abc")
	markCred(p, req)
	h := http.Header{
		"X-Cache-Ttl":   {"60"},
		"Set-Cookie":    {"FLYING_SPAGUETTI_MONSTER_PRODUCTION=track; Path=/"},
		"Cache-Control": {"no-store, no-cache, must-revalidate"},
		"Pragma":        {"no-cache"},
	}
	d := p.EvalResponse(req, 200, h)
	if !d.Cacheable || d.TTL != 60*time.Second {
		t.Fatalf("Set-Cookie + X-Cache-Ttl must STORE (signal overrides+strips the cookie), got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}
	if !d.CredentialedStore {
		t.Error("CredentialedStore must be set so the server strips Set-Cookie + weak headers on store+deliver")
	}
}

// TestCacheCredentialedSetCookieNoSignalNotStored: the per-user `favorites` case — Set-Cookie
// but NO X-Cache-Ttl ⇒ no positive signal ⇒ NOT stored (fail-closed via the signal gate).
func TestCacheCredentialedSetCookieNoSignalNotStored(t *testing.T) {
	p := compileSrc(t, credSrc)
	req := credReq("/v3/readmodel/cache/favorites", "session=abc")
	markCred(p, req)
	h := http.Header{"Set-Cookie": {"session=fresh; Path=/; HttpOnly"}}
	if d := p.EvalResponse(req, 200, h); d.Cacheable {
		t.Fatal("Set-Cookie WITHOUT a positive signal must NOT store (the per-user favorites case)")
	}
}

// TestCacheCredentialedVaryWithSignalStores: an uncovered Vary is NOT a refusal when the
// positive signal fired — the signal is the operator's explicit shared opt-in (faithful to the
// VCL). Without the signal it does not store (the signal is the sole gate).
func TestCacheCredentialedVaryWithSignalStores(t *testing.T) {
	p := compileSrc(t, credSrc)
	req := credReq("/v3/readmodel/cache/home", "session=abc")
	markCred(p, req)
	if d := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": {"60"}, "Vary": {"Cookie"}}); !d.Cacheable {
		t.Fatal("Vary: Cookie + X-Cache-Ttl must STORE in a cache_credentialed scope (signal is the gate)")
	}
	if d := p.EvalResponse(req, 200, http.Header{"Vary": {"Cookie"}}); d.Cacheable {
		t.Fatal("Vary: Cookie WITHOUT a positive signal must NOT store (fail-closed)")
	}
}

// TestCacheCredentialedAuthorization: v1 covers Authorization too — a request with
// Authorization (no Cookie) in a cache_credentialed scope + positive signal + shareable
// response is cached shared; with Set-Cookie or no signal it is not.
func TestCacheCredentialedAuthorization(t *testing.T) {
	p := compileSrc(t, credSrc)
	req := &Request{Path: "/v3/readmodel/cache/home", Header: http.Header{"Authorization": {"Bearer xyz"}}}
	if !markCred(p, req) {
		t.Fatal("authorization request should match the scope")
	}
	if d := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": {"30"}}); !d.Cacheable || d.TTL != 30*time.Second {
		t.Fatalf("authorization + positive signal ⇒ store, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}
	// Authorization + Set-Cookie + signal ⇒ STILL stored (signal overrides+strips the cookie).
	if d := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": {"30"}, "Set-Cookie": {"s=1"}}); !d.Cacheable {
		t.Fatal("authorization + Set-Cookie + signal ⇒ stored shared (cookie stripped on store+deliver)")
	}
	if d := p.EvalResponse(req, 200, http.Header{}); d.Cacheable {
		t.Fatal("authorization + no signal ⇒ not stored")
	}
}

// TestCacheCredentialedGuardBCacheUnsafeCannotThin: with a GLOBAL cache_unsafe, a `private`
// response with NO Set-Cookie and NO positive signal must NOT store in a cache_credentialed
// scope (cache_unsafe cannot thin the refusal in scope). Regression: OUTSIDE the scope,
// cache_unsafe still lifts `private`.
func TestCacheCredentialedGuardBCacheUnsafeCannotThin(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_unsafe
    @rm path_regex ^/v3/readmodel/cache/
    @other path /other
    cache_credentialed @rm
    cache_key path
    cache_ttl @rm from_header X-Cache-Ttl
    cache_ttl @other ttl 1h
}`)
	// In-scope: a private response with NO positive in-scope signal must NOT store despite a
	// global cache_unsafe — the cred precedence never consults cache_unsafe (Guard B).
	in := credReq("/v3/readmodel/cache/x", "session=abc")
	markCred(p, in)
	if d := p.EvalResponse(in, 200, http.Header{"Cache-Control": {"private"}}); d.Cacheable {
		t.Fatal("Guard B: in a cache_credentialed scope, cache_unsafe must NOT make a private no-signal response store")
	}
	// Out-of-scope: cache_unsafe still lifts `private` (the @other rule fires, ttl 1h).
	out := &Request{Path: "/other", Header: http.Header{}}
	markCred(p, out)
	if d := p.EvalResponse(out, 200, http.Header{"Cache-Control": {"private"}}); !d.Cacheable || !d.ForcedPrivate {
		t.Fatalf("regression: outside the scope cache_unsafe must still lift private (ForcedPrivate), got cacheable=%v forcedPrivate=%v", d.Cacheable, d.ForcedPrivate)
	}
}

// liveCredSrc is the REAL brand-a.example config shape (D101 live-exploit repro): a scoped
// `from_header X-Cache-Ttl` per-response signal rule co-existing with a STATIC
// `cache_ttl default ttl 60s grace 10m`. The static default is the trap: it sets
// Cacheable=true for an in-scope response that carries NO X-Cache-Ttl, which (before the
// fail-closed fix) leaked the credentialed body under the shared key.
const liveCredSrc = `example.com {
    @rm path_regex ^/v3/readmodel/cache/
    cache_credentialed @rm
    cache_key path
    cache_ttl @rm from_header X-Cache-Ttl
    cache_ttl default ttl 60s grace 10m
}`

// TestCacheCredentialedStaticDefaultNoSignalNotStored is the cross-user-leak regression
// (the failing-then-fixed test). A credentialed in-scope request whose origin 200 carries
// NO X-Cache-Ttl, NO Set-Cookie, and NO uncacheable Cache-Control falls onto the static
// `default ttl 60s` (Cacheable=true, perResponseSignal=false). The fail-closed gate MUST
// refuse it: a static TTL is NOT authorization to share a credentialed response.
func TestCacheCredentialedStaticDefaultNoSignalNotStored(t *testing.T) {
	p := compileSrc(t, liveCredSrc)
	req := credReq("/v3/readmodel/cache/favorites", "session=abc")
	markCred(p, req)
	d := p.EvalResponse(req, 200, http.Header{"Content-Type": {"application/json"}})
	if d.Cacheable {
		t.Fatalf("LEAK: in a cache_credentialed scope a static default ttl must NOT store a no-signal credentialed response (got cacheable=%v ttl=%v)", d.Cacheable, d.TTL)
	}
	if d.TTL != 0 || d.Grace != 0 || d.MaxStale != 0 {
		t.Fatalf("fail-closed must zero the windows, got ttl=%v grace=%v maxStale=%v", d.TTL, d.Grace, d.MaxStale)
	}
}

// TestCacheCredentialedStaticDefaultWithSignalStillStores is the legit-path regression
// guard: with the SAME static-default config, an in-scope response that DOES carry
// X-Cache-Ttl still fires the scoped from_header rule, stores under the shared key, and
// strips Set-Cookie/weak controls (CredentialedStore). The fail-closed fix must not touch it.
func TestCacheCredentialedStaticDefaultWithSignalStillStores(t *testing.T) {
	p := compileSrc(t, liveCredSrc)
	req := credReq("/v3/readmodel/cache/home", "session=abc")
	markCred(p, req)
	d := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": {"60"}, "Set-Cookie": {"s=1"}})
	if !d.Cacheable || d.TTL != 60*time.Second {
		t.Fatalf("legit signal path must still store, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}
	if !d.CredentialedStore {
		t.Error("CredentialedStore must remain set so the server strips Set-Cookie + weak headers")
	}
}

// TestCacheCredentialedStaticDefaultOutOfScopeUnaffected: a request to a path OUTSIDE the
// cache_credentialed scope under the SAME config still uses the normal path — the static
// `default ttl 60s` caches a shareable response as before. The fail-closed gate is scoped, so
// it must not regress ordinary caching of traffic the directive does not cover.
func TestCacheCredentialedStaticDefaultOutOfScopeUnaffected(t *testing.T) {
	p := compileSrc(t, liveCredSrc)
	req := &Request{Path: "/static/banner.json", Header: http.Header{}}
	if markCred(p, req) {
		t.Fatal("an out-of-scope path must NOT match the cache_credentialed scope")
	}
	d := p.EvalResponse(req, 200, http.Header{"Content-Type": {"application/json"}})
	if !d.Cacheable || d.TTL != 60*time.Second {
		t.Fatalf("out-of-scope request must cache under the static default as before, got cacheable=%v ttl=%v", d.Cacheable, d.TTL)
	}
}

// TestCacheCredentialedGuardACompileError: cache_credentialed and strip_cookies covering the
// SAME scope is a positioned compile error (strip_cookies would disarm the Set-Cookie hard
// refusal under the shared key).
func TestCacheCredentialedGuardACompileError(t *testing.T) {
	ce := compileErr(t, `example.com {
    @rm path_regex ^/v3/readmodel/cache/
    cache_credentialed @rm
    strip_cookies @rm
    cache_key path
    cache_ttl @rm from_header X-Cache-Ttl
}`)
	if ce.Pos.Line == 0 {
		t.Error("Guard A compile error must be positioned")
	}
	if !strings.Contains(ce.Msg, "strip_cookies") || !strings.Contains(ce.Msg, "cache_credentialed") {
		t.Errorf("Guard A error should name both directives, got %q", ce.Msg)
	}
}

// TestCacheCredentialedUnscopedRejected: an unscoped cache_credentialed is a compile error
// (it is a SCOPED opt-out; a global form would make ALL credentialed traffic authoritative).
func TestCacheCredentialedUnscopedRejected(t *testing.T) {
	_ = compileErr(t, `example.com {
    cache_credentialed
    cache_key path
}`)
}

// TestCacheCredentialedResponsePhaseMatcherRejected: a response-phase matcher cannot scope it
// (the directive gates a RECV-time decision).
func TestCacheCredentialedResponsePhaseMatcherRejected(t *testing.T) {
	_ = compileErr(t, `example.com {
    @sc set_cookie
    cache_credentialed @sc
    cache_key path
}`)
}

// TestCacheCredentialedDefaultUnchanged: WITHOUT the directive, an identical credentialed
// request still bypasses and the response shareability gate is unchanged.
func TestCacheCredentialedDefaultUnchanged(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_key path
    cache_ttl default from_header X-Cache-Ttl
}`)
	req := credReq("/v3/readmodel/cache/home", "session=abc")
	if markCred(p, req) {
		t.Fatal("no directive ⇒ no cache_credentialed match")
	}
	if !p.BypassForCredentials(req) {
		t.Fatal("without cache_credentialed, a cookie-bearing request the key does not cover must still bypass")
	}
	// A no-store private response is still refused (normal safe default), even with X-Cache-Ttl.
	if d := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": {"60"}, "Set-Cookie": {"s=1"}}); d.Cacheable {
		t.Fatal("normal safe-default: a Set-Cookie response is refused")
	}
}
