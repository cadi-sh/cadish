package pipeline

import (
	"net/http"
	"sort"
	"strings"
	"testing"
)

// COOKIE-NORM (derives_from): a classify token may declare the request cookies it
// consumes. cadish then (1) derives the token from the ORIGINAL cookies (surviving
// any cookie_allow strip), (2) keys by the normalized token, and (3) strips the
// declared cookies from the request before the credential check + origin fetch — the
// Varnish "derive → unset Cookie → key normalized" cardinality collapse, fail-closed
// via auto-strip (no coverage-extension).

const derivesFromSrc = `example.com {
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
}`

func dfReq(cookie string) *Request {
	h := http.Header{}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return &Request{Method: "GET", Host: "example.com", Path: "/p", Header: h}
}

// applyCookieFlow mirrors the server handler ordering: cookie_allow filter (RECV) →
// EvalRequest (key) → StripDerivedCookies (post-key, pre-credential). It returns the
// captured key and the request whose Header has been mutated exactly as the handler
// would mutate it before BypassForCredentials + the origin fetch.
func applyCookieFlow(p *Pipeline, req *Request) (key string) {
	if filtered, active := p.FilterRequestCookies(req.Header.Get("Cookie")); active {
		if filtered == "" {
			req.Header.Del("Cookie")
		} else {
			req.Header.Set("Cookie", filtered)
		}
	}
	rd := p.EvalRequest(req)
	if p.HasDerivesFrom() {
		p.StripDerivedCookies(req)
	}
	return rd.CacheKey
}

//  1. The derives_from cookie is READ pre-strip: the classifier resolves from the
//     ORIGINAL cookie even though cookie_allow is strip-all.
func TestDerivesFromReadBeforeStrip(t *testing.T) {
	p := compileSrc(t, derivesFromSrc)
	key := applyCookieFlow(p, dfReq("verified-prod=1; _ga=GA1.2.3"))
	parts := splitKey(key)
	if got := parts[len(parts)-1]; got != "0" {
		t.Fatalf("classify must derive {ageverify}=0 from the ORIGINAL verified-prod cookie despite cookie_allow strip-all; key tail = %q (full %q)", got, key)
	}
}

// 2. After keying, the declared cookie is ABSENT from the (origin-bound) request.
func TestDerivesFromStrippedFromOrigin(t *testing.T) {
	p := compileSrc(t, derivesFromSrc)
	req := dfReq("verified-prod=1; userType=registered; _ga=GA1")
	_ = applyCookieFlow(p, req)
	if v := req.Header.Get("Cookie"); v != "" {
		// verified-prod + userType are derives_from (stripped); _ga is not allow-listed
		// (cookie_allow strip-all) so it is stripped too. Net: no Cookie reaches origin.
		t.Fatalf("declared derives_from cookies must be stripped before origin; Cookie=%q", v)
	}
	if p.BypassForCredentials(req) {
		t.Fatal("after stripping the derived cookies the request must NOT bypass (origin is anonymous)")
	}
}

// 3. The request CACHES (no credential bypass) keyed by {ageverify}.
func TestDerivesFromCachesNoBypass(t *testing.T) {
	p := compileSrc(t, derivesFromSrc)
	req := dfReq("verified-prod=1")
	_ = applyCookieFlow(p, req)
	if p.BypassForCredentials(req) {
		t.Fatal("a request whose only cookie is a derives_from input must cache (the cookie is stripped) — got bypass")
	}
}

//  4. Two requests differing only in verified-prod get DIFFERENT cache entries; a
//     third cookie (_ga) does NOT fragment the key.
func TestDerivesFromKeyVariesAndIgnoresTracking(t *testing.T) {
	p := compileSrc(t, derivesFromSrc)
	k1 := applyCookieFlow(p, dfReq("verified-prod=1"))
	k0 := applyCookieFlow(p, dfReq("verified-prod=0"))
	if k1 == k0 {
		t.Fatalf("verified-prod=1 (ageverify 0) and verified-prod=0 (ageverify 2) must key differently; both %q", k1)
	}
	// Adding an unrelated tracking cookie must not change the key.
	kGa := applyCookieFlow(p, dfReq("verified-prod=1; _ga=GA1.2.99999"))
	if kGa != k1 {
		t.Fatalf("a non-axis cookie (_ga) must not fragment the normalized key: %q != %q", kGa, k1)
	}
}

//  5. An UNDECLARED identity cookie still bypasses (fail-closed): an axis that does
//     not list all its inputs leaks nothing — the unlisted cookie forces a bypass.
func TestDerivesFromUndeclaredCookieBypasses(t *testing.T) {
	// Here `sid` is an identity cookie NOT declared by derives_from and NOT keyed.
	// cookie_allow keeps it (so it is not stripped by cookie_allow), and it is not a
	// derived axis input → it must force a bypass.
	src := `example.com {
    @verified cookie verified-prod 1
    classify {ageverify} {
        derives_from cookie verified-prod
        when @verified -> 0
        default        -> 2
    }
    cookie_allow verified-prod sid
    cache_key default host url {ageverify}
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	req := dfReq("verified-prod=1; sid=alice")
	_ = applyCookieFlow(p, req)
	if !p.BypassForCredentials(req) {
		t.Fatal("an allow-listed-but-unkeyed identity cookie (sid) that is NOT a derives_from input must still BYPASS (fail-closed)")
	}
}

//  6. GATE: a derives_from token NOT in the SELECTED key recipe must NOT strip — the
//     request behaves exactly as today (the cookie is keyed raw or bypasses).
func TestDerivesFromGateInactiveWhenNotInSelectedRecipe(t *testing.T) {
	// {ageverify} appears only in the @special recipe; the default recipe omits it.
	// A normal request selects `default`, so derives_from is INACTIVE and the cookie
	// must NOT be stripped (and, being unkeyed under cookie_allow, must bypass).
	src := `example.com {
    @verified cookie verified-prod 1
    @special  path /special
    classify {ageverify} {
        derives_from cookie verified-prod
        when @verified -> 0
        default        -> 2
    }
    cookie_allow verified-prod
    cache_key @special host url {ageverify}
    cache_key default host url
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	// default recipe: token inactive → cookie NOT stripped → survives.
	req := dfReq("verified-prod=1")
	_ = applyCookieFlow(p, req)
	if v := req.Header.Get("Cookie"); v == "" {
		t.Fatal("gate: a derives_from cookie whose token is NOT in the selected recipe must NOT be stripped")
	}
	if !p.BypassForCredentials(req) {
		t.Fatal("gate: the un-stripped, un-keyed cookie must bypass exactly as today")
	}
	// @special recipe: token active → cookie stripped → caches.
	sp := &Request{Method: "GET", Host: "example.com", Path: "/special", Header: http.Header{"Cookie": {"verified-prod=1"}}}
	_ = applyCookieFlow(p, sp)
	if v := sp.Header.Get("Cookie"); v != "" {
		t.Fatalf("on the @special recipe the active derives_from cookie must be stripped; Cookie=%q", v)
	}
	if p.BypassForCredentials(sp) {
		t.Fatal("on the @special recipe the request must cache (no bypass)")
	}
}

//  7. Cardinality: the normalized axis collapses the keyspace. The raw cookie product
//     of N verified-prod values × M tracking values collapses to the bounded axis.
func TestDerivesFromCardinalityCollapse(t *testing.T) {
	p := compileSrc(t, derivesFromSrc)
	keys := map[string]bool{}
	for _, vp := range []string{"0", "1", "2", "3"} {
		for ga := 0; ga < 50; ga++ {
			req := dfReq("verified-prod=" + vp + "; _ga=GA" + itoa(ga))
			keys[applyCookieFlow(p, req)] = true
		}
	}
	// verified-prod=1 -> ageverify 0; everything else -> ageverify 2 (default). So the
	// 4*50 = 200 raw combinations collapse to exactly 2 normalized cache entries.
	if len(keys) != 2 {
		t.Fatalf("normalized axis must collapse 200 raw cookie combos to 2 entries, got %d", len(keys))
	}
}

// HasDerivesFrom / fast-path: a site with no derives_from declares none, so the
// strip is a no-op and the path is unchanged.
func TestNoDerivesFromIsInert(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_key host path
    cache_ttl default ttl 60s
}`)
	if p.HasDerivesFrom() {
		t.Fatal("a site with no derives_from must report HasDerivesFrom()==false")
	}
	req := dfReq("a=1; b=2")
	if p.StripDerivedCookies(req) {
		t.Fatal("StripDerivedCookies must be a no-op when no derives_from is declared")
	}
	if got := req.Header.Get("Cookie"); got != "a=1; b=2" {
		t.Fatalf("StripDerivedCookies must not touch the Cookie header when inert; got %q", got)
	}
}

// SelectedDerivedStripCookies reports the active axis inputs for a request's recipe.
func TestSelectedDerivedStripCookies(t *testing.T) {
	p := compileSrc(t, derivesFromSrc)
	got := p.SelectedDerivedStripCookies(dfReq("verified-prod=1"))
	sort.Strings(got)
	want := []string{"userType", "verified-prod"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("SelectedDerivedStripCookies = %v, want %v", got, want)
	}
}

// TestDerivesFrom_BothModeConflictRejected (Finding 4) guards that a cookie declared
// BOTH forward-mode (`derives_from cookie X forward`) and strip-mode (bare
// `derives_from cookie X`) across two classify tokens that CO-OCCUR in a cache_key
// recipe is a positioned COMPILE error. Before the fix this config compiled but Go
// (forward wins → keeps X) and the edge (builds the strip set without subtracting the
// forward list → strips X) diverged — a Go≠JS parity break + operator footgun. Making
// the config invalid in both check and run renders the edge divergence unreachable.
func TestDerivesFrom_BothModeConflictRejected(t *testing.T) {
	src := `example.com {
    @a cookie X aval
    @b cookie X bval
    classify {ca} {
        derives_from cookie X forward
        when @a -> 1
        default -> 0
    }
    classify {cb} {
        derives_from cookie X
        when @b -> 1
        default -> 0
    }
    cache_key default host url {ca} {cb}
    cache_ttl default ttl 60s
}`
	ce := compileErr(t, src)
	if !strings.Contains(ce.Msg, "X") {
		t.Fatalf("error = %q, want it to name the conflicting cookie X", ce.Msg)
	}
	if ce.Pos.Line == 0 {
		t.Errorf("compile error must be positioned, got %+v", ce)
	}
}

// TestDerivesFrom_SingleModeStillCompiles (Finding 4) guards that the same cookie in a
// SINGLE mode across tokens — forward-only or strip-only — still compiles; only the
// genuine both-modes conflict is rejected.
func TestDerivesFrom_SingleModeStillCompiles(t *testing.T) {
	forwardOnly := `example.com {
    @a cookie X aval
    @b cookie X bval
    classify {ca} {
        derives_from cookie X forward
        when @a -> 1
        default -> 0
    }
    classify {cb} {
        derives_from cookie X forward
        when @b -> 1
        default -> 0
    }
    cache_key default host url {ca} {cb}
    cache_ttl default ttl 60s
}`
	stripOnly := `example.com {
    @a cookie X aval
    @b cookie X bval
    classify {ca} {
        derives_from cookie X
        when @a -> 1
        default -> 0
    }
    classify {cb} {
        derives_from cookie X
        when @b -> 1
        default -> 0
    }
    cache_key default host url {ca} {cb}
    cache_ttl default ttl 60s
}`
	_ = compileSrc(t, forwardOnly)
	_ = compileSrc(t, stripOnly)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
