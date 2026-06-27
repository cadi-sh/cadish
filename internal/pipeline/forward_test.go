package pipeline

import (
	"net/http"
	"sort"
	"strings"
	"testing"
)

// COOKIE-NORM `forward` (alias `keep`) mode: a `derives_from cookie NAME… forward`
// row reads + keys + COVERS the cookie like strip-mode, but FORWARDS it to origin
// unchanged (does NOT strip). The token MUST be in the SELECTED recipe (same gate as
// strip-mode); when it is, the forwarded cookie is treated as covered so the request
// caches without a credential bypass. When the token is NOT in the selected recipe the
// cookie is NOT covered and falls through to the normal path (bypass / cookie_allow) —
// the critical fail-closed property: a forwarded-but-uncovered cookie never lands a
// per-user body under a shared key.

const forwardSrc = `example.com {
    @adultcookie cookie AdultContent 1
    classify {adult_php} {
        derives_from cookie AdultContent forward
        when @adultcookie -> 1
        default           -> 0
    }
    cookie_allow
    cache_key default host url {adult_php}
    cache_ttl default ttl 60s
}`

// A cookie declared BOTH strip (bare) and forward within ONE classify block is a loud
// compile error — the safe-default strip must never be silently downgraded to forward
// (R35). The recipe-scoped checkDerivedCookieModeConflict cannot see this because
// isForwardCookie collapses both rows to a single forward set; compileClassify catches it.
func TestForwardStripSameCookieSameBlockIsError(t *testing.T) {
	ce := compileErr(t, `example.com {
    @c cookie sess 1
    classify {axis} {
        derives_from cookie sess forward
        derives_from cookie sess
        when @c -> 1
        default -> 0
    }
    cookie_allow
    cache_key default host url {axis}
    cache_ttl default ttl 60s
}`)
	if !strings.Contains(ce.Msg, "sess") || !strings.Contains(ce.Msg, "both") {
		t.Fatalf("error must name the conflicting cookie and say it is declared both ways; got %q", ce.Msg)
	}
}

// Guard the legitimate cases the R35 fix must NOT break: a forward-only declaration and a
// strip-only declaration of a cookie each compile cleanly (the cookie is in derivesFrom
// for both, and for forward it is also in derivesForward — that overlap is NOT a conflict).
func TestForwardOnlyAndStripOnlyStillCompile(t *testing.T) {
	compileSrc(t, `example.com {
    @c cookie sess 1
    classify {axis} {
        derives_from cookie sess forward
        when @c -> 1
        default -> 0
    }
    cookie_allow
    cache_key default host url {axis}
    cache_ttl default ttl 60s
}`)
	compileSrc(t, `example.com {
    @c cookie sess 1
    classify {axis} {
        derives_from cookie sess
        when @c -> 1
        default -> 0
    }
    cookie_allow
    cache_key default host url {axis}
    cache_ttl default ttl 60s
}`)
}

//  1. A `forward` cookie is read pre-key, contributes to {TOKEN}, REMAINS in the origin
//     request (NOT stripped), and the request CACHES (no credential bypass).
func TestForwardCookieReadKeyedForwardedAndCaches(t *testing.T) {
	p := compileSrc(t, forwardSrc)
	req := dfReq("AdultContent=1; _ga=GA1.2.3")
	key := applyCookieFlow(p, req)

	// keyed by the normalized axis derived from the ORIGINAL cookie.
	if got := splitKey(key); got[len(got)-1] != "1" {
		t.Fatalf("{adult_php} must derive 1 from the original AdultContent cookie; key tail = %q (full %q)", got[len(got)-1], key)
	}
	// The forward cookie REMAINS in the (origin-bound) request; _ga (not allow-listed) is stripped.
	if v := req.Header.Get("Cookie"); v != "AdultContent=1" {
		t.Fatalf("a forward cookie must be FORWARDED to origin unchanged; Cookie=%q want %q", v, "AdultContent=1")
	}
	// And the request caches: the forward cookie is covered by {adult_php}.
	if p.BypassForCredentials(req) {
		t.Fatal("a forward-mode covered cookie must NOT trigger a credential bypass (it caches keyed by its axis)")
	}
}

//  2. CRITICAL SAFETY: a `forward` cookie whose token is NOT in the SELECTED recipe is
//     NOT covered → it behaves like an undeclared/kept cookie (bypass), NOT forwarded-and-
//     cached under a shared key.
func TestForwardCookieNotInSelectedRecipeBypasses(t *testing.T) {
	// {adult_php} appears ONLY in the @special recipe; the default recipe omits it. A
	// normal request selects `default`, so the forward axis is INACTIVE: the cookie is
	// kept (forward never strips) but UNCOVERED → must bypass (no shared-key store).
	src := `example.com {
    @adultcookie cookie AdultContent 1
    @special     path /special
    classify {adult_php} {
        derives_from cookie AdultContent forward
        when @adultcookie -> 1
        default           -> 0
    }
    cookie_allow AdultContent
    cache_key @special host url {adult_php}
    cache_key default host url
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)

	// default recipe: token inactive → cookie kept (forward) but UNCOVERED → bypass.
	req := dfReq("AdultContent=1")
	_ = applyCookieFlow(p, req)
	if v := req.Header.Get("Cookie"); v != "AdultContent=1" {
		t.Fatalf("a forward cookie is never stripped; Cookie=%q want kept", v)
	}
	if !p.BypassForCredentials(req) {
		t.Fatal("SAFETY: a forward cookie whose token is NOT in the selected recipe must BYPASS (never covered under a shared key)")
	}

	// @special recipe: token active → cookie kept AND covered → caches.
	sp := &Request{Method: "GET", Host: "example.com", Path: "/special", Header: http.Header{"Cookie": {"AdultContent=1"}}}
	_ = applyCookieFlow(p, sp)
	if v := sp.Header.Get("Cookie"); v != "AdultContent=1" {
		t.Fatalf("on @special the forward cookie must still be forwarded; Cookie=%q", v)
	}
	if p.BypassForCredentials(sp) {
		t.Fatal("on the @special recipe the forward cookie is covered → must cache (no bypass)")
	}
}

//  3. Two users with different AdultContent values get DIFFERENT cache entries (keyed by
//     the axis); a third unrelated cookie does not fragment the key and (when stripped by
//     cookie_allow) does not force a bypass.
func TestForwardCookieKeyVariesByAxis(t *testing.T) {
	p := compileSrc(t, forwardSrc)
	k1 := applyCookieFlow(p, dfReq("AdultContent=1"))
	k0 := applyCookieFlow(p, dfReq("AdultContent=0"))
	if k1 == k0 {
		t.Fatalf("AdultContent=1 (axis 1) and AdultContent=0 (axis 0) must key differently; both %q", k1)
	}
	// An unrelated tracking cookie (stripped by cookie_allow strip-all) must not fragment the key.
	kGa := applyCookieFlow(p, dfReq("AdultContent=1; _ga=GA9"))
	if kGa != k1 {
		t.Fatalf("a non-axis cookie must not fragment the normalized key: %q != %q", kGa, k1)
	}
}

//  4. A classify with a STRIP derives_from line AND a FORWARD derives_from line: the strip
//     cookie is removed, the forward cookie remains, both contribute to the key.
func TestForwardAndStripPerLineGranularity(t *testing.T) {
	src := `example.com {
    @strip   cookie StripMe yes
    @forward cookie KeepMe yes
    classify {axis} {
        derives_from cookie StripMe
        derives_from cookie KeepMe forward
        when @strip   -> 1
        when @forward -> 2
        default       -> 0
    }
    cookie_allow
    cache_key default host url {axis}
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	// Both cookies present: StripMe stripped, KeepMe forwarded; key derived from both.
	req := dfReq("StripMe=yes; KeepMe=yes; _ga=GA1")
	key := applyCookieFlow(p, req)
	if got := splitKey(key); got[len(got)-1] != "1" {
		t.Fatalf("{axis} must derive from the ORIGINAL cookies (StripMe wins first row); key tail=%q", got[len(got)-1])
	}
	if v := req.Header.Get("Cookie"); v != "KeepMe=yes" {
		t.Fatalf("strip cookie must be removed, forward cookie kept; Cookie=%q want %q", v, "KeepMe=yes")
	}
	if p.BypassForCredentials(req) {
		t.Fatal("the request must cache: StripMe stripped, KeepMe covered (forward)")
	}
}

//  5. SelectedDerivedStripCookies EXCLUDES forward cookies; SelectedDerivedForwardCookies
//     returns them. The two partitions are disjoint.
func TestForwardStripPartition(t *testing.T) {
	src := `example.com {
    @strip   cookie StripMe yes
    @forward cookie KeepMe yes
    classify {axis} {
        derives_from cookie StripMe
        derives_from cookie KeepMe forward
        when @strip   -> 1
        when @forward -> 2
        default       -> 0
    }
    cookie_allow
    cache_key default host url {axis}
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	req := dfReq("StripMe=yes; KeepMe=yes")
	strip := p.SelectedDerivedStripCookies(req)
	sort.Strings(strip)
	if len(strip) != 1 || strip[0] != "StripMe" {
		t.Fatalf("SelectedDerivedStripCookies = %v, want [StripMe] (forward excluded)", strip)
	}
	fwd := p.SelectedDerivedForwardCookies(req)
	sort.Strings(fwd)
	if len(fwd) != 1 || fwd[0] != "KeepMe" {
		t.Fatalf("SelectedDerivedForwardCookies = %v, want [KeepMe]", fwd)
	}
}

//  6. A SECOND uncovered cookie alongside a forward cookie still forces a bypass (only the
//     explicitly-forwarded, keyed cookie is covered).
func TestForwardCookieDoesNotCoverOthers(t *testing.T) {
	// cookie_allow keeps both AdultContent (forward) and uid (an identity cookie). uid is
	// neither keyed nor forward-declared → it must force a bypass even though AdultContent
	// is covered.
	src := `example.com {
    @adultcookie cookie AdultContent 1
    classify {adult_php} {
        derives_from cookie AdultContent forward
        when @adultcookie -> 1
        default           -> 0
    }
    cookie_allow AdultContent uid
    cache_key default host url {adult_php}
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	req := dfReq("AdultContent=1; uid=alice")
	_ = applyCookieFlow(p, req)
	if !p.BypassForCredentials(req) {
		t.Fatal("an uncovered identity cookie (uid) alongside a forward cookie must still BYPASS (forward covers ONLY its own keyed axis)")
	}
}

//  7. forward cookie sent more than once with DIFFERING values is NOT safely covered (the
//     classifier may have read a specific occurrence; the key is ambiguous) → bypass.
func TestForwardCookieMultipleOccurrencesBypasses(t *testing.T) {
	p := compileSrc(t, forwardSrc)
	// AdultContent sent twice with DIFFERENT values: genuinely ambiguous — the derived axis
	// could depend on which occurrence the classifier read — so the collapsed key cannot
	// safely cover it.
	req := dfReq("AdultContent=1; AdultContent=0")
	_ = applyCookieFlow(p, req)
	if !p.BypassForCredentials(req) {
		t.Fatal("a forward cookie sent multiple times with DIFFERING values must BYPASS (ambiguous axis) — fail-closed")
	}
}

// SPEC-DUP-COOKIE: a `derives_from … forward` cookie sent more than once with BYTE-IDENTICAL
// values is keyed by a DERIVED axis (occurrence-independent) and the origin sees N identical
// values, so no cross-user divergence is possible → covered, no bypass. A differing-value
// duplicate (TestForwardCookieMultipleOccurrencesBypasses above) and a raw-keyed duplicate
// (cookie_dup_test.go) still bypass. The source axis is {ageverify} ← `userType` forward,
// mirroring the real cutover case (a domain+host-scoped `userType=registered` sent twice).
const forwardUserTypeSrc = `example.com {
    @registered cookie userType registered
    classify {ageverify} {
        derives_from cookie userType forward
        when @registered -> 1
        default          -> 0
    }
    cookie_allow
    cache_key default host url {ageverify}
    cache_ttl default ttl 60s
}`

// 8. baseline — userType=registered once is covered (no bypass).
func TestForwardCookieSingleOccurrenceCaches(t *testing.T) {
	p := compileSrc(t, forwardUserTypeSrc)
	req := dfReq("userType=registered")
	_ = applyCookieFlow(p, req)
	if p.BypassForCredentials(req) {
		t.Fatal("a single forward-covered userType cookie must cache (covered by {ageverify}) — got bypass")
	}
}

//  9. SPEC-DUP-COOKIE core: userType=registered sent TWICE (same value) → covered (the
//     relaxation; would FAIL before this change).
func TestForwardCookieDuplicateSameValueCaches(t *testing.T) {
	p := compileSrc(t, forwardUserTypeSrc)
	req := dfReq("userType=registered; userType=registered")
	_ = applyCookieFlow(p, req)
	if p.BypassForCredentials(req) {
		t.Fatal("a forward-covered cookie sent twice with IDENTICAL values must CACHE (derived axis is occurrence-independent; origin sees N identical values) — got bypass")
	}
}

// 10. differing-value duplicate of the SAME forward axis still bypasses (ambiguous).
func TestForwardCookieDuplicateDifferentValueBypasses(t *testing.T) {
	p := compileSrc(t, forwardUserTypeSrc)
	req := dfReq("userType=registered; userType=guest")
	_ = applyCookieFlow(p, req)
	if !p.BypassForCredentials(req) {
		t.Fatal("a forward-covered cookie sent twice with DIFFERING values must BYPASS (the classifier may have read a specific occurrence) — fail-closed")
	}
}

// 11. another forward-covered cookie (AdultContent) sent twice with identical values caches.
func TestForwardCookieAdultContentDuplicateSameValueCaches(t *testing.T) {
	p := compileSrc(t, forwardSrc)
	req := dfReq("AdultContent=1; AdultContent=1")
	_ = applyCookieFlow(p, req)
	if p.BypassForCredentials(req) {
		t.Fatal("AdultContent forward-covered duplicate with identical values must CACHE — got bypass")
	}
}

//  12. a STRIPPED cookie sent twice is removed before the credential check → unaffected (the
//     request caches; the duplicate never reaches the coverage check). _ga is not allow-listed
//     under cookie_allow strip-all, so it is stripped regardless of the duplicate.
func TestForwardStrippedDuplicateUnaffected(t *testing.T) {
	p := compileSrc(t, forwardUserTypeSrc)
	req := dfReq("userType=registered; _ga=a; _ga=b")
	_ = applyCookieFlow(p, req)
	if v := req.Header.Get("Cookie"); strings.Contains(v, "_ga") {
		t.Fatalf("a non-allow-listed tracking cookie must be stripped before the check; Cookie=%q", v)
	}
	if p.BypassForCredentials(req) {
		t.Fatal("a stripped duplicate (_ga ×2) must not affect coverage — the forward-covered userType still caches")
	}
}
