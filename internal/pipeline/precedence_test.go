package pipeline

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// This file pins the RULE-PRECEDENCE contract of the request pipeline: which rule
// wins within a phase (first-match-wins, source order) and which directive kind wins
// across kinds (respond > redirect > pass, the RECV terminal ladder). These are guard
// tests — a future refactor that flips an iteration direction or an early break/return
// must turn one of these red.

// --- Cross-kind RECV terminal ladder: respond > redirect > pass --------------------

// TestPrecedenceRespondBeatsRedirectSamePath pins that a `respond` matching the same
// path as a `redirect` wins (respond loop runs to completion, returning, BEFORE the
// redirect loop). docs/pipeline.md: "respond is checked first so an exact-path respond
// can pre-empt a broader redirect."
func TestPrecedenceRespondBeatsRedirectSamePath(t *testing.T) {
	p := compileSrc(t, `x {
		redirect ^/thing 301 https://{host}/moved
		respond /thing 200 "stay"
	}
`)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/thing"})
	if dec.Synthetic == nil {
		t.Fatalf("respond must win over a same-path redirect; got Synthetic=nil, Redirect=%+v", dec.Redirect)
	}
	if dec.Redirect != nil {
		t.Errorf("Redirect must be nil when respond wins, got %+v", dec.Redirect)
	}
	if dec.Synthetic.Status != 200 || dec.Synthetic.Body != "stay" {
		t.Errorf("Synthetic = %+v, want {200 stay}", dec.Synthetic)
	}
}

// TestPrecedenceRespondBeatsPass pins that a matching `respond` short-circuits before
// the `pass` loop is even reached (respond returns immediately). A request matching
// both must get the synthetic, never a cache bypass.
func TestPrecedenceRespondBeatsPass(t *testing.T) {
	p := compileSrc(t, `x {
		pass path /health
		respond /health 200 "OK"
	}
`)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/health"})
	if dec.Synthetic == nil {
		t.Fatalf("respond must short-circuit before pass; got Synthetic=nil, Pass=%v", dec.Pass)
	}
	if dec.Pass {
		t.Errorf("Pass must be false when respond wins (respond returns before the pass loop)")
	}
}

// TestPrecedenceRedirectBeatsPass pins that a matching `redirect` short-circuits before
// the `pass` loop (redirect returns immediately, after respond, before pass).
func TestPrecedenceRedirectBeatsPass(t *testing.T) {
	p := compileSrc(t, `x {
		pass path /old
		redirect ^/old 301 https://{host}/new
	}
`)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/old"})
	if dec.Redirect == nil {
		t.Fatalf("redirect must short-circuit before pass; got Redirect=nil, Pass=%v", dec.Pass)
	}
	if dec.Pass {
		t.Errorf("Pass must be false when redirect wins (redirect returns before the pass loop)")
	}
}

// --- First-match-wins within the respond phase -------------------------------------

// TestPrecedenceRespondFirstMatchWins pins that when two respond rules both match, the
// FIRST in source order wins (the loop returns on the first match).
func TestPrecedenceRespondFirstMatchWins(t *testing.T) {
	p := compileSrc(t, `x {
		@all path /*
		respond @all 200 "first"
		respond /thing 503 "second"
	}
`)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/thing"})
	if dec.Synthetic == nil || dec.Synthetic.Body != "first" {
		t.Fatalf("first matching respond must win, got %+v", dec.Synthetic)
	}
}

// --- First-match-wins within the redirect phase ------------------------------------

// TestPrecedenceRedirectFirstMatchWins pins source-order first-match for redirect: an
// earlier broad regex wins over a later, more specific one.
func TestPrecedenceRedirectFirstMatchWins(t *testing.T) {
	p := compileSrc(t, `x {
		redirect ^/a 301 https://{host}/broad
		redirect ^/a/b 302 https://{host}/specific
	}
`)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/a/b"})
	if dec.Redirect == nil {
		t.Fatal("expected a redirect")
	}
	if dec.Redirect.Status != 301 || !strings.HasSuffix(dec.Redirect.Location, "/broad") {
		t.Errorf("first matching redirect must win, got %+v", dec.Redirect)
	}
}

// --- upgrade implies pass ----------------------------------------------------------

// TestPrecedenceUpgradeImpliesPass pins that a matching `upgrade` rule sets BOTH Upgrade
// and Pass (a tunnel is off the caching path).
func TestPrecedenceUpgradeImpliesPass(t *testing.T) {
	p := compileSrc(t, `x {
		@ws path /ws/*
		upgrade @ws
	}
`)
	dec := p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/ws/chat"})
	if !dec.Upgrade || !dec.Pass {
		t.Errorf("upgrade must imply pass; Upgrade=%v Pass=%v", dec.Upgrade, dec.Pass)
	}
}

// --- cache_ttl first-match-wins + safe-default error refusal -----------------------

// TestPrecedenceTTLFirstMatchWins pins source-order first-match for cache_ttl: an
// earlier scoped rule wins over a later one that would also match.
func TestPrecedenceTTLFirstMatchWins(t *testing.T) {
	p := compileSrc(t, `x {
		@a path /a/*
		@all path /*
		cache_ttl @a   ttl 1h
		cache_ttl @all ttl 5m
		cache_ttl default ttl 30s
	}
`)
	req := &Request{Method: "GET", Host: "h", Path: "/a/x"}
	got := p.EvalResponse(req, 200, http.Header{}).TTL
	if got != time.Hour {
		t.Errorf("TTL = %v, want 1h (@a wins over @all by source order)", got)
	}
}

// TestPrecedenceTTLExplicitStatusVsBroadScope pins the SAFE-BY-DEFAULT interaction with
// first-match-wins for an uncacheable error (5xx): a BROAD selector that matches first
// refuses to STORE the error (it wins, but the win is "do not cache"), and it does NOT
// fall through to a later explicit `status` rule. The explicit `status 500` rule still
// caches the error for any request the broad rule does NOT cover. This is the documented
// first-match-wins composed with the NEG-ALL safe default — pinned so a future change to
// the break/continue is a conscious decision, not an accident.
func TestPrecedenceTTLExplicitStatusVsBroadScope(t *testing.T) {
	p := compileSrc(t, `x {
		@api path /api/*
		cache_ttl @api ttl 1h
		cache_ttl status 500 ttl 5m
		cache_ttl default ttl 10m
	}
`)
	// /api request returning 500: @api matches FIRST. It is a broad (non-status) selector,
	// so the NEG-ALL safe default refuses to store the 5xx AND does not fall through to
	// the explicit `status 500` rule. Result: not cacheable.
	api500 := p.EvalResponse(&Request{Method: "GET", Host: "h", Path: "/api/x"}, 500, http.Header{})
	if api500.Cacheable || api500.TTL != 0 {
		t.Errorf("/api 500: Cacheable=%v TTL=%v, want not cacheable (broad @api wins and refuses the 5xx)", api500.Cacheable, api500.TTL)
	}
	// /api request returning 200: @api wins normally → 1h.
	api200 := p.EvalResponse(&Request{Method: "GET", Host: "h", Path: "/api/x"}, 200, http.Header{})
	if !api200.Cacheable || api200.TTL != time.Hour {
		t.Errorf("/api 200: Cacheable=%v TTL=%v, want 1h", api200.Cacheable, api200.TTL)
	}
	// /other request returning 500: @api does NOT match; the EXPLICIT `status 500` rule is
	// reached and DOES cache the error (an explicit positive status selector may store a
	// 5xx). This proves the explicit rule is not globally dead — it fires where reached.
	other500 := p.EvalResponse(&Request{Method: "GET", Host: "h", Path: "/other"}, 500, http.Header{})
	if !other500.Cacheable || other500.TTL != 5*time.Minute {
		t.Errorf("/other 500: Cacheable=%v TTL=%v, want 5m (explicit status 500 rule caches it)", other500.Cacheable, other500.TTL)
	}
}

// --- storage first-match-wins ------------------------------------------------------

// TestPrecedenceStorageFirstMatchWins pins source-order first-match for storage tier.
func TestPrecedenceStorageFirstMatchWins(t *testing.T) {
	p := compileSrc(t, `x {
		@a path /a/*
		@all path /*
		cache_ttl default ttl 1h
		storage @a   -> ram
		storage @all -> disk
		storage default -> disk
	}
`)
	got := p.EvalResponse(&Request{Method: "GET", Host: "h", Path: "/a/x"}, 200, http.Header{}).StoreTier
	if got != "ram" {
		t.Errorf("StoreTier = %q, want ram (@a wins over @all)", got)
	}
}

// --- cache_key: two scoped recipes both match -> first wins ------------------------

// TestPrecedenceCacheKeyTwoScopedFirstWins pins that when TWO scoped cache_key recipes
// both match a request, the earlier one in source order builds the key (the gateway
// same-path-precedence bug class).
func TestPrecedenceCacheKeyTwoScopedFirstWins(t *testing.T) {
	p := compileSrc(t, `x {
		@a path /a/*
		@all path /*
		cache_key @a   host path
		cache_key @all host url
		cache_key default host method
	}
`)
	req := &Request{Method: "GET", Host: "h", Path: "/a/x", Query: url.Values{"q": {"1"}}}
	got := p.EvalRequest(req).CacheKey
	want := strings.Join([]string{"h", "/a/x"}, keyTokenSep) // @a: host path (query dropped)
	if got != want {
		t.Errorf("key = %q, want %q (@a wins over @all; query must be dropped)", got, want)
	}
}

// --- strip_cookies is a boolean first-match (any match -> true) ---------------------

// TestPrecedenceStripCookiesAnyMatch pins that strip_cookies is an OR: any matching rule
// sets StripCookies (and the loop breaks on the first).
func TestPrecedenceStripCookiesAnyMatch(t *testing.T) {
	p := compileSrc(t, `x {
		@a path /a/*
		cache_ttl default ttl 1h
		strip_cookies @a
	}
`)
	dec := p.EvalDeliver(&Request{Method: "GET", Host: "h", Path: "/a/x"}, http.Header{}, CacheStatusMiss)
	if !dec.StripCookies {
		t.Error("StripCookies must be true when an @a strip rule matches")
	}
	dec = p.EvalDeliver(&Request{Method: "GET", Host: "h", Path: "/b"}, http.Header{}, CacheStatusMiss)
	if dec.StripCookies {
		t.Error("StripCookies must be false when no strip rule matches")
	}
}

// --- only one cors per site (duplicate is a compile error, like encode) ------------

// TestPrecedenceDuplicateCorsErrors pins that a SECOND cors directive is a compile error
// rather than a silent overwrite (which would quietly drop the first, scoped cors).
func TestPrecedenceDuplicateCorsErrors(t *testing.T) {
	ce := compileErr(t, `x {
		@api path /api/*
		@web path /web/*
		cors @api https://api.example.com
		cors @web https://web.example.com
	}
`)
	if !strings.Contains(ce.Error(), "only one cors") {
		t.Errorf("error = %q, want substring %q", ce.Error(), "only one cors")
	}
}
