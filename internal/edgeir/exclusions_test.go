package edgeir

import (
	"strings"
	"testing"
)

// excludableFor compiles a single-site Cadishfile and returns the always-computed
// route-excludable set from its coverage report.
func excludableFor(t *testing.T, src string) []string {
	t.Helper()
	p := compile(t, src)
	_, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	return rep.RouteExcludable
}

// irExclusionsFor returns the PROJECTED IR.RouteExclusions (populated only under the
// `bypass_passes` toggle).
func irExclusionsFor(t *testing.T, src string) []string {
	t.Helper()
	p := compile(t, src)
	ir, _, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	return ir.RouteExclusions
}

func hasPattern(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

// TestExcludablePathOnlyPassIsExcludable: a path-only unconditional pass with no other
// edge directive touching it IS excludable, and the toggle gates IR projection.
func TestExcludablePathOnlyPassIsExcludable(t *testing.T) {
	src := `example.com {
    pass path /transmit/*
    cache_ttl default ttl 1m grace 10m

    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	got := excludableFor(t, src)
	if !hasPattern(got, "example.com/transmit/*") {
		t.Fatalf("expected example.com/transmit/* excludable, got %v", got)
	}
	// Toggle off => not projected into the IR.
	if ir := irExclusionsFor(t, src); len(ir) != 0 {
		t.Fatalf("toggle off: IR.RouteExclusions must be empty, got %v", ir)
	}

	// Toggle on => projected into the IR.
	on := strings.Replace(src, "route  example.com/*", "route  example.com/*\n        bypass_passes", 1)
	if ir := irExclusionsFor(t, on); !hasPattern(ir, "example.com/transmit/*") {
		t.Fatalf("toggle on: expected example.com/transmit/* in IR, got %v", ir)
	}
}

// TestExcludableExactPath: an exact-path pass reduces to a host+path route (no '*').
func TestExcludableExactPath(t *testing.T) {
	src := `example.com {
    pass path /v3/cache/affiliates/promo/json
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	got := excludableFor(t, src)
	if !hasPattern(got, "example.com/v3/cache/affiliates/promo/json") {
		t.Fatalf("expected exact-path exclusion, got %v", got)
	}
}

// TestConditionalPassNotExcludable: a pass gated on a non-path condition (cookie) is
// NOT excludable — the worker must evaluate the condition.
func TestConditionalPassNotExcludable(t *testing.T) {
	src := `example.com {
    @loggedin cookie session
    pass @loggedin
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); len(got) != 0 {
		t.Fatalf("conditional (cookie) pass must not be excludable, got %v", got)
	}
}

// TestMixedOrPassNotExcludable: a pass whose OR scope mixes a path with a non-path
// matcher is NOT excludable (the non-path branch can pass any path).
func TestMixedOrPassNotExcludable(t *testing.T) {
	src := `example.com {
    @apath path /api/*
    @ahost host api.example.com
    pass @apath @ahost
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); len(got) != 0 {
		t.Fatalf("mixed OR pass must not be excludable, got %v", got)
	}
}

// TestPassWithRedirectNotExcludable: a path that ALSO has a redirect on it is NOT
// excludable (the edge would redirect, not just pass).
func TestPassWithRedirectNotExcludable(t *testing.T) {
	src := `example.com {
    pass path /go/*
    redirect @r 301 https://example.com/new
    @r path /go/old
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); len(got) != 0 {
		t.Fatalf("a passed path overlapping a redirect must not be excludable, got %v", got)
	}
}

// TestPassWithScopedHeaderStillExcludable: a scoped header on the same path does NOT
// disqualify it — the additive cadish server behind reproduces the header op for the
// route-excluded request, so excluding loses nothing.
func TestPassWithScopedHeaderStillExcludable(t *testing.T) {
	src := `example.com {
    pass path /assets/*
    @a path /assets/*
    header @a +X-Thing yes
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); !hasPattern(got, "example.com/assets/*") {
		t.Fatalf("a passed path with only a scoped header should still be excludable, got %v", got)
	}
}

// TestUnconditionalHeaderDoesNotBlock: an unconditional header op no longer blocks
// exclusions — the server behind applies it, so a pure-pass path is still excludable.
func TestUnconditionalHeaderDoesNotBlock(t *testing.T) {
	src := `example.com {
    pass path /transmit/*
    header X-Forwarded-Host {host}
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); !hasPattern(got, "example.com/transmit/*") {
		t.Fatalf("an unconditional header must NOT block exclusions (additive server reproduces it), got %v", got)
	}
}

// TestPassPlusHeaderPlusDefaultRouteExcludable mirrors the canonical additive demo: a
// pure path-only pass that ALSO carries a scoped header op AND a default `route ->
// origin` (+ a default cache_ttl) IS excludable — none of those are edge-unique.
func TestPassPlusHeaderPlusDefaultRouteExcludable(t *testing.T) {
	src := `example.com {
    upstream origin { to http://127.0.0.1:9999 }
    route -> origin
    cache_ttl default ttl 5m
    @hdr path /transmit* /v2/*
    header @hdr +X-Tag yes
    pass path /transmit*
    pass path /v2/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	got := excludableFor(t, src)
	if !hasPattern(got, "example.com/transmit*") || !hasPattern(got, "example.com/v2/*") {
		t.Fatalf("pass+header+default-route should yield both exclusions, got %v", got)
	}
}

// TestPassWithScopedCacheTTLNotExcludable: a scoped cache_ttl on the same path
// disqualifies it (operator intent to do something special there).
func TestPassWithScopedCacheTTLNotExcludable(t *testing.T) {
	src := `example.com {
    pass path /v3/*
    @sub path /v3/readmodel/*
    cache_ttl @sub ttl 1m grace 5m
    cache_ttl default ttl 1m grace 10m
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); len(got) != 0 {
		t.Fatalf("a passed path overlapping a scoped cache_ttl must not be excludable, got %v", got)
	}
}

// TestNonReducibleRegexPassNotExcludable: an alternation/char-class path_regex pass is
// NOT reducible to a CF glob, so not excludable.
func TestNonReducibleRegexPassNotExcludable(t *testing.T) {
	src := `example.com {
    @v23 path_regex (?i)^/v[23]/
    @alt path_regex ^/(foo|bar)
    pass @v23
    pass @alt
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); len(got) != 0 {
		t.Fatalf("non-reducible regex passes must not be excludable, got %v", got)
	}
}

// TestReducibleAnchoredLiteralRegexExcludable: an anchored-literal path_regex (no
// metacharacters) reduces to a prefix glob and IS excludable.
func TestReducibleAnchoredLiteralRegexExcludable(t *testing.T) {
	src := `example.com {
    @t path_regex (?i)^/transmit
    pass @t
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	got := excludableFor(t, src)
	if !hasPattern(got, "example.com/transmit*") {
		t.Fatalf("expected example.com/transmit* from anchored-literal regex, got %v", got)
	}
}

// TestOverlappingPrefixesCollapse: a broad prefix subsumes a more-specific one.
func TestOverlappingPrefixesCollapse(t *testing.T) {
	src := `example.com {
    pass path /v3/*
    pass path /v3/sub/*
    pass path /other/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	got := excludableFor(t, src)
	if hasPattern(got, "example.com/v3/sub/*") {
		t.Fatalf("the /v3/sub/* prefix should collapse under /v3/*, got %v", got)
	}
	if !hasPattern(got, "example.com/v3/*") || !hasPattern(got, "example.com/other/*") {
		t.Fatalf("expected /v3/* and /other/* to survive, got %v", got)
	}
}

// TestExclusionsCrossAllRouteHosts: every catch-all worker route host gets the
// carve-out; a non-catch-all route is not carved.
func TestExclusionsCrossAllRouteHosts(t *testing.T) {
	src := `example.com {
    pass path /transmit/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
        route  es.example.com/*
        route  api.example.com/special/*
    }
}`
	got := excludableFor(t, src)
	if !hasPattern(got, "example.com/transmit/*") || !hasPattern(got, "es.example.com/transmit/*") {
		t.Fatalf("expected carve-outs for both catch-all hosts, got %v", got)
	}
	if hasPattern(got, "api.example.com/special/transmit/*") || hasPattern(got, "api.example.com/transmit/*") {
		t.Fatalf("a non-catch-all route must not be carved, got %v", got)
	}
}

// TestPassWithScopedRouteStillExcludable: a path that is also `route`d to a non-default
// upstream IS excludable — the route-excluded request still reaches the cadish server
// behind, which reproduces the `route` and fetches the same backend. Routing is not
// edge-unique, so it no longer disqualifies.
func TestPassWithScopedRouteStillExcludable(t *testing.T) {
	src := `example.com {
    upstream captures { to http://captures:80 }
    @capt path /captures/*
    pass  @capt
    route @capt -> captures
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); !hasPattern(got, "example.com/captures/*") {
		t.Fatalf("a routed path should still be excludable (server behind reproduces the route), got %v", got)
	}
}

// TestMethodOnlyPassNotExcludable: a `pass method …` (a non-path condition) is not a
// path pattern and never produces an exclusion.
func TestMethodOnlyPassNotExcludable(t *testing.T) {
	src := `example.com {
    pass method POST PUT DELETE
    edge {
        zone   example.com
        worker w
        route  example.com/*
    }
}`
	if got := excludableFor(t, src); len(got) != 0 {
		t.Fatalf("a method-only pass must not produce exclusions, got %v", got)
	}
}

// explicitFor returns the host-crossed explicit `bypass` exclusion set + its overlap
// warnings from the coverage report.
func explicitFor(t *testing.T, src string) (patterns, warnings []string) {
	t.Helper()
	p := compile(t, src)
	_, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	return rep.RouteExcludableExplicit, rep.BypassOverlapWarnings
}

// TestExplicitBypassProjectsIntoIR: operator-declared `bypass` patterns land in
// RouteExclusions (host-crossed) WITHOUT requiring `bypass_passes`, and ALSO compose with
// the auto-derived set when `bypass_passes` is on.
func TestExplicitBypassProjectsIntoIR(t *testing.T) {
	src := `example.com {
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /transmit* /v2/*
    }
}`
	pats, _ := explicitFor(t, src)
	if !hasPattern(pats, "example.com/transmit*") || !hasPattern(pats, "example.com/v2/*") {
		t.Fatalf("explicit report set = %v, want both host-crossed", pats)
	}
	ir := irExclusionsFor(t, src)
	if !hasPattern(ir, "example.com/transmit*") || !hasPattern(ir, "example.com/v2/*") {
		t.Fatalf("explicit bypass must project into IR without bypass_passes, got %v", ir)
	}

	with := `example.com {
    pass path /captures/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /transmit*
        bypass_passes
    }
}`
	ir2 := irExclusionsFor(t, with)
	if !hasPattern(ir2, "example.com/transmit*") {
		t.Fatalf("explicit /transmit* missing from composed IR, got %v", ir2)
	}
	if !hasPattern(ir2, "example.com/captures/*") {
		t.Fatalf("auto-derived /captures/* missing from composed IR, got %v", ir2)
	}
}

// TestExplicitBypassCrossesAllRouteHosts: every catch-all worker route host gets the
// operator-declared carve-out; a non-catch-all route is not carved.
func TestExplicitBypassCrossesAllRouteHosts(t *testing.T) {
	src := `example.com {
    edge {
        zone   example.com
        worker w
        route  example.com/*
        route  es.example.com/*
        route  api.example.com/special/*
        bypass /transmit*
    }
}`
	pats, _ := explicitFor(t, src)
	if !hasPattern(pats, "example.com/transmit*") || !hasPattern(pats, "es.example.com/transmit*") {
		t.Fatalf("expected explicit carve-outs for both catch-all hosts, got %v", pats)
	}
	if hasPattern(pats, "api.example.com/special/transmit*") || hasPattern(pats, "api.example.com/transmit*") {
		t.Fatalf("a non-catch-all route must not be carved, got %v", pats)
	}
}

// TestExplicitBypassOverlapWarns: `bypass /v3*` overlapping a scoped cache_ttl on
// /v3/readmodel* emits the overlap WARNING and STILL includes the pattern.
func TestExplicitBypassOverlapWarns(t *testing.T) {
	src := `example.com {
    @rm path /v3/readmodel*
    cache_ttl @rm ttl 1m grace 5m
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /v3*
    }
}`
	pats, warns := explicitFor(t, src)
	if !hasPattern(pats, "example.com/v3*") {
		t.Fatalf("overlapping bypass must STILL be projected, got %v", pats)
	}
	if len(warns) == 0 {
		t.Fatalf("expected an overlap WARNING for bypass /v3* shadowing a cached path, got none")
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "/v3*") || !strings.Contains(joined, "/v3/readmodel*") {
		t.Fatalf("warning must name the bypass pattern and the cached path, got %q", joined)
	}
}

// TestExplicitBypassNoOverlapNoWarn: a non-overlapping `bypass /transmit*` produces no
// warning even when a scoped cache rule exists elsewhere.
func TestExplicitBypassNoOverlapNoWarn(t *testing.T) {
	src := `example.com {
    @rm path /v3/readmodel*
    cache_ttl @rm ttl 1m grace 5m
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /transmit*
    }
}`
	pats, warns := explicitFor(t, src)
	if !hasPattern(pats, "example.com/transmit*") {
		t.Fatalf("expected /transmit* exclusion, got %v", pats)
	}
	if len(warns) != 0 {
		t.Fatalf("non-overlapping bypass must not warn, got %v", warns)
	}
}

// TestAllRouteExcludableUnion (F-D4): rep.AllRouteExcludable returns the union of the
// auto-derived (bypass_passes) and explicit `bypass` no-script routes — the full set
// `cadish edge disable` must tear down. The explicit route is present even with no
// bypass_passes (declaring `bypass` is the opt-in), so disable can no longer leave it
// attached.
func TestAllRouteExcludableUnion(t *testing.T) {
	src := `example.com {
    pass path /captures/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /transmit*
        bypass_passes
    }
}`
	p := compile(t, src)
	_, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	all := rep.AllRouteExcludable()
	if !hasPattern(all, "example.com/transmit*") {
		t.Fatalf("AllRouteExcludable missing the explicit bypass route, got %v", all)
	}
	if !hasPattern(all, "example.com/captures/*") {
		t.Fatalf("AllRouteExcludable missing the auto-derived route, got %v", all)
	}

	// Explicit-only (no bypass_passes): the auto set is empty, but the explicit route
	// must STILL be in AllRouteExcludable so disable removes it (the F-D4 core case).
	explicitOnly := `example.com {
    pass path /captures/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /transmit*
    }
}`
	p2 := compile(t, explicitOnly)
	_, rep2, err := Project(p2)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if !hasPattern(rep2.AllRouteExcludable(), "example.com/transmit*") {
		t.Fatalf("explicit-only AllRouteExcludable must include the bypass route, got %v", rep2.AllRouteExcludable())
	}
}

// TestAllRouteExcludableNoCrossCollapse (F-D1-r2): when an auto-derived pass route
// (broader) would subsume an explicit bypass (narrower) and bypass_passes is OFF, enable
// creates the NARROW explicit route, so disable's AllRouteExcludable must keep BOTH (no
// cross-source coverage-collapse) — otherwise the created narrow route is orphaned.
func TestAllRouteExcludableNoCrossCollapse(t *testing.T) {
	src := `example.com {
    pass path /api/*
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /api/v2*
    }
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// bypass_passes OFF: enable projects only the explicit narrow route.
	if !hasPattern(ir.RouteExclusions, "example.com/api/v2*") {
		t.Fatalf("enable should create the explicit /api/v2* route, got %v", ir.RouteExclusions)
	}
	// disable's teardown set must include the created narrow route AND the auto broad one.
	all := rep.AllRouteExcludable()
	if !hasPattern(all, "example.com/api/v2*") {
		t.Fatalf("AllRouteExcludable dropped the created narrow route /api/v2* (orphan!): %v", all)
	}
	if !hasPattern(all, "example.com/api/*") {
		t.Fatalf("AllRouteExcludable missing the auto /api/* route: %v", all)
	}
}

// TestExplicitBypassDefaultCacheWarns (next#2): a `bypass` over a site cached by an
// UNCONDITIONAL `cache_ttl default` warns — cacheStorePathGlobs (scoped-only) reports
// nothing, so without this the silent POP-cache loss had no warning.
func TestExplicitBypassDefaultCacheWarns(t *testing.T) {
	src := `example.com {
    cache_ttl default ttl 1m
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /static*
    }
}`
	pats, warns := explicitFor(t, src)
	if !hasPattern(pats, "example.com/static*") {
		t.Fatalf("bypass must still be projected, got %v", pats)
	}
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "/static*") || !strings.Contains(joined, "default") {
		t.Fatalf("expected a default-cache overlap warning naming /static*, got %q", joined)
	}
}

// TestExplicitBypassStatusCacheWarns (F-D2-r2): a `bypass` over a site cached by a
// STATUS-scoped catch-all (`cache_ttl status 200`) warns — status_in is path-unconditional.
func TestExplicitBypassStatusCacheWarns(t *testing.T) {
	src := `example.com {
    cache_ttl status 200 ttl 5m
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /static*
    }
}`
	_, warns := explicitFor(t, src)
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "/static*") || !strings.Contains(joined, "default") {
		t.Fatalf("expected a default-cache overlap warning for a status-scoped store, got %q", joined)
	}
}

// TestExplicitBypassHFMDefaultNoFalseWarn (F-D2-r2): a hit-for-miss-only default stores
// no servable content, so a bypass forgoes nothing — no "POP caching lost" false warning.
func TestExplicitBypassHFMDefaultNoFalseWarn(t *testing.T) {
	src := `example.com {
    cache_ttl default hit_for_miss 30s
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /static*
    }
}`
	_, warns := explicitFor(t, src)
	for _, w := range warns {
		if strings.Contains(w, "caches by default") {
			t.Fatalf("HFM-only default must NOT fire a POP-caching-lost warning, got %q", w)
		}
	}
}

// TestExplicitBypassCorsDeliverOpWarns (F-D3-r2): a `bypass` over a path carrying a
// scoped `cors` (a deliver-phase op beyond strip_cookies) warns.
func TestExplicitBypassCorsDeliverOpWarns(t *testing.T) {
	src := `example.com {
    @s path /shop*
    cors @s https://app.example.com
    cache_ttl @s ttl 1m
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /shop*
    }
}`
	_, warns := explicitFor(t, src)
	if !strings.Contains(strings.Join(warns, "\n"), "deliver-phase op") {
		t.Fatalf("expected a deliver-op overlap warning for a scoped cors over bypass /shop*, got %q", warns)
	}
}

// TestExplicitBypassDeliverOpWarns (next#1): a `bypass` over a path carrying a
// deliver-phase op (strip_cookies) warns — the op is applied only by a cadish server
// behind the worker, lost against a non-cadish origin.
func TestExplicitBypassDeliverOpWarns(t *testing.T) {
	src := `example.com {
    @s path /shop*
    strip_cookies @s
    cache_ttl @s ttl 1m
    edge {
        zone   example.com
        worker w
        route  example.com/*
        bypass /shop*
    }
}`
	_, warns := explicitFor(t, src)
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "deliver-phase op") {
		t.Fatalf("expected a deliver-op overlap warning for bypass /shop*, got %q", joined)
	}
}
