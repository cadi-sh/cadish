package pipeline

import "testing"

// Finding 5: an INLINE geo / upstream_healthy matcher written directly in an
// `upgrade @scope` rule must be seen by the compile pre-pass (computeUsesGeo /
// computeNeedsPoolHealth) — otherwise the pre-pass never injects the geo / pool-health
// view and the matcher fails closed, so the tunnel silently never engages.
//
// Inline matchers are anonymous (NOT in the named-matcher map), so forEachScope is the
// ONLY place they can be discovered — which is exactly the omission this pins. A NAMED
// matcher would be found via p.matchers regardless, so these tests deliberately use the
// inline form.

func TestUpgradeInlineUpstreamHealthyNeedsPoolHealth(t *testing.T) {
	src := `x {
	upgrade upstream_healthy cache_pool
}
`
	p := compileSrc(t, src)
	if !p.NeedsPoolHealth() {
		t.Fatal("an inline upstream_healthy matcher in `upgrade @scope` must set NeedsPoolHealth() (else it fails closed)")
	}
}

func TestUpgradeInlineGeoUsesGeoToken(t *testing.T) {
	src := `x {
	upgrade geo continent EU
}
`
	p := compileSrc(t, src)
	if !p.UsesGeoToken() {
		t.Fatal("an inline geo matcher in `upgrade @scope` must set UsesGeoToken() (else the geo pre-pass never runs and it fails closed)")
	}
}
