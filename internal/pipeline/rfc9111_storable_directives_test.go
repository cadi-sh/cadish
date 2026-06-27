package pipeline

import (
	"net/http"
	"testing"
)

// storableSite caches everything for 5m with a broad `default` rule — the same
// shape cache_safe_default_test uses, so these assertions exercise the SHAREABILITY
// gate (safelyShareable / hasUncacheableCC) on an already-Cacheable response.
const storableSite = `example.com {
    cache_key path
    cache_ttl default ttl 5m
}`

// TestStorableNonRefusalDirectives pins the DELIBERATE exclusions in hasUncacheableCC
// (ADR D97 / RFC 9111 §5.2.2). A SHARED cache MAY store these responses while fresh;
// the directives that only constrain serving STALE (must-revalidate / proxy-revalidate,
// and a POSITIVE s-maxage) are NOT storage refusals in cadish's operator-authoritative
// model — `cache_ttl` drives freshness and an explicit `grace` drives stale-serving.
// `immutable` and `public` are likewise storable. The companion serve-stale behavior is
// pinned end-to-end in internal/server (must-revalidate / s-maxage under grace).
func TestStorableNonRefusalDirectives(t *testing.T) {
	req := &Request{Path: "/x"}
	p := compileSrc(t, storableSite)

	storable := []string{
		"must-revalidate",             // §5.2.2.1: only forbids serving stale, not storing
		"proxy-revalidate",            // §5.2.2.8: shared-cache analogue, same
		"must-revalidate, max-age=60", // still storable; grace decides stale-serve
		"s-maxage=10",                 // POSITIVE s-maxage is a freshness hint cache_ttl overrides
		"s-maxage=10, public",         //
		"immutable",                   // §5.2.2.6: don't-revalidate-while-fresh; fresh serve only
		"public",                      // §5.2.2.9
		"public, max-age=300",         //
	}
	for _, cc := range storable {
		h := http.Header{}
		h.Set("Cache-Control", cc)
		if d := p.EvalResponse(req, 200, h); !d.Cacheable {
			t.Errorf("Cache-Control %q SHOULD be storable (D97: not a shared-cache storage refusal)", cc)
		}
	}

	// A no-store/private/no-cache directive ALONGSIDE one of the above still REFUSES:
	// the absolute-refusal directive wins (fail-safe), even paired with must-revalidate.
	refuse := []string{
		"must-revalidate, no-store",
		"proxy-revalidate, private",
		"public, no-cache",
		"immutable, no-store",
		"s-maxage=0, must-revalidate",
	}
	for _, cc := range refuse {
		h := http.Header{}
		h.Set("Cache-Control", cc)
		if d := p.EvalResponse(req, 200, h); d.Cacheable {
			t.Errorf("Cache-Control %q must NOT be storable (a no-store/private/no-cache/s-maxage=0 wins)", cc)
		}
	}
}
