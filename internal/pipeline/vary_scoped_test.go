package pipeline

import (
	"net/http"
	"testing"
)

// TestVaryCoverageIsPerRequestRecipe guards the per-request scoping of the Vary
// safe-default: a `Vary: NAME` response is "covered" (cacheable) ONLY when the cache
// key recipe SELECTED for THIS request keys that header — not merely when some OTHER
// scoped recipe does. Using the global union of keyed header names would let a request
// on the `default` recipe cache a Vary variant it doesn't actually partition on, so a
// later request with a different X-Variant gets the wrong variant (cross-serving).
func TestVaryCoverageIsPerRequestRecipe(t *testing.T) {
	p := compileSrc(t, `example.com {
    @v2 path /v2/*
    cache_key @v2     host path header:X-Variant
    cache_key default host path
    cache_ttl default ttl 60s
}`)

	h := http.Header{}
	h.Set("Vary", "X-Variant")

	// DEFAULT recipe (host path) does NOT key X-Variant → a Vary: X-Variant response
	// must be refused, even though the @v2 recipe keys it.
	if d := p.EvalResponse(&Request{Path: "/x"}, 200, h); d.Cacheable {
		t.Error("Vary: X-Variant must be refused on the default recipe that doesn't key it (variant cross-serving)")
	}

	// @v2 recipe DOES key X-Variant → covered → cacheable.
	if d := p.EvalResponse(&Request{Path: "/v2/foo"}, 200, h); !d.Cacheable {
		t.Error("Vary: X-Variant should be cacheable when the selected (@v2) recipe keys it")
	}
}
