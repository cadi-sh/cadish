package pipeline

import (
	"strings"
	"testing"
)

// TestCacheKeyGeoToken: the {geo} key token renders Request.Geo, so two requests
// from different geo classes get different cache keys (and same class shares).
func TestCacheKeyGeoToken(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key host path {geo}\n}")
	if !p.UsesGeoToken() {
		t.Fatal("UsesGeoToken() = false, want true")
	}
	us := p.EvalRequest(&Request{Host: "h", Path: "/x", Geo: "US"}).CacheKey
	es := p.EvalRequest(&Request{Host: "h", Path: "/x", Geo: "ES"}).CacheKey
	if us == es {
		t.Fatalf("{geo} did not vary the key: both = %q", us)
	}
	if !strings.Contains(us, "US") {
		t.Errorf("US key %q does not contain the geo class", us)
	}
	// Empty Geo (no source) renders an empty token, no panic.
	_ = p.EvalRequest(&Request{Host: "h", Path: "/x"}).CacheKey
}

func TestUsesGeoTokenFalse(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key host path\n}")
	if p.UsesGeoToken() {
		t.Error("UsesGeoToken() = true, want false")
	}
}
