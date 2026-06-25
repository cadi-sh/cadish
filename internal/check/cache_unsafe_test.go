package check

import "testing"

// TestCacheUnsafeCatalog verifies the `cache_unsafe` override (safe-by-default
// caching opt-out) is taught to the catalog: it is a SETUP directive (a parse-once
// site-level toggle with no per-request matcher cost) and a known directive, so a
// config using it does not raise an unknown-directive warning.
func TestCacheUnsafeCatalog(t *testing.T) {
	if got := phaseOf("cache_unsafe"); got != PhaseSetup {
		t.Errorf("phaseOf(cache_unsafe) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["cache_unsafe"] {
		t.Error("cache_unsafe missing from the known-directive set")
	}

	src := []byte("example.com {\n" +
		"  upstream u {\n" +
		"    to http://origin.internal:8080\n" +
		"  }\n" +
		"  cache_unsafe\n" +
		"  cache_ttl default ttl 5m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("got %d unknown-directive diagnostics, want 0", n)
	}
}
