package check

import "testing"

// TestClientCacheControlCatalog verifies the `client_cache_control` opt-out
// (SPEC-IGNORE-CLIENT-CC: do not honor a request's client-forced revalidation) is
// taught to the catalog: it is a SETUP directive (a parse-once site-level toggle
// with no per-request matcher cost) and a known directive, so a config using it
// does not raise an unknown-directive warning.
func TestClientCacheControlCatalog(t *testing.T) {
	if got := phaseOf("client_cache_control"); got != PhaseSetup {
		t.Errorf("phaseOf(client_cache_control) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["client_cache_control"] {
		t.Error("client_cache_control missing from the known-directive set")
	}

	src := []byte("example.com {\n" +
		"  upstream u {\n" +
		"    to http://origin.internal:8080\n" +
		"  }\n" +
		"  client_cache_control ignore\n" +
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
