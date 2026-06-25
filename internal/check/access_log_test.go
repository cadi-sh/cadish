package check

import "testing"

// TestAccessLogCatalog verifies the global `access_log` option (D44) is taught to
// the catalog: it is a SETUP directive (read once at startup; no per-request matcher
// cost) and a known directive, so a config using `access_log off` does not raise an
// unknown-directive warning.
func TestAccessLogCatalog(t *testing.T) {
	if got := phaseOf("access_log"); got != PhaseSetup {
		t.Errorf("phaseOf(access_log) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["access_log"] {
		t.Error("access_log missing from the known-directive set")
	}

	src := []byte("{\n" +
		"  access_log off\n" +
		"}\n" +
		"example.com {\n" +
		"  upstream u {\n" +
		"    to http://origin.internal:8080\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("got %d unknown-directive diagnostics, want 0", n)
	}
}
