package check

import "testing"

// TestHostHeaderCatalog verifies the `host_header` directive (backlog #11) is
// taught to the catalog: it is a SETUP directive and a known directive, so an
// `upstream` block using it does not raise an unknown-directive warning.
func TestHostHeaderCatalog(t *testing.T) {
	if got := phaseOf("host_header"); got != PhaseSetup {
		t.Errorf("phaseOf(host_header) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["host_header"] {
		t.Error("host_header missing from the known-directive set")
	}

	src := []byte("example.com {\n" +
		"  upstream u {\n" +
		"    to http://origin.internal:8080\n" +
		"    host_header preserve\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	for _, code := range []string{"unknown-directive"} {
		if n := codes(r)[code]; n != 0 {
			t.Errorf("got %d %q diagnostics, want 0", n, code)
		}
	}
}
