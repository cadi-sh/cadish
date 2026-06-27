package check

import (
	"strings"
	"testing"
)

// TestTLSVerifyCatalog verifies the TLSVERIFY knobs are taught to the catalog:
// `tls_insecure`/`ca_file`/`alpn` are SETUP directives (zero per-request cost), are
// known directives (no unknown-directive warning), and contribute nothing to the
// site's per-request cost breakdown.
func TestTLSVerifyCatalog(t *testing.T) {
	for _, name := range []string{"tls_insecure", "ca_file", "alpn"} {
		if got := phaseOf(name); got != PhaseSetup {
			t.Errorf("phaseOf(%s) = %v, want PhaseSetup", name, got)
		}
		if !defaultDirectives[name] {
			t.Errorf("%s missing from the known-directive set", name)
		}
	}

	src := []byte("example.com {\n" +
		"  upstream blog {\n" +
		"    to https://1.2.3.4:443\n" +
		"    alpn http/1.1\n" +
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
	for _, s := range r.Sites {
		if c := s.CostBreakdown; c.Exact+c.Glob+c.Regex != 0 {
			t.Errorf("TLSVERIFY knobs contributed per-request cost: %+v", c)
		}
	}
}

// TestInsecureOriginTLSWarning verifies `cadish check` emits a security WARNING (with
// a file:line) when an upstream sets `tls_insecure`, and that it is a warning, not an
// error (the knob is a legitimate, deliberate escape hatch).
func TestInsecureOriginTLSWarning(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream blog {\n" +
		"    to https://origin.internal:443\n" +
		"    tls_insecure\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["insecure-origin-tls"]; n != 1 {
		t.Fatalf("got %d insecure-origin-tls diagnostics, want 1", n)
	}
	var found bool
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == "insecure-origin-tls" {
				found = true
				if d.Severity != SevWarning {
					t.Errorf("insecure-origin-tls severity = %v, want warning", d.Severity)
				}
				if !strings.Contains(d.Position, ":") {
					t.Errorf("insecure-origin-tls has no file:line position: %q", d.Position)
				}
			}
		}
	}
	if !found {
		t.Fatal("no insecure-origin-tls diagnostic found")
	}
}

// TestNoInsecureWarningWithoutKnob verifies a verifying upstream (no tls_insecure,
// or the secure ca_file alternative) does NOT raise the warning.
func TestNoInsecureWarningWithoutKnob(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream blog {\n" +
		"    to https://origin.internal:443\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["insecure-origin-tls"]; n != 0 {
		t.Errorf("verifying upstream warned insecure-origin-tls, got %d", n)
	}
}
