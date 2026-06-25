package check

import (
	"strings"
	"testing"
)

// TestSNIHTTPReuseCatalog verifies the gap-H6 transport knobs are taught to the
// catalog: `sni`/`http_reuse` are SETUP directives (zero per-request cost) and are
// known directives (no unknown-directive warning), and contribute nothing to the
// site's per-request cost breakdown.
func TestSNIHTTPReuseCatalog(t *testing.T) {
	for _, name := range []string{"sni", "http_reuse"} {
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
		"    sni www.placercams.com\n" +
		"    http_reuse never\n" +
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
	if n := codes(r)["sni-without-https"]; n != 0 {
		t.Errorf("https backend should NOT warn sni-without-https, got %d", n)
	}
	// Zero per-request cost: a Setup-only site has an empty cost breakdown.
	for _, s := range r.Sites {
		if c := s.CostBreakdown; c.Exact+c.Glob+c.Regex != 0 {
			t.Errorf("sni/http_reuse contributed per-request cost: %+v", c)
		}
	}
}

// TestSNIWithoutHTTPSWarning verifies the lint WARNING fires (with a file:line)
// when a transport knob is set on an upstream whose every `to` is plaintext
// http://, and that it is a warning, not an error.
func TestSNIWithoutHTTPSWarning(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream u {\n" +
		"    to http://origin.internal:8080\n" +
		"    sni www.example.com\n" +
		"    http_reuse never\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	// One warning per knob (sni + http_reuse), both pointing at their own line.
	if n := codes(r)["sni-without-https"]; n != 2 {
		t.Fatalf("got %d sni-without-https diagnostics, want 2 (sni + http_reuse)", n)
	}
	var found bool
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == "sni-without-https" {
				found = true
				if d.Severity != SevWarning {
					t.Errorf("sni-without-https severity = %v, want warning", d.Severity)
				}
				if !strings.Contains(d.Position, ":") {
					t.Errorf("sni-without-https has no file:line position: %q", d.Position)
				}
			}
		}
	}
	if !found {
		t.Fatal("no sni-without-https diagnostic found")
	}
}

// TestSNIMixedSchemeNoWarning verifies a MIXED-scheme pool (one https:// backend)
// does NOT warn — the pool will dial HTTPS, so the knob is meaningful.
func TestSNIMixedSchemeNoWarning(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream u {\n" +
		"    to http://a:80 https://b:443\n" +
		"    sni www.example.com\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["sni-without-https"]; n != 0 {
		t.Errorf("mixed-scheme pool should NOT warn, got %d sni-without-https", n)
	}
}
