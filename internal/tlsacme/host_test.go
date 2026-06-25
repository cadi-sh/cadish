package tlsacme

import "testing"

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"Example.COM":        "example.com",
		"example.com:443":    "example.com",
		"example.com.":       "example.com",
		" example.com ":      "example.com",
		"[::1]:8443":         "[::1]",
		"static.MILE.com:80": "static.mile.com",
	}
	for in, want := range tests {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostMatcher(t *testing.T) {
	m := newHostMatcher()
	m.add("example.com")
	m.add("*.example.com")
	m.add("Static.Other.COM")

	allow := []string{"example.com", "a.example.com", "API.example.com", "static.other.com", "example.com:443"}
	for _, h := range allow {
		if !m.matches(h) {
			t.Errorf("matches(%q) = false, want true", h)
		}
	}
	deny := []string{"evil.com", "a.b.example.com", "example.org", ""}
	for _, h := range deny {
		if m.matches(h) {
			t.Errorf("matches(%q) = true, want false", h)
		}
	}
}

func TestHostMatcherEmpty(t *testing.T) {
	m := newHostMatcher()
	if !m.empty() {
		t.Error("new matcher should be empty")
	}
	m.add("x.com")
	if m.empty() {
		t.Error("matcher with host should not be empty")
	}
}
