package pipeline

import "testing"

// TestHostParts covers the public-suffix-aware split behind {host.base}/{host.sub}:
// the registrable base domain and the leading subdomain label(s). The crucial case
// is the multi-label suffix (cam4you.tech555.io): a naive strip-first-label would
// wrongly yield tech555.io; with tech555.io listed as a multi-label suffix the whole
// host is the base and the subdomain is empty.
func TestHostParts(t *testing.T) {
	tests := []struct {
		host     string
		wantBase string
		wantSub  string
	}{
		// Single-label TLD (default rule): base = last two labels.
		{"es.nudity.tv", "nudity.tv", "es"},
		{"www.amateur.tv", "amateur.tv", "www"},
		{"pt.amateur.tv", "amateur.tv", "pt"},
		{"nudity.tv", "nudity.tv", ""},              // bare registrable host: empty sub
		{"amateur.tv", "amateur.tv", ""},            // bare registrable host
		{"a.b.es.nudity.tv", "nudity.tv", "a.b.es"}, // multi-level subdomain
		// Multi-label public suffix: tech555.io behaves like co.uk.
		{"cam4you.tech555.io", "cam4you.tech555.io", ""},      // bare registrable on a 2-label suffix
		{"es.cam4you.tech555.io", "cam4you.tech555.io", "es"}, // subdomain over a 2-label suffix
		{"shop.example.co.uk", "example.co.uk", "shop"},
		{"example.co.uk", "example.co.uk", ""},
		// Normalization: case + :port + trailing dot are stripped before splitting.
		{"WWW.Amateur.TV", "amateur.tv", "www"},
		{"es.nudity.tv:8443", "nudity.tv", "es"},
		{"es.nudity.tv.", "nudity.tv", "es"},
		// Degenerate hosts.
		{"localhost", "localhost", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			base, sub := hostParts(tc.host)
			if base != tc.wantBase || sub != tc.wantSub {
				t.Fatalf("hostParts(%q) = (%q, %q), want (%q, %q)", tc.host, base, sub, tc.wantBase, tc.wantSub)
			}
		})
	}
}

// TestExpandTemplateHostParts proves the {host.base}/{host.sub} tokens render off
// the env Host through the template expander, including the multi-label suffix and a
// bare base host (empty {host.sub}).
func TestExpandTemplateHostParts(t *testing.T) {
	tests := []struct {
		host string
		tmpl string
		want string
	}{
		{"es.nudity.tv", "https://www.{host.base}/x", "https://www.nudity.tv/x"},
		{"es.nudity.tv", "{host.sub}", "es"},
		{"www.amateur.tv", "https://www.{host.base}", "https://www.amateur.tv"},
		{"nudity.tv", "https://www.{host.base}", "https://www.nudity.tv"},
		{"nudity.tv", "[{host.sub}]", "[]"}, // bare base -> empty sub
		{"cam4you.tech555.io", "https://www.{host.base}", "https://www.cam4you.tech555.io"},
		{"es.nudity.tv", "https://www.{host.base}/lang/{host.sub}", "https://www.nudity.tv/lang/es"},
	}
	for _, tc := range tests {
		t.Run(tc.tmpl+"@"+tc.host, func(t *testing.T) {
			env := &TemplateEnv{Host: tc.host, Path: "/p"}
			if got := expandTemplate(tc.tmpl, env, classifyResolver{}); got != tc.want {
				t.Fatalf("expandTemplate(%q) host=%q = %q, want %q", tc.tmpl, tc.host, got, tc.want)
			}
		})
	}
}
