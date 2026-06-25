package lb

import (
	"strings"
	"testing"
)

// TestParseUpstreamSNIHTTPReuse is the gap-H6 happy path: an upstream with `sni`
// and `http_reuse never` (a real multi-`to` pool so it goes through parsePool)
// parses to Config{SNI, DisableReuse:true}.
func TestParseUpstreamSNIHTTPReuse(t *testing.T) {
	src := `upstream blog {
    to         https://10.0.0.1:443
    to         https://10.0.0.2:443
    sni        www.placercams.com
    http_reuse never
}`
	d := parseDirective(t, src)
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	if cfg.SNI != "www.placercams.com" {
		t.Errorf("SNI = %q, want www.placercams.com", cfg.SNI)
	}
	if !cfg.DisableReuse {
		t.Error("DisableReuse = false, want true (http_reuse never)")
	}
}

// TestParseUpstreamSNIErrors covers the arity/validity errors for `sni`.
func TestParseUpstreamSNIErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"zero args", `upstream u {
    to https://a https://b
    sni
}`},
		{"two args", `upstream u {
    to https://a https://b
    sni a b
}`},
		{"matcher ref", `upstream u {
    to https://a https://b
    sni @ref
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := parseDirective(t, tc.src)
			if _, err := ParseUpstream(d); err == nil {
				t.Fatalf("ParseUpstream(%s): want error, got nil", tc.name)
			}
		})
	}
}

// TestParseUpstreamHTTPReuseErrors verifies only `never` is accepted; every other
// keyword (incl. HAProxy's safe/aggressive/always) is a positioned error naming
// the supported set.
func TestParseUpstreamHTTPReuseErrors(t *testing.T) {
	for _, kw := range []string{"safe", "aggressive", "always", "garbage"} {
		src := `upstream u {
    to https://a https://b
    http_reuse ` + kw + `
}`
		d := parseDirective(t, src)
		_, err := ParseUpstream(d)
		if err == nil {
			t.Fatalf("http_reuse %s: want error, got nil", kw)
		}
		if !strings.Contains(err.Error(), "never") {
			t.Errorf("http_reuse %s error %q does not name the supported value `never`", kw, err)
		}
	}
	// Zero args is also an error.
	d := parseDirective(t, `upstream u {
    to https://a https://b
    http_reuse
}`)
	if _, err := ParseUpstream(d); err == nil {
		t.Fatal("http_reuse with no arg: want error, got nil")
	}
}
