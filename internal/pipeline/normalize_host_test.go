package pipeline

import "testing"

// TestNormalizeHostTrailingDot is the WB1 guard: an FQDN trailing dot is stripped (and
// folded with port-stripping + lower-casing) so `example.com.` routes, matches, and
// keys identically to `example.com`.
func TestNormalizeHostTrailingDot(t *testing.T) {
	cases := map[string]string{
		"example.com":       "example.com",
		"example.com.":      "example.com",
		"Example.COM.":      "example.com",
		"example.com.:8080": "example.com",
		"example.com:8080":  "example.com",
		"[::1]:8080":        "[::1]",
		"::1":               "::1",
		"":                  "",
		"sub.example.com.":  "sub.example.com",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
