package config

import "testing"

// TestTrivialUpstreamCheckRunParity is a check≡run regression guard for the TRIVIAL
// single-`to` upstream path. Before the fix, buildOne fed the RAW `to` token straight
// to httporigin.New, which (a) rejected a scheme-less `to host:port` that
// lb.ParseTarget — used by both the pooled path and `cadish check`
// (config.ParseUpstreamURL) — normalizes by prepending http:// (check passed, run
// failed), and (b) PROXIED to an SSRF link-local / cloud-metadata literal that
// lb.ParseTarget BLOCKS (check rejected, run silently bypassed the SSRF guard). The
// trivial path now routes its `to` through lb.ParseTarget too, so the structural
// pre-flight (ValidateStructure, the `cadish check` gate) and the real build
// (LoadString, the `cadish run` path) accept/reject the exact same set.
func TestTrivialUpstreamCheckRunParity(t *testing.T) {
	cases := []struct {
		to        string
		wantError bool
		why       string
	}{
		{"http://127.0.0.1:8080", false, "canonical scheme-ful target"},
		{"https://origin.example.com", false, "scheme-ful host, no port"},
		{"example.com", false, "scheme-less host implies http"},
		{"127.0.0.1:8080", false, "scheme-less host:port implies http"},
		{"example.com:8080", false, "scheme-less host:port implies http"},
		{"http://169.254.169.254:80", true, "SSRF: IPv4 cloud-metadata literal must be blocked at run too"},
		{"ftp://example.com", true, "unsupported scheme"},
	}
	for _, tc := range cases {
		src := "example.com {\n  upstream web { to " + tc.to + " }\n}\n"
		checkErr := ValidateStructure("c.cadish", src, ".")
		_, runErr := LoadString("c.cadish", src)
		if (checkErr == nil) != (runErr == nil) {
			t.Errorf("to %q (%s): check≡run DIVERGENCE: check=%v run=%v", tc.to, tc.why, checkErr, runErr)
			continue
		}
		if tc.wantError && runErr == nil {
			t.Errorf("to %q (%s): expected both check and run to reject, both accepted", tc.to, tc.why)
		}
		if !tc.wantError && runErr != nil {
			t.Errorf("to %q (%s): expected both to accept, run rejected: %v", tc.to, tc.why, runErr)
		}
	}
}
