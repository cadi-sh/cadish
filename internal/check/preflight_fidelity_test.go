package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errorDiags returns every SevError diagnostic across the whole report (preamble
// + per-site), used to assert `cadish check` catches a config-build failure.
func errorDiags(r *Report) []Diagnostic {
	var out []Diagnostic
	for _, d := range r.Diagnostics {
		if d.Severity == SevError {
			out = append(out, d)
		}
	}
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			if d.Severity == SevError {
				out = append(out, d)
			}
		}
	}
	return out
}

// hasErrorContaining reports whether any error diagnostic's message contains substr.
func hasErrorContaining(r *Report, substr string) bool {
	for _, d := range errorDiags(r) {
		if strings.Contains(d.Message, substr) {
			return true
		}
	}
	return false
}

// TestCheckRunFidelity is the CHK-SYS regression guard: every config below FAILS
// `cadish run` at config-build time, so `cadish check` must report the SAME error
// (the documented invariant: check exit 0 ⇒ run builds the config). These were the
// empirically-confirmed check↔run divergences from the 2026-06-25 testing loop.
//
// The cases are all pure (no filesystem) so CheckSource exercises them directly.
func TestCheckRunFidelity(t *testing.T) {
	const validSite = "example.com {\n  upstream app { to http://localhost:8080 }\n}\n"
	cases := []struct {
		name string
		src  string
		want string // substring of the build error check must now surface
	}{
		{
			name: "proxy_protocol trust bad cidr (B1 sibling)",
			src:  "{\n  proxy_protocol { trust notacidr }\n}\n" + validSite,
			want: "notacidr",
		},
		{
			name: "access_log on (only off supported)",
			src:  "{\n  access_log on\n}\n" + validSite,
			want: "off",
		},
		{
			name: "cache ram with no size",
			src:  "example.com {\n  cache { ram }\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "needs a size",
		},
		{
			name: "empty geo block (source required)",
			src:  "example.com {\n  geo { }\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "source",
		},
		{
			name: "geo trust_proxy bad cidr (B1)",
			src:  "example.com {\n  geo { source header CF-IPCountry\n trust_proxy notacidr }\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "trust_proxy",
		},
		{
			name: "geo three sources (composition: at most two)",
			src:  "example.com {\n  geo { source header A\n source header B\n source header C }\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "at most two",
		},
		{
			name: "geo two non-pair sources (composition: pair-only)",
			src:  "example.com {\n  geo { source header A\n source header B }\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "pair",
		},
		{
			name: "site-level trust_proxy bad cidr (B1)",
			src:  "example.com {\n  trust_proxy 1\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "trust_proxy",
		},
		{
			name: "upstream bucket but no to",
			src:  "example.com {\n  upstream be { bucket b }\n}\n",
			want: "bucket",
		},
		{
			name: "sign cloudfront no key",
			src:  "example.com {\n  upstream cf {\n    to https://d111.cloudfront.net\n    sign cloudfront KEYPAIRID\n  }\n}\n",
			want: "key",
		},
		{
			name: "admin missing auth_token (B2)",
			src:  "{\n  admin { listen 127.0.0.1:9090 }\n}\n" + validSite,
			want: "auth_token",
		},
		{
			name: "strict_host with an argument (arity)",
			src:  "{\n  strict_host yes please\n}\n" + validSite,
			want: "strict_host",
		},
		{
			name: "malformed host_header on a trivial upstream",
			src:  "example.com {\n  upstream app { to http://localhost:8080\n host_header }\n}\n",
			want: "host_header",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := CheckSource("fidelity.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource returned a hard error: %v", err)
			}
			if !hasErrorContaining(r, tc.want) {
				t.Errorf("check did not surface the run build-error (want substring %q)\nerror diags: %v", tc.want, errorDiags(r))
			}
		})
	}
}

// warningDiags returns every SevWarning diagnostic across the report.
func warningDiags(r *Report) []Diagnostic {
	var out []Diagnostic
	for _, d := range r.Diagnostics {
		if d.Severity == SevWarning {
			out = append(out, d)
		}
	}
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			if d.Severity == SevWarning {
				out = append(out, d)
			}
		}
	}
	return out
}

// TestCheckFileExistence is the TLS-D1/TLS-D2 guard: `check` should WARN (not hard-
// error) when a referenced cert/key/PEM file is absent at check time. A missing file
// is a deploy precondition, not a config-structure error (configs are authored on one
// host for another), so the config stays exit-0 valid while the typo is surfaced.
func TestCheckFileExistence(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "static cert/key files missing (TLS-D1)",
			src:  "example.com {\n  tls { cert /nope-cert.pem key /nope-key.pem }\n  upstream app { to http://localhost:8080 }\n}\n",
			want: "nope",
		},
		{
			name: "cfsign key file missing (TLS-D2)",
			src:  "example.com {\n  upstream cf {\n    to https://d111.cloudfront.net\n    sign cloudfront KP key /nope-sign-key.pem\n  }\n}\n",
			want: "nope-sign-key.pem",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := write("c.cadish", tc.src)
			r, err := Check(cfg)
			if err != nil {
				t.Fatalf("Check returned a hard error: %v", err)
			}
			// A missing file must WARN, not error (the config is still valid).
			if len(errorDiags(r)) != 0 {
				t.Errorf("missing file should not be a hard error; got %v", errorDiags(r))
			}
			warned := false
			for _, d := range warningDiags(r) {
				if d.Code == "file-not-found" && strings.Contains(d.Message, tc.want) {
					warned = true
				}
			}
			if !warned {
				t.Errorf("check did not warn on the missing file (want substring %q)\nwarnings: %v", tc.want, warningDiags(r))
			}
		})
	}
}
