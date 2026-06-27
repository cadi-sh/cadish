package tlsacme

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// parseTLS parses a single-site Cadishfile and returns its tls SiteTLS.
func parseTLS(t *testing.T, src string) (SiteTLS, []error) {
	t.Helper()
	f, err := cadishfile.Parse("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(f.Sites))
	}
	sc, errs := SiteConfigFromSite(f.Sites[0])
	return sc.TLS, errs
}

func TestParseSiteTLS_Modes(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want SiteTLS
	}{
		{
			name: "acme block",
			src:  "example.com {\n tls { acme me@x.io }\n}\n",
			want: SiteTLS{Mode: ModeACME, Email: "me@x.io"},
		},
		{
			name: "acme inline",
			src:  "example.com {\n tls acme me@x.io\n}\n",
			want: SiteTLS{Mode: ModeACME, Email: "me@x.io"},
		},
		{
			name: "off inline",
			src:  "example.com {\n tls off\n}\n",
			want: SiteTLS{Mode: ModeOff},
		},
		{
			name: "off block",
			src:  "example.com {\n tls { off }\n}\n",
			want: SiteTLS{Mode: ModeOff},
		},
		{
			name: "static fused",
			src:  "example.com {\n tls { cert /etc/c.pem key /etc/k.pem }\n}\n",
			want: SiteTLS{Mode: ModeStatic, CertFile: "/etc/c.pem", KeyFile: "/etc/k.pem"},
		},
		{
			name: "static split",
			src:  "example.com {\n tls {\n cert /etc/c.pem\n key /etc/k.pem\n }\n}\n",
			want: SiteTLS{Mode: ModeStatic, CertFile: "/etc/c.pem", KeyFile: "/etc/k.pem"},
		},
		{
			name: "no tls directive",
			src:  "example.com {\n cache_key url\n}\n",
			want: SiteTLS{Mode: ModeOff},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := parseTLS(t, tt.src)
			got.HSTS = HSTS{} // compared separately
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseSiteTLS_HSTS(t *testing.T) {
	cfg, errs := parseTLS(t, "example.com {\n tls {\n acme me@x.io\n hsts max_age 31536000 includeSubdomains preload\n }\n}\n")
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if cfg.HSTS.MaxAge != 31536000 || !cfg.HSTS.IncludeSubdomains || !cfg.HSTS.Preload {
		t.Errorf("HSTS = %+v", cfg.HSTS)
	}
	want := "max-age=31536000; includeSubDomains; preload"
	if got := cfg.HSTS.HeaderValue(); got != want {
		t.Errorf("HeaderValue = %q, want %q", got, want)
	}
}

func TestHSTS_HeaderValueEmpty(t *testing.T) {
	if v := (HSTS{}).HeaderValue(); v != "" {
		t.Errorf("empty HSTS HeaderValue = %q, want empty", v)
	}
}

func TestParseSiteTLS_UnknownOption(t *testing.T) {
	_, errs := parseTLS(t, "example.com {\n tls { bogus 1 }\n}\n")
	if len(errs) == 0 {
		t.Error("expected a soft error for unknown tls option")
	}
}

func TestParseSiteTLS_Nil(t *testing.T) {
	cfg, errs := ParseSiteTLS(nil)
	if cfg.Mode != ModeOff || errs != nil {
		t.Errorf("nil directive = %+v, %v", cfg, errs)
	}
}

// hasWarn reports whether any soft diagnostic contains substr.
func hasWarn(errs []error, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}

// TestParseSiteTLS_DuplicateDirective (TLS-P1): two `tls` directives in one site
// silently first-wins; the second must be flagged so its discarded intent shows.
func TestParseSiteTLS_DuplicateDirective(t *testing.T) {
	cfg, errs := parseTLS(t, "example.com {\n tls off\n tls { acme me@x.io }\n}\n")
	if cfg.Mode != ModeOff {
		t.Errorf("first `tls` should win → ModeOff, got %v", cfg.Mode)
	}
	if !hasWarn(errs, "duplicate `tls` directive") {
		t.Errorf("expected a duplicate-tls warning; got %v", errs)
	}
}

// TestParseSiteTLS_SingleDirectiveNoDupWarn guards against a false positive: a
// site with exactly one `tls` directive must not be flagged as a duplicate.
func TestParseSiteTLS_SingleDirectiveNoDupWarn(t *testing.T) {
	_, errs := parseTLS(t, "example.com {\n tls { acme me@x.io }\n}\n")
	if hasWarn(errs, "duplicate `tls` directive") {
		t.Errorf("single tls directive wrongly flagged duplicate: %v", errs)
	}
}

// TestParseSiteTLS_ConflictingModeInBlock (TLS-P1): mixing modes inside one block
// (cert/key then off) is last-write-wins and discards the cert; flag it.
func TestParseSiteTLS_ConflictingModeInBlock(t *testing.T) {
	cfg, errs := parseTLS(t, "example.com {\n tls {\n cert /c.pem\n key /k.pem\n off\n }\n}\n")
	if cfg.Mode != ModeOff {
		t.Errorf("last statement (`off`) should win, got %v", cfg.Mode)
	}
	if !hasWarn(errs, "conflicting `tls` mode") {
		t.Errorf("expected a conflicting-mode warning; got %v", errs)
	}
}

// TestParseSiteTLS_CertKeyNotConflict guards a false positive: a `cert` and a
// separate `key` statement are the SAME mode (Static) and must not be flagged.
func TestParseSiteTLS_CertKeyNotConflict(t *testing.T) {
	cfg, errs := parseTLS(t, "example.com {\n tls {\n cert /c.pem\n key /k.pem\n }\n}\n")
	if cfg.Mode != ModeStatic {
		t.Fatalf("cert+key → ModeStatic, got %v", cfg.Mode)
	}
	if hasWarn(errs, "conflicting `tls` mode") {
		t.Errorf("cert+key wrongly flagged conflicting: %v", errs)
	}
}

// TestParseSiteTLS_ACMENoEmail (TLS-P2): `tls { acme }` with no contact email
// must warn (Let's Encrypt expiry/rate-limit notices have nowhere to go).
func TestParseSiteTLS_ACMENoEmail(t *testing.T) {
	_, errs := parseTLS(t, "example.com {\n tls { acme }\n}\n")
	if !hasWarn(errs, "no contact email") {
		t.Errorf("expected a no-email warning for `tls { acme }`; got %v", errs)
	}
	// Inline form too.
	_, errs = parseTLS(t, "example.com {\n tls acme\n}\n")
	if !hasWarn(errs, "no contact email") {
		t.Errorf("expected a no-email warning for inline `tls acme`; got %v", errs)
	}
}

// TestParseSiteTLS_ACMEWithEmailNoWarn guards the false positive: an email present
// must silence the TLS-P2 warning.
func TestParseSiteTLS_ACMEWithEmailNoWarn(t *testing.T) {
	_, errs := parseTLS(t, "example.com {\n tls { acme me@x.io }\n}\n")
	if hasWarn(errs, "no contact email") {
		t.Errorf("acme with email wrongly warned no-email: %v", errs)
	}
}

// TestParseSiteTLS_EmptyBlockWording (TLS-P3): both `tls {}` (literal) and
// `tls { }` (real empty block) become ModeOff and must carry the clarified
// "treated as `tls off`" wording, not "literal token".
func TestParseSiteTLS_EmptyBlockWording(t *testing.T) {
	for _, src := range []string{
		"example.com {\n tls {}\n}\n",
		"example.com {\n tls { }\n}\n",
	} {
		cfg, errs := parseTLS(t, src)
		if cfg.Mode != ModeOff {
			t.Errorf("%q → want ModeOff, got %v", src, cfg.Mode)
		}
		if !hasWarn(errs, "treated as `tls off`") {
			t.Errorf("%q: expected clarified empty-block wording; got %v", src, errs)
		}
		if hasWarn(errs, "literal token") {
			t.Errorf("%q: still uses misleading 'literal token' wording: %v", src, errs)
		}
	}
}

// TestParseSiteTLS_HTTPRedirectExcept: the `http_redirect_except /path …` sub-option is
// parsed into SiteTLS.RedirectExcept WITHOUT setting a TLS mode (it composes with
// acme/cert), accepts multiple paths, and warns on a path that cannot match a request.
func TestParseSiteTLS_HTTPRedirectExcept(t *testing.T) {
	cfg, errs := parseTLS(t, "example.com {\n tls {\n acme me@x.io\n http_redirect_except /aws-health-check /webhook\n }\n}\n")
	if cfg.Mode != ModeACME || cfg.Email != "me@x.io" {
		t.Errorf("mode/email = %v/%q, want acme/me@x.io (exemption must not change mode)", cfg.Mode, cfg.Email)
	}
	want := []string{"/aws-health-check", "/webhook"}
	if len(cfg.RedirectExcept) != len(want) {
		t.Fatalf("RedirectExcept = %v, want %v", cfg.RedirectExcept, want)
	}
	for i, p := range want {
		if cfg.RedirectExcept[i] != p {
			t.Errorf("RedirectExcept[%d] = %q, want %q", i, cfg.RedirectExcept[i], p)
		}
	}
	if hasWarn(errs, "unknown tls option") {
		t.Errorf("http_redirect_except wrongly flagged unknown: %v", errs)
	}

	// A path without a leading "/" can never match a request path → soft warning.
	_, errs2 := parseTLS(t, "example.com {\n tls {\n acme me@x.io\n http_redirect_except no-slash\n }\n}\n")
	if !hasWarn(errs2, "must start with `/`") {
		t.Errorf("expected leading-slash warning; got %v", errs2)
	}

	// No path at all → soft warning.
	_, errs3 := parseTLS(t, "example.com {\n tls {\n acme me@x.io\n http_redirect_except\n }\n}\n")
	if !hasWarn(errs3, "needs at least one path") {
		t.Errorf("expected empty-args warning; got %v", errs3)
	}
}
