package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/metrics"
)

// TestSourceEndpointRedacts proves the /api/source HTTP handler serves redacted
// text end-to-end: a literal auth_token in the on-disk config must not reach the
// client.
func TestSourceEndpointRedacts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Cadishfile")
	src := "example.com {\n  admin {\n    auth_token hunter2\n  }\n  cache_key url\n}\n"
	if err := os.WriteFile(cfgPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	ac := &config.AdminConfig{Listen: "127.0.0.1:0", AuthToken: "secret"}
	srv := New(ac, metrics.New(), fakeLive{}, nil, nil, cfgPath)

	req := httptest.NewRequest("GET", "/api/source", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var sr sourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(sr.Source, "hunter2") {
		t.Fatalf("plaintext secret leaked in /api/source: %q", sr.Source)
	}
	if !strings.Contains(sr.Source, "auth_token ***") {
		t.Fatalf("expected redacted token, got: %q", sr.Source)
	}
}

// TestRedactSecrets verifies that /api/source never leaks plaintext credentials:
// the literal value of a secret-bearing directive (auth_token / access_key /
// secret_key) is replaced with ***, while an ${ENV} / {$ENV} reference (not a
// secret) is preserved so the source view stays useful.
func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"literal admin token", "admin {\n\tauth_token hunter2\n}", "admin {\n\tauth_token ***\n}"},
		{"env admin token kept", "auth_token {$CADISH_ADMIN_TOKEN}", "auth_token {$CADISH_ADMIN_TOKEN}"},
		{"quoted literal token", "auth_token \"s3cr3t value\"", "auth_token ***"},
		{
			"s3 inline literals",
			"s3 { access_key AKIAEXAMPLE; secret_key wJalrXUtnFEMI; region gra }",
			"s3 { access_key ***; secret_key ***; region gra }",
		},
		{"s3 env refs kept", "access_key ${S3_KEY}; secret_key ${S3_SECRET}", "access_key ${S3_KEY}; secret_key ${S3_SECRET}"},
		{"non-secret untouched", "cache_ttl default ttl 10s", "cache_ttl default ttl 10s"},
		{"partial env not whitelisted", "secret_key ${S3_SECRET}-x", "secret_key ***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSecrets(tc.in); got != tc.want {
				t.Fatalf("redactSecrets(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedactSensitiveMatcherMultipleValues verifies that ALL value tokens after a
// sensitive header/cookie name are redacted, not just the first. A matcher such as
// `@tok header X-Purge-Token tokenA tokenB tokenC` must have ALL of tokenA/B/C
// replaced — the current regex captures only the first bare token. An env reference
// (${ENV} / {$ENV}) is preserved if it is the only value, or all literal tokens are
// replaced; a mix keeps env refs and redacts literals, collapsing to a single ***.
func TestRedactSensitiveMatcherMultipleValues(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantNot []string // none of these must appear in output
		wantHas []string // all of these must appear in output
	}{
		{
			"bearer plus extra token leaks second",
			`@auth header Authorization Bearer xyz`,
			[]string{"xyz"},
			[]string{"***"},
		},
		{
			"three value tokens all redacted",
			`@tok header X-Purge-Token tokenA tokenB tokenC`,
			[]string{"tokenA", "tokenB", "tokenC"},
			[]string{"***"},
		},
		{
			"two value tokens both redacted",
			`header X-Purge-Token tokenA tokenB`,
			[]string{"tokenA", "tokenB"},
			[]string{"***"},
		},
		{
			"env ref in sensitive header is preserved",
			`header Authorization {$TOKEN}`,
			[]string{},
			[]string{"{$TOKEN}"},
		},
		// Negative: non-sensitive headers must not be touched.
		{
			"cache_key url host unchanged",
			"cache_key url host",
			[]string{},
			[]string{"cache_key url host"},
		},
		{
			"X-Frame-Options DENY unchanged",
			"header X-Frame-Options DENY",
			[]string{},
			[]string{"header X-Frame-Options DENY"},
		},
		{
			"Cache-Control no-store unchanged",
			"header Cache-Control no-store",
			[]string{},
			[]string{"header Cache-Control no-store"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSecrets(tc.in)
			for _, bad := range tc.wantNot {
				if strings.Contains(got, bad) {
					t.Errorf("redactSecrets(%q) = %q; must not contain %q", tc.in, got, bad)
				}
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(got, want) {
					t.Errorf("redactSecrets(%q) = %q; must contain %q", tc.in, got, want)
				}
			}
		})
	}
}

// TestRedactSensitiveMatcherValues verifies that header/cookie matcher values
// whose name looks sensitive (Authorization, *-Token, *-Key, Secret, Password,
// Auth) are redacted, while non-sensitive header names and env refs are preserved.
// The fix is defense-in-depth for #15: inline purge tokens and bearer values must
// not appear in the /api/source response even though the endpoint is token-gated.
func TestRedactSensitiveMatcherValues(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// Positive: sensitive header values must be redacted.
		{
			"purge header token",
			"purge when header X-Purge-Token hunter2",
			"purge when header X-Purge-Token ***",
		},
		{
			"named matcher purge token",
			"@tok header X-Purge-Token hunter2",
			"@tok header X-Purge-Token ***",
		},
		{
			"authorization bearer",
			`@auth header Authorization "Bearer s3cr3t"`,
			"@auth header Authorization ***",
		},
		{
			"api key header",
			"@a header X-Api-Key AKIA1234567890",
			"@a header X-Api-Key ***",
		},
		{
			"cookie named secret",
			"@s cookie session-secret abc123",
			"@s cookie session-secret ***",
		},
		// Env references in sensitive matchers must be preserved.
		{
			"purge token env ref preserved",
			"purge when header X-Purge-Token {$PURGE_TOKEN}",
			"purge when header X-Purge-Token {$PURGE_TOKEN}",
		},
		{
			"authorization env ref preserved",
			"@auth header Authorization ${ADMIN_TOKEN}",
			"@auth header Authorization ${ADMIN_TOKEN}",
		},
		// Negative: non-sensitive header names must NOT be redacted.
		{
			"cache_key unchanged",
			"cache_key url host",
			"cache_key url host",
		},
		{
			"non-sensitive header unchanged",
			"header X-Frame-Options DENY",
			"header X-Frame-Options DENY",
		},
		{
			"cache-control header unchanged",
			"header Cache-Control no-store",
			"header Cache-Control no-store",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactSecrets(tc.in); got != tc.want {
				t.Fatalf("redactSecrets(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
		})
	}
}
