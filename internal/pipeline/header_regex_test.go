package pipeline

import (
	"net/http"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"net/url"
	"testing"
)

// TestHeaderRegexMatcher exercises the raw matcher: an RE2 regex applied to a request
// header value. The canonical case is `req.http.Accept-Language ~ "^es"` — a real
// browser sends `es-ES,es;q=0.9,en;q=0.8`, which the exact `header` matcher cannot
// match but `header_regex` does (prefix on the raw value, NOT q-value parsing).
func TestHeaderRegexMatcher(t *testing.T) {
	m, err := compileMatcher("lang_es", "header_regex", []string{"Accept-Language", "(?i)^es"}, cadishfile.Pos{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cases := []struct {
		name string
		hdr  http.Header
		want bool
	}{
		{"real browser es header", http.Header{"Accept-Language": {"es-ES,es;q=0.9,en;q=0.8"}}, true},
		{"bare es", http.Header{"Accept-Language": {"es"}}, true},
		{"uppercase ES (case-insensitive flag)", http.Header{"Accept-Language": {"ES-es"}}, true},
		{"english only", http.Header{"Accept-Language": {"en-US,en;q=0.9"}}, false},
		{"absent header", http.Header{}, false},
		{"multi-value: 2nd matches", http.Header{"Accept-Language": {"en-US", "es-ES"}}, true},
		{"multi-value: none match", http.Header{"Accept-Language": {"en-US", "fr-FR"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newMatchContext(&Request{Header: tc.hdr}, "")
			if got := m.match(c); got != tc.want {
				t.Errorf("match(%v) = %v, want %v", tc.hdr, got, tc.want)
			}
		})
	}
}

func TestHeaderRegexCompileErrors(t *testing.T) {
	if _, err := compileMatcher("", "header_regex", []string{"Accept-Language"}, cadishfile.Pos{}); err == nil {
		t.Errorf("expected error for missing PATTERN")
	}
	if _, err := compileMatcher("", "header_regex", []string{"Accept-Language", "(["}, cadishfile.Pos{}); err == nil {
		t.Errorf("expected error for invalid regex")
	}
	if _, err := compileMatcher("", "header_regex", []string{"", "^es"}, cadishfile.Pos{}); err == nil {
		t.Errorf("expected error for empty NAME")
	}
}

// TestLanguageRedirectRecipe is the DELIVERABLE PROOF: the auto-language
// redirect, end to end. A www request whose Accept-Language starts with `es` gets a
// 302 to the es. subdomain (preserving the URI); an en request does not.
func TestLanguageRedirectRecipe(t *testing.T) {
	p := compileSrc(t, `example.com {
    upstream b { to http://x:80 }
    @lang_es header_regex Accept-Language (?i)^es
    @on_www  host_regex (?i)^www\.
    classify {to_es} { when @on_www @lang_es -> 1 ; default -> 0 }
    @to_es classify {to_es}==1
    redirect @to_es 302 https://es.example.com{uri}
    cache_ttl default ttl 1m grace 5m
}
`)

	cases := []struct {
		name    string
		host    string
		path    string
		query   url.Values
		accLang string
		wantLoc string // "" => no redirect expected
	}{
		{
			name:    "www + es browser header -> 302 to es subdomain",
			host:    "www.example.com",
			path:    "/registro",
			accLang: "es-ES,es;q=0.9,en;q=0.8",
			wantLoc: "https://es.example.com/registro",
		},
		{
			name:    "www + es preserves query in {uri}",
			host:    "www.example.com",
			path:    "/registro",
			query:   url.Values{"utm_source": {"x"}},
			accLang: "es-ES,es;q=0.9",
			wantLoc: "https://es.example.com/registro?utm_source=x",
		},
		{
			name:    "www + en browser header -> NO redirect",
			host:    "www.example.com",
			path:    "/registro",
			accLang: "en-US,en;q=0.9",
			wantLoc: "",
		},
		{
			name:    "es header but not www -> NO redirect (already on es.)",
			host:    "es.example.com",
			path:    "/registro",
			accLang: "es-ES,es;q=0.9",
			wantLoc: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := tc.query
			if q == nil {
				q = url.Values{}
			}
			req := &Request{
				Method: "GET", Host: tc.host, Path: tc.path, Query: q,
				Header: http.Header{"Accept-Language": {tc.accLang}},
			}
			dec := p.EvalRequest(req)
			if tc.wantLoc == "" {
				if dec.Redirect != nil {
					t.Fatalf("expected no redirect, got %+v", dec.Redirect)
				}
				return
			}
			if dec.Redirect == nil {
				t.Fatalf("expected 302 redirect, got nil")
			}
			if dec.Redirect.Status != 302 {
				t.Errorf("status = %d, want 302", dec.Redirect.Status)
			}
			if dec.Redirect.Location != tc.wantLoc {
				t.Errorf("location = %q, want %q", dec.Redirect.Location, tc.wantLoc)
			}
		})
	}
}
