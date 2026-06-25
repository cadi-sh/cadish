package pipeline

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestScopedCacheKeyFirstMatch covers the core example.com migration scenario: an SSR
// branch (selected by an X-IS-SSR-URL header) that STRIPS the query, and a PHP
// catch-all that keys on the FULL query. This is the "query axis" a single key
// cannot express (see the spec) — first-match-wins recipe selection closes it.
func TestScopedCacheKeyFirstMatch(t *testing.T) {
	p := compileSrc(t, `x {
		@ssr header X-IS-SSR-URL true
		cache_key @ssr     host path
		cache_key default  host url
	}
`)
	q := url.Values{"utm_source": {"mailing"}, "page": {"2"}}

	// SSR request: query stripped -> key is host + path only.
	ssr := &Request{Method: "GET", Host: "example.com", Path: "/list", Query: q,
		Header: http.Header{"X-Is-Ssr-Url": {"true"}}}
	got := p.EvalRequest(ssr).CacheKey
	want := strings.Join([]string{"example.com", "/list"}, keyTokenSep)
	if got != want {
		t.Errorf("SSR key = %q, want %q (query must be stripped)", got, want)
	}

	// PHP request (no SSR header): full query kept via `url`.
	php := &Request{Method: "GET", Host: "example.com", Path: "/list", Query: q}
	got = p.EvalRequest(php).CacheKey
	want = strings.Join([]string{"example.com", "/list?page=2&utm_source=mailing"}, keyTokenSep)
	if got != want {
		t.Errorf("PHP key = %q, want %q (full query kept)", got, want)
	}

	// The two branches must NOT collide on the same path+query.
	if p.EvalRequest(ssr).CacheKey == p.EvalRequest(php).CacheKey {
		t.Error("SSR and PHP recipes must produce distinct keys")
	}
}

// TestScopedCacheKeyOrderWins verifies source order decides ties: an earlier scoped
// rule wins even when a later rule would also match.
func TestScopedCacheKeyOrderWins(t *testing.T) {
	p := compileSrc(t, `x {
		@home path /home
		@any path /*
		cache_key @home  host path
		cache_key @any   host url
		cache_key default host method
	}
`)
	r := &Request{Method: "GET", Host: "h", Path: "/home", Query: url.Values{"x": {"1"}}}
	got := p.EvalRequest(r).CacheKey
	want := strings.Join([]string{"h", "/home"}, keyTokenSep) // @home wins, query stripped
	if got != want {
		t.Errorf("key = %q, want %q (@home should win over @any)", got, want)
	}
}

// TestScopedCacheKeyDefaultFallback verifies a request matching no scope falls to the
// default recipe.
func TestScopedCacheKeyDefaultFallback(t *testing.T) {
	p := compileSrc(t, `x {
		@api path /api/*
		cache_key @api    host path header:Accept
		cache_key default host path
	}
`)
	r := &Request{Method: "GET", Host: "h", Path: "/page", Header: http.Header{"Accept": {"application/json"}}}
	got := p.EvalRequest(r).CacheKey
	want := strings.Join([]string{"h", "/page"}, keyTokenSep) // default: no Accept in key
	if got != want {
		t.Errorf("key = %q, want %q (default recipe, Accept excluded)", got, want)
	}
}

// TestScopedCacheKeyCompileErrors covers the new compile-time guards.
func TestScopedCacheKeyCompileErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantSub string
	}{
		{
			"missing-default",
			"x {\n @ssr header X-S 1\n cache_key @ssr host path\n}\n",
			"catch-all",
		},
		{
			"status-selector",
			"x {\n cache_key status 200 host path\n cache_key default host path\n}\n",
			"response-phase",
		},
		{
			"response-phase-matcher",
			"x {\n @sc set_cookie .\n cache_key @sc host path\n cache_key default host path\n}\n",
			"response-phase",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ce := compileErr(t, tt.src)
			if !strings.Contains(ce.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", ce.Error(), tt.wantSub)
			}
		})
	}
}

// TestScopedCacheKeyBackwardCompat verifies a single unscoped cache_key compiles to
// exactly one default recipe and is NOT treated as scoped (edge stays projectable).
func TestScopedCacheKeyBackwardCompat(t *testing.T) {
	p := compileSrc(t, "x {\n cache_key host path query\n}\n")
	if len(p.keyRules) != 1 || p.keyRules[0].sel.kind != selDefault {
		t.Fatalf("unscoped cache_key should be one default recipe, got %d rules", len(p.keyRules))
	}
	if p.HasScopedCacheKey() {
		t.Error("a single unscoped cache_key must not report as scoped")
	}
}

// TestHasScopedCacheKey verifies the edge-guard predicate.
func TestHasScopedCacheKey(t *testing.T) {
	scoped := compileSrc(t, "x {\n @s path /a/*\n cache_key @s host path\n cache_key default host url\n}\n")
	if !scoped.HasScopedCacheKey() {
		t.Error("scoped cache_key should report as scoped")
	}
	none := compileSrc(t, "x {\n pass method POST\n}\n")
	if none.HasScopedCacheKey() {
		t.Error("no cache_key should not report as scoped")
	}
}
