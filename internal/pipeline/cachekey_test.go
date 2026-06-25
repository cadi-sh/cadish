package pipeline

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// compileKey compiles a `cache_key TOKENS` line and returns the (single) recipe's
// tokens.
func compileKeyTokens(t *testing.T, tokens string) []keyToken {
	t.Helper()
	src := "x {\n cache_key " + tokens + "\n}\n"
	p := compileSrc(t, src)
	if len(p.keyRules) != 1 {
		t.Fatalf("want 1 cache_key recipe, got %d", len(p.keyRules))
	}
	return p.keyRules[0].toks
}

func TestCacheKeyDefault(t *testing.T) {
	// No cache_key directive => default method host path.
	p := compileSrc(t, "x {\n pass method POST\n}\n")
	if len(p.keyRules) != 0 {
		t.Fatalf("want 0 cache_key recipes, got %d", len(p.keyRules))
	}
	req := &Request{Method: "get", Host: "Example.COM:80", Path: "/p"}
	got := buildKey(nil, req, p.stickyCookie, nil)
	want := strings.Join([]string{"GET", "example.com", "/p"}, keyTokenSep)
	if got != want {
		t.Errorf("default key = %q, want %q", got, want)
	}
}

func TestCacheKeyComposition(t *testing.T) {
	toks := compileKeyTokens(t, "url host header:X-Lang")
	req := &Request{
		Method: "GET",
		Host:   "h.example.com",
		Path:   "/list",
		Query:  url.Values{"b": {"2"}, "a": {"1"}},
		Header: http.Header{"X-Lang": {"es"}},
	}
	got := buildKey(toks, req, "", nil)
	want := strings.Join([]string{"/list?a=1&b=2", "h.example.com", "es"}, keyTokenSep)
	if got != want {
		t.Errorf("key = %q, want %q", got, want)
	}
}

func TestCacheKeyQueryCanonical(t *testing.T) {
	toks := compileKeyTokens(t, "path query")
	r1 := &Request{Path: "/x", Query: url.Values{"a": {"1"}, "b": {"2"}}}
	r2 := &Request{Path: "/x", Query: url.Values{"b": {"2"}, "a": {"1"}}}
	if buildKey(toks, r1, "", nil) != buildKey(toks, r2, "", nil) {
		t.Error("query order should not affect the cache key")
	}
}

func TestCacheKeySticky(t *testing.T) {
	toks := compileKeyTokens(t, "path {sticky}")
	// With cookie present -> cookie value.
	r := &Request{Path: "/x", Header: http.Header{"Cookie": {"PHPSESSID=abc123"}}, ClientIP: "9.9.9.9"}
	got := buildKey(toks, r, "PHPSESSID", nil)
	if !strings.HasSuffix(got, keyTokenSep+"abc123") {
		t.Errorf("sticky-with-cookie key = %q, want suffix abc123", got)
	}
	// No cookie -> ClientIP fallback.
	r2 := &Request{Path: "/x", ClientIP: "9.9.9.9"}
	got2 := buildKey(toks, r2, "PHPSESSID", nil)
	if !strings.HasSuffix(got2, keyTokenSep+"9.9.9.9") {
		t.Errorf("sticky-fallback key = %q, want suffix 9.9.9.9", got2)
	}
}

func TestCacheKeyDeviceGeoEmpty(t *testing.T) {
	toks := compileKeyTokens(t, "path {device} {geo}")
	r := &Request{Path: "/x"}
	got := buildKey(toks, r, "", nil)
	want := strings.Join([]string{"/x", "", ""}, keyTokenSep)
	if got != want {
		t.Errorf("device/geo key = %q, want %q (empty placeholders)", got, want)
	}
}

func TestCacheKeyQueryAllow(t *testing.T) {
	// query_allow keeps ONLY the listed params (genre/age/camLang), dropping utm_*
	// and every unlisted param, and renders them sorted + re-encoded like `query`.
	toks := compileKeyTokens(t, "path query_allow genre age camLang")
	r := &Request{Path: "/", Query: url.Values{
		"genre":      {"horror"},
		"age":        {"18"},
		"camLang":    {"es"},
		"utm_source": {"google"},
		"utm_medium": {"cpc"},
		"unlisted":   {"x"},
	}}
	got := buildKey(toks, r, "", nil)
	want := strings.Join([]string{"/", "age=18&camLang=es&genre=horror"}, keyTokenSep)
	if got != want {
		t.Errorf("query_allow key = %q, want %q", got, want)
	}
}

func TestCacheKeyQueryAllowGlob(t *testing.T) {
	// query_allow supports `*` globs (keep every ff-*/pub-* param), and the result
	// is byte-stable regardless of request map order.
	toks := compileKeyTokens(t, "query_allow ff-* pub-*")
	r1 := &Request{Path: "/", Query: url.Values{
		"ff-a":  {"1"},
		"pub-x": {"y"},
		"utm_x": {"drop"},
		"ff":    {"drop"}, // not ff-* (no dash)
	}}
	r2 := &Request{Path: "/", Query: url.Values{
		"pub-x": {"y"},
		"ff-a":  {"1"},
	}}
	got1 := buildKey(toks, r1, "", nil)
	got2 := buildKey(toks, r2, "", nil)
	if got1 != got2 {
		t.Errorf("query_allow not order-stable: %q vs %q", got1, got2)
	}
	if got1 != "ff-a=1&pub-x=y" {
		t.Errorf("query_allow glob key = %q, want %q", got1, "ff-a=1&pub-x=y")
	}
}

func TestCacheKeyQueryAllowEmpty(t *testing.T) {
	// No matching params -> the token renders empty (no fragmentation).
	toks := compileKeyTokens(t, "path query_allow genre")
	r := &Request{Path: "/p", Query: url.Values{"utm_source": {"x"}}}
	got := buildKey(toks, r, "", nil)
	want := strings.Join([]string{"/p", ""}, keyTokenSep)
	if got != want {
		t.Errorf("query_allow empty key = %q, want %q", got, want)
	}
}

func TestCacheKeyQueryAllowNeedsName(t *testing.T) {
	_, err := compileCacheKey([]cadishfile.Arg{{Raw: "query_allow"}}, cadishfile.Pos{}, nil, nil, "", nil)
	if err == nil {
		t.Fatal("want error for query_allow with no param names")
	}
}

func TestCacheKeyUnknownNormalizer(t *testing.T) {
	_, err := compileCacheKey([]cadishfile.Arg{{Raw: "{bogus}", Kind: cadishfile.ArgPlaceholder}}, cadishfile.Pos{}, nil, nil, "", nil)
	if err == nil {
		t.Fatal("want error for unknown normalizer")
	}
}
