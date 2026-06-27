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

func TestCacheKeyQueryStrip(t *testing.T) {
	// query_strip keeps the FULL canonical query MINUS the named/globbed params
	// (utm_*, a_mute, gclid), so meaningful params survive and tracking junk is
	// dropped. The kept params are sorted + re-encoded like the whole-`query` token.
	toks := compileKeyTokens(t, "path query_strip utm_* a_mute gclid")
	r := &Request{Path: "/", Query: url.Values{
		"genre":      {"horror"},
		"age":        {"18"},
		"utm_source": {"google"},
		"utm_medium": {"cpc"},
		"a_mute":     {"1"},
		"gclid":      {"abc"},
	}}
	got := buildKey(toks, r, "", nil)
	want := strings.Join([]string{"/", "age=18&genre=horror"}, keyTokenSep)
	if got != want {
		t.Errorf("query_strip key = %q, want %q", got, want)
	}
}

func TestCacheKeyQueryStripSameKeyOnTracking(t *testing.T) {
	// Two URLs differing ONLY in a stripped tracking param (utm_source) must produce
	// the SAME key (the F2 fix: tracking no longer fragments the cache).
	toks := compileKeyTokens(t, "host path query_strip utm_* gclid")
	r1 := &Request{Host: "h", Path: "/p", Query: url.Values{"id": {"7"}, "utm_source": {"a"}}}
	r2 := &Request{Host: "h", Path: "/p", Query: url.Values{"id": {"7"}, "utm_source": {"b"}}}
	if buildKey(toks, r1, "", nil) != buildKey(toks, r2, "", nil) {
		t.Errorf("differing utm_source should share a key: %q vs %q",
			buildKey(toks, r1, "", nil), buildKey(toks, r2, "", nil))
	}
	// But a difference in a MEANINGFUL (non-stripped) param must vary the key.
	r3 := &Request{Host: "h", Path: "/p", Query: url.Values{"id": {"8"}, "utm_source": {"a"}}}
	if buildKey(toks, r1, "", nil) == buildKey(toks, r3, "", nil) {
		t.Error("differing meaningful param (id) must produce different keys")
	}
}

func TestCacheKeyQueryStripOrderStable(t *testing.T) {
	// The surviving params render byte-stable regardless of incoming map order.
	toks := compileKeyTokens(t, "query_strip utm_*")
	r1 := &Request{Path: "/", Query: url.Values{"b": {"2"}, "a": {"1"}, "utm_x": {"z"}}}
	r2 := &Request{Path: "/", Query: url.Values{"a": {"1"}, "utm_x": {"z"}, "b": {"2"}}}
	got1, got2 := buildKey(toks, r1, "", nil), buildKey(toks, r2, "", nil)
	if got1 != got2 {
		t.Errorf("query_strip not order-stable: %q vs %q", got1, got2)
	}
	if got1 != "a=1&b=2" {
		t.Errorf("query_strip key = %q, want %q", got1, "a=1&b=2")
	}
}

func TestCacheKeyQueryStripExactName(t *testing.T) {
	// Exact (non-glob) names are dropped; a same-prefix but unlisted param survives.
	toks := compileKeyTokens(t, "query_strip a_mute t p")
	r := &Request{Path: "/", Query: url.Values{
		"a_mute": {"1"}, "t": {"x"}, "p": {"2"}, "page": {"3"}, "topic": {"news"},
	}}
	got := buildKey(toks, r, "", nil)
	// a_mute/t/p dropped; page/topic kept (not exact matches).
	want := "page=3&topic=news"
	if got != want {
		t.Errorf("query_strip exact key = %q, want %q", got, want)
	}
}

func TestCacheKeyQueryStripNeedsName(t *testing.T) {
	_, err := compileCacheKey([]cadishfile.Arg{{Raw: "query_strip"}}, cadishfile.Pos{}, nil, nil, "", nil)
	if err == nil {
		t.Fatal("want error for query_strip with no param names")
	}
}

func TestCacheKeyQueryAllowStripMutuallyExclusive(t *testing.T) {
	ce := compileErr(t, "x {\n cache_key host query_allow genre query_strip utm_*\n}\n")
	if ce == nil {
		t.Fatal("want compile error for query_allow + query_strip in one recipe")
	}
	if !strings.Contains(ce.Msg, "query_strip") || !strings.Contains(ce.Msg, "query_allow") {
		t.Errorf("error should mention both tokens, got: %q", ce.Msg)
	}
}

// Finding 6: query_strip combined with a whole-`query`/`url` token in ONE recipe is a
// compile error — the whole-query token re-emits the stripped params, silently defeating
// the strip. Symmetric with the query_allow⊕query_strip guard above.
func TestCacheKeyQueryStripWithWholeQueryRejected(t *testing.T) {
	for _, src := range []string{
		"x {\n cache_key host query query_strip utm_*\n}\n",
		"x {\n cache_key host url query_strip utm_*\n}\n",
		"x {\n cache_key host query_strip utm_* query\n}\n", // order-insensitive
	} {
		ce := compileErr(t, src)
		if ce == nil {
			t.Fatalf("want compile error for query_strip + whole-query token in %q", src)
		}
		if !strings.Contains(ce.Msg, "query_strip") {
			t.Errorf("error should mention query_strip, got: %q", ce.Msg)
		}
	}
}

func TestCacheKeyQueryStripScoped(t *testing.T) {
	// query_strip composes with a scoped first-match recipe exactly like query_allow.
	src := "x {\n @ssr header X-S 1\n cache_key @ssr host path query_strip utm_*\n cache_key default host path\n}\n"
	p := compileSrc(t, src)
	if len(p.keyRules) != 2 {
		t.Fatalf("want 2 recipes, got %d", len(p.keyRules))
	}
	// The scoped recipe's last token is the query_strip token.
	toks := p.keyRules[0].toks
	last := toks[len(toks)-1]
	if last.kind != tokQueryStrip {
		t.Fatalf("scoped recipe should end in tokQueryStrip, got kind %d", last.kind)
	}
	r := &Request{Host: "h", Path: "/p", Query: url.Values{"id": {"7"}, "utm_source": {"a"}}}
	got := buildKey(toks, r, "", nil)
	want := strings.Join([]string{"h", "/p", "id=7"}, keyTokenSep)
	if got != want {
		t.Errorf("scoped query_strip key = %q, want %q", got, want)
	}
}
