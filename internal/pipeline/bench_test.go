package pipeline

import (
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// loadStorefrontBench parses the canonical A-flat config, substitutes env,
// splices the imported nocache.cadish fragment, and compiles it — the full
// real-world matcher-heavy site (mirrors the test helper, for benchmarks).
func loadStorefrontBench(b *testing.B) *Pipeline {
	b.Helper()
	site := spliceStorefront(b)
	p, err := Compile(site)
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	return p
}

func spliceStorefront(b *testing.B) *cadishfile.Site {
	b.Helper()
	dir := filepath.FromSlash("testdata")
	f, err := cadishfile.ParseFile(filepath.Join(dir, "storefront.A-flat.cadish"))
	if err != nil {
		b.Fatalf("parse A-flat: %v", err)
	}
	cadishfile.SubstituteEnv(f, func(name string) (string, bool) {
		if name == "PURGE_TOKEN" {
			return "topsecret", true
		}
		return "", false
	})
	site, err := SpliceImports(f.Sites[0], FileImportResolver(dir))
	if err != nil {
		b.Fatalf("splice imports: %v", err)
	}
	return site
}

func ajaxHeader() http.Header {
	h := http.Header{}
	h.Set("X-Requested-With", "XMLHttpRequest")
	h.Set("Cookie", "PHPSESSID=abc123; other=1")
	return h
}

// BenchmarkEvalRequest measures the per-request RECV+KEY evaluation (matcher
// scan + cache-key build) over the real storefront site, for request shapes
// that take different paths through the rule set: a cacheable listing, a pass
// via @ajax, a route via host_regex (@static), and the synthetic respond.
func BenchmarkEvalRequest(b *testing.B) {
	p := loadStorefrontBench(b)
	cases := []struct {
		name string
		req  *Request
	}{
		{"cacheable", &Request{Method: "GET", Host: "example.com", Path: "/catalog/widgets", Query: url.Values{"page": {"2"}}}},
		{"pass_ajax", &Request{Method: "GET", Host: "example.com", Path: "/home", Query: url.Values{}, Header: ajaxHeader()}},
		{"route_static", &Request{Method: "GET", Host: "static.example.com", Path: "/img/logo.png", Query: url.Values{}}},
		{"respond", &Request{Method: "GET", Host: "example.com", Path: "/health-check", Query: url.Values{}}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = p.EvalRequest(tc.req)
			}
		})
	}
}

// BenchmarkEvalRequestParallel measures the evaluation core under concurrency
// (it is stateless/read-only, so this confirms it scales without contention).
func BenchmarkEvalRequestParallel(b *testing.B) {
	p := loadStorefrontBench(b)
	req := &Request{Method: "GET", Host: "example.com", Path: "/catalog/widgets", Query: url.Values{"page": {"2"}}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = p.EvalRequest(req)
		}
	})
}

// BenchmarkEvalResponse measures the response-phase evaluation (status-based
// cache_ttl selection + response header rules).
func BenchmarkEvalResponse(b *testing.B) {
	p := loadStorefrontBench(b)
	req := &Request{Method: "GET", Host: "example.com", Path: "/catalog/widgets", Query: url.Values{}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.EvalResponse(req, 200, nil)
	}
}

// BenchmarkCompile measures one-time config compilation of the real site (paid
// at startup/reload, not per request) so regressions there stay visible.
func BenchmarkCompile(b *testing.B) {
	site := spliceStorefront(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Compile(site); err != nil {
			b.Fatal(err)
		}
	}
}

// --- Matcher engine in isolation: glob/trie pathSet vs path_regex -----------

// benchPaths are representative request paths exercised against both matchers.
var benchPaths = []string{
	"/panel/settings", "/catalog/widgets/featured", "/img/logo.png",
	"/static/app.css", "/home", "/pagina/42", "/cart", "/admin/users/1",
}

// BenchmarkMatcherPathSet measures the glob/trie path matcher (exact set +
// prefix trie + glob list) — the engine cadish uses for `path` matchers.
func BenchmarkMatcherPathSet(b *testing.B) {
	s := newPathSet()
	for _, pat := range []string{"/panel/*", "/admin/*", "/cart", "/pagina/*", "/home"} {
		s.add(pat)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = s.Match(benchPaths[i&7])
	}
}

// BenchmarkMatcherPathRegex measures an equivalent compiled regexp (the
// `path_regex` matcher) over the same paths, for an apples-to-apples comparison
// with the glob/trie engine.
func BenchmarkMatcherPathRegex(b *testing.B) {
	re := regexp.MustCompile(`^(/panel/.*|/admin/.*|/cart|/pagina/.*|/home)$`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = re.MatchString(benchPaths[i&7])
	}
}
