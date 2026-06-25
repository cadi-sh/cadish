package pipeline

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// compileBench compiles a single-site config string for a benchmark, failing the
// benchmark on any parse/compile error. It is the *testing.B twin of compileSrc.
func compileBench(b *testing.B, src string) *Pipeline {
	b.Helper()
	f, err := cadishfile.Parse("bench.cadish", []byte(src))
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		b.Fatalf("want exactly 1 site, got %d", len(f.Sites))
	}
	p, err := Compile(f.Sites[0])
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	return p
}

// benchReq is the common cacheable request shape exercised by the feature
// zero-cost benchmarks (a plain GET with one query param).
func benchReq() *Request {
	return &Request{
		Method: "GET",
		Host:   "example.com",
		Path:   "/catalog/widgets",
		Query:  url.Values{"page": {"2"}},
	}
}

// --- Zero-cost-when-unused: the baseline no-feature path --------------------
//
// baselineConfig is a minimal cacheable site that uses NONE of this session's
// features: no classify, no geo, no query_allow, no query_present, no dynamic
// header, no ban/purge, no admin. EvalRequest on it must stay at the round-1
// baseline (2 allocs / 96 B — the cache-key string + the request-header-op
// slice; the match context is stack-backed and does not escape). Every
// per-feature benchmark below compares against THIS to prove the feature adds
// zero work when the config does not use it.
const baselineConfig = `
example.com {
    cache { ram 1GiB }
    cache_key   method host path query
    cache_ttl   default ttl 2s grace 24h
    header      X-Frame-Options SAMEORIGIN
}
`

// BenchmarkFeatureBaseline is the reference no-feature EvalRequest. The
// per-feature "Unused" benchmarks must match its allocs/B exactly.
func BenchmarkFeatureBaseline(b *testing.B) {
	p := compileBench(b, baselineConfig)
	req := benchReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalRequest(req)
	}
}

// --- classify ---------------------------------------------------------------

// classifyConfig adds a classify token used in the cache key (the WHEN-USED
// cost: the request now also resolves a first-match rule table). The matchers
// it references are memoized in the same stack-backed context as the rest of
// the phase, so the only added per-request work is the table walk itself.
const classifyConfig = `
example.com {
    cache { ram 1GiB }
    @adult   query_present adult_content
    classify {tier} {
        when @adult       -> gated
        default           -> open
    }
    cache_key   method host path {tier}
    cache_ttl   default ttl 2s grace 24h
    header      X-Frame-Options SAMEORIGIN
}
`

func BenchmarkFeatureClassify(b *testing.B) {
	p := compileBench(b, classifyConfig)
	req := benchReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalRequest(req)
	}
}

// --- query_allow ------------------------------------------------------------

// queryAllowConfig keeps only an allowlisted set of params in the key (the
// WHEN-USED cost is the per-param glob/exact filter inside writeCanonicalQuery,
// which the whole-query token already paid).
const queryAllowConfig = `
example.com {
    cache { ram 1GiB }
    cache_key   method host path query_allow page genre
    cache_ttl   default ttl 2s grace 24h
}
`

func BenchmarkFeatureQueryAllow(b *testing.B) {
	p := compileBench(b, queryAllowConfig)
	req := benchReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalRequest(req)
	}
}

// --- query_present matcher --------------------------------------------------

// queryPresentConfig gates a pass on a query_present matcher (the WHEN-USED
// cost is a presence-OR scan over the request's params).
const queryPresentConfig = `
example.com {
    cache { ram 1GiB }
    @noindex  query_present preview draft utm_*
    pass      @noindex
    cache_key method host path query
    cache_ttl default ttl 2s grace 24h
}
`

func BenchmarkFeatureQueryPresent(b *testing.B) {
	p := compileBench(b, queryPresentConfig)
	req := benchReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalRequest(req)
	}
}

// --- geo matcher (request-phase work; the pre-pass is measured in the server) -

// geoConfig varies the cache key on the resolved geo country (the geo pre-pass
// itself runs in the server, gated by UsesGeoToken; here we measure the
// pipeline-side cost of a {geo} key token + a geo matcher scope).
const geoConfig = `
example.com {
    cache { ram 1GiB }
    @eu       geo continent EU
    pass      @eu
    cache_key method host path {geo}
    cache_ttl default ttl 2s grace 24h
}
`

func BenchmarkFeatureGeo(b *testing.B) {
	p := compileBench(b, geoConfig)
	req := benchReq()
	req.Geo = "US"
	req.GeoContinent = "NA"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalRequest(req)
	}
}

// --- dynamic header value (#17) ---------------------------------------------
//
// dynHeaderUnusedConfig declares a classifier (so the classify-resolver path is
// COMPILED in) but its header ops are all STATIC. This is the critical
// zero-cost case: the dynamic-header machinery must not allocate or escape the
// match context when no header op actually carries a placeholder. Its
// EvalRequest must match the baseline (the header op resolution happens in the
// DELIVER phase; EvalRequest just builds the key + req-header ops).
const dynHeaderUnusedConfig = `
example.com {
    cache { ram 1GiB }
    @adult   query_present adult_content
    classify {tier} { when @adult -> gated ; default -> open }
    cache_key method host path
    cache_ttl default ttl 2s grace 24h
    header   X-Frame-Options SAMEORIGIN
    header   Cache-Control "public, max-age=60"
}
`

// BenchmarkFeatureDynHeaderUnusedReq proves the request phase is baseline even
// with classifiers compiled in but no templated header op.
func BenchmarkFeatureDynHeaderUnusedReq(b *testing.B) {
	p := compileBench(b, dynHeaderUnusedConfig)
	req := benchReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalRequest(req)
	}
}

// dynHeaderUsedConfig has a TEMPLATED response header (the WHEN-USED cost: the
// DELIVER phase lazily builds a stack TemplateEnv and expands the placeholder).
// We measure EvalDeliver here because that is where the expansion happens.
const dynHeaderUsedConfig = `
example.com {
    cache { ram 1GiB }
    cache_key method host path
    cache_ttl default ttl 2s grace 24h
    header   Access-Control-Allow-Origin {http.Origin}
    header   X-Real-IP {client_ip}
}
`

// dynHeaderStaticConfig is the same shape with STATIC header values, the
// zero-cost reference for the EvalDeliver comparison.
const dynHeaderStaticConfig = `
example.com {
    cache { ram 1GiB }
    cache_key method host path
    cache_ttl default ttl 2s grace 24h
    header   Access-Control-Allow-Origin "https://app.example.com"
    header   X-Real-IP "0.0.0.0"
}
`

func BenchmarkFeatureDynHeaderDeliverStatic(b *testing.B) {
	p := compileBench(b, dynHeaderStaticConfig)
	req := benchReq()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalDeliver(req, nil, CacheStatusHit)
	}
}

func BenchmarkFeatureDynHeaderDeliverTemplated(b *testing.B) {
	p := compileBench(b, dynHeaderUsedConfig)
	req := benchReq()
	req.ClientIP = "203.0.113.7"
	req.Header = http.Header{"Origin": {"https://app.example.com"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.EvalDeliver(req, nil, CacheStatusHit)
	}
}
