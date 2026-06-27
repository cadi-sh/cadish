package pipeline

import (
	"net/http"
	"testing"
	"time"
)

// grace_from_header sources the grace window from a named origin response header,
// mirroring from_header for the TTL. The literal `grace` stays as the fallback.
func TestGraceFromHeaderPresent(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace_from_header X-Cache-Grace grace 1m
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	h := http.Header{"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"5m"}}
	dec := p.EvalResponse(req, 200, h)
	if !dec.Cacheable || dec.TTL != time.Minute || dec.Grace != 5*time.Minute {
		t.Fatalf("TTL=%v grace=%v cacheable=%v, want 1m/5m/cacheable", dec.TTL, dec.Grace, dec.Cacheable)
	}
}

// An absent/garbage grace header falls back to the literal `grace`.
func TestGraceFromHeaderFallback(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace_from_header X-Cache-Grace grace 1m
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	for name, h := range map[string]http.Header{
		"absent":   {"X-Cache-Ttl": []string{"60s"}},
		"garbage":  {"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"abc"}},
		"empty":    {"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{""}},
		"zero":     {"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"0"}},
		"over-cap": {"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"400d"}},
	} {
		dec := p.EvalResponse(req, 200, h)
		if dec.Grace != time.Minute {
			t.Errorf("%s: grace=%v, want fallback 1m", name, dec.Grace)
		}
	}
}

// grace_from_header is valid on the literal `ttl` action too.
func TestGraceFromHeaderOnLiteralTTL(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default ttl 30s grace_from_header X-Cache-Grace grace 1m
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	dec := p.EvalResponse(req, 200, http.Header{"X-Cache-Grace": []string{"5m"}})
	if dec.TTL != 30*time.Second || dec.Grace != 5*time.Minute {
		t.Fatalf("TTL=%v grace=%v, want 30s/5m", dec.TTL, dec.Grace)
	}
	// Absent -> literal grace fallback.
	dec = p.EvalResponse(req, 200, http.Header{})
	if dec.Grace != time.Minute {
		t.Fatalf("grace=%v, want fallback 1m", dec.Grace)
	}
}

// max_stale_from_header sources the error-fallback window from an origin header.
func TestMaxStaleFromHeaderPresent(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace 1m max_stale_from_header X-Cache-Max-Stale max_stale 2h
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	h := http.Header{"X-Cache-Ttl": []string{"60s"}, "X-Cache-Max-Stale": []string{"30m"}}
	dec := p.EvalResponse(req, 200, h)
	if dec.MaxStale != 30*time.Minute {
		t.Fatalf("maxStale=%v, want 30m", dec.MaxStale)
	}
	// Absent -> literal fallback.
	dec = p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": []string{"60s"}})
	if dec.MaxStale != 2*time.Hour {
		t.Fatalf("maxStale=%v, want fallback 2h", dec.MaxStale)
	}
}

// The max_stale >= grace invariant is enforced against the RESOLVED values: an
// origin max_stale below the effective grace is IGNORED (set to 0) rather than
// erroring at runtime.
func TestMaxStaleResolvedInvariant(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace_from_header X-Cache-Grace max_stale_from_header X-Cache-Max-Stale grace 1m max_stale 2h
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	// effective grace 5m, max_stale 1m < grace -> ignored.
	below := http.Header{"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"5m"}, "X-Cache-Max-Stale": []string{"1m"}}
	if dec := p.EvalResponse(req, 200, below); dec.MaxStale != 0 {
		t.Fatalf("maxStale=%v, want 0 (below effective grace, ignored)", dec.MaxStale)
	}
	// effective grace 5m, max_stale 10m >= grace -> kept.
	above := http.Header{"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"5m"}, "X-Cache-Max-Stale": []string{"10m"}}
	if dec := p.EvalResponse(req, 200, above); dec.MaxStale != 10*time.Minute {
		t.Fatalf("maxStale=%v, want 10m", dec.MaxStale)
	}
}

// A from_header-family rule that APPLIES records its consumed control header names on
// the decision so the server strips them from the delivered response.
func TestGraceFromHeaderStripList(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace_from_header X-Cache-Grace max_stale_from_header X-Cache-Max-Stale grace 1m max_stale 2h
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	h := http.Header{"X-Cache-Ttl": []string{"60s"}, "X-Cache-Grace": []string{"5m"}}
	dec := p.EvalResponse(req, 200, h)
	want := map[string]bool{"X-Cache-Ttl": true, "X-Cache-Grace": true, "X-Cache-Max-Stale": true}
	if len(dec.StripHeaders) != len(want) {
		t.Fatalf("StripHeaders=%v, want the 3 control headers", dec.StripHeaders)
	}
	for _, n := range dec.StripHeaders {
		if !want[n] {
			t.Fatalf("unexpected strip header %q (got %v)", n, dec.StripHeaders)
		}
	}
}

// A plain `ttl` rule (no from_header family) leaves StripHeaders nil — the fast path
// must be untouched when the feature is inactive.
func TestNoStripHeadersWhenInactive(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default ttl 30s grace 1m
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	dec := p.EvalResponse(req, 200, http.Header{})
	if dec.StripHeaders != nil {
		t.Fatalf("StripHeaders=%v, want nil (no from_header rule fired)", dec.StripHeaders)
	}
}

// A from_header rule that FALLS THROUGH (TTL header absent) consumes nothing and so
// records no strip headers — the later plain rule decides without a strip list.
func TestNoStripHeadersOnFallthrough(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace_from_header X-Cache-Grace
		cache_ttl default ttl 30s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	dec := p.EvalResponse(req, 200, http.Header{}) // no X-Cache-Ttl
	if !dec.Cacheable || dec.TTL != 30*time.Second {
		t.Fatalf("want fall through to 30s, got TTL=%v cacheable=%v", dec.TTL, dec.Cacheable)
	}
	if dec.StripHeaders != nil {
		t.Fatalf("StripHeaders=%v, want nil (from_header rule did not apply)", dec.StripHeaders)
	}
}

// grace_from_header / max_stale_from_header are rejected on hit_for_miss (mirrors the
// existing max_stale-on-HFM guard).
func TestGraceFromHeaderRejectedOnHFM(t *testing.T) {
	if ce := compileErr(t, "x {\n cache_ttl default hit_for_miss 30s grace_from_header X-Cache-Grace\n}\n"); ce == nil {
		t.Fatal("want error for grace_from_header on hit_for_miss")
	}
	if ce := compileErr(t, "x {\n cache_ttl default hit_for_miss 30s max_stale_from_header X-Cache-Max-Stale\n}\n"); ce == nil {
		t.Fatal("want error for max_stale_from_header on hit_for_miss")
	}
}

// grace_from_header / max_stale_from_header need a header name argument.
func TestGraceFromHeaderCompileErrors(t *testing.T) {
	if ce := compileErr(t, "x {\n cache_ttl default ttl 30s grace_from_header\n}\n"); ce == nil {
		t.Fatal("want error for grace_from_header with no header name")
	}
	if ce := compileErr(t, "x {\n cache_ttl default ttl 30s max_stale_from_header\n}\n"); ce == nil {
		t.Fatal("want error for max_stale_from_header with no header name")
	}
}
