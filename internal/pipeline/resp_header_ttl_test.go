package pipeline

import (
	"net/http"
	"testing"
	"time"
)

// A `cache_ttl resp_header X-Powered-By Express` rule selects the SSR tier ONLY
// when the origin response carries that header; otherwise evaluation falls through
// to the PHP/default ladder.
func TestRespHeaderTTLSelectsSSRTier(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl resp_header X-Powered-By Express ttl 1m grace 2w
		cache_ttl default ttl 5s grace 1m
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}

	// Origin signals SSR via the response header -> SSR tier (1m / 2w).
	ssr := http.Header{"Content-Type": []string{"text/html"}, "X-Powered-By": []string{"Express"}}
	if dec := p.EvalResponse(req, 200, ssr); !dec.Cacheable || dec.TTL != time.Minute || dec.Grace != 14*24*time.Hour {
		t.Errorf("SSR response: TTL=%v grace=%v cacheable=%v, want 1m/2w cacheable", dec.TTL, dec.Grace, dec.Cacheable)
	}
	// No header (PHP origin) -> falls through to the default ladder (5s / 1m).
	php := http.Header{"Content-Type": []string{"text/html"}}
	if dec := p.EvalResponse(req, 200, php); !dec.Cacheable || dec.TTL != 5*time.Second || dec.Grace != time.Minute {
		t.Errorf("PHP response: TTL=%v grace=%v cacheable=%v, want 5s/1m cacheable", dec.TTL, dec.Grace, dec.Cacheable)
	}
	// Header present but a DIFFERENT value -> the resp_header rule misses -> default.
	other := http.Header{"X-Powered-By": []string{"PHP/8.2"}}
	if dec := p.EvalResponse(req, 200, other); dec.TTL != 5*time.Second {
		t.Errorf("different value: TTL=%v, want default 5s", dec.TTL)
	}
	// nil respHeader (origin-error path) -> resp_header rule can't read -> default.
	if dec := p.EvalResponse(req, 200, nil); dec.TTL != 5*time.Second {
		t.Errorf("nil header: TTL=%v, want default 5s", dec.TTL)
	}
}

// The resp_header value accepts a `*`-glob (mirrors the query/name glob engine).
func TestRespHeaderTTLValueGlob(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl resp_header X-Powered-By Exp* ttl 1m
		cache_ttl default ttl 5s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	if dec := p.EvalResponse(req, 200, http.Header{"X-Powered-By": []string{"Express"}}); dec.TTL != time.Minute {
		t.Errorf("glob Exp* vs Express: TTL=%v, want 1m", dec.TTL)
	}
	if dec := p.EvalResponse(req, 200, http.Header{"X-Powered-By": []string{"Django"}}); dec.TTL != 5*time.Second {
		t.Errorf("glob Exp* vs Django: TTL=%v, want default 5s", dec.TTL)
	}
}

// A bare `*` value (or no value) is a presence test of the header.
func TestRespHeaderTTLPresence(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl resp_header X-Powered-By * ttl 1m
		cache_ttl default ttl 5s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	if dec := p.EvalResponse(req, 200, http.Header{"X-Powered-By": []string{"anything"}}); dec.TTL != time.Minute {
		t.Errorf("presence: TTL=%v, want 1m", dec.TTL)
	}
	if dec := p.EvalResponse(req, 200, http.Header{"Content-Type": []string{"text/html"}}); dec.TTL != 5*time.Second {
		t.Errorf("absent: TTL=%v, want default 5s", dec.TTL)
	}
}

// The header NAME match is case-insensitive (HTTP header semantics).
func TestRespHeaderTTLCaseInsensitiveName(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl resp_header x-powered-by Express ttl 1m
		cache_ttl default ttl 5s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	// Origin uses the canonical mixed case; config used lower case.
	if dec := p.EvalResponse(req, 200, http.Header{"X-Powered-By": []string{"Express"}}); dec.TTL != time.Minute {
		t.Errorf("case-insensitive name: TTL=%v, want 1m", dec.TTL)
	}
}

// The residual SSR-vs-PHP 404 split: both are `status 404`, only the response
// header distinguishes them. X-Powered-By present -> SSR 1m/24h; absent -> PHP
// 10s/1m. resp_header combines with `status` in one rule's scope (AND).
func TestRespHeaderTTL404Split(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl resp_header X-Powered-By Express status 404 ttl 1m grace 24h
		cache_ttl status 404 ttl 10s grace 1m
		cache_ttl default ttl 1m grace 10m
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/missing"}

	// 404 from the SSR origin (X-Powered-By: Express) -> 1m / 24h.
	ssr := http.Header{"X-Powered-By": []string{"Express"}}
	if dec := p.EvalResponse(req, 404, ssr); !dec.Cacheable || dec.TTL != time.Minute || dec.Grace != 24*time.Hour {
		t.Errorf("SSR 404: TTL=%v grace=%v cacheable=%v, want 1m/24h cacheable", dec.TTL, dec.Grace, dec.Cacheable)
	}
	// 404 from the PHP origin (no header) -> the resp_header+status rule misses,
	// the plain `status 404` rule wins -> 10s / 1m.
	if dec := p.EvalResponse(req, 404, http.Header{}); !dec.Cacheable || dec.TTL != 10*time.Second || dec.Grace != time.Minute {
		t.Errorf("PHP 404: TTL=%v grace=%v cacheable=%v, want 10s/1m cacheable", dec.TTL, dec.Grace, dec.Cacheable)
	}
	// 200 from SSR -> neither 404 rule matches -> default 1m/10m.
	if dec := p.EvalResponse(req, 200, ssr); dec.TTL != time.Minute || dec.Grace != 10*time.Minute {
		t.Errorf("SSR 200: TTL=%v grace=%v, want default 1m/10m", dec.TTL, dec.Grace)
	}
}

// resp_header also works as a NAMED matcher referenced by a cache_ttl @scope.
func TestRespHeaderTTLNamedMatcher(t *testing.T) {
	p := compileSrc(t, `x {
		@ssr resp_header X-Powered-By Express
		cache_ttl @ssr ttl 1m
		cache_ttl default ttl 5s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	if dec := p.EvalResponse(req, 200, http.Header{"X-Powered-By": []string{"Express"}}); dec.TTL != time.Minute {
		t.Errorf("named resp_header: TTL=%v, want 1m", dec.TTL)
	}
	if dec := p.EvalResponse(req, 200, http.Header{}); dec.TTL != 5*time.Second {
		t.Errorf("named resp_header absent: TTL=%v, want 5s", dec.TTL)
	}
}

// Fast path: a config with NO resp_header rule compiles every cache_ttl selector
// with a nil respHeader term (zero overhead), and behaves exactly as before.
func TestRespHeaderTTLFastPathUnchanged(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl status 404 ttl 10s
		cache_ttl default ttl 1m
	}
`)
	for _, r := range p.ttlRules {
		if r.sel.respHeader != nil {
			t.Fatalf("no resp_header rule was written, but a selector carries a respHeader term")
		}
	}
}

// resp_header is response-phase-only: using it to scope a request-phase directive
// is a compile error (mirrors the status / content_type / set_cookie phase guard).
func TestRespHeaderTTLPhaseGuard(t *testing.T) {
	for _, src := range []string{
		"x {\n @ssr resp_header X-Powered-By Express\n pass @ssr\n}\n",
		"x {\n @ssr resp_header X-Powered-By Express\n route @ssr -> y\n upstream y { to http://127.0.0.1:1 }\n}\n",
		"x {\n respond resp_header X-Powered-By Express 200 hi\n}\n",
		"x {\n @ssr resp_header X-Powered-By Express\n cache_key @ssr url\n cache_key default url\n}\n",
	} {
		if ce := compileErr(t, src); ce == nil {
			t.Errorf("want a compile error for a request-phase use of resp_header:\n%s", src)
		}
	}
}

func TestRespHeaderTTLCompileErrors(t *testing.T) {
	// resp_header in a cache_ttl selector needs a NAME and a VALUE.
	if ce := compileErr(t, "x {\n cache_ttl resp_header X-Powered-By\n}\n"); ce == nil {
		t.Fatal("want error: resp_header selector with NAME but no VALUE")
	}
	if ce := compileErr(t, "x {\n cache_ttl resp_header\n}\n"); ce == nil {
		t.Fatal("want error: resp_header selector with no NAME/VALUE")
	}
}
