package pipeline

import (
	"net/http"
	"testing"
	"time"
)

// cache_ttl accepts an optional third window, `max_stale DUR`, after grace on both
// the `ttl` and `from_header` actions, and EvalResponse surfaces it as MaxStale.
func TestCacheTTLMaxStale(t *testing.T) {
	p := compileSrc(t, `x {
		@hdr content_type text/html
		cache_ttl @hdr from_header X-Cache-Ttl grace 5m max_stale 24h
		cache_ttl default ttl 60s grace 5m max_stale 24h
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}

	// static ttl branch
	dec := p.EvalResponse(req, 200, http.Header{"Content-Type": []string{"image/png"}})
	if dec.TTL != time.Minute || dec.Grace != 5*time.Minute || dec.MaxStale != 24*time.Hour {
		t.Fatalf("static: TTL=%v grace=%v max_stale=%v, want 1m/5m/24h", dec.TTL, dec.Grace, dec.MaxStale)
	}

	// from_header branch (also carries max_stale)
	h := http.Header{"Content-Type": []string{"text/html"}, "X-Cache-Ttl": []string{"30s"}}
	dec = p.EvalResponse(req, 200, h)
	if dec.TTL != 30*time.Second || dec.Grace != 5*time.Minute || dec.MaxStale != 24*time.Hour {
		t.Fatalf("from_header: TTL=%v grace=%v max_stale=%v, want 30s/5m/24h", dec.TTL, dec.Grace, dec.MaxStale)
	}
}

// max_stale defaults to zero (disabled) when not configured.
func TestCacheTTLMaxStaleDefaultZero(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default ttl 60s grace 5m
	}
`)
	dec := p.EvalResponse(&Request{Method: "GET", Host: "x", Path: "/a"}, 200, nil)
	if dec.MaxStale != 0 {
		t.Fatalf("MaxStale=%v, want 0 (unset)", dec.MaxStale)
	}
}

// max_stale without a preceding grace is accepted (grace defaults to 0, and
// max_stale >= 0 holds).
func TestCacheTTLMaxStaleNoGrace(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default ttl 60s max_stale 1h
	}
`)
	dec := p.EvalResponse(&Request{Method: "GET", Host: "x", Path: "/a"}, 200, nil)
	if dec.Grace != 0 || dec.MaxStale != time.Hour {
		t.Fatalf("grace=%v max_stale=%v, want 0/1h", dec.Grace, dec.MaxStale)
	}
}

func TestCacheTTLMaxStaleCompileErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"on hit_for_miss", "x {\n cache_ttl default hit_for_miss 30s max_stale 1h\n}\n"},
		{"less than grace", "x {\n cache_ttl default ttl 60s grace 5m max_stale 1m\n}\n"},
		{"no duration", "x {\n cache_ttl default ttl 60s grace 5m max_stale\n}\n"},
		{"bad duration", "x {\n cache_ttl default ttl 60s grace 5m max_stale bogus\n}\n"},
		{"from_header less than grace", "x {\n cache_ttl default from_header X-Ttl grace 5m max_stale 1m\n}\n"},
		{"trailing junk after max_stale", "x {\n cache_ttl default ttl 60s grace 5m max_stale 1h junk\n}\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ce := compileErr(t, c.src); ce == nil {
				t.Fatalf("want compile error for %q", c.name)
			}
		})
	}
}
