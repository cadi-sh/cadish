package pipeline

import (
	"net/http"
	"testing"
	"time"
)

// cache_ttl from_header reads the TTL from a named origin response header in
// several duration spellings (bare integer = seconds, plus unit forms).
func TestCacheTTLFromHeader(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	cases := []struct {
		hdr  string
		want time.Duration
	}{
		{"300", 300 * time.Second}, // bare integer = seconds (Cache-Control max-age idiom)
		{"300s", 300 * time.Second},
		{"5m", 5 * time.Minute},
		{"1h", time.Hour},
		{"1d", 24 * time.Hour},
	}
	for _, c := range cases {
		h := http.Header{"X-Cache-Ttl": []string{c.hdr}}
		dec := p.EvalResponse(req, 200, h)
		if !dec.Cacheable || dec.TTL != c.want {
			t.Errorf("from_header %q: TTL=%v cacheable=%v, want %v cacheable", c.hdr, dec.TTL, dec.Cacheable, c.want)
		}
	}
}

// An absent or garbage header makes the from_header rule NOT apply, falling
// through to a later `default` rule.
func TestCacheTTLFromHeaderFallthrough(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl
		cache_ttl default ttl 30s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	for name, h := range map[string]http.Header{
		"absent":   {},
		"garbage":  {"X-Cache-Ttl": []string{"abc"}},
		"empty":    {"X-Cache-Ttl": []string{""}},
		"zero":     {"X-Cache-Ttl": []string{"0"}},
		"negative": {"X-Cache-Ttl": []string{"-5"}},
		"badunit":  {"X-Cache-Ttl": []string{"5xz"}},
	} {
		dec := p.EvalResponse(req, 200, h)
		if !dec.Cacheable || dec.TTL != 30*time.Second {
			t.Errorf("%s: want fall through to default 30s, got TTL=%v cacheable=%v", name, dec.TTL, dec.Cacheable)
		}
	}
}

// from_header carries an optional static grace window.
func TestCacheTTLFromHeaderGrace(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl grace 1h
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	dec := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": []string{"60s"}})
	if dec.TTL != time.Minute || dec.Grace != time.Hour {
		t.Errorf("TTL=%v grace=%v, want 1m/1h", dec.TTL, dec.Grace)
	}
}

// from_header composes with a @scope selector and a nil respHeader (e.g. an origin
// error path) makes it fall through.
func TestCacheTTLFromHeaderScopeAndNilHeader(t *testing.T) {
	p := compileSrc(t, `x {
		@html content_type text/html
		cache_ttl @html from_header X-Cache-Ttl
		cache_ttl default ttl 10s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	// HTML response with the header -> scoped from_header applies.
	html := http.Header{"Content-Type": []string{"text/html"}, "X-Cache-Ttl": []string{"45s"}}
	if dec := p.EvalResponse(req, 200, html); dec.TTL != 45*time.Second {
		t.Errorf("scoped from_header: TTL=%v, want 45s", dec.TTL)
	}
	// Non-HTML -> scope misses -> default 10s.
	other := http.Header{"Content-Type": []string{"image/png"}, "X-Cache-Ttl": []string{"45s"}}
	if dec := p.EvalResponse(req, 200, other); dec.TTL != 10*time.Second {
		t.Errorf("non-html: TTL=%v, want default 10s", dec.TTL)
	}
	// nil respHeader (origin-error path) -> from_header can't read -> default 10s.
	if dec := p.EvalResponse(req, 200, nil); dec.TTL != 10*time.Second {
		t.Errorf("nil header: TTL=%v, want default 10s", dec.TTL)
	}
}

// An origin-controlled value large enough to overflow the int64-nanosecond seconds
// multiply (and silently wrap NEGATIVE) must NOT apply: it falls through to a later
// rule, never caching with a wrapped/past TTL. 9300000000 s (~295 y) and
// 10000000000 s both exceed the ~9.22e9 s overflow point; both must fall through to
// the 30s default, NOT produce a negative or absurd TTL.
func TestCacheTTLFromHeaderOverflowFallsThrough(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl
		cache_ttl default ttl 30s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	for name, val := range map[string]string{
		"overflow-wraps-negative": "9300000000",
		"overflow-larger":         "10000000000",
		"max-int64":               "9223372036854775807",
		"above-year-cap-seconds":  "40000000",    // ~463 days > 365d cap, no overflow
		"above-year-cap-duration": "400d",        // > 365d cap, parsed path
		"huge-duration-overflow":  "9999999999h", // overflows the parseDuration path
	} {
		h := http.Header{"X-Cache-Ttl": []string{val}}
		dec := p.EvalResponse(req, 200, h)
		if !dec.Cacheable || dec.TTL != 30*time.Second {
			t.Errorf("%s (%q): want fall through to default 30s, got TTL=%v cacheable=%v", name, val, dec.TTL, dec.Cacheable)
		}
		if dec.TTL < 0 {
			t.Errorf("%s (%q): NEGATIVE TTL %v leaked through", name, val, dec.TTL)
		}
	}
}

// A value at exactly the one-year cap still applies; just over it falls through.
func TestCacheTTLFromHeaderCapBoundary(t *testing.T) {
	p := compileSrc(t, `x {
		cache_ttl default from_header X-Cache-Ttl
		cache_ttl default ttl 30s
	}
`)
	req := &Request{Method: "GET", Host: "x", Path: "/a"}
	oneYear := 365 * 24 * time.Hour
	// Exactly at the cap (in seconds and as a duration spelling): applies.
	for _, v := range []string{"31536000", "365d"} {
		dec := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": []string{v}})
		if !dec.Cacheable || dec.TTL != oneYear {
			t.Errorf("at-cap %q: TTL=%v cacheable=%v, want %v cacheable", v, dec.TTL, dec.Cacheable, oneYear)
		}
	}
	// One second over the cap: falls through to the 30s default.
	dec := p.EvalResponse(req, 200, http.Header{"X-Cache-Ttl": []string{"31536001"}})
	if !dec.Cacheable || dec.TTL != 30*time.Second {
		t.Errorf("over-cap: want fall through to 30s, got TTL=%v cacheable=%v", dec.TTL, dec.Cacheable)
	}
}

func TestCacheTTLFromHeaderCompileErrors(t *testing.T) {
	if ce := compileErr(t, "x {\n cache_ttl default from_header\n}\n"); ce == nil {
		t.Fatal("want error for from_header with no header name")
	}
	if ce := compileErr(t, "x {\n cache_ttl default from_header X-Ttl bogus 1h\n}\n"); ce == nil {
		t.Fatal("want error for from_header with a non-grace trailing token")
	}
}
