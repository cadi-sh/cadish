package pipeline

import (
	"net/http"
	"net/url"
	"testing"
)

// TestQueryReEncodeNoCollision verifies security review #4: a decoded delimiter in
// one query field can no longer collide with a differently-structured query.
func TestQueryReEncodeNoCollision(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_key url
	cache_ttl default ttl 60s
}
`)
	keyFor := func(rawQuery string) string {
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			t.Fatalf("parse query %q: %v", rawQuery, err)
		}
		return p.EvalRequest(&Request{Host: "example.com", Path: "/p", Query: q}).CacheKey
	}
	// "a=x%26b=y" => one param a = "x&b=y"; "a=x&b=y" => two params. These are
	// semantically different and must NOT share a cache key.
	k1 := keyFor("a=x%26b=y")
	k2 := keyFor("a=x&b=y")
	if k1 == k2 {
		t.Fatalf("distinct queries collided on one cache key: %q", k1)
	}
}

// TestPurgeRegexBounded verifies security review #6: a request-sourced purge ban
// regex is rejected when it is empty, a mass-flush "match everything" pattern, or
// over-long; a narrow pattern is preserved; an operator literal is trusted.
func TestPurgeRegexBounded(t *testing.T) {
	p := compileSrc(t, `example.com {
	@tok header X-Purge-Token s3cr3t
	purge when @tok regex {http.X-Purge-Pattern}
	cache_ttl default ttl 60s
}
`)
	purgeRegex := func(pattern string) (string, bool) {
		h := http.Header{"X-Purge-Token": {"s3cr3t"}}
		if pattern != "" {
			h.Set("X-Purge-Pattern", pattern)
		}
		d := p.EvalRequest(&Request{Host: "example.com", Path: "/p", Header: h})
		if d.Purge == nil {
			t.Fatal("purge guard did not match")
		}
		return d.Purge.Regex, true
	}

	// Mass-flush patterns are rejected → "" (purge only the request's own key).
	for _, broad := range []string{".*", ".+", "^.*$", "(?s).*", "a?"} {
		if got, _ := purgeRegex(broad); got != "" {
			t.Errorf("broad pattern %q accepted as %q, want rejected (\"\")", broad, got)
		}
	}
	// A narrow, anchored pattern survives.
	if got, _ := purgeRegex("^/video/42/"); got != "^/video/42/" {
		t.Errorf("narrow pattern dropped: got %q", got)
	}
	// An invalid RE2 is rejected.
	if got, _ := purgeRegex("("); got != "" {
		t.Errorf("invalid regex accepted as %q", got)
	}
	// An over-long pattern is rejected.
	long := "^/" + string(make([]byte, maxRequestPurgeRegexLen))
	if got, _ := purgeRegex(long); got != "" {
		t.Errorf("over-long pattern accepted (len %d)", len(long))
	}
}

// TestPurgeRegexOperatorLiteralTrusted verifies an operator-written literal regex
// (not a {http.*} placeholder) is NOT bounded — operators may legitimately flush
// broadly.
func TestPurgeRegexOperatorLiteralTrusted(t *testing.T) {
	p := compileSrc(t, `example.com {
	@tok header X-Purge-Token s3cr3t
	purge when @tok regex ^/assets/.*
	cache_ttl default ttl 60s
}
`)
	d := p.EvalRequest(&Request{
		Host:   "example.com",
		Path:   "/p",
		Header: http.Header{"X-Purge-Token": {"s3cr3t"}},
	})
	if d.Purge == nil || d.Purge.Regex != "^/assets/.*" {
		t.Fatalf("operator literal regex not preserved: %+v", d.Purge)
	}
}

// TestHeaderMatchConstantTime is a functional check that the constant-time header
// value compare (security review #12) still matches and rejects correctly.
func TestHeaderMatchConstantTime(t *testing.T) {
	p := compileSrc(t, `example.com {
	@tok header X-Token right-value
	pass @tok
	cache_ttl default ttl 60s
}
`)
	match := func(v string) bool {
		return p.EvalRequest(&Request{
			Host:   "example.com",
			Path:   "/p",
			Header: http.Header{"X-Token": {v}},
		}).Pass
	}
	if !match("right-value") {
		t.Error("correct token did not match")
	}
	if match("wrong-value") {
		t.Error("wrong token matched")
	}
	if match("") {
		t.Error("empty token matched")
	}
}
