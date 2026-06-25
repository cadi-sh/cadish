package pipeline

import (
	"net/http"
	"strings"
	"testing"
)

// hasSetOp reports whether ops contains a Set of name=value.
func hasSetOp(ops []HeaderOp, name, value string) bool {
	for _, op := range ops {
		if op.Op == OpSet && op.Name == name && op.Value == value {
			return true
		}
	}
	return false
}

const longCache = "public, max-age=31536000"

// TestContentTypeMatcher: a content_type matcher fires against the response
// Content-Type (substring, case-insensitive) and only in the DELIVER phase.
func TestContentTypeMatcher(t *testing.T) {
	p := compileSrc(t, `example.com {
    @longcache content_type text/css image/svg+xml
    cache_key path
    header @longcache Cache-Control "`+longCache+`"
}`)

	// text/css (with charset param) matches.
	css := http.Header{}
	css.Set("Content-Type", "text/css; charset=utf-8")
	if d := p.EvalDeliver(&Request{Path: "/x"}, css, CacheStatusHit); !hasSetOp(d.RespHeaderOps, "Cache-Control", longCache) {
		t.Error("text/css response should get the long Cache-Control")
	}

	// image/svg+xml matches the second arg.
	svg := http.Header{}
	svg.Set("Content-Type", "image/svg+xml")
	if d := p.EvalDeliver(&Request{Path: "/x"}, svg, CacheStatusHit); !hasSetOp(d.RespHeaderOps, "Cache-Control", longCache) {
		t.Error("image/svg+xml response should get the long Cache-Control")
	}

	// text/html does NOT match.
	html := http.Header{}
	html.Set("Content-Type", "text/html; charset=utf-8")
	if d := p.EvalDeliver(&Request{Path: "/x"}, html, CacheStatusHit); hasSetOp(d.RespHeaderOps, "Cache-Control", longCache) {
		t.Error("text/html response should NOT get the long Cache-Control")
	}

	// A nil response header (e.g. a bodyless negative entry) never matches and
	// must not panic.
	if d := p.EvalDeliver(&Request{Path: "/x"}, nil, CacheStatusHit); hasSetOp(d.RespHeaderOps, "Cache-Control", longCache) {
		t.Error("nil response header should not match content_type")
	}
}

// TestContentTypeInline: the inline single-arg form on a deliver directive works.
func TestContentTypeInline(t *testing.T) {
	p := compileSrc(t, `example.com {
    cache_key path
    header content_type text/css Cache-Control "`+longCache+`"
}`)
	css := http.Header{}
	css.Set("Content-Type", "text/css")
	if d := p.EvalDeliver(&Request{Path: "/x"}, css, CacheStatusHit); !hasSetOp(d.RespHeaderOps, "Cache-Control", longCache) {
		t.Error("inline content_type text/css should fire")
	}
	html := http.Header{}
	html.Set("Content-Type", "application/json")
	if d := p.EvalDeliver(&Request{Path: "/x"}, html, CacheStatusHit); hasSetOp(d.RespHeaderOps, "Cache-Control", longCache) {
		t.Error("inline content_type should not fire for application/json")
	}
}

// TestContentTypeResponseScopesCompile: content_type is a response-phase matcher,
// so it may scope the origin-response directives (cache_ttl, storage — the response
// Content-Type is known once the origin replies) and the DELIVER directives
// (response header, strip_cookies, cors).
func TestContentTypeResponseScopesCompile(t *testing.T) {
	compileSrc(t, `example.com {
    @css content_type text/css
    cache_key path
    cache_ttl @css ttl 1h
    storage @css -> disk
    header @css X-Foo bar
    strip_cookies @css
    cors @css *
}`)
}

// TestContentTypePhaseErrors: scoping a request/origin-phase directive with a
// content_type matcher is a compile error (the response isn't known yet).
func TestContentTypePhaseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"pass", `example.com {
    @css content_type text/css
    pass @css
}`},
		{"route", `example.com {
    upstream u { to http://h:80 }
    @css content_type text/css
    route @css -> u
}`},
		{"purge", `example.com {
    @css content_type text/css
    purge when @css
}`},
		{"request_header", `example.com {
    @css content_type text/css
    header @css X-Foo bar
    cache_key path
}`},
		{"pass_inline", `example.com {
    pass content_type text/css
}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := compileErr(t, tc.src)
			if err == nil {
				t.Fatalf("expected a compile error for content_type scoping %s", tc.name)
			}
			if !strings.Contains(err.Msg, "content_type") {
				t.Fatalf("error %q should mention content_type", err.Msg)
			}
		})
	}
}
