package pipeline

import (
	"net/http"
	"strings"
	"testing"
)

// TestBuildKeySeparatorNotInjectable is the WB-S1 guard: the 0x1f key separator must
// not appear inside a token value, or two different (value, value) splits would render
// to the same key and collide. The separator byte is stripped from request-derived
// token values.
func TestBuildKeySeparatorNotInjectable(t *testing.T) {
	sep := "\x1f"
	toks := []keyToken{{kind: tokPath}, {kind: tokHeader, arg: "X-Val"}}
	mk := func(path, xval string) string {
		req := &Request{Host: "h", Path: path, Header: http.Header{"X-Val": {xval}}}
		return buildKey(toks, req, "", nil)
	}
	// Without sanitization these two distinct (path, header) pairs collide on "/a\x1fb\x1fc".
	k1 := mk("/a"+sep+"b", "c")
	k2 := mk("/a", "b"+sep+"c")
	if k1 == k2 {
		t.Errorf("WB-S1: distinct requests collided on the same key\n k1=%q\n k2=%q", k1, k2)
	}
	// And no key carries the separator inside a token value (only as the real delimiter).
	if strings.Count(k1, sep) != 1 {
		t.Errorf("key should contain exactly one separator (the real delimiter), got %d in %q", strings.Count(k1, sep), k1)
	}
}

// TestBuildKeyCookieToken checks the new cookie:NAME token keys on the cookie's value.
func TestBuildKeyCookieToken(t *testing.T) {
	toks := []keyToken{{kind: tokPath}, {kind: tokCookie, arg: "session"}}
	mk := func(cookie string) string {
		req := &Request{Host: "h", Path: "/x", Header: http.Header{"Cookie": {cookie}}}
		return buildKey(toks, req, "", nil)
	}
	if a, b := mk("session=AAA"), mk("session=BBB"); a == b {
		t.Errorf("cookie:session must key per-value: %q == %q", a, b)
	}
	if a, b := mk("session=AAA"), mk("session=AAA; other=1"); a != b {
		t.Errorf("cookie:session must ignore other cookies: %q != %q", a, b)
	}
}
