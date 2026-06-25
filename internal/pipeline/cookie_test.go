package pipeline

import (
	"net/http"
	"testing"
)

func reqWithCookie(cookie string) *Request {
	h := http.Header{}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return &Request{Method: "GET", Path: "/", Header: h}
}

// TestCookiePresence: `cookie NAME` matches when the named cookie is present.
func TestCookiePresence(t *testing.T) {
	p := compileSrc(t, "example.com {\n @authed cookie sessionid\n pass @authed\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }

	if !pass("sessionid=abc123") {
		t.Error("sessionid present should match")
	}
	if !pass("foo=1; sessionid=abc; bar=2") {
		t.Error("sessionid among other cookies should match")
	}
	if !pass("sessionid=") { // present with empty value still counts
		t.Error("sessionid present (empty value) should match")
	}
	if pass("other=1") {
		t.Error("no sessionid should not match")
	}
	if pass("") { // no Cookie header
		t.Error("no Cookie header should not match")
	}
}

// TestCookieValue: `cookie NAME VALUE…` matches when the cookie equals one of the
// values (OR).
func TestCookieValue(t *testing.T) {
	p := compileSrc(t, "example.com {\n @paid cookie tier premium vip\n pass @paid\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }

	if !pass("tier=premium") {
		t.Error("tier=premium should match")
	}
	if !pass("tier=vip") {
		t.Error("tier=vip (second OR value) should match")
	}
	if pass("tier=free") {
		t.Error("tier=free should not match")
	}
	if pass("other=premium") { // wrong cookie name
		t.Error("a different cookie with the value should not match")
	}
	if pass("") {
		t.Error("no cookie should not match a value test")
	}
}

// TestCookieInline: the inline form `pass cookie NAME` works (no named matcher).
func TestCookieInline(t *testing.T) {
	p := compileSrc(t, "example.com {\n pass cookie sessionid\n}")
	if !p.EvalRequest(reqWithCookie("sessionid=x")).Pass {
		t.Error("inline cookie matcher should match a present cookie")
	}
	if p.EvalRequest(reqWithCookie("nope=1")).Pass {
		t.Error("inline cookie matcher should not match an absent cookie")
	}
}

// TestCookieInKey: a cookie matcher is request-phase, usable to scope a KEY-phase
// directive (here, a response-header rule scoped on a cookie compiles & matches).
func TestCookieInKeyPhase(t *testing.T) {
	// cookie scoping a request-phase header (before cache_key) must compile —
	// proving it is NOT restricted to deliver phase like content_type.
	compileSrc(t, "example.com {\n @authed cookie sessionid\n header @authed X-Authed yes\n cache_key path\n}")
}

func TestCookieNeedsName(t *testing.T) {
	if compileErr(t, "example.com {\n @x cookie\n pass @x\n}") == nil {
		t.Error("a cookie matcher with no name should be a compile error")
	}
}

// TestCookiePrefixGlob: `cookie NAME*` matches any cookie whose name has that
// prefix (the WordPress logged-in case: wordpress_logged_in_<md5>).
func TestCookiePrefixGlob(t *testing.T) {
	p := compileSrc(t, "example.com {\n @wp cookie wordpress_logged_in_*\n pass @wp\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }

	if !pass("wordpress_logged_in_abc123=tok") {
		t.Error("hashed wordpress_logged_in_ cookie should match the prefix glob")
	}
	if !pass("foo=1; wordpress_logged_in_deadbeef=tok; bar=2") {
		t.Error("prefixed cookie among others should match")
	}
	if !pass("wordpress_logged_in_=") { // prefix present, empty suffix + empty value
		t.Error("bare prefix (empty suffix) present should match")
	}
	if pass("wordpress_test_cookie=x") { // shares a shorter prefix but not this one
		t.Error("a cookie not starting with the prefix should not match")
	}
	if pass("other=1") {
		t.Error("an unrelated cookie should not match")
	}
	if pass("") {
		t.Error("no Cookie header should not match")
	}
}

// TestCookieExactNotPrefix: a bare `cookie NAME` stays an EXACT match — it must
// NOT match a longer name that merely has NAME as a prefix.
func TestCookieExactNotPrefix(t *testing.T) {
	p := compileSrc(t, "example.com {\n @s cookie sessionid\n pass @s\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }

	if !pass("sessionid=abc") {
		t.Error("exact sessionid should match")
	}
	if pass("sessionid_extra=abc") { // exact must not behave like a prefix
		t.Error("exact cookie must not match a longer prefixed name")
	}
}

// TestCookieGlobIsPresenceOnly: combining a glob NAME with value args is a compile
// error — a glob name is presence-only (a value would have ambiguous semantics
// across the set of matching cookies, and constant-time value compare is reserved
// for an exact, single-named cookie).
func TestCookieGlobIsPresenceOnly(t *testing.T) {
	if compileErr(t, "example.com {\n @x cookie wordpress_logged_in_* tok\n pass @x\n}") == nil {
		t.Error("a glob cookie name with value args should be a compile error")
	}
}
