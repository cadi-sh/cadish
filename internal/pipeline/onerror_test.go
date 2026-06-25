package pipeline

import (
	"net/http"
	"testing"
)

// TestEvalOnErrorUnconfigured: a site with no `respond on_error` returns nil (the
// zero-cost path the server's HasOnError gate relies on).
func TestEvalOnErrorUnconfigured(t *testing.T) {
	p := compileSrc(t, "x {\n cache_ttl default ttl 60s\n}\n")
	if p.HasOnError() {
		t.Fatal("HasOnError = true, want false for a site without respond on_error")
	}
	if oe := p.EvalOnError(&Request{Method: "GET", Path: "/"}, 502); oe != nil {
		t.Fatalf("EvalOnError = %+v, want nil when unconfigured", oe)
	}
}

// TestEvalOnErrorUnscoped: a bare `respond on_error STATUS BODY` matches every
// request, with the default Content-Type.
func TestEvalOnErrorUnscoped(t *testing.T) {
	p := compileSrc(t, "x {\n respond on_error 503 \"down for maintenance\"\n}\n")
	if !p.HasOnError() {
		t.Fatal("HasOnError = false, want true")
	}
	oe := p.EvalOnError(&Request{Method: "GET", Path: "/anything"}, 502)
	if oe == nil {
		t.Fatal("EvalOnError = nil, want a synthetic")
	}
	if oe.Status != 503 {
		t.Errorf("Status = %d, want 503", oe.Status)
	}
	if string(oe.Body) != "down for maintenance" {
		t.Errorf("Body = %q, want %q", oe.Body, "down for maintenance")
	}
	if oe.ContentType != defaultOnErrorContentType {
		t.Errorf("ContentType = %q, want %q", oe.ContentType, defaultOnErrorContentType)
	}
}

// TestEvalOnErrorContentType: a trailing `content_type T` overrides the default.
func TestEvalOnErrorContentType(t *testing.T) {
	p := compileSrc(t, "x {\n respond on_error 503 \"oops\" content_type \"application/json\"\n}\n")
	oe := p.EvalOnError(&Request{Method: "GET", Path: "/"}, 502)
	if oe == nil || oe.ContentType != "application/json" {
		t.Fatalf("ContentType = %+v, want application/json", oe)
	}
	if string(oe.Body) != "oops" {
		t.Errorf("Body = %q, want oops (content_type must not bleed into the body)", oe.Body)
	}
}

// TestEvalOnErrorScopeMatch: a `respond on_error @scope STATUS BODY` fires only for
// requests matching the request-phase scope.
func TestEvalOnErrorScopeMatch(t *testing.T) {
	p := compileSrc(t, `x {
		@api path /api/*
		respond on_error @api 503 "api down"
	}
`)
	if oe := p.EvalOnError(&Request{Method: "GET", Path: "/api/users"}, 502); oe == nil || string(oe.Body) != "api down" {
		t.Fatalf("matching path = %+v, want api-down synthetic", oe)
	}
	if oe := p.EvalOnError(&Request{Method: "GET", Path: "/home"}, 502); oe != nil {
		t.Errorf("non-matching path = %+v, want nil (falls through to bare fallback)", oe)
	}
}

// TestEvalOnErrorFirstMatchWins: source order resolves which page is served.
func TestEvalOnErrorFirstMatchWins(t *testing.T) {
	p := compileSrc(t, `x {
		@api path /api/*
		respond on_error @api 503 "api"
		respond on_error 502 "generic"
	}
`)
	if oe := p.EvalOnError(&Request{Method: "GET", Path: "/api/x"}, 0); oe == nil || string(oe.Body) != "api" {
		t.Fatalf("api path = %+v, want the api page (first match)", oe)
	}
	if oe := p.EvalOnError(&Request{Method: "GET", Path: "/other"}, 0); oe == nil || string(oe.Body) != "generic" {
		t.Fatalf("other path = %+v, want the generic page (second, unscoped)", oe)
	}
}

// TestCompileOnErrorRejectsResponsePhaseScope: a response-phase matcher
// (content_type/set_cookie) cannot scope on_error — the origin-error path has no
// upstream response headers to match on.
func TestCompileOnErrorRejectsResponsePhaseScope(t *testing.T) {
	ce := compileErr(t, `x {
		@html content_type text/html
		respond on_error @html 503 "down"
	}
`)
	if ce == nil {
		t.Fatal("want a compile error for a response-phase on_error scope")
	}
}

// TestCompileOnErrorArity: STATUS and BODY are required.
func TestCompileOnErrorArity(t *testing.T) {
	if ce := compileErr(t, "x {\n respond on_error 503\n}\n"); ce == nil {
		t.Fatal("want a compile error for a missing BODY")
	}
	if ce := compileErr(t, "x {\n respond on_error notanumber \"x\"\n}\n"); ce == nil {
		t.Fatal("want a compile error for a non-numeric STATUS")
	}
}

// TestOnErrorScopeMatcherNotUnused: a matcher referenced ONLY by an on_error scope
// is wired into forEachScope, so it gets a memo slot and resolves correctly (the
// pipeline-level analogue of the check "unused matcher" regression guard).
func TestOnErrorScopeMatcherNotUnused(t *testing.T) {
	p := compileSrc(t, `x {
		@api path /api/*
		respond on_error @api 503 "down"
	}
`)
	// If the scope matcher had no memo slot (idx -1), scopeMatches would panic or
	// misbehave; a clean match confirms it is indexed.
	if oe := p.EvalOnError(&Request{Method: "GET", Path: "/api/x", Header: http.Header{}}, 0); oe == nil {
		t.Fatal("scoped on_error did not resolve; the scope matcher may be unindexed")
	}
}
