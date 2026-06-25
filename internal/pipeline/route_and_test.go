package pipeline

import "testing"

// TestRouteMultiRefOR pins Fix #4: a `route @a @b -> u` with MULTIPLE refs is an OR
// (matches if ANY ref matches), consistent with `pass @a @b` and the rest of the
// language. (Slice 2 briefly made this an AND for the Gateway translator; that special
// form is removed — the Gateway translator now expresses AND via the `all` composite
// matcher instead.)
func TestRouteMultiRefOR(t *testing.T) {
	p := compileSite(t, `example.com {
		upstream web { to http://10.0.0.1:80 }
		upstream other { to http://10.0.0.2:80 }
		@p path /api /api/*
		@m method POST
		route @p @m -> web
		route -> other
	}`)

	// path matches (method does not) -> OR routes to web.
	if got := p.resolveUpstream(&Request{Method: "GET", Host: "example.com", Path: "/api/x"}); got != "web" {
		t.Errorf("OR: path-only match should route to web, got %q", got)
	}
	// method matches (path does not) -> OR routes to web.
	if got := p.resolveUpstream(&Request{Method: "POST", Host: "example.com", Path: "/nope"}); got != "web" {
		t.Errorf("OR: method-only match should route to web, got %q", got)
	}
	// neither matches -> falls through to the catch-all.
	if got := p.resolveUpstream(&Request{Method: "GET", Host: "example.com", Path: "/nope"}); got != "other" {
		t.Errorf("OR: neither match should fall through to other, got %q", got)
	}
}

// TestRouteAllCompositeAND verifies the AND requirement (the Gateway translator's need)
// is expressed via the EXISTING `all` AND-composite matcher: a single `route @gw -> u`
// where @gw ANDs the path + method. Every criterion must hold.
func TestRouteAllCompositeAND(t *testing.T) {
	p := compileSite(t, `example.com {
		upstream web { to http://10.0.0.1:80 }
		upstream other { to http://10.0.0.2:80 }
		@p path /api /api/*
		@m method POST
		@gw all @p @m
		route @gw -> web
		route -> other
	}`)

	// path AND method both match -> web.
	if got := p.resolveUpstream(&Request{Method: "POST", Host: "example.com", Path: "/api/x"}); got != "web" {
		t.Errorf("all: path+method match should route to web, got %q", got)
	}
	// path only -> AND not satisfied, fall through to other.
	if got := p.resolveUpstream(&Request{Method: "GET", Host: "example.com", Path: "/api/x"}); got != "other" {
		t.Errorf("all: AND must require method too; GET should fall through, got %q", got)
	}
	// method only -> AND not satisfied, fall through to other.
	if got := p.resolveUpstream(&Request{Method: "POST", Host: "example.com", Path: "/nope"}); got != "other" {
		t.Errorf("all: AND must require path too; /nope should fall through, got %q", got)
	}
}

// TestRouteAllNegatedTerm: an `all` composite honors per-term negation (AND with a NOT),
// the same grammar allow/deny use — this is how the Gateway translator could express a
// negated criterion within a match.
func TestRouteAllNegatedTerm(t *testing.T) {
	p := compileSite(t, `example.com {
		upstream web { to http://10.0.0.1:80 }
		upstream other { to http://10.0.0.2:80 }
		@p path /api /api/*
		@internal header X-Internal yes
		@gw all @p !@internal
		route @gw -> web
		route -> other
	}`)
	if got := p.resolveUpstream(&Request{Method: "GET", Host: "example.com", Path: "/api", Header: nil}); got != "web" {
		t.Errorf("path match without the internal header should route to web, got %q", got)
	}
	req := &Request{Method: "GET", Host: "example.com", Path: "/api", Header: map[string][]string{"X-Internal": {"yes"}}}
	if got := p.resolveUpstream(req); got != "other" {
		t.Errorf("!@internal must exclude requests carrying X-Internal: yes, got %q", got)
	}
}

// TestRouteSingleRefStillOR pins that a single-ref route (what the Ingress translator
// emits) is unaffected — it routes on that one matcher.
func TestRouteSingleRefStillOR(t *testing.T) {
	p := compileSite(t, `example.com {
		upstream web { to http://10.0.0.1:80 }
		@p path /api /api/*
		route @p -> web
	}`)
	if got := p.resolveUpstream(&Request{Method: "GET", Host: "example.com", Path: "/api/x"}); got != "web" {
		t.Errorf("single-ref route should still match, got %q", got)
	}
}

// TestQueryMatcherExactValue: the `query NAME VALUE…` matcher tests one named query
// param's value against an OR set (the Gateway queryParams Exact case).
func TestQueryMatcherExactValue(t *testing.T) {
	p := compileSite(t, `example.com {
		upstream web { to http://10.0.0.1:80 }
		upstream other { to http://10.0.0.2:80 }
		@beta query channel beta canary
		route @beta -> web
		route -> other
	}`)
	mk := func(q string) *Request {
		return &Request{Method: "GET", Host: "example.com", Path: "/", Query: parseQ(q)}
	}
	if got := p.resolveUpstream(mk("channel=beta")); got != "web" {
		t.Errorf("channel=beta should route to web, got %q", got)
	}
	if got := p.resolveUpstream(mk("channel=canary")); got != "web" {
		t.Errorf("channel=canary (OR value) should route to web, got %q", got)
	}
	if got := p.resolveUpstream(mk("channel=stable")); got != "other" {
		t.Errorf("channel=stable should NOT match, got %q", got)
	}
	if got := p.resolveUpstream(mk("other=beta")); got != "other" {
		t.Errorf("a different param name must not match, got %q", got)
	}
}

func parseQ(q string) map[string][]string {
	out := map[string][]string{}
	for _, kv := range splitAmp(q) {
		if i := indexEq(kv); i >= 0 {
			out[kv[:i]] = append(out[kv[:i]], kv[i+1:])
		} else {
			out[kv] = append(out[kv], "")
		}
	}
	return out
}

func splitAmp(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '&' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func indexEq(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return i
		}
	}
	return -1
}
