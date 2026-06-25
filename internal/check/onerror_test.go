package check

import "testing"

// TestOnErrorIsOriginPhase: `respond on_error` is the origin-error fallback (D57),
// so `cadish check` must count it in the ORIGIN phase, not RECV (where the bare
// `respond PATH STATUS BODY` short-circuit lives).
func TestOnErrorIsOriginPhase(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	respond /health 200 "OK"
	respond on_error 503 "down for maintenance"
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	s := firstSite(t, r)
	// The bare respond is RECV; the on_error form is ORIGIN.
	if got := s.PhaseCounts[PhaseRECV]; got != 1 {
		t.Errorf("PhaseCounts[RECV] = %d, want 1 (the bare respond)\n%s", got, render(t, r))
	}
	if got := s.PhaseCounts[PhaseORIGIN]; got != 2 {
		// cache_ttl (ORIGIN) + respond on_error (ORIGIN) = 2.
		t.Errorf("PhaseCounts[ORIGIN] = %d, want 2 (cache_ttl + respond on_error)\n%s", got, render(t, r))
	}
}

// TestOnErrorScopeMatcherNotUnused: a matcher referenced ONLY by a `respond
// on_error @scope` must not be flagged unused (mirrors the replace/rate_limit
// regression guards).
func TestOnErrorScopeMatcherNotUnused(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	@api path /api/*
	respond on_error @api 503 "api down"
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-matcher"]; n != 0 {
		t.Fatalf("unused-matcher warnings = %d, want 0 (@api is used by respond on_error)\n%s", n, render(t, r))
	}
	if n := codes(r)["undefined-matcher"]; n != 0 {
		t.Fatalf("undefined-matcher warnings = %d, want 0\n%s", n, render(t, r))
	}
}

// TestOnErrorArity: a `respond on_error` missing its BODY is flagged.
func TestOnErrorArity(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	respond on_error 503
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["arity"]; n == 0 {
		t.Fatalf("arity warnings = %d, want >=1 for `respond on_error 503` with no body\n%s", n, render(t, r))
	}
}
