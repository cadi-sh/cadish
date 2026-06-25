package check

import "testing"

// TestSetCookieMatcherClassified verifies that a set_cookie matcher is a
// recognized (not "unknown") matcher type, is classified as a cheap exact-class
// compare (not a regex eval), and that a matcher referenced only by a
// set_cookie-scoped cache_ttl rule is not falsely flagged "unused" nor a
// dead/phase-mismatched rule.
func TestSetCookieMatcherClassified(t *testing.T) {
	src := []byte(`example.com {
    @session set_cookie sessionid
    cache_key path
    cache_ttl @session hit_for_miss 0s
    cache_ttl default ttl 1h
}`)
	r, err := CheckSource("setcookie.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if n := c["unknown-matcher-type"]; n != 0 {
		t.Errorf("set_cookie should be a known matcher type, got %d unknown-matcher-type warnings", n)
	}
	if n := c["unused-matcher"]; n != 0 {
		t.Errorf("@session is referenced by a cache_ttl rule, got %d unused-matcher warnings", n)
	}
	if n := c["dead-rule"]; n != 0 {
		t.Errorf("a set_cookie-scoped cache_ttl is reachable, got %d dead-rule warnings", n)
	}
	s := firstSite(t, r)
	if s.RegexEvalsPerRequest != 0 {
		t.Errorf("RegexEvalsPerRequest = %d, want 0 (set_cookie is not a regex)", s.RegexEvalsPerRequest)
	}
	if s.CostBreakdown.Regex != 0 {
		t.Errorf("CostBreakdown.Regex = %d, want 0", s.CostBreakdown.Regex)
	}
	if s.CostBreakdown.Exact < 1 {
		t.Errorf("CostBreakdown.Exact = %d, want >=1 (set_cookie is exact-class)", s.CostBreakdown.Exact)
	}
}

// TestSetCookiePresenceForm verifies the bare `set_cookie` (presence) form is
// also a known, exact-class matcher and may scope deliver-phase directives
// without producing unknown/unused warnings.
func TestSetCookiePresenceForm(t *testing.T) {
	src := []byte(`example.com {
    @sc set_cookie
    cache_key path
    cache_ttl @sc hit_for_miss 0s
    header @sc X-Had-Cookie yes
}`)
	r, err := CheckSource("setcookie2.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if n := c["unknown-matcher-type"]; n != 0 {
		t.Errorf("bare set_cookie should be known, got %d unknown-matcher-type warnings", n)
	}
	if n := c["unused-matcher"]; n != 0 {
		t.Errorf("@sc is referenced, got %d unused-matcher warnings", n)
	}
}
