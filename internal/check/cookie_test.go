package check

import "testing"

// TestCookieMatcherRecognized: `cookie` is a known matcher type (no unknown
// warning), classified exact (not regex), and counted in the directive's phase
// (RECV for `pass`).
func TestCookieMatcherRecognized(t *testing.T) {
	src := []byte(`example.com {
    @authed cookie sessionid
    pass @authed
}`)
	r, err := CheckSource("cookie.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("cookie should be a known matcher type, got %d unknown-matcher-type", n)
	}
	s := firstSite(t, r)
	if s.CostBreakdown.Regex != 0 {
		t.Errorf("cookie is not a regex; CostBreakdown.Regex=%d, want 0", s.CostBreakdown.Regex)
	}
	if s.CostBreakdown.Exact < 1 {
		t.Errorf("cookie should be exact-class; Exact=%d, want >=1", s.CostBreakdown.Exact)
	}
	if s.PhaseCounts[PhaseRECV] < 1 {
		t.Errorf("the `pass @authed` should count in RECV; got %d", s.PhaseCounts[PhaseRECV])
	}
}

// TestCookieGlobMatcherRecognized: a `cookie NAME*` prefix glob is a known matcher
// type (no unknown/unused warning), classified glob (it scans every cookie name),
// and not regex.
func TestCookieGlobMatcherRecognized(t *testing.T) {
	src := []byte(`example.com {
    @wp cookie wordpress_logged_in_*
    pass @wp
}`)
	r, err := CheckSource("cookie_glob.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("cookie should be a known matcher type, got %d unknown-matcher-type", n)
	}
	if n := codes(r)["unused-matcher"]; n != 0 {
		t.Errorf("a referenced glob cookie matcher must not be flagged unused, got %d", n)
	}
	s := firstSite(t, r)
	if s.CostBreakdown.Regex != 0 {
		t.Errorf("a glob cookie is not a regex; Regex=%d, want 0", s.CostBreakdown.Regex)
	}
	if s.CostBreakdown.Glob < 1 {
		t.Errorf("a `cookie NAME*` glob should be glob-class; Glob=%d, want >=1", s.CostBreakdown.Glob)
	}
}
