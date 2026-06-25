package check

import "testing"

// TestCookieJSONMatcherRecognized: `cookie_json` is a known matcher type (no
// unknown warning), charged at the regex cost tier (a bounded JSON parse) but NOT
// counted as a regex eval, and counted in the directive's phase (RECV for `pass`).
func TestCookieJSONMatcherRecognized(t *testing.T) {
	src := []byte(`example.com {
    @nv cookie_json nsfwCookie needVerify true
    pass @nv
}`)
	r, err := CheckSource("cookie_json.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("cookie_json should be a known matcher type, got %d unknown-matcher-type", n)
	}
	s := firstSite(t, r)
	if s.CostBreakdown.Regex < 1 {
		t.Errorf("cookie_json is charged at the regex cost tier; Regex=%d, want >=1", s.CostBreakdown.Regex)
	}
	if s.RegexEvalsPerRequest != 0 {
		t.Errorf("cookie_json is a JSON parse, not an RE2 eval; RegexEvalsPerRequest=%d, want 0", s.RegexEvalsPerRequest)
	}
	if s.PhaseCounts[PhaseRECV] < 1 {
		t.Errorf("the `pass @nv` should count in RECV; got %d", s.PhaseCounts[PhaseRECV])
	}
}

// TestHeaderJSONMatcherRecognized: `header_json` is recognized and behaves like
// cookie_json for cost/phase.
func TestHeaderJSONMatcherRecognized(t *testing.T) {
	src := []byte(`example.com {
    @pro header_json X-Session plan.tier pro enterprise
    pass @pro
}`)
	r, err := CheckSource("header_json.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("header_json should be a known matcher type, got %d unknown-matcher-type", n)
	}
	if s := firstSite(t, r); s.RegexEvalsPerRequest != 0 {
		t.Errorf("header_json must not inflate the regex-eval headline; got %d", s.RegexEvalsPerRequest)
	}
}

// TestCookieJSONNotUnusedInClassify: a cookie_json matcher used ONLY inside a
// classify `when` row must not be flagged unused (mirrors the replace/classify
// regression guard).
func TestCookieJSONNotUnusedInClassify(t *testing.T) {
	src := []byte(`example.com {
    @nv cookie_json nsfwCookie needVerify true
    classify {needVerify} {
        when @nv -> 1
        default  -> 0
    }
    cache_key host path {needVerify}
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if c := codes(r)["unused-matcher"]; c != 0 {
		t.Errorf("a cookie_json used only by a classify `when` row must not be unused; got %d", c)
	}
}
