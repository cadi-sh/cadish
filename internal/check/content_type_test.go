package check

import "testing"

// TestContentTypeMatcherClassified verifies that a content_type matcher is a
// recognized (not "unknown") matcher type, is classified as a cheap exact-class
// compare (not a regex eval), and that the deliver-phase directive scoping on it
// is counted in the DELIVER phase.
func TestContentTypeMatcherClassified(t *testing.T) {
	src := []byte(`example.com {
    @longcache content_type text/css image/svg+xml
    cache_key path
    header @longcache Cache-Control "public, max-age=31536000"
}`)
	r, err := CheckSource("ctype.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("content_type should be a known matcher type, got %d unknown-matcher-type warnings", n)
	}
	s := firstSite(t, r)
	if s.RegexEvalsPerRequest != 0 {
		t.Errorf("RegexEvalsPerRequest = %d, want 0 (content_type is not a regex)", s.RegexEvalsPerRequest)
	}
	if s.CostBreakdown.Regex != 0 {
		t.Errorf("CostBreakdown.Regex = %d, want 0", s.CostBreakdown.Regex)
	}
	if s.CostBreakdown.Exact < 1 {
		t.Errorf("CostBreakdown.Exact = %d, want >=1 (content_type is exact-class)", s.CostBreakdown.Exact)
	}
	if got := s.PhaseCounts[PhaseDELIVER]; got < 1 {
		t.Errorf("PhaseCounts[DELIVER] = %d, want >=1 (the header using @longcache)", got)
	}
}
