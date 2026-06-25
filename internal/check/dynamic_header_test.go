package check

import "testing"

// TestDynamicHeaderValueNotRegex verifies that a `header` directive whose VALUE
// interpolates request-derived placeholders ({http.Origin}, {client_ip}) — the
// dynamic header values feature (#17) — is not mis-classified by `cadish check`:
// a templated value is a literal string to emit, not a header-matcher regex, so it
// must contribute zero regex evals and raise no unknown-matcher-type warning.
func TestDynamicHeaderValueNotRegex(t *testing.T) {
	src := []byte(`example.com {
    cache_key path
    header Access-Control-Allow-Origin {http.Origin}
    header X-Real-IP {client_ip}
    header +Vary Origin
}`)
	r, err := CheckSource("dyn.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-matcher-type"]; n != 0 {
		t.Errorf("dynamic header values should raise no unknown-matcher-type warnings, got %d", n)
	}
	s := firstSite(t, r)
	if s.RegexEvalsPerRequest != 0 {
		t.Errorf("RegexEvalsPerRequest = %d, want 0 (a templated header VALUE is not a regex)", s.RegexEvalsPerRequest)
	}
	if s.CostBreakdown.Regex != 0 {
		t.Errorf("CostBreakdown.Regex = %d, want 0 (templated header value is not a regex eval)", s.CostBreakdown.Regex)
	}
}
