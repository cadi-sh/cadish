package check

import "testing"

// TestHeaderPresentMatcherCheck verifies the G3 `header_present` matcher is taught
// to the catalog: a `@has_origin header_present Origin` used only to scope a
// `header` directive is NOT flagged unused, and it adds no regex cost (it is a
// cheap exact lookup).
func TestHeaderPresentMatcherCheck(t *testing.T) {
	src := []byte(`vast.example {
	cache { ram 64MiB }
	upstream backend { to http://origin.example.com }
	@has_origin header_present Origin
	cache_key host path
	header Access-Control-Allow-Origin https://{host}
	header @has_origin +Access-Control-Allow-Origin {http.Origin}
	header @has_origin +Vary Origin
	cache_ttl default ttl 60s
}
`)
	r, err := CheckSource("test.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unused-matcher"] != 0 {
		t.Errorf("@has_origin flagged unused-matcher: %v", c)
	}
	if c["unknown-matcher-type"] != 0 {
		t.Errorf("header_present flagged unknown-matcher-type: %v", c)
	}
	// It is a cheap exact matcher — contributes no regex eval.
	for _, s := range r.Sites {
		if s.CostBreakdown.Regex != 0 {
			t.Errorf("header_present contributed regex cost: %+v", s.CostBreakdown)
		}
	}
}
