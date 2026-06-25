package check

import "testing"

// A matcher referenced only by a `replace` directive must not be reported as
// unused (regression: the deliver-phase replace scope was not scanned).
func TestReplaceReferencesMatcher(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	@html content_type text/html
	replace @html OLD NEW
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-matcher"]; n != 0 {
		t.Fatalf("unused-matcher warnings = %d, want 0 (@html is used by replace)\n%s", n, render(t, r))
	}
}
