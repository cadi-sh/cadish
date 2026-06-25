package check

import "testing"

// TestTenantBlockNoted: a request-derived `tenant { … }` block is recognized and
// {tenant} draws a bounded-normalizer note reporting the tenant count.
func TestTenantBlockNoted(t *testing.T) {
	src := []byte(`example.com {
    tenant {
        from    host
        map     *.acme.example   -> acme
        map     globex.example   -> globex
        default other
    }
    cache_key {tenant} host path
}`)
	r, err := CheckSource("t.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["unknown-directive"] != 0 {
		t.Errorf("`tenant` block should be a known directive")
	}
	s := firstSite(t, r)
	// 3 tenant ids: acme, globex, other.
	if !hasSuggestion(s, "varies on the 3 bounded tenant ids") {
		t.Errorf("expected {tenant} note with 3 ids; got %v", s.Suggestions)
	}
}
