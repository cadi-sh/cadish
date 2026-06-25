package check

import "testing"

// TestClassifyRecognized: `classify` is a known directive and the matchers its
// `when` rows reference are counted as USED (not flagged dead). The derived
// {age} cache_key token is bounded (no unbounded-key warning).
func TestClassifyRecognized(t *testing.T) {
	src := []byte(`example.com {
    @regulated  header X-Region gated
    @verified   cookie verified_prod
    classify {age} {
        when @verified   -> ok
        when @regulated  -> gate
        default          -> open
    }
    cache_key method host path {age}
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unknown-directive"] != 0 {
		t.Errorf("classify should be a known directive; codes=%v", c)
	}
	if c["unused-matcher"] != 0 {
		t.Errorf("matchers used by classify `when` rows must not be flagged unused; codes=%v", c)
	}
	if c["unbounded-key-token"] != 0 {
		t.Errorf("a {age} classify token is bounded; should not warn unbounded; codes=%v", c)
	}
}

// TestClassifyUndefinedMatcher: a `when @nope` referencing an undefined matcher
// is flagged.
func TestClassifyUndefinedMatcher(t *testing.T) {
	src := []byte(`example.com {
    classify {age} {
        when @nope   -> gate
        default      -> open
    }
    cache_key {age}
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatal(err)
	}
	if codes(r)["undefined-matcher"] == 0 {
		t.Errorf("an undefined matcher in a classify row should be flagged; codes=%v", codes(r))
	}
}

// TestClassifyMatcherTypeRecognized: the `@g classify {age}==gate` token-as-scope
// matcher type is recognized (no unknown-matcher-type) and counts as used by the
// directive that references it.
func TestClassifyMatcherTypeRecognized(t *testing.T) {
	src := []byte(`example.com {
    @verified   cookie verified_prod
    classify {age} {
        when @verified   -> ok
        default          -> gate
    }
    @gated  classify {age}==gate
    pass @gated
    cache_key {age}
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatal(err)
	}
	c := codes(r)
	if c["unknown-matcher-type"] != 0 {
		t.Errorf("classify is a known matcher type; codes=%v", c)
	}
	if c["unused-matcher"] != 0 {
		t.Errorf("@gated is referenced by pass; should not be unused; codes=%v", c)
	}
}
