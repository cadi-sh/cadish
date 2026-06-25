package check

import "testing"

// TestNormalizeRecognizedAndNoted: `normalize` is a known directive, and a
// cache_key using {NAME} draws the bounded-normalizer note.
func TestNormalizeRecognizedAndNoted(t *testing.T) {
	src := []byte(`example.com {
    normalize plan {
        from   header X-Plan
        map    pro -> paid
        default free
    }
    cache_key host path {plan}
}`)
	r, err := CheckSource("n.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["unknown-directive"] != 0 {
		t.Errorf("normalize should be a known directive")
	}
	if codes(r)["unbounded-key-token"] != 0 {
		t.Errorf("{plan} is a bounded normalizer; should not warn unbounded")
	}
	s := firstSite(t, r)
	if !hasSuggestion(s, "varies on the 2 bounded buckets of `normalize plan`") {
		t.Errorf("expected bounded-normalizer note (with bucket count) for {plan}; got %v", s.Suggestions)
	}
}

// TestUnboundedKeyTokenWarns: keying on a raw header or {sticky} (unbounded)
// warns and points at `normalize` — the flip side of the bounded note.
func TestUnboundedKeyTokenWarns(t *testing.T) {
	rawHeader, err := CheckSource("h.cadish", []byte("example.com {\n cache_key host path header:X-Plan\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if codes(rawHeader)["unbounded-key-token"] != 1 {
		t.Errorf("raw header key should warn unbounded; codes=%v", codes(rawHeader))
	}

	sticky, err := CheckSource("s.cadish", []byte("example.com {\n cache_key host path {sticky}\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if codes(sticky)["unbounded-key-token"] != 1 {
		t.Errorf("{sticky} key should warn unbounded; codes=%v", codes(sticky))
	}

	query, err := CheckSource("q.cadish", []byte("example.com {\n cache_key host path query\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if codes(query)["unbounded-key-token"] != 1 {
		t.Errorf("bare `query` key should warn unbounded; codes=%v", codes(query))
	}

	// url/host/path/method are NOT flagged (resource identity / bounded).
	ok, err := CheckSource("ok.cadish", []byte("example.com {\n cache_key method host url\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if codes(ok)["unbounded-key-token"] != 0 {
		t.Errorf("url/host/method should not warn unbounded; codes=%v", codes(ok))
	}
}
