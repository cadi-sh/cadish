package check

import "testing"

// TestGeoRecognizedAndNoted: `geo` is a known SETUP directive, and a cache_key
// using {geo} (with a geo block present) draws the bounded-normalizer note and
// no geo-unconfigured warning.
func TestGeoRecognizedAndNoted(t *testing.T) {
	src := []byte(`example.com {
    geo {
        source header CF-IPCountry
        trust_proxy 10.0.0.0/8
    }
    cache_key host path {geo}
}`)
	r, err := CheckSource("geo.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unknown-directive"] != 0 {
		t.Errorf("geo should be a known directive")
	}
	if c["geo-unconfigured"] != 0 {
		t.Errorf("a configured geo source should not warn geo-unconfigured")
	}
	s := firstSite(t, r)
	if s.PhaseCounts[PhaseSetup] < 1 {
		t.Errorf("PhaseCounts[SETUP] = %d, want >=1 (geo)", s.PhaseCounts[PhaseSetup])
	}
	if !hasSuggestion(s, "varies on a bounded geo class") {
		t.Errorf("expected a bounded-normalizer note for {geo}; got %v", s.Suggestions)
	}
}

// TestGeoUnconfiguredWarns: {geo} in a cache_key without a `geo` block warns.
func TestGeoUnconfiguredWarns(t *testing.T) {
	src := []byte("example.com {\n cache_key host path {geo}\n}")
	r, err := CheckSource("geo.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["geo-unconfigured"] != 1 {
		t.Errorf("expected a geo-unconfigured warning; codes=%v", codes(r))
	}
}

// TestGeoGranularTokensUnconfiguredWarn: {geo.continent}/{geo.region} with no geo
// block warn geo-unconfigured (every granularity needs the country source).
func TestGeoGranularTokensUnconfiguredWarn(t *testing.T) {
	for _, tok := range []string{"{geo.continent}", "{geo.region}"} {
		src := []byte("example.com {\n cache_key host path " + tok + "\n}")
		r, err := CheckSource("geo.cadish", src)
		if err != nil {
			t.Fatalf("CheckSource: %v", err)
		}
		if codes(r)["geo-unconfigured"] != 1 {
			t.Errorf("%s without geo block: expected geo-unconfigured; codes=%v", tok, codes(r))
		}
	}
}

// TestGeoRegionNeedsHeader: {geo.region} with a geo block but no region_header
// warns geo-region-unconfigured (region needs an upstream header — no GeoIP DB).
func TestGeoRegionNeedsHeader(t *testing.T) {
	src := []byte(`example.com {
    geo { source header CF-IPCountry }
    cache_key host path {geo.region}
}`)
	r, err := CheckSource("geo.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["geo-region-unconfigured"] != 1 {
		t.Errorf("expected geo-region-unconfigured; codes=%v", c)
	}
	if c["geo-unconfigured"] != 0 {
		t.Errorf("country source is present; should not warn geo-unconfigured; codes=%v", c)
	}
}

// TestGeoRegionHeaderConfigured: with region_header present, no region warning.
func TestGeoRegionHeaderConfigured(t *testing.T) {
	src := []byte(`example.com {
    geo {
        source        header CF-IPCountry
        region_header CF-Region
    }
    cache_key host path {geo.region}
}`)
	r, err := CheckSource("geo.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["geo-region-unconfigured"] != 0 || c["geo-unconfigured"] != 0 {
		t.Errorf("configured region should not warn; codes=%v", c)
	}
}

// TestGeoMatcherRecognizedAndUsed: a `geo` matcher is a known matcher type and,
// when referenced, is not flagged as a dead/unused matcher.
func TestGeoMatcherRecognizedAndUsed(t *testing.T) {
	src := []byte(`example.com {
    @eu        geo continent EU
    @regulated geo region US-UT US-TX
    geo {
        source        header CF-IPCountry
        region_header CF-Region
    }
    pass @eu
    pass @regulated
}`)
	r, err := CheckSource("geo.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unknown-matcher-type"] != 0 {
		t.Errorf("geo should be a known matcher type; codes=%v", c)
	}
	if c["unused-matcher"] != 0 {
		t.Errorf("referenced geo matchers should not be flagged unused; codes=%v", c)
	}
}
