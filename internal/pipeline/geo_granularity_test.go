package pipeline

import (
	"net/http"
	"strings"
	"testing"
)

// --- tokens ---------------------------------------------------------------

// TestCacheKeyGeoContinentToken: {geo.continent} renders Request.GeoContinent, so
// the key varies on the continent (EU vs NA) and the gate is reported by
// UsesGeoToken (the server must run the geo pre-pass).
func TestCacheKeyGeoContinentToken(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key host path {geo.continent}\n}")
	if !p.UsesGeoToken() {
		t.Fatal("UsesGeoToken() = false, want true for {geo.continent}")
	}
	eu := p.EvalRequest(&Request{Host: "h", Path: "/x", GeoContinent: "EU"}).CacheKey
	na := p.EvalRequest(&Request{Host: "h", Path: "/x", GeoContinent: "NA"}).CacheKey
	if eu == na {
		t.Fatalf("{geo.continent} did not vary the key: both = %q", eu)
	}
	if !strings.Contains(eu, "EU") {
		t.Errorf("EU key %q does not contain the continent class", eu)
	}
}

// TestCacheKeyGeoRegionToken: {geo.region} renders Request.GeoRegion (US-UT vs
// US-TX) and gates the geo pre-pass.
func TestCacheKeyGeoRegionToken(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key host path {geo.region}\n}")
	if !p.UsesGeoToken() {
		t.Fatal("UsesGeoToken() = false, want true for {geo.region}")
	}
	ut := p.EvalRequest(&Request{Host: "h", Path: "/x", GeoRegion: "US-UT"}).CacheKey
	tx := p.EvalRequest(&Request{Host: "h", Path: "/x", GeoRegion: "US-TX"}).CacheKey
	if ut == tx {
		t.Fatalf("{geo.region} did not vary the key: both = %q", ut)
	}
	if !strings.Contains(ut, "US-UT") {
		t.Errorf("UT key %q does not contain the region class", ut)
	}
}

// TestUsesGeoTokenGranularities: each granularity token gates the geo pre-pass;
// a key with none does not.
func TestUsesGeoTokenGranularities(t *testing.T) {
	for _, src := range []string{
		"example.com {\n cache_key host path {geo}\n}",
		"example.com {\n cache_key host path {geo.continent}\n}",
		"example.com {\n cache_key host path {geo.region}\n}",
	} {
		if p := compileSrc(t, src); !p.UsesGeoToken() {
			t.Errorf("UsesGeoToken() = false for %q", src)
		}
	}
	if p := compileSrc(t, "example.com {\n cache_key host path\n}"); p.UsesGeoToken() {
		t.Error("UsesGeoToken() = true with no geo token")
	}
}

// --- matcher --------------------------------------------------------------

// TestGeoMatcherCountry: `geo country US ES` matches Request.Geo.
func TestGeoMatcherCountry(t *testing.T) {
	p := compileSrc(t, "example.com {\n @us geo country US ES\n pass @us\n}")
	if !p.EvalRequest(&Request{Host: "h", Path: "/", Geo: "US"}).Pass {
		t.Error("geo country US did not match Geo=US")
	}
	if !p.EvalRequest(&Request{Host: "h", Path: "/", Geo: "ES"}).Pass {
		t.Error("geo country US ES did not match Geo=ES (OR)")
	}
	if p.EvalRequest(&Request{Host: "h", Path: "/", Geo: "FR"}).Pass {
		t.Error("geo country US ES matched Geo=FR (should not)")
	}
}

// TestGeoMatcherContinent: `geo continent EU` matches Request.GeoContinent.
func TestGeoMatcherContinent(t *testing.T) {
	p := compileSrc(t, "example.com {\n @eu geo continent EU\n pass @eu\n}")
	if !p.EvalRequest(&Request{Host: "h", Path: "/", GeoContinent: "EU"}).Pass {
		t.Error("geo continent EU did not match GeoContinent=EU")
	}
	if p.EvalRequest(&Request{Host: "h", Path: "/", GeoContinent: "NA"}).Pass {
		t.Error("geo continent EU matched GeoContinent=NA (should not)")
	}
}

// TestGeoMatcherRegion: `geo region US-UT US-TX` matches Request.GeoRegion (OR).
func TestGeoMatcherRegion(t *testing.T) {
	p := compileSrc(t, "example.com {\n @regulated geo region US-UT US-TX\n pass @regulated\n}")
	if !p.EvalRequest(&Request{Host: "h", Path: "/", GeoRegion: "US-UT"}).Pass {
		t.Error("geo region US-UT US-TX did not match GeoRegion=US-UT")
	}
	if !p.EvalRequest(&Request{Host: "h", Path: "/", GeoRegion: "US-TX"}).Pass {
		t.Error("geo region US-UT US-TX did not match GeoRegion=US-TX")
	}
	if p.EvalRequest(&Request{Host: "h", Path: "/", GeoRegion: "US-CA"}).Pass {
		t.Error("geo region US-UT US-TX matched GeoRegion=US-CA (should not)")
	}
}

// TestGeoMatcherCaseInsensitive: matcher args are compared case-insensitively to
// the resolved class (which the geo source upper-cases).
func TestGeoMatcherCaseInsensitive(t *testing.T) {
	p := compileSrc(t, "example.com {\n @us geo country us\n pass @us\n}")
	if !p.EvalRequest(&Request{Host: "h", Path: "/", Geo: "US"}).Pass {
		t.Error("geo country us (lower) did not match Geo=US")
	}
}

// TestGeoMatcherInClassify: the geo matcher feeds a classify row (geo→business
// mapping expressed by the operator), e.g. a `regulated` flag from US states.
func TestGeoMatcherInClassify(t *testing.T) {
	src := `example.com {
  @regulated geo region US-UT US-TX
  classify {gate} {
    when @regulated -> on
    default         -> off
  }
  cache_key host path {gate}
}`
	p := compileSrc(t, src)
	on := p.EvalRequest(&Request{Host: "h", Path: "/", GeoRegion: "US-UT"}).CacheKey
	off := p.EvalRequest(&Request{Host: "h", Path: "/", GeoRegion: "US-CA"}).CacheKey
	if on == off {
		t.Fatalf("classify over geo region did not vary: both %q", on)
	}
	if !strings.Contains(on, "on") {
		t.Errorf("UT key %q missing the derived 'on' flag", on)
	}
}

// TestGeoTokensInHeaderValue: the granular geo tokens are usable as header values
// (so an operator can reflect the resolved continent/region back to the origin).
func TestGeoTokensInHeaderValue(t *testing.T) {
	src := `example.com {
  cache_key host path
  header X-Country   {geo}
  header X-Continent {geo.continent}
  header X-Region    {geo.region}
}`
	p := compileSrc(t, src)
	req := &Request{Host: "h", Path: "/x", Geo: "US", GeoContinent: "NA", GeoRegion: "US-UT"}
	dec := p.EvalDeliver(req, http.Header{}, CacheStatusHit)
	got := map[string]string{}
	for _, op := range dec.RespHeaderOps {
		got[op.Name] = op.Value
	}
	if got["X-Country"] != "US" {
		t.Errorf("X-Country = %q, want US", got["X-Country"])
	}
	if got["X-Continent"] != "NA" {
		t.Errorf("X-Continent = %q, want NA", got["X-Continent"])
	}
	if got["X-Region"] != "US-UT" {
		t.Errorf("X-Region = %q, want US-UT", got["X-Region"])
	}
}

// TestGeoMatcherErrors: malformed geo matchers are compile errors.
func TestGeoMatcherErrors(t *testing.T) {
	for _, src := range []string{
		"example.com {\n @x geo\n pass @x\n}",          // no granularity
		"example.com {\n @x geo country\n pass @x\n}",  // no value
		"example.com {\n @x geo bogus US\n pass @x\n}", // unknown granularity
	} {
		compileErr(t, src)
	}
}
