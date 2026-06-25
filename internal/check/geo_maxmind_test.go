package check

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	cityFixture    = "../geo/testdata/GeoIP2-City-Test.mmdb"
	countryFixture = "../geo/testdata/GeoLite2-Country-Test.mmdb"
)

// writeConfigWithFixture writes a Cadishfile and the named .mmdb fixture into a temp
// dir and returns the Cadishfile path (so baseDir resolution mirrors a real run).
func writeConfigWithFixture(t *testing.T, fixture, mmdbName, config string) string {
	t.Helper()
	dir := t.TempDir()
	if fixture != "" {
		b, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, mmdbName), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(p, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestGeoMaxMindSourceAccepted: `source maxmind FILE` is accepted (known directive, no
// invalid-geo-source) when the file is a real .mmdb.
func TestGeoMaxMindSourceAccepted(t *testing.T) {
	p := writeConfigWithFixture(t, cityFixture, "City.mmdb", `example.com {
    geo { source maxmind City.mmdb }
    cache_key host path {geo}
}`)
	r, err := Check(p)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	c := codes(r)
	if c["invalid-geo-source"] != 0 {
		t.Errorf("a valid maxmind source should not warn; codes=%v", c)
	}
	if c["geo-unconfigured"] != 0 {
		t.Errorf("a configured maxmind source should not warn geo-unconfigured; codes=%v", c)
	}
}

// TestGeoMaxMindMissingPathFlagged: a missing .mmdb path is flagged at lint time.
func TestGeoMaxMindMissingPathFlagged(t *testing.T) {
	p := writeConfigWithFixture(t, "", "", `example.com {
    geo { source maxmind /nope/none.mmdb }
    cache_key host path {geo}
}`)
	r, err := Check(p)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes(r)["invalid-geo-source"] != 1 {
		t.Errorf("expected invalid-geo-source for a missing .mmdb; codes=%v", codes(r))
	}
}

// TestGeoMaxMindEmptyPathFlagged: an empty maxmind path is flagged.
func TestGeoMaxMindEmptyPathFlagged(t *testing.T) {
	// `source maxmind` with no path: the parser keeps it as a 1-arg source; the lint
	// only inspects 2-arg maxmind forms, so an empty/absent path surfaces via the
	// runtime build. Use an explicit empty-quoted path to exercise the lint branch.
	p := writeConfigWithFixture(t, "", "", "example.com {\n geo { source maxmind \"\" }\n cache_key host path {geo}\n}")
	r, err := Check(p)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes(r)["invalid-geo-source"] != 1 {
		t.Errorf("expected invalid-geo-source for an empty path; codes=%v", codes(r))
	}
}

// TestGeoMaxMindCitySuppressesRegionWarning: a City-edition maxmind source supplies
// {geo.region}, so no region warning even without a region_header.
func TestGeoMaxMindCitySuppressesRegionWarning(t *testing.T) {
	p := writeConfigWithFixture(t, cityFixture, "City.mmdb", `example.com {
    geo { source maxmind City.mmdb }
    cache_key host path {geo.region}
}`)
	r, err := Check(p)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	c := codes(r)
	if c["geo-region-unconfigured"] != 0 {
		t.Errorf("a City-edition maxmind source supplies region; should not warn; codes=%v", c)
	}
}

// TestGeoMaxMindCountryWarnsRegion: a Country-edition maxmind source has no
// subdivisions, so {geo.region} still needs a region_header — the warning fires.
func TestGeoMaxMindCountryWarnsRegion(t *testing.T) {
	p := writeConfigWithFixture(t, countryFixture, "Country.mmdb", `example.com {
    geo { source maxmind Country.mmdb }
    cache_key host path {geo.region}
}`)
	r, err := Check(p)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	c := codes(r)
	if c["geo-region-unconfigured"] != 1 {
		t.Errorf("a Country-edition maxmind source needs a region_header; expected the warning; codes=%v", c)
	}
}

// TestGeoMaxMindCountryWithRegionHeaderOK: a Country-edition maxmind source paired with
// a region_header supplies region; no warning.
func TestGeoMaxMindCountryWithRegionHeaderOK(t *testing.T) {
	p := writeConfigWithFixture(t, countryFixture, "Country.mmdb", `example.com {
    geo {
        source        maxmind Country.mmdb
        region_header CF-Region
    }
    cache_key host path {geo.region}
}`)
	r, err := Check(p)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	c := codes(r)
	if c["geo-region-unconfigured"] != 0 {
		t.Errorf("Country DB + region_header supplies region; should not warn; codes=%v", c)
	}
}
