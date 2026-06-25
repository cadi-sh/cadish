package config

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// geo test fixtures live in the geo package's testdata (vendored sample DBs).
const (
	cityFixture    = "../geo/testdata/GeoIP2-City-Test.mmdb"
	countryFixture = "../geo/testdata/GeoLite2-Country-Test.mmdb"
)

// copyFixture copies a vendored .mmdb fixture into dir under name and returns dir.
func copyFixture(t *testing.T, src, dir, name string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

// TestLoadMaxMindWiresAndCloses: a full config Load wires the maxmind source into
// Site.Geo / Site.GeoRegion, and Close releases the reader (lifecycle: opened at load,
// closed on teardown — the SIGHUP reload re-runs Load opening a fresh reader, then
// CloseExcept closes the old one).
func TestLoadMaxMindWiresAndCloses(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, cityFixture, dir, "City.mmdb")
	cfgText := `x.com {
	upstream a { to http://h:80 }
	route -> a
	geo { source maxmind City.mmdb }
	cache_key host path {geo} {geo.region}
}
`
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s := cfg.Sites[0]
	if s.Geo == nil || s.GeoRegion == nil {
		t.Fatalf("maxmind source not wired: Geo=%v GeoRegion=%v", s.Geo, s.GeoRegion)
	}
	if got := s.Geo.Lookup(netip.MustParseAddr("216.160.83.56"), nil); got != "US" {
		t.Errorf("wired country = %q, want US", got)
	}
	if got := s.GeoRegion.Lookup(netip.MustParseAddr("216.160.83.56"), nil); got != "US-WA" {
		t.Errorf("wired region = %q, want US-WA", got)
	}
	if len(s.geoDBs) != 1 {
		t.Fatalf("want 1 tracked maxmind reader, got %d", len(s.geoDBs))
	}
	if !s.geoDBs[0].HasRegion() {
		t.Error("City edition DB should report HasRegion()")
	}
	if err := cfg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close the reader is released (its metadata type goes empty).
	if dt := s.geoDBs[0].DatabaseType(); dt != "" {
		t.Errorf("reader not closed: DatabaseType=%q", dt)
	}
}

// TestBuildGeoMaxMindCity: `source maxmind FILE` (City edition) builds a country
// source and a region source from the same reader; the path is resolved relative to
// the Cadishfile dir.
func TestBuildGeoMaxMindCity(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, cityFixture, dir, "City.mmdb")
	src, region, _, dbs, err := buildGeo(parseSite(t, `example.com {
    geo { source maxmind City.mmdb }
    cache_key path {geo} {geo.region}
}`), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	})
	if src == nil {
		t.Fatal("want a maxmind country source")
	}
	if got := src.Lookup(netip.MustParseAddr("216.160.83.56"), nil); got != "US" {
		t.Errorf("country = %q, want US", got)
	}
	if region == nil {
		t.Fatal("a maxmind City source should supply {geo.region} without a region_header")
	}
	if got := region.Lookup(netip.MustParseAddr("216.160.83.56"), nil); got != "US-WA" {
		t.Errorf("region = %q, want US-WA", got)
	}
	if len(dbs) != 1 {
		t.Errorf("want 1 opened maxmind reader, got %d", len(dbs))
	}
}

// TestBuildGeoMaxMindCountryEdition: a Country-edition DB resolves the country but its
// region is Unknown (no subdivisions).
func TestBuildGeoMaxMindCountryEdition(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, countryFixture, dir, "Country.mmdb")
	src, region, _, dbs, err := buildGeo(parseSite(t, `example.com {
    geo { source maxmind Country.mmdb }
    cache_key path {geo} {geo.region}
}`), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	})
	if got := src.Lookup(netip.MustParseAddr("216.160.83.56"), nil); got != "US" {
		t.Errorf("country = %q, want US", got)
	}
	if got := region.Lookup(netip.MustParseAddr("216.160.83.56"), nil); got != "unknown" {
		t.Errorf("region on a Country edition = %q, want unknown", got)
	}
}

// TestBuildGeoMaxMindHeaderFallback: the narrow {maxmind, header} pair assembles a
// declared-order fallback — maxmind primary wins on a hit, falls through to the header
// on a miss.
func TestBuildGeoMaxMindHeaderFallback(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, cityFixture, dir, "City.mmdb")
	src, _, _, dbs, err := buildGeo(parseSite(t, `example.com {
    geo {
        source maxmind City.mmdb
        source header  CF-IPCountry
    }
    cache_key path {geo}
}`), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	})
	hdr := http.Header{"Cf-Ipcountry": {"FR"}}
	// maxmind hit wins.
	if got := src.Lookup(netip.MustParseAddr("216.160.83.56"), hdr); got != "US" {
		t.Errorf("fallback hit = %q, want US (maxmind primary wins)", got)
	}
	// maxmind miss -> header.
	if got := src.Lookup(netip.MustParseAddr("10.0.0.1"), hdr); got != "FR" {
		t.Errorf("fallback miss = %q, want FR (header fallback)", got)
	}
}

// TestBuildGeoMaxMindHeaderFallbackReverse: header-primary then maxmind fallback.
func TestBuildGeoMaxMindHeaderFallbackReverse(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, cityFixture, dir, "City.mmdb")
	src, _, _, dbs, err := buildGeo(parseSite(t, `example.com {
    geo {
        source header  CF-IPCountry
        source maxmind City.mmdb
    }
    cache_key path {geo}
}`), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	})
	// header present wins.
	if got := src.Lookup(netip.MustParseAddr("216.160.83.56"), http.Header{"Cf-Ipcountry": {"FR"}}); got != "FR" {
		t.Errorf("reverse hit = %q, want FR (header primary wins)", got)
	}
	// no header -> maxmind.
	if got := src.Lookup(netip.MustParseAddr("216.160.83.56"), http.Header{}); got != "US" {
		t.Errorf("reverse miss = %q, want US (maxmind fallback)", got)
	}
}

// TestBuildGeoMaxMindErrors: missing/empty path, and disallowed source pairings.
func TestBuildGeoMaxMindErrors(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, cityFixture, dir, "City.mmdb")
	copyFixture(t, countryFixture, dir, "Country.mmdb")
	cases := map[string]string{
		"missing maxmind file": "example.com {\n geo {\n source maxmind /nope/none.mmdb\n}\n}",
		"empty maxmind path":   "example.com {\n geo {\n source maxmind\n}\n}",
		// non-{maxmind,header} pairs keep the duplicate-source error:
		"cidr+maxmind pair":   "example.com {\n geo {\n source cidr City.mmdb\n source maxmind City.mmdb\n}\n}",
		"two maxmind sources": "example.com {\n geo {\n source maxmind City.mmdb\n source maxmind Country.mmdb\n}\n}",
		"three sources":       "example.com {\n geo {\n source maxmind City.mmdb\n source header A\n source header B\n}\n}",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, err := buildGeo(parseSite(t, src), dir, true); err == nil {
				t.Errorf("expected an error for %s", name)
			}
		})
	}
}

// TestBuildGeoMaxMindRegionHeaderWins: an explicit region_header overrides the maxmind
// region (operator's explicit choice).
func TestBuildGeoMaxMindRegionHeaderWins(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, cityFixture, dir, "City.mmdb")
	_, region, _, dbs, err := buildGeo(parseSite(t, `example.com {
    geo {
        source        maxmind City.mmdb
        region_header CF-Region
    }
    cache_key path {geo.region}
}`), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, db := range dbs {
			_ = db.Close()
		}
	})
	// The region now comes from the header, not the DB.
	if got := region.Lookup(netip.MustParseAddr("216.160.83.56"), http.Header{"Cf-Region": {"us-tx"}}); got != "US-TX" {
		t.Errorf("region (header wins) = %q, want US-TX", got)
	}
}
