package config

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// writeTemp writes content to a temp file in dir and returns its base name.
func writeTemp(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildGeoNone(t *testing.T) {
	src, region, trusted, _, err := buildGeo(parseSite(t, "example.com {\n cache_key path {geo}\n}"), t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	if src != nil || region != nil || trusted != nil {
		t.Errorf("no geo block => want (nil, nil, nil), got (%v, %v, %v)", src, region, trusted)
	}
}

func TestBuildGeoHeader(t *testing.T) {
	src, region, trusted, _, err := buildGeo(parseSite(t, `example.com {
    geo {
        source header CF-IPCountry
        trust_proxy 10.0.0.0/8 ::1/128
    }
    cache_key path {geo}
}`), t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	if src == nil {
		t.Fatal("want a header source")
	}
	if region != nil {
		t.Errorf("no region_header => want nil region source, got %v", region)
	}
	if got := src.Lookup(netip.Addr{}, http.Header{"Cf-Ipcountry": {"us"}}); got != "US" {
		t.Errorf("header lookup = %q, want US", got)
	}
	if len(trusted) != 2 {
		t.Errorf("trusted = %d, want 2", len(trusted))
	}
}

// TestBuildGeoRegionHeader: `region_header NAME` builds a region source the server
// reads into Request.GeoRegion. Region needs an upstream geo header (no GeoIP DB).
func TestBuildGeoRegionHeader(t *testing.T) {
	src, region, _, _, err := buildGeo(parseSite(t, `example.com {
    geo {
        source        header CF-IPCountry
        region_header CF-Region
    }
    cache_key path {geo.region}
}`), t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	if src == nil {
		t.Fatal("want a country source")
	}
	if region == nil {
		t.Fatal("want a region source")
	}
	if got := region.Lookup(netip.Addr{}, http.Header{"Cf-Region": {"us-ut"}}); got != "US-UT" {
		t.Errorf("region lookup = %q, want US-UT", got)
	}
}

func TestBuildGeoCIDR(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "geo.csv", "203.0.113.0/24, FR\n10.0.0.0/8 US\n")
	src, _, _, _, err := buildGeo(parseSite(t, `example.com {
    geo { source cidr geo.csv }
    cache_key path {geo}
}`), dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := src.Lookup(netip.MustParseAddr("203.0.113.5"), nil); got != "FR" {
		t.Errorf("cidr lookup = %q, want FR", got)
	}
}

func TestBuildGeoErrors(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no block", "example.com {\n geo source header X\n}"},
		{"no source", "example.com {\n geo {\n trust_proxy 10.0.0.0/8\n}\n}"},
		{"bad source kind", "example.com {\n geo {\n source dns foo\n}\n}"},
		{"dup source", "example.com {\n geo {\n source header A\n source header B\n}\n}"},
		{"bad trust cidr", "example.com {\n geo {\n source header X\n trust_proxy not-a-cidr\n}\n}"},
		{"missing cidr file", "example.com {\n geo {\n source cidr /nope/none.csv\n}\n}"},
		{"two blocks", "example.com {\n geo {\n source header A\n}\n geo {\n source header B\n}\n}"},
		{"unknown setting", "example.com {\n geo {\n frobnicate x\n}\n}"},
	}
	cases = append(cases,
		struct{ name, src string }{"dup region_header", "example.com {\n geo {\n source header A\n region_header X\n region_header Y\n}\n}"},
		struct{ name, src string }{"empty region_header", "example.com {\n geo {\n source header A\n region_header\n}\n}"},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := buildGeo(parseSite(t, tc.src), t.TempDir(), true); err == nil {
				t.Errorf("expected an error for %s", tc.name)
			}
		})
	}
}
