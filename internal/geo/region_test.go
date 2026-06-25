package geo

import (
	"net/http"
	"net/netip"
	"testing"
)

// TestRegionSource: a configurable CDN region header → the region/subdivision
// class, upper-cased; absent/blank yields Unknown.
func TestRegionSource(t *testing.T) {
	s := NewRegionSource("CF-Region")
	h := http.Header{}
	h.Set("CF-Region", "us-ut") // lower-case from upstream
	if got := s.Lookup(netip.Addr{}, h); got != "US-UT" {
		t.Errorf("region header => %q, want US-UT (upper-cased)", got)
	}
	if got := s.Lookup(netip.Addr{}, http.Header{}); got != Unknown {
		t.Errorf("missing region header => %q, want %q", got, Unknown)
	}
	if got := s.Lookup(netip.Addr{}, nil); got != Unknown {
		t.Errorf("nil header => %q, want %q", got, Unknown)
	}
}

// TestRegionSourceOperatorNamed: any operator-named header works (X-Geo-Region,
// X-Geo-Subdivision, …), mirroring the country header config knob.
func TestRegionSourceOperatorNamed(t *testing.T) {
	for _, name := range []string{"X-Geo-Region", "X-Geo-Subdivision", "X-Region"} {
		s := NewRegionSource(name)
		h := http.Header{}
		h.Set(name, "US-TX")
		if got := s.Lookup(netip.Addr{}, h); got != "US-TX" {
			t.Errorf("region header %q => %q, want US-TX", name, got)
		}
	}
}
