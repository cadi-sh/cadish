package geo

// NewRegionSource builds a Source that reads the region / subdivision class (e.g.
// "US-UT", "US-TX") from a configurable upstream CDN/LB header (CF-Region,
// X-Geo-Region, or any operator-named header). The value is upper-cased; an
// absent/blank header yields Unknown.
//
// Why a header, not the IP: turning a raw client IP into a US state needs a GeoIP
// database, a dependency cadish deliberately avoids (D11). So — exactly like the
// country, which comes from CF-IPCountry today — the region is sourced from an
// upstream geo header the CDN already computed. There is intentionally no bundled
// GeoIP DB and no CIDR-subdivision table: region granularity REQUIRES an upstream
// geo header. It is mechanically identical to the country header source.
func NewRegionSource(name string) Source {
	return NewHeaderSource(name)
}
