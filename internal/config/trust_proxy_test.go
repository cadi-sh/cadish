package config

import (
	"net/netip"
	"testing"
)

// TestStandaloneTrustProxyNoGeoBlock: a pure-security site (an `ip` ACL with NO
// geo block) can declare `trust_proxy …` and it populates TrustedProxies — the
// fix for the silent-no-op (TrustedProxies was previously nil without a geo block).
func TestStandaloneTrustProxyNoGeoBlock(t *testing.T) {
	site := parseSite(t, `example.com {
    @bad ip 203.0.113.9/32
    deny @bad
    trust_proxy 10.0.0.0/8 ::1/128
    cache_ttl default ttl 60s
}`)
	got, err := buildSiteTrustProxies(site)
	if err != nil {
		t.Fatalf("buildSiteTrustProxies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("standalone trust_proxy: got %d prefixes, want 2: %v", len(got), got)
	}
	if !inAnyPrefix(got, netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("10.1.2.3 not covered by %v", got)
	}
}

// TestGeoTrustProxyBackCompat: a geo-only `geo { trust_proxy … }` config (no
// standalone directive) is unchanged — back-compat.
func TestGeoTrustProxyBackCompat(t *testing.T) {
	site := parseSite(t, `example.com {
    geo {
        source header CF-IPCountry
        trust_proxy 10.0.0.0/8
    }
    cache_key path {geo}
}`)
	_, _, geoTrusted, _, err := buildGeo(site, t.TempDir(), true)
	if err != nil {
		t.Fatalf("buildGeo: %v", err)
	}
	siteTrusted, err := buildSiteTrustProxies(site)
	if err != nil {
		t.Fatalf("buildSiteTrustProxies: %v", err)
	}
	if len(siteTrusted) != 0 {
		t.Fatalf("no standalone trust_proxy, got %d", len(siteTrusted))
	}
	union := unionPrefixes(geoTrusted, siteTrusted)
	if len(union) != 1 {
		t.Fatalf("geo-only trust_proxy: union = %d, want 1: %v", len(union), union)
	}
}

// TestTrustProxyUnionDedups: when BOTH a `geo { trust_proxy }` and a standalone
// `trust_proxy` are present they UNION; identical prefixes are de-duplicated.
func TestTrustProxyUnionDedups(t *testing.T) {
	site := parseSite(t, `example.com {
    geo {
        source header CF-IPCountry
        trust_proxy 10.0.0.0/8
    }
    trust_proxy 10.0.0.0/8 172.16.0.0/12
    cache_key path {geo}
}`)
	_, _, geoTrusted, _, err := buildGeo(site, t.TempDir(), true)
	if err != nil {
		t.Fatalf("buildGeo: %v", err)
	}
	siteTrusted, err := buildSiteTrustProxies(site)
	if err != nil {
		t.Fatalf("buildSiteTrustProxies: %v", err)
	}
	union := unionPrefixes(geoTrusted, siteTrusted)
	// 10.0.0.0/8 (shared, deduped) + 172.16.0.0/12 = 2.
	if len(union) != 2 {
		t.Fatalf("union with dup: got %d, want 2 (deduped): %v", len(union), union)
	}
	if !inAnyPrefix(union, netip.MustParseAddr("172.16.5.5")) || !inAnyPrefix(union, netip.MustParseAddr("10.9.9.9")) {
		t.Errorf("union does not cover both nets: %v", union)
	}
}

// TestStandaloneTrustProxyErrors: an empty arg list or a bad CIDR is a compile error.
func TestStandaloneTrustProxyErrors(t *testing.T) {
	for _, src := range []string{
		"example.com {\n trust_proxy\n}",
		"example.com {\n trust_proxy not-a-cidr\n}",
	} {
		site := parseSite(t, src)
		if _, err := buildSiteTrustProxies(site); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}

func inAnyPrefix(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
