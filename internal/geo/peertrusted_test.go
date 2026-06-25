package geo

import (
	"net/netip"
	"testing"
)

func TestPeerTrusted(t *testing.T) {
	trusted, err := ParsePrefixes([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}

	cases := []struct {
		name       string
		remoteAddr string
		trusted    []netip.Prefix
		want       bool
	}{
		{"trusted v4 peer", "10.1.2.3:5555", trusted, true},
		{"trusted v6 peer", "[2001:db8::1]:443", trusted, true},
		{"untrusted v4 peer", "198.51.100.9:5555", trusted, false},
		{"untrusted v6 peer", "[2001:dead::1]:443", trusted, false},
		// No trusted prefixes configured: the direct peer is NOT a trusted proxy,
		// so header-sourced geo must NOT be honored (header geo REQUIRES trust_proxy).
		{"no trusted set", "10.1.2.3:5555", nil, false},
		{"unparseable remoteAddr", "garbage", trusted, false},
		{"bare host no port", "10.1.2.3", trusted, true},
	}
	for _, c := range cases {
		if got := PeerTrusted(c.remoteAddr, c.trusted); got != c.want {
			t.Errorf("%s: PeerTrusted(%q) = %v, want %v", c.name, c.remoteAddr, got, c.want)
		}
	}
}
