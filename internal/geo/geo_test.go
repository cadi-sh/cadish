package geo

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestHeaderSource(t *testing.T) {
	s := NewHeaderSource("CF-IPCountry")
	h := http.Header{}
	h.Set("CF-IPCountry", "us") // lower-case from upstream
	if got := s.Lookup(netip.Addr{}, h); got != "US" {
		t.Errorf("header => %q, want US (upper-cased)", got)
	}
	// Missing header → unknown.
	if got := s.Lookup(netip.Addr{}, http.Header{}); got != Unknown {
		t.Errorf("missing header => %q, want %q", got, Unknown)
	}
	if got := s.Lookup(netip.Addr{}, nil); got != Unknown {
		t.Errorf("nil header => %q, want %q", got, Unknown)
	}
}

// TestHeaderSourceBoundsCardinality guards the round-2 fix: a client-spoofable geo
// header must not inject arbitrary, unbounded, or out-of-charset values into the
// {geo}/{geo.region} cache-key normalizer (cache-key-cardinality DoS + CRLF). A
// valid ISO-ish code passes through (upper-cased); anything else maps to Unknown.
func TestHeaderSourceBoundsCardinality(t *testing.T) {
	s := NewHeaderSource("CF-IPCountry")
	get := func(v string) string {
		h := http.Header{}
		h.Set("CF-IPCountry", v)
		return s.Lookup(netip.Addr{}, h)
	}
	cases := map[string]string{
		"us":                                    "US",    // legitimate country, upper-cased
		"US-UT":                                 "US-UT", // legitimate subdivision (hyphen allowed)
		"GB":                                    "GB",    // legitimate
		"this-is-way-too-long-to-be-a-geo-code": Unknown, // over the length cap
		"US; DROP":                              Unknown, // out-of-charset (space, ';')
		"US\r\nX-Evil: 1":                       Unknown, // CRLF must never reach a key or header
		"../../etc":                             Unknown, // out-of-charset ('.', '/')
		"😀":                                     Unknown, // out-of-charset (non-ASCII)
	}
	for in, want := range cases {
		if got := get(in); got != want {
			t.Errorf("geo header %q => %q, want %q", in, got, want)
		}
	}
}

func TestCIDRSourceLongestPrefix(t *testing.T) {
	entries, err := LoadCIDRTable(strings.NewReader(`
# comment
10.0.0.0/8       US
10.1.0.0/16      ES
203.0.113.0/24   FR
2001:db8::/32    DE
`))
	if err != nil {
		t.Fatal(err)
	}
	s := NewCIDRSource(entries)
	cases := map[string]string{
		"10.2.3.4":     "US", // /8 only
		"10.1.2.3":     "ES", // /16 wins over /8 (longest prefix)
		"203.0.113.50": "FR",
		"2001:db8::1":  "DE",
		"8.8.8.8":      Unknown, // no match
	}
	for ip, want := range cases {
		if got := s.Lookup(addr(ip), nil); got != want {
			t.Errorf("Lookup(%s) = %q, want %q", ip, got, want)
		}
	}
	// Invalid IP → unknown.
	if got := s.Lookup(netip.Addr{}, nil); got != Unknown {
		t.Errorf("invalid ip => %q, want %q", got, Unknown)
	}
}

func TestLoadCIDRTableErrors(t *testing.T) {
	for _, src := range []string{
		"not-a-cidr US",
		"10.0.0.0/8",     // missing country
		"10.0.0.0/33 US", // bad mask
	} {
		if _, err := LoadCIDRTable(strings.NewReader(src)); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	trusted, err := ParsePrefixes([]string{"10.0.0.0/8", "::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	xff := func(v string) http.Header { return http.Header{"X-Forwarded-For": []string{v}} }

	// Peer is a trusted proxy → take the rightmost NON-trusted XFF entry (the
	// real client behind the proxy).
	if got := ClientIP("10.0.0.5:1234", xff("203.0.113.9, 10.0.0.5"), trusted); got != addr("203.0.113.9") {
		t.Errorf("trusted peer => %v, want 203.0.113.9 (real client)", got)
	}
	// Untrusted peer → ignore XFF entirely (spoofable); use the socket peer.
	if got := ClientIP("198.51.100.7:9999", xff("203.0.113.9"), trusted); got != addr("198.51.100.7") {
		t.Errorf("untrusted peer => %v, want 198.51.100.7 (XFF ignored)", got)
	}
	// No trusted proxies configured → always the peer.
	if got := ClientIP("10.0.0.5:1234", xff("203.0.113.9"), nil); got != addr("10.0.0.5") {
		t.Errorf("no trust config => %v, want 10.0.0.5", got)
	}
	// Chained trusted proxies → skip all trusted, return the client.
	if got := ClientIP("10.0.0.5:1234", xff("203.0.113.9, 10.9.9.9, 10.0.0.5"), trusted); got != addr("203.0.113.9") {
		t.Errorf("chained proxies => %v, want 203.0.113.9", got)
	}
	// Trusted peer but no XFF → fall back to the peer.
	if got := ClientIP("10.0.0.5:1234", http.Header{}, trusted); got != addr("10.0.0.5") {
		t.Errorf("trusted peer no XFF => %v, want 10.0.0.5", got)
	}
}

// TestHeaderSourceIgnoresIP / CIDRSourceIgnoresHeader: each source uses only its
// own input.
func TestSourcesUseOwnInput(t *testing.T) {
	hs := NewHeaderSource("X-Geo")
	if got := hs.Lookup(addr("203.0.113.1"), http.Header{"X-Geo": {"GB"}}); got != "GB" {
		t.Errorf("header source = %q, want GB", got)
	}
	cs := NewCIDRSource([]CIDREntry{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Country: "FR"}})
	if got := cs.Lookup(addr("203.0.113.1"), http.Header{"X-Geo": {"GB"}}); got != "FR" {
		t.Errorf("cidr source = %q, want FR (ignores header)", got)
	}
}
