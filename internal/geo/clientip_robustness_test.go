package geo

import (
	"net/http"
	"testing"
)

// TestClientIPMultiLineXFFFlattening pins the trust-matrix cell where a client
// supplies SEVERAL X-Forwarded-For header lines (not one comma-joined line):
// forwardedFor flattens hdr.Values in wire order (leftmost line first), so the
// right→left walk still returns the rightmost-untrusted entry — the verified real
// client the trusted proxy appended. A spoofed leftmost line can NEVER be selected.
func TestClientIPMultiLineXFFFlattening(t *testing.T) {
	trusted, err := ParsePrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	// Two separate XFF lines: an attacker-forged value on the first line, the real
	// client appended by the trusted proxy on the second. The peer is the trusted
	// proxy. The walk must return the real client (203.0.113.9), never the forged 9.9.9.9.
	hdr := http.Header{"X-Forwarded-For": []string{"9.9.9.9", "203.0.113.9"}}
	if got := ClientIP("10.0.0.5:1234", hdr, trusted); got != addr("203.0.113.9") {
		t.Errorf("multi-line XFF => %v, want 203.0.113.9 (rightmost-untrusted; forged leftmost ignored)", got)
	}

	// Attacker appends a TRUSTED-looking entry after a forged one to try to push the
	// walk past the real selection: `9.9.9.9` then a trusted `10.0.0.250`, then the
	// proxy appends the real client. The real client is still rightmost-untrusted.
	hdr = http.Header{"X-Forwarded-For": []string{"9.9.9.9, 10.0.0.250", "203.0.113.9"}}
	if got := ClientIP("10.0.0.5:1234", hdr, trusted); got != addr("203.0.113.9") {
		t.Errorf("multi-line XFF with injected trusted entry => %v, want 203.0.113.9", got)
	}
}

// TestClientIPXFFEntryPortsAndBrackets pins parseHostAddr robustness inside the XFF
// walk: an entry may carry a :port or be a bracketed IPv6 literal. Such an entry must
// parse to the bare address (so a trusted entry with a port is correctly recognized
// as trusted and skipped), not be mis-bucketed or skipped wholesale.
func TestClientIPXFFEntryPortsAndBrackets(t *testing.T) {
	trusted, err := ParsePrefixes([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	// IPv4 real client carries a port; trailing trusted hop also carries a port.
	hdr := http.Header{"X-Forwarded-For": []string{"203.0.113.9:51234, 10.0.0.5:443"}}
	if got := ClientIP("10.0.0.5:1234", hdr, trusted); got != addr("203.0.113.9") {
		t.Errorf("XFF with ports => %v, want 203.0.113.9 (port stripped, trusted hop skipped)", got)
	}
	// Bracketed IPv6 client behind a bracketed trusted IPv6 hop (both with ports).
	hdr = http.Header{"X-Forwarded-For": []string{"[2001:db9::abcd]:51234, [2001:db8::5]:443"}}
	if got := ClientIP("[2001:db8::5]:1234", hdr, trusted); got != addr("2001:db9::abcd") {
		t.Errorf("bracketed IPv6 XFF => %v, want 2001:db9::abcd", got)
	}
}

// TestClientIPXFFGarbageEntriesDropped pins that malformed/blank XFF entries are
// dropped (never parsed into a bogus Addr) and — because the walk is right→left and
// selects the rightmost VALID untrusted entry — dropping garbage does not shift the
// result or panic. A malformed entry can never become the selected client IP.
func TestClientIPXFFGarbageEntriesDropped(t *testing.T) {
	trusted, err := ParsePrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		xff  string
		want string
	}{
		{"trailing garbage after client", "203.0.113.9, garbage, 10.0.0.5", "203.0.113.9"},
		{"empty entries", "203.0.113.9, , 10.0.0.5", "203.0.113.9"},
		{"not-an-ip token", "not-an-ip, 203.0.113.9, 10.0.0.5", "203.0.113.9"},
		{"all garbage falls back to peer", "garbage, , nope", "10.0.0.5"},
	}
	for _, c := range cases {
		hdr := http.Header{"X-Forwarded-For": []string{c.xff}}
		if got := ClientIP("10.0.0.5:1234", hdr, trusted); got != addr(c.want) {
			t.Errorf("%s: ClientIP(%q) = %v, want %v", c.name, c.xff, got, c.want)
		}
	}
}

// TestClientIPUnparseablePeerNoTrust pins the fail-safe for an unparseable
// RemoteAddr: with no trusted set the result is the (invalid) peer — never an XFF
// entry — so a direct client with a garbage RemoteAddr cannot promote its spoofable
// XFF into the resolved client IP. The caller treats an invalid Addr as "no IP".
func TestClientIPUnparseablePeerNoTrust(t *testing.T) {
	hdr := http.Header{"X-Forwarded-For": []string{"203.0.113.9"}}
	if got := ClientIP("garbage", hdr, nil); got.IsValid() {
		t.Errorf("unparseable peer, no trust => %v valid, want invalid (XFF must NOT be used)", got)
	}
	// Even WITH a trust set, an unparseable peer is not in any prefix, so XFF stays ignored.
	trusted, _ := ParsePrefixes([]string{"10.0.0.0/8"})
	if got := ClientIP("garbage", hdr, trusted); got.IsValid() {
		t.Errorf("unparseable peer, with trust => %v valid, want invalid (peer not trusted => XFF ignored)", got)
	}
}
