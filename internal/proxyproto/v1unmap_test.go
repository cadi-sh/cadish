package proxyproto

import "testing"

// TestParseV1UnmapsV4in6: a v1 TCP6 header with an IPv4-mapped address resolves to the bare
// IPv4 (matching the v2 parser), so a trusted-proxy / ip ACL decides consistently across both.
func TestParseV1UnmapsV4in6(t *testing.T) {
	ap, err := parseV1AddrPort("::ffff:1.2.3.4", "443", false)
	if err != nil {
		t.Fatalf("parseV1AddrPort: %v", err)
	}
	if got := ap.Addr().String(); got != "1.2.3.4" {
		t.Errorf("addr = %q, want bare IPv4 1.2.3.4 (unmapped like v2)", got)
	}
}
