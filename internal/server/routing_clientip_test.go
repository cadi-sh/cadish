package server

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
)

// TestRoutingClientIP_TrustedProxyParity verifies that the load-balancing routing
// key resolves the client IP through the SAME trusted-proxy / XFF logic as the
// security gate and {geo} (decision #16): behind a trusted proxy it pins on the
// real client (from X-Forwarded-For), and with no trusted proxy it never honours a
// spoofed XFF — it uses the peer. This is what makes sticky-by-ip and shard-by-key
// pools distribute on the real client rather than collapsing onto the proxy IP.
func TestRoutingClientIP_TrustedProxyParity(t *testing.T) {
	t.Run("trusted proxy: real client from XFF", func(t *testing.T) {
		site := &boundSite{Site: &config.Site{
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}}
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.RemoteAddr = "10.1.2.3:5555" // the trusted proxy
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		if got := routingClientIP(site, r); got != "203.0.113.7" {
			t.Fatalf("routingClientIP = %q, want real client 203.0.113.7", got)
		}
	})

	t.Run("untrusted peer: spoofed XFF ignored", func(t *testing.T) {
		site := &boundSite{Site: &config.Site{}} // no trusted proxies
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.RemoteAddr = "198.51.100.9:5555"
		r.Header.Set("X-Forwarded-For", "1.2.3.4") // spoof attempt
		if got := routingClientIP(site, r); got != "198.51.100.9" {
			t.Fatalf("routingClientIP = %q, want peer 198.51.100.9 (XFF must not be trusted)", got)
		}
	})
}
