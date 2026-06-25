package geo

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP resolves the REAL client IP from the socket peer (remoteAddr) and the
// X-Forwarded-For header, trusting XFF only when the immediate peer is a
// configured trusted proxy.
//
// Rationale: X-Forwarded-For is client-spoofable, so it is trusted only when the
// request actually arrived from a known proxy. The algorithm:
//
//   - Parse the peer from remoteAddr. If there are no trusted prefixes, or the
//     peer is NOT in one, return the peer and IGNORE XFF (a direct/untrusted
//     client cannot forge its source IP at the socket layer).
//   - If the peer IS a trusted proxy, walk the XFF chain right→left (nearest
//     proxy first) and return the first address that is NOT itself a trusted
//     proxy — the real client. If every XFF hop is trusted (or XFF is absent),
//     fall back to the peer.
//
// The returned Addr is Unmap'd (4-in-6 normalized); it is invalid only when
// remoteAddr is unparseable and no usable XFF entry exists.
func ClientIP(remoteAddr string, hdr http.Header, trusted []netip.Prefix) netip.Addr {
	peer := parseHostAddr(remoteAddr)
	if !peer.IsValid() || len(trusted) == 0 || !inAny(peer, trusted) {
		return peer
	}
	// Peer is a trusted proxy: consult XFF.
	ips := forwardedFor(hdr)
	for i := len(ips) - 1; i >= 0; i-- {
		if !inAny(ips[i], trusted) {
			return ips[i]
		}
	}
	return peer
}

// PeerTrusted reports whether the IMMEDIATE socket peer (parsed from remoteAddr)
// is a configured trusted proxy. It is the gate for honoring client-supplied geo
// headers (CF-IPCountry, CF-Region, …): exactly like X-Forwarded-For in ClientIP,
// a header-sourced geo value may be trusted ONLY when the request actually arrived
// from a known proxy — otherwise a direct client could spoof its country/region to
// bypass a geo-fence or choose its {geo} cache bucket.
//
// With no trusted prefixes configured the direct peer is NOT a trusted proxy, so
// this returns false — the safe, intended behavior: header geo REQUIRES trust_proxy.
func PeerTrusted(remoteAddr string, trusted []netip.Prefix) bool {
	if len(trusted) == 0 {
		return false
	}
	peer := parseHostAddr(remoteAddr)
	return peer.IsValid() && inAny(peer, trusted)
}

// forwardedFor flattens the X-Forwarded-For header(s) into parsed addresses, in
// order (leftmost = original client … rightmost = nearest proxy).
func forwardedFor(hdr http.Header) []netip.Addr {
	if hdr == nil {
		return nil
	}
	var out []netip.Addr
	for _, v := range hdr.Values("X-Forwarded-For") {
		for _, part := range strings.Split(v, ",") {
			if a := parseHostAddr(strings.TrimSpace(part)); a.IsValid() {
				out = append(out, a)
			}
		}
	}
	return out
}

// parseHostAddr parses an address that may carry a :port (and may be an
// IPv6 literal with or without brackets), returning an Unmap'd netip.Addr.
func parseHostAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// inAny reports whether addr is contained by any of the prefixes.
func inAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParsePrefixes parses CIDR strings into prefixes (for trust_proxy config).
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
