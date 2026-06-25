package config

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/geo"
)

// ProxyProtocolConfig is the parsed global `proxy_protocol { … }` option: the opt-in
// PROXY-protocol listener (recover the real client IP behind an L4/TCP-passthrough
// LB). It is NIL when no block is present (the common case) — the listener wrapper is
// then never installed and the accept path is byte-for-byte unchanged (zero cost).
//
// SECURITY (load-bearing): Trust is the set of trusted PROXY-header source CIDRs. A
// PROXY header is honored ONLY from a peer in this set; from anyone else it is
// rejected (REQUIRE policy). The set is REQUIRED and non-empty — an enabled
// proxy_protocol with an empty `trust` is a config error here, because an empty set
// would let any peer forge its source address.
type ProxyProtocolConfig struct {
	// Trust is the trusted PROXY-header source CIDRs (typically the LB addresses).
	Trust []netip.Prefix
}

// proxyProtocolFromFile parses the optional global `proxy_protocol { trust … }` block,
// which lives in the leading global-options block ("{ … }" at the top of the file),
// like `admin`/`security`. Returns (nil, nil) when absent. An empty trust set, a bad
// CIDR, or an unknown sub-directive is a positioned config error.
//
// The block form:
//
//	{
//	  proxy_protocol {
//	    trust 10.0.0.0/8 192.0.2.7/32
//	  }
//	}
func proxyProtocolFromFile(f *cadishfile.File) (*ProxyProtocolConfig, error) {
	if f == nil || f.Global == nil {
		return nil, nil
	}
	var dir *cadishfile.Directive
	for _, n := range f.Global.Body {
		d, ok := n.(*cadishfile.Directive)
		if ok && d.Name == "proxy_protocol" {
			dir = d
		}
	}
	if dir == nil {
		return nil, nil
	}

	var cidrs []string
	sawTrust := false
	for _, bn := range dir.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "trust":
			sawTrust = true
			if len(bd.Args) == 0 {
				return nil, compileErr(bd.Pos, "proxy_protocol: `trust` needs at least one CIDR (trusted PROXY-header source — required to prevent client-IP forgery)")
			}
			for _, a := range bd.Args {
				cidrs = append(cidrs, a.Raw)
			}
		default:
			return nil, compileErr(bd.Pos, "proxy_protocol: unknown directive "+quoteName(bd.Name))
		}
	}

	if !sawTrust || len(cidrs) == 0 {
		return nil, compileErr(dir.Pos, "proxy_protocol: a non-empty `trust` CIDR set is REQUIRED when the PROXY-protocol listener is enabled (an empty trust set would let any peer forge its client IP)")
	}
	prefixes, err := geo.ParsePrefixes(cidrs)
	if err != nil {
		return nil, compileErr(dir.Pos, "proxy_protocol: trust: "+err.Error())
	}
	return &ProxyProtocolConfig{Trust: prefixes}, nil
}

// ParseProxyProtocolFlag builds a ProxyProtocolConfig from the `-proxy-protocol-trust`
// run flag (a comma-separated CIDR list). It enforces the same REQUIRE-non-empty
// security rule as the Cadishfile block: an empty trust set is an error (an enabled
// PROXY listener with no trusted sources would let any peer forge its client IP).
func ParseProxyProtocolFlag(trust string) (*ProxyProtocolConfig, error) {
	var cidrs []string
	for _, part := range strings.Split(trust, ",") {
		if p := strings.TrimSpace(part); p != "" {
			cidrs = append(cidrs, p)
		}
	}
	if len(cidrs) == 0 {
		return nil, errors.New("a non-empty -proxy-protocol-trust CIDR set is REQUIRED (an empty trust set would let any peer forge its client IP)")
	}
	prefixes, err := geo.ParsePrefixes(cidrs)
	if err != nil {
		return nil, err
	}
	return &ProxyProtocolConfig{Trust: prefixes}, nil
}
