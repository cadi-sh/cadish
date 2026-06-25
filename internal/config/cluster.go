package config

import (
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/cluster"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/chain"
)

// buildCluster builds the per-site cluster membership from a `cluster { peers … }`
// block, if present, and returns it together with the (possibly wrapped) default
// origin. Coexistence of #7 and #8 is decided here by the mode:
//
//   - read_through (#7): the peer read-through origin is composed BEFORE the real
//     origin in a chain, so a local miss first asks the owning peer and only a peer
//     miss / unreachable falls through to origin. Every node may serve any key.
//
//   - owner (#8): ownership routing is AUTHORITATIVE — a non-owner reverse-proxies
//     to the owner (the server's clusterRoute seam), so the def origin is left as
//     the REAL origin (no peer chain): when we are the owner we fetch from origin
//     directly, never bouncing a key back to ourselves. The degraded fallback
//     (owner down) still uses the PeerOrigin opportunistically, but that is driven
//     by the server, not by wrapping def.
//
// When no `cluster` membership block is present, membership is nil and def is
// returned unchanged — the zero-cost path for a non-clustered cadish.
func buildCluster(site *cadishfile.Site, def origin.Origin) (*cluster.Membership, origin.Origin, error) {
	d := findMembershipBlock(site)
	if d == nil {
		return nil, def, nil
	}
	cfg, err := cluster.Parse(d)
	if err != nil {
		return nil, def, err
	}
	m, err := cluster.New(cfg)
	if err != nil {
		return nil, def, err
	}

	if m.Mode() == cluster.ModeReadThrough {
		// A peer miss / unreachable surfaces as a fall-through condition (404 /
		// connection error), so chain falls to def — exactly DefaultFallThrough.
		wrapped, werr := chain.New([]origin.Origin{m.PeerOrigin(), def})
		if werr != nil {
			return nil, def, werr
		}
		return m, wrapped, nil
	}
	// Owner mode: def stays the real origin; routing is done by the server seam.
	return m, def, nil
}

// findMembershipBlock returns the site's `cluster { peers … }` membership directive
// (the nameless form), or nil. A named `cluster NAME { to … }` LB pool is NOT a
// membership block and is skipped (cluster.IsMembershipBlock distinguishes them).
func findMembershipBlock(site *cadishfile.Site) *cadishfile.Directive {
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		if cluster.IsMembershipBlock(d) {
			return d
		}
	}
	return nil
}
