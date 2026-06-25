// Package cluster turns N cadish nodes in a region into a sharded / cooperative
// cache. It implements two interlocking features driven by one `cluster { … }`
// Cadishfile membership block:
//
//   - PEER READ-THROUGH (#7): on a LOCAL cache miss, consult peer cadish nodes
//     (same region) before going to origin; if a peer has the object, stream it
//     locally (same tee contract as origin). Modeled as an origin.Origin
//     (internal/origin/peerorigin) composed BEFORE the real origin in a chain.
//
//   - OWNERSHIP ROUTING (#8): one node OWNS each cache key via a consistent-hash
//     ring over the cluster peers (the SAME lb ring used for upstream sharding).
//     A request landing on a non-owner is reverse-proxied to the owner so the
//     object is cached once per region, not N times.
//
// Both share cluster membership + peer health (reused from internal/lb) and a hop
// guard (the X-Cadish-Peer header) that prevents forward loops/storms: a request
// already forwarded to a peer is never re-forwarded.
//
// ZERO COST WHEN ABSENT. Everything here is gated by the presence of a `cluster`
// membership block; a non-clustered cadish constructs no Membership and behaves
// exactly as before.
package cluster

import (
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/lb"
)

// HopHeader marks a request as already forwarded to a peer cadish node. A node
// that sees it MUST NOT forward again (read-through or owner-route), which is what
// makes the cluster loop-safe and storm-safe. Its value is the originating
// region, used to ignore cross-region hops.
const HopHeader = "X-Cadish-Peer"

// Mode selects how #7 (read-through) and #8 (ownership routing) coexist.
type Mode int

const (
	// ModeReadThrough (the default) is #7 ONLY: opportunistic peer read-through.
	// On a local miss, the owning peer is asked for the key (hop-guarded); a peer
	// hit is streamed-and-stored locally, a peer miss falls through to origin.
	// Requests are never re-routed — every node may serve any key.
	ModeReadThrough Mode = iota
	// ModeOwner is #8 PRIMARY with #7 as the fallback: each key has one owner on
	// the ring. A request landing on a non-owner is reverse-proxied to the owner
	// so the object is cached once per region. If the owner is down, Fallback
	// decides between serving locally (strict) or the next ring node (degraded);
	// the degraded path also tries peer read-through before origin.
	ModeOwner
)

// String renders the mode keyword.
func (m Mode) String() string {
	switch m {
	case ModeOwner:
		return "owner"
	default:
		return "read_through"
	}
}

// Fallback selects owner-mode behavior when the computed owner is unavailable.
type Fallback int

const (
	// FallbackDegraded (the default) serves the request from the next eligible
	// ring node, then peer read-through, then local origin — availability over
	// strict single-ownership. A flapping owner degrades to "cached on a neighbor"
	// rather than failing.
	FallbackDegraded Fallback = iota
	// FallbackStrict serves the request locally (this node's cache→origin) when
	// the owner is down, accepting a transient duplicate cache entry rather than
	// chaining proxies. No second hop.
	FallbackStrict
)

// String renders the fallback keyword.
func (f Fallback) String() string {
	switch f {
	case FallbackStrict:
		return "strict"
	default:
		return "degraded"
	}
}

// Config is a parsed `cluster { … }` membership block.
type Config struct {
	// Self is this node's own peer URL (must appear in Peers). It identifies which
	// ring node is "us" for ownership decisions and is excluded from peer fetches.
	Self string
	// Peers are the peer cadish node targets (static URLs and/or dns://, k8s://
	// discovery), parsed with the same lb.Target syntax as upstream `to`. At least
	// one required; Self must be among them.
	Peers []lb.Target
	// Region scopes the cluster; it is the value of the X-Cadish-Peer hop header so
	// a node ignores hops stamped by a different region.
	Region string
	// Mode selects #7/#8 coexistence (default read_through).
	Mode Mode
	// Fallback selects owner-mode behavior on owner-down (default degraded).
	Fallback Fallback
	// Health is the active peer-health probe spec (reused verbatim from lb). Nil
	// disables active probing (peers are then always eligible).
	Health *lb.HealthSpec
	// Replicas is the consistent-hash virtual-node count per peer (0 ⇒ lb default).
	Replicas int
	// Pos is the directive's source position.
	Pos cadishfile.Pos
}

// IsMembershipBlock reports whether a `cluster` directive is the membership form
// (this package) rather than the pre-existing `cluster NAME { to … }` LB-pool
// form (internal/lb). The membership block has NO name argument and carries a
// `peers` directive; the LB-pool form has a name and `to` backends. Distinguishing
// by shape lets both coexist without a keyword clash.
func IsMembershipBlock(d *cadishfile.Directive) bool {
	if d == nil || d.Name != "cluster" {
		return false
	}
	if len(d.Args) != 0 {
		return false // `cluster NAME { … }` ⇒ LB pool, not membership
	}
	for _, n := range d.Block {
		if sub, ok := n.(*cadishfile.Directive); ok && sub.Name == "peers" {
			return true
		}
	}
	return false
}
