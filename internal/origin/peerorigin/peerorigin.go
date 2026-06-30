// Package peerorigin is the cadish peer-cache read-through origin (#7). It is an
// origin.Origin that, on Fetch, asks a PEER cadish node for the object instead of
// the real upstream. Composed BEFORE the real origin in an origin chain, it turns
// a region of cadish nodes into a cooperative cache: a local miss first tries the
// owning peer (LAN/RTT ≪ origin); only a peer miss falls through to origin.
//
// Reuse, not reinvention: the peer pool is an internal/lb Upstream (consistent-
// hash shard-by-key over the peers, with lb's health FSM, failover, passive ejection and
// dns:// discovery). PeerOrigin only adds two things on top:
//
//   - it routes by the CACHE KEY (lb.WithRoutingKey), so a given key always asks
//     the same owning peer — the object is cached once per region, and a peer that
//     already has it answers from its own cache; and
//   - it stamps the X-Cadish-Peer hop header so the peer does NOT re-forward
//     (loop/storm guard). A peer that sees the header serves only from its local
//     cache and 404s a miss, which surfaces here as origin.ErrNotFound so the
//     chain falls through to the real origin.
//
// The streaming/ownership contract is honored verbatim — the lb.Upstream returns
// the peer body unchanged (a transparent close hook for connection accounting),
// so there is no extra copy and the server tees it into the local cache exactly
// as it tees an origin body.
package peerorigin

import (
	"context"
	"net/http"

	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
)

// PeerOrigin fetches an object from the owning peer cadish node.
type PeerOrigin struct {
	peers     *lb.Upstream
	hopHeader string
	region    string
	self      string // this node's peer base URL; never read-through to ourselves
}

// New builds a PeerOrigin over a peer pool (which MUST be a shard-by-key
// lb.Upstream so a cache key routes to its owning peer). hopHeader is the loop-
// guard header name (cluster.HopHeader) and region is its value, stamped on every
// peer fetch so the peer does not re-forward. self is this node's own peer URL: a
// key the ring assigns to us is served locally (ErrNotFound here), never fetched
// from ourselves — that would deadlock against request coalescing (a self-fetch is
// a second in-flight request for the same key, which the coalescer makes wait on
// the very request issuing it). The header name is passed in (rather than imported)
// so this package does not depend on internal/cluster (avoids an import cycle).
func New(peers *lb.Upstream, hopHeader, region, self string) *PeerOrigin {
	return &PeerOrigin{peers: peers, hopHeader: hopHeader, region: region, self: self}
}

// Fetch implements origin.Origin. It attaches the cache key as the lb routing key
// (so the peer pool's shard ring targets the owning peer), stamps the hop header,
// and delegates to the peer pool. A peer miss surfaces as origin.ErrNotFound and a
// peer-unreachable as a connection-class error, either of which lets a chain fall
// through to the real origin.
func (p *PeerOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	// Cache-bypass guard: a `pass` / credential-bypass request is never stored, so a
	// peer read-through is pure wasted latency (the peer would only pass to origin
	// too). Surface ErrSkip — a no-op decline (body untouched) so the chain falls
	// through to the real origin even for a write — the read-through twin of the server
	// skipping the owner seam for a `pass`. Checked first: no routing, no hop stamp, no
	// peer dial.
	if req.Bypass {
		return nil, origin.ErrSkip
	}

	// Write guard (F-B1): only the cacheable, body-less methods (GET/HEAD) are
	// read-through-routed to a peer. A write (POST/PUT/… or any request carrying a
	// body) gains nothing from a peer — it is never cached — and routing it risks the
	// same consumed-body hazard the owner-mode path avoids (server/cluster.go): the
	// peer pool streams req.Body with no replay. Surface ErrSkip — a no-op decline that
	// did NOT read req.Body — so the chain falls THROUGH to the real origin even though
	// the request carries a body (ErrNotFound would be terminal for a body request and
	// 404 the write, dropping it — F-C). The body reaches the real origin intact, the
	// read-through twin of server/cluster.go's GET/HEAD-only owner routing.
	if (req.Method != "" && req.Method != http.MethodGet && req.Method != http.MethodHead) || req.Body != nil {
		return nil, origin.ErrSkip
	}

	// Loop guard: if THIS request was already forwarded to us by a peer (it carries
	// the hop header), we must NOT read-through to a peer again — that would bounce
	// the request around the cluster. Surface ErrSkip (no-op decline, body untouched)
	// so the chain falls through to the real origin, serving the object locally. This
	// is the read-through twin of the server's owner-route hop guard.
	if req.Header != nil && req.Header.Get(p.hopHeader) != "" {
		return nil, origin.ErrSkip
	}

	// If the ring assigns this object to US, do not read-through (a self-fetch
	// deadlocks against coalescing). Serve it locally: surface ErrSkip (no-op decline,
	// body untouched) so the chain falls through to the real origin on this node.
	//
	// The guard resolves the owner health-aware (healthyOnly=true), matching where
	// Fetch's pickRing would route, so it fires in the steady state when the topological
	// owner is down and self is the eligible successor. But the guard is a point-in-time
	// read; a health flap between it and Fetch's pick could still let pickRing walk onto
	// self. The WithExcludeBaseURL(ctx, self) below is the race-proof backstop — pick
	// can never select self regardless of flap timing (F-B2) — so the two together both
	// avoid a wasted dial in the common case and make a self-dial structurally
	// impossible.
	if p.self != "" {
		if owner, ok := p.peers.Owner(req.Key, true); ok && owner == p.self {
			return nil, origin.ErrSkip
		}
	}

	// Route by the cache key. The server passes the cache key as req.Key for the
	// peer fetch (it equals the object identity), so shard-by-key and the request
	// path coincide; attach it explicitly so a shard-by-key pool pins correctly.
	ctx = lb.WithRoutingKey(ctx, req.Key)
	// Never dial self for a read-through (see the self-guard rationale above): self
	// stays in the ownership ring but is excluded from the routing decision, closing
	// the guard/pick health-flap race structurally.
	if p.self != "" {
		ctx = lb.WithExcludeBaseURL(ctx, p.self)
	}

	// Stamp the loop guard. Clone the header so we never mutate the caller's map.
	hopReq := *req
	if req.Header != nil {
		hopReq.Header = req.Header.Clone()
	} else {
		hopReq.Header = http.Header{}
	}
	hopReq.Header.Set(p.hopHeader, p.region)

	resp, err := p.peers.Fetch(ctx, &hopReq)
	if err != nil {
		return nil, err
	}
	// A peer 404/410 now arrives as a full-body NEGATIVE response (origin contract,
	// D15) rather than ErrNotFound. In the read-through context a peer's negative is
	// just a cache MISS ("the peer doesn't have it") — never an authoritative answer
	// to cache here — so drain+close it and surface ErrNotFound, letting the chain
	// fall through to the real origin exactly as before D15.
	if resp != nil && resp.Negative {
		if resp.Body != nil {
			resp.Body.Close()
		}
		return nil, origin.ErrNotFound
	}
	return resp, nil
}
