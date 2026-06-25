package cluster

import (
	"context"
	"net/http"

	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/origin/peerorigin"
)

// Membership is the live cluster state for one node: the peer pool (an lb.Upstream
// that consistent-hash-shards a cache key to its owning peer, with reused health /
// failover / discovery), this node's identity, and the #7/#8 policy. It is built
// once from a Config and is safe for concurrent use. A non-clustered cadish never
// constructs one (zero cost when absent).
type Membership struct {
	cfg   Config
	peers *lb.Upstream // shard-by-key over peers (ring + health + discovery)
	peer  *peerorigin.PeerOrigin
	self  string // normalized self peer URL (== a backend baseURL for static peers)
}

// New builds a Membership from cfg. The peer pool is a shard-by-key lb.Upstream so
// a cache key routes to its owning peer; the same pool answers Owner() for #8 and
// backs the read-through PeerOrigin for #7. Background health probing / dns
// re-resolution start on Start(ctx). New itself does no network I/O beyond lb's
// initial resolution.
func New(cfg Config) (*Membership, error) {
	lbCfg := lb.Config{
		Name:     "cluster-peers",
		Kind:     "cluster",
		Backends: cfg.Peers,
		Policy:   lb.Shard,
		Shard:    lb.ShardKeyVal,
		Health:   cfg.Health,
		Replicas: cfg.Replicas,
	}
	up, err := lb.New(lbCfg)
	if err != nil {
		return nil, err
	}
	return &Membership{
		cfg:   cfg,
		peers: up,
		peer:  peerorigin.New(up, HopHeader, cfg.Region, cfg.Self),
		self:  cfg.Self,
	}, nil
}

// Start launches the peer pool's background workers (active health probing +
// dynamic re-resolution), bound to ctx. Idempotent.
func (m *Membership) Start(ctx context.Context) {
	if m == nil {
		return
	}
	m.peers.Start(ctx)
}

// Close is a no-op placeholder for symmetry (the peer pool stops with its Start
// context). Present so callers can `defer m.Close()` uniformly.
func (m *Membership) Close() {}

// Mode reports the configured coexistence mode.
func (m *Membership) Mode() Mode { return m.cfg.Mode }

// Fallback reports the owner-mode fallback policy.
func (m *Membership) Fallback() Fallback { return m.cfg.Fallback }

// Region reports the cluster region (the hop-header value).
func (m *Membership) Region() string { return m.cfg.Region }

// Self reports this node's normalized peer URL.
func (m *Membership) Self() string { return m.self }

// PeerOrigin returns the read-through origin (#7) to compose BEFORE the real
// origin in a chain. Never nil.
func (m *Membership) PeerOrigin() origin.Origin { return m.peer }

// Owner returns the base URL of the HEALTHY peer that owns key on the ring, and
// whether one exists. Walks past unhealthy/ejected peers (lb's health-aware ring
// walk), so the result is the node a sharded key currently lives on. Used by #8 to
// decide owner-vs-self.
func (m *Membership) Owner(key string) (string, bool) {
	return m.peers.Owner(key, true)
}

// IntendedOwner returns the ring owner IGNORING health — the topological owner
// even when it is down. Used to detect "the owner is unavailable" so the caller
// can apply the strict-vs-degraded fallback.
func (m *Membership) IntendedOwner(key string) (string, bool) {
	return m.peers.Owner(key, false)
}

// IsSelf reports whether a peer base URL is this node.
func (m *Membership) IsSelf(peerURL string) bool { return peerURL == m.self }

// OwnsKey reports whether THIS node is the (healthy) owner of key. When no healthy
// owner exists it returns false (the caller then applies fallback).
func (m *Membership) OwnsKey(key string) bool {
	owner, ok := m.Owner(key)
	return ok && owner == m.self
}

// IsForwardedHop reports whether an inbound request was already forwarded to us by
// a peer in OUR region (the X-Cadish-Peer loop guard). Such a request must NOT be
// re-forwarded (read-through or owner-route) — it is served locally. A hop stamped
// by a DIFFERENT region is foreign (a separate cluster) and is treated as a fresh
// client request.
func (m *Membership) IsForwardedHop(h http.Header) bool {
	v := h.Get(HopHeader)
	return v != "" && v == m.cfg.Region
}

// PeerCount reports the number of currently-known peer endpoints (post-resolution).
func (m *Membership) PeerCount() int { return len(m.peers.Endpoints()) }
