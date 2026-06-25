package lb

import "github.com/cadi-sh/cadish/internal/cadishfile"

// ParseTarget parses one `to`-style backend token (http://, https://, dns://,
// k8s://, or a bare host:port ⇒ http) into a Target, with a positioned error on
// a bad token. Exported so the cluster layer (internal/cluster) reuses the exact
// same target syntax + validation as upstream pools, rather than reinventing it.
func ParseTarget(tok string, pos cadishfile.Pos) (Target, error) {
	return parseTarget(tok, pos)
}

// ParseHealthSpec parses a `health METHOD PATH expect CODE interval D window N
// threshold T` directive into a HealthSpec. Exported so the cluster layer reuses
// the same active-health probe configuration as upstream pools.
func ParseHealthSpec(d *cadishfile.Directive) (*HealthSpec, error) {
	return parseHealth(d)
}

// Ring is an exported, immutable consistent-hash ring over a set of string ids.
// It wraps the same Ketama-style ring the sticky/shard policies use internally,
// so cluster ownership routing (internal/cluster) hashes a cache key onto the
// SAME ring topology as upstream sharding — one well-tested implementation, no
// reinvention. A Ring is safe for concurrent Lookup; membership changes build a
// new Ring (NewRing).
type Ring struct{ r *ring }

// NewRing builds a Ring placing each id at `replicas` virtual nodes (<=0 ⇒ the
// package default, 160). Duplicate ids are de-duplicated; the result is
// deterministic for a given (ids, replicas).
func NewRing(replicas int, ids []string) *Ring {
	return &Ring{r: newRing(replicas, ids)}
}

// Lookup returns the id that owns key, walking clockwise past any id rejected by
// eligible (nil ⇒ all eligible) until an eligible id is found. ok is false when
// the ring is empty or no id is eligible. Walking past ineligible owners — rather
// than rebuilding the ring — is what makes a dead node's keys rehash only to the
// next node while every other key stays put.
func (r *Ring) Lookup(key string, eligible func(id string) bool) (string, bool) {
	if r == nil || r.r == nil {
		return "", false
	}
	return r.r.lookup(key, eligible)
}

// Len reports the number of distinct ids on the ring.
func (r *Ring) Len() int {
	if r == nil || r.r == nil {
		return 0
	}
	return r.r.len()
}
