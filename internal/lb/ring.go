package lb

import (
	"crypto/md5"
	"encoding/binary"
	"sort"
	"strconv"
)

// defaultReplicas is the per-backend virtual-node count on the consistent-hash
// ring. More replicas ⇒ smoother key distribution and smaller reshuffle on
// membership change, at a small memory/lookup cost. 160 (Ketama's default) keeps
// the per-backend share within a tight band even for small pools. Points are
// derived 4-at-a-time from an MD5 digest, so the value is rounded up to a
// multiple of 4.
const defaultReplicas = 160

// maxReplicas bounds the configurable per-backend virtual-node count. The ring
// allocates O(backends * replicas) hash points; without a cap a typo like
// "replicas 2000000000" would try to allocate gigabytes and wedge startup.
// 1,000,000 is orders of magnitude above any distribution-smoothing need.
const maxReplicas = 1_000_000

// ringHash maps an arbitrary key into the 32-bit ring space, using the low 4
// bytes of its MD5 digest. MD5 (not a security use here — just a well-spread,
// stdlib, dependency-free mixer) distributes similar inputs far more evenly than
// a linear checksum like CRC32.
func ringHash(key string) uint32 {
	sum := md5.Sum([]byte(key))
	return binary.LittleEndian.Uint32(sum[0:4])
}

// ring is a consistent-hash ring with virtual nodes. Each backend id is placed
// at `replicas` points around a 32-bit hash space; a key is owned by the first
// backend clockwise from the key's hash. Adding or removing a backend only
// reshuffles the keys that fall in that backend's arcs (≈ 1/N of all keys),
// never the whole keyspace — the property the sticky/shard policies rely on.
//
// A ring is immutable once built; membership changes (re-resolution) build a new
// ring. Lookups are read-only and safe for concurrent use.
type ring struct {
	replicas int
	points   []uint32          // sorted virtual-node hashes
	owner    map[uint32]string // point hash -> backend id
	ids      []string          // distinct backend ids, in insertion order
}

// newRing builds a ring over ids with the given replica count (<=0 ⇒
// defaultReplicas). Duplicate ids are de-duplicated. The result is deterministic
// for a given (ids, replicas).
func newRing(replicas int, ids []string) *ring {
	if replicas <= 0 {
		replicas = defaultReplicas
	}
	rounds := (replicas + 3) / 4 // 4 points harvested per MD5 digest
	r := &ring{replicas: rounds * 4, owner: make(map[uint32]string)}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		r.ids = append(r.ids, id)
		for i := 0; i < rounds; i++ {
			sum := md5.Sum([]byte(strconv.Itoa(i) + "-" + id))
			for j := 0; j < 4; j++ {
				h := binary.LittleEndian.Uint32(sum[j*4 : j*4+4])
				// On the rare collision, nudge deterministically until free so every
				// virtual node lands somewhere (collisions would otherwise silently
				// drop a node's weight).
				for {
					if _, taken := r.owner[h]; !taken {
						break
					}
					h++
				}
				r.owner[h] = id
				r.points = append(r.points, h)
			}
		}
	}
	sort.Slice(r.points, func(i, j int) bool { return r.points[i] < r.points[j] })
	return r
}

// len reports the number of distinct backends on the ring.
func (r *ring) len() int { return len(r.ids) }

// lookup returns the backend id that owns key, walking clockwise past any
// backend rejected by eligible (nil ⇒ all eligible) until an eligible backend is
// found. ok is false when the ring is empty or no backend is eligible. Walking —
// rather than rebuilding the ring without the dead nodes — is what makes a dead
// backend's keys rehash to the NEXT backend while every other key stays put.
func (r *ring) lookup(key string, eligible func(id string) bool) (string, bool) {
	if len(r.points) == 0 {
		return "", false
	}
	h := ringHash(key)
	idx := sort.Search(len(r.points), func(i int) bool { return r.points[i] >= h })
	if idx == len(r.points) {
		idx = 0
	}
	// Track distinct backend ids already considered so each backend's eligibility
	// is checked at most once and the walk terminates once all backends are seen.
	// Backed by a fixed stack array (pools are small) and a linear scan, so the
	// common lookup is allocation-free — the previous map[string]bool cost ~3 heap
	// allocs once the pool grew past the compiler's small-map threshold. A larger
	// pool may spill the slice to the heap (one alloc), still cheaper than a map,
	// and never on the common first-hit path.
	var stack [ringSeenStack]string
	seen := stack[:0]
	n := len(r.points)
	total := len(r.ids)
	for i := 0; i < n && len(seen) < total; i++ {
		id := r.owner[r.points[(idx+i)%n]]
		if containsString(seen, id) {
			continue
		}
		seen = append(seen, id)
		if eligible == nil || eligible(id) {
			return id, true
		}
	}
	return "", false
}

// ringSeenStack sizes the stack-backed "already considered" set used by lookup.
// It covers realistic pool sizes (≤64 backends) without a heap allocation; a
// larger pool simply grows the slice on the heap.
const ringSeenStack = 64

// containsString reports whether ss contains s (linear scan; ss is tiny).
func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
