package ingress

// Per-tenant (per-namespace) resource caps (B1, hostile-multi-tenant hardening).
//
// A noisy or hostile tenant (namespace) can blow up render/compile cost by declaring a
// huge number of hosts or paths, or by attaching an enormous cadi.sh/policy fragment.
// These OPERATOR-CONFIGURED, OFF-BY-DEFAULT caps bound each namespace's footprint:
//
//   - MaxSitesPerNamespace  — max distinct hosts (sites) a namespace may render.
//   - MaxRoutesPerNamespace — max routes (path rules) a namespace may render.
//   - MaxFragmentBytes      — max size (bytes) of a cadi.sh/policy fragment.
//
// When a namespace exceeds a cap the EXCESS is rejected DETERMINISTICALLY — oldest-wins,
// reusing the same creationTimestamp-then-ns/name ordering routing host-ownership uses,
// so the earlier (already-serving) sites/routes keep rendering and only the newest
// over-the-line ones are dropped, each with a per-Ingress warning Event. OTHER tenants
// are never affected. Every cap defaults to 0 = unlimited = unchanged behaviour.

import "fmt"

// ResourceCaps holds the operator-configured per-namespace resource caps. The zero value
// (every field 0) disables all caps, so the controller behaves exactly as before. Caps
// are evaluated per namespace, oldest-Ingress-first, so the excess (not the earlier
// claims) is what gets rejected.
type ResourceCaps struct {
	// MaxSitesPerNamespace bounds the number of distinct hosts (sites) a single
	// namespace may render. 0 = unlimited.
	MaxSitesPerNamespace int
	// MaxRoutesPerNamespace bounds the number of routes (accepted path rules) a single
	// namespace may render. 0 = unlimited.
	MaxRoutesPerNamespace int
	// MaxFragmentBytes bounds the size in bytes of a single cadi.sh/policy fragment. An
	// over-size fragment is rejected (with an Event) BEFORE it is validated/compiled.
	// 0 = unlimited.
	MaxFragmentBytes int
}

// capCounter tracks a namespace's running site/route counts for cap enforcement during a
// single TranslateSites pass. Hosts already admitted for the namespace are remembered so
// re-encountering an admitted host (a second path / a second Ingress on the same host)
// does not re-charge the site budget.
type capCounter struct {
	caps     ResourceCaps
	sites    map[string]int             // namespace -> admitted distinct-host count
	routes   map[string]int             // namespace -> admitted route count
	hostSeen map[string]map[string]bool // namespace -> set of hosts already admitted
}

func newCapCounter(caps ResourceCaps) *capCounter {
	return &capCounter{
		caps:     caps,
		sites:    map[string]int{},
		routes:   map[string]int{},
		hostSeen: map[string]map[string]bool{},
	}
}

// admitHost reports whether namespace ns may render host without exceeding the site cap.
// An already-admitted host is always allowed (it does not charge the budget again); a
// NEW host is allowed only while the namespace is under MaxSitesPerNamespace, and on
// admission charges one site. reason is non-empty when the host is rejected.
func (cc *capCounter) admitHost(ns, host string) (ok bool, reason string) {
	if cc == nil || cc.caps.MaxSitesPerNamespace <= 0 {
		return true, ""
	}
	seen := cc.hostSeen[ns]
	if seen != nil && seen[host] {
		return true, "" // already admitted; not a new site
	}
	if cc.sites[ns] >= cc.caps.MaxSitesPerNamespace {
		return false, fmt.Sprintf("namespace %q exceeds the per-namespace site cap of %d (host %q rejected; oldest-wins keeps the earlier sites)",
			ns, cc.caps.MaxSitesPerNamespace, host)
	}
	if seen == nil {
		seen = map[string]bool{}
		cc.hostSeen[ns] = seen
	}
	seen[host] = true
	cc.sites[ns]++
	return true, ""
}

// admitRoute reports whether namespace ns may render one more route without exceeding
// the route cap, charging one route on admission. reason is non-empty on rejection.
func (cc *capCounter) admitRoute(ns, host, path string) (ok bool, reason string) {
	if cc == nil || cc.caps.MaxRoutesPerNamespace <= 0 {
		return true, ""
	}
	if cc.routes[ns] >= cc.caps.MaxRoutesPerNamespace {
		return false, fmt.Sprintf("namespace %q exceeds the per-namespace route cap of %d (route %q on host %q rejected; oldest-wins keeps the earlier routes)",
			ns, cc.caps.MaxRoutesPerNamespace, path, host)
	}
	cc.routes[ns]++
	return true, ""
}
