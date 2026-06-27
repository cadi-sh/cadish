package gateway

import (
	"fmt"
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// attachedListeners returns the owned listeners this route attaches to via its parentRefs.
// A parentRef naming one of our Gateways attaches to that Gateway's listeners (or just the
// named sectionName) ONLY when the listener's AllowedRoutes admit the route — the Gateway-API
// listener attachment-trust control: AllowedRoutes.Namespaces.From (Same default / All / None;
// Selector conservatively degraded to Same) and AllowedRoutes.Kinds (cadish renders HTTPRoute).
// Cross-namespace attachment is therefore the Gateway owner's explicit decision (From: All),
// NOT a ReferenceGrant (which governs backendRef/Secret, not route→Gateway attachment). A
// parentRef that matches one of our Gateways but is admitted by no listener is rejected
// NotAllowedByListeners.
func attachedListeners(rt *gatewayv1.HTTPRoute, listenersByGW map[string][]httpListener, rejects *[]Reject) []httpListener {
	var out []httpListener
	rk := routeKey(rt)
	for pi := range rt.Spec.ParentRefs {
		pr := &rt.Spec.ParentRefs[pi]
		if pr.Group != nil && *pr.Group != "" && *pr.Group != gatewayv1.GroupName {
			continue
		}
		if pr.Kind != nil && *pr.Kind != "Gateway" {
			continue
		}
		ns := rt.Namespace
		if pr.Namespace != nil && string(*pr.Namespace) != "" {
			ns = string(*pr.Namespace)
		}
		gwKey := ns + "/" + string(pr.Name)
		ls, ok := listenersByGW[gwKey]
		if !ok {
			continue
		}
		section := ""
		if pr.SectionName != nil {
			section = string(*pr.SectionName)
		}
		matchedListener, admitted := false, false
		for _, l := range ls {
			if section != "" && l.section != section {
				continue
			}
			matchedListener = true
			if !l.admitsRoute(rt.Namespace, "HTTPRoute") {
				continue // AllowedRoutes (From/Kinds) refuses this route on this listener
			}
			admitted = true
			out = append(out, l)
		}
		// The parentRef named a real listener of ours, but its AllowedRoutes admitted none.
		if matchedListener && !admitted {
			*rejects = append(*rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: fmt.Sprintf("Gateway %s/%s does not allow this route to attach (NotAllowedByListeners): check the listener's allowedRoutes (namespaces.from / kinds)", ns, pr.Name)})
		}
	}
	return out
}

// distinctAttachedListenerKeys returns the deduped per-listener status keys
// ("gateway\x00section") for the listeners that admit at least one of the route's effective
// hosts. A listener with no hostname constraint admits any host; a hostname-scoped listener
// admits only a host its hostname covers (honoring a "*.suffix" wildcard). The section is the
// listener Name (the lkey the status writer uses). Used for per-listener attachedRoutes (GW2).
func distinctAttachedListenerKeys(ls []httpListener, hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range ls {
		if l.hostname != "" && !listenerAdmitsAnyHost(l.hostname, hosts) {
			continue
		}
		key := l.gateway + "\x00" + l.section
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

// listenerAdmitsAnyHost reports whether the listener hostname admits at least one of hosts,
// honoring a "*.suffix" wildcard listener hostname (the same semantics as hostMatchesAny).
func listenerAdmitsAnyHost(listenerHost string, hosts []string) bool {
	lset := map[string]bool{listenerHost: true}
	for _, h := range hosts {
		if hostMatchesAny(h, lset) {
			return true
		}
	}
	return false
}

// attachedGateways returns the set of Gateway "ns/name" among the attached listeners.
func attachedGateways(ls []httpListener) map[string]bool {
	out := map[string]bool{}
	for _, l := range ls {
		out[l.gateway] = true
	}
	return out
}

// effectiveHosts computes the site hostnames for a route given its attached listeners: the
// route's hostnames intersected with the listeners' hostnames (the UNION over listeners of
// each per-listener intersection); when the route declares no hostnames it inherits the
// listeners' concrete hostnames. The intersection follows Gateway API semantics — an
// unconstrained (empty-hostname) listener admits any route host as-is, a wildcard listener
// admits a covered concrete route host (and vice versa: a wildcard ROUTE host is admitted by
// a covered concrete LISTENER host), with the more-specific name winning. A route with
// neither a concrete hostname nor a concrete listener hostname is rejected (cadish renders
// one named site per host).
func effectiveHosts(rt *gatewayv1.HTTPRoute, attached []httpListener) ([]string, []Reject) {
	rk := routeKey(rt)
	var rejects []Reject

	var routeHosts []string
	for _, h := range rt.Spec.Hostnames {
		host := strings.ToLower(strings.TrimSpace(string(h)))
		if host == "" {
			continue
		}
		if !validHost(host) {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: fmt.Sprintf("hostname %q is not a valid DNS hostname; ignored", host)})
			continue
		}
		routeHosts = append(routeHosts, host)
	}

	// Partition the attached listeners: an unconstrained (empty-hostname) listener admits any
	// host; the rest carry a hostname the route host must intersect.
	var listenerHosts []string
	hasUnconstrained := false
	for _, l := range attached {
		if l.hostname == "" {
			hasUnconstrained = true
		} else {
			listenerHosts = append(listenerHosts, l.hostname)
		}
	}

	set := map[string]bool{}
	switch {
	case len(routeHosts) > 0:
		// Per-listener intersection, unioned. An unconstrained listener admits each route host
		// as itself (incl. a wildcard route host, which becomes a wildcard site); constrained
		// listeners contribute the more-specific intersection name (so a wildcard route host
		// meeting a concrete listener serves the concrete host, and vice versa).
		for _, rh := range routeHosts {
			if hasUnconstrained {
				set[rh] = true
				continue
			}
			for _, lh := range listenerHosts {
				if eff, ok := intersectHost(rh, lh); ok {
					set[eff] = true
				}
			}
		}
		if len(set) == 0 {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: "no route hostname intersects an attached listener's hostname; route serves nothing"})
		}
	case len(listenerHosts) > 0:
		// Route declares no hostnames: inherit the listeners' concrete hostnames.
		for _, lh := range listenerHosts {
			set[lh] = true
		}
	default:
		rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
			Reason: "route has no hostname and attaches only to listeners without a hostname; a named site is required"})
	}
	return sortedKeys(set), rejects
}

// intersectHost returns the effective hostname for one route host meeting one (non-empty)
// listener host per Gateway API hostname intersection, and whether they intersect at all.
// Equal names intersect to themselves; when exactly one side is a "*.suffix" wildcard that
// covers the other, the concrete (more-specific) side wins; two wildcards intersect to the
// more-specific of the two when one covers the other. Wildcard coverage reuses the same
// suffix semantics as hostMatchesAny.
func intersectHost(routeHost, listenerHost string) (string, bool) {
	if routeHost == listenerHost {
		return routeHost, true
	}
	rWild := strings.HasPrefix(routeHost, "*.")
	lWild := strings.HasPrefix(listenerHost, "*.")
	switch {
	case lWild && !rWild:
		if wildcardCovers(listenerHost, routeHost) {
			return routeHost, true // concrete route host is more specific
		}
	case rWild && !lWild:
		if wildcardCovers(routeHost, listenerHost) {
			return listenerHost, true // concrete listener host is more specific
		}
	case rWild && lWild:
		// Both wildcards: the one whose base falls under the other's suffix is more specific.
		if wildcardCovers(listenerHost, routeHost[2:]) {
			return routeHost, true
		}
		if wildcardCovers(routeHost, listenerHost[2:]) {
			return listenerHost, true
		}
	}
	return "", false
}

// wildcardCovers reports whether the "*.suffix" wildcard admits name (a concrete host, or a
// more-specific name under the same suffix) — the same suffix match hostMatchesAny uses.
func wildcardCovers(wild, name string) bool {
	suffix := wild[1:] // ".suffix"
	return strings.HasSuffix(name, suffix) && len(name) > len(suffix)
}

// hostMatchesAny reports whether host is admitted by the listener hostname set, honoring a
// "*.suffix" wildcard listener hostname (a suffix match) per Gateway API semantics.
func hostMatchesAny(host string, listenerHosts map[string]bool) bool {
	if listenerHosts[host] {
		return true
	}
	for lh := range listenerHosts {
		if strings.HasPrefix(lh, "*.") {
			suffix := lh[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return false
}
