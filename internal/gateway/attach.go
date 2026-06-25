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
// route's hostnames constrained to the listeners' hostnames (intersection); when the route
// declares no hostnames it inherits the listeners' concrete hostnames. A route with neither
// a concrete hostname nor a concrete listener hostname is rejected (cadish renders one named
// site per host).
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

	listenerHosts := map[string]bool{}
	listenerHasConstraint := false
	for _, l := range attached {
		if l.hostname != "" {
			listenerHosts[l.hostname] = true
			listenerHasConstraint = true
		}
	}

	set := map[string]bool{}
	switch {
	case len(routeHosts) > 0 && listenerHasConstraint:
		for _, h := range routeHosts {
			if hostMatchesAny(h, listenerHosts) {
				set[h] = true
			}
		}
		if len(set) == 0 {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: "no route hostname intersects an attached listener's hostname; route serves nothing"})
		}
	case len(routeHosts) > 0:
		for _, h := range routeHosts {
			set[h] = true
		}
	case listenerHasConstraint:
		for h := range listenerHosts {
			set[h] = true
		}
	default:
		rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
			Reason: "route has no hostname and attaches only to listeners without a hostname; a named site is required"})
	}
	return sortedKeys(set), rejects
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
