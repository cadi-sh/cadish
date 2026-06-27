package gateway

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/ingress"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Inputs is the snapshot the translator renders: the GatewayClasses this controller may
// own, the Gateways, the HTTPRoutes, and the ReferenceGrants that authorize cross-namespace
// references. The translator is PURE (deterministic, no I/O): identical inputs render
// byte-identical output, so the controller can skip no-op swaps.
//
// secretUsable / certCovers inject the controller's TLS-Secret validation so the translator
// stays pure and unit-testable (mirroring ingress.TLSPlan):
//   - secretUsable(ns, name) reports whether the kubernetes.io/tls Secret EXISTS and parses
//     into a usable keypair (a present-but-corrupt Secret reports false);
//   - certCovers(ns, name, host) reports whether that Secret's certificate SANs cover host
//     (the F10 SAN-coverage gate).
//
// Both may be nil (TLS off / older tests): then HTTPS listeners are acknowledged but not
// programmed (no BYO cert is registered).
type Inputs struct {
	Classes  []*gatewayv1.GatewayClass
	Gateways []*gatewayv1.Gateway
	Routes   []*gatewayv1.HTTPRoute
	Grants   []*gatewayv1.ReferenceGrant

	secretUsable func(ns, name string) bool
	certCovers   func(ns, name, host string) bool

	// serviceExists reports whether the core Service ns/name EXISTS (GW1). A backendRef to
	// a non-existent Service is BackendNotFound (ResolvedRefs=False). May be nil (older
	// tests / no Service informer): then existence is NOT enforced and a backendRef
	// resolves on its structural checks alone (the pre-fix behavior).
	serviceExists func(ns, name string) bool
}

// Reject records one element (GatewayClass / Gateway / HTTPRoute) that was skipped, with
// a reason. The controller turns rejects into status conditions; serving is unaffected.
type Reject struct {
	Kind   string // "GatewayClass" | "Gateway" | "HTTPRoute"
	Object string // "ns/name" (or "name" for the cluster-scoped GatewayClass)
	Reason string
}

// listenerRejectInvalidHostname is the ListenerRejects reason for a listener whose hostname is
// not a valid DNS name. Shared so the status writer can map it to Accepted=False (Invalid)
// rather than the cert-pending case (Accepted=True, Programmed=False).
const listenerRejectInvalidHostname = "invalid hostname"

// byoClaim identifies a BYO TLS Secret (namespace + name) claimed by an HTTPS listener.
type byoClaim struct{ ns, name string }

// httpListener is an accepted listener on an owned Gateway: a (gateway, section)
// attachment point with an optional hostname constraint. tls marks an HTTPS listener
// programmed for TLS termination (its hostnames carry a BYO cert).
type httpListener struct {
	gateway     string // "ns/name" of the owning Gateway
	gwNamespace string // the owning Gateway's namespace (for AllowedRoutes.Namespaces evaluation)
	section     string // listener Name (the parentRef sectionName, when set)
	hostname    string // listener hostname constraint ("" = match any)
	tls         bool   // an HTTPS listener whose cert was programmed (slice 2)
	// allowedFrom is the listener's AllowedRoutes.Namespaces.From (default Same): which
	// namespaces' routes may attach. allowedKinds is AllowedRoutes.Kinds by Kind name (empty
	// ⇒ the protocol default, i.e. HTTPRoute). Together they are the Gateway-API listener
	// attachment-trust control — without them a Gateway owner cannot restrict attachment.
	allowedFrom  gatewayv1.FromNamespaces
	allowedKinds []string
}

// admitsRoute reports whether a route in routeNS of kind routeKind is allowed to attach to
// this listener per its AllowedRoutes. Namespaces.From: Same/None/Selector restrict to the
// Gateway's own namespace (Selector conservatively degrades to Same — the pure translator has
// no namespace-label lister, so it never OVER-attaches cross-namespace on an unevaluated
// selector); All admits any namespace. Kinds, when set, must include the route kind.
func (l httpListener) admitsRoute(routeNS, routeKind string) bool {
	if len(l.allowedKinds) > 0 {
		ok := false
		for _, k := range l.allowedKinds {
			if k == routeKind {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	switch l.allowedFrom {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromNone:
		return false
	default: // Same, Selector (degraded to Same), and the unset default
		return routeNS == l.gwNamespace
	}
}

// listenerAllowedFrom returns a listener's AllowedRoutes.Namespaces.From, defaulting to Same.
func listenerAllowedFrom(l *gatewayv1.Listener) gatewayv1.FromNamespaces {
	if l.AllowedRoutes != nil && l.AllowedRoutes.Namespaces != nil && l.AllowedRoutes.Namespaces.From != nil {
		return *l.AllowedRoutes.Namespaces.From
	}
	return gatewayv1.NamespacesFromSame
}

// listenerAllowedKinds returns the Kind names in a listener's AllowedRoutes.Kinds (empty ⇒ the
// protocol default). cadish renders HTTPRoutes; a listener that lists only other kinds (e.g.
// TLSRoute) therefore admits no cadish-rendered route.
func listenerAllowedKinds(l *gatewayv1.Listener) []string {
	if l.AllowedRoutes == nil || len(l.AllowedRoutes.Kinds) == 0 {
		return nil
	}
	ks := make([]string, 0, len(l.AllowedRoutes.Kinds))
	for _, k := range l.AllowedRoutes.Kinds {
		ks = append(ks, string(k.Kind))
	}
	return ks
}

// SecretRef is one BYO TLS Secret to load (re-exported shape of ingress.SecretRef so the
// controller injects Gateway and Ingress certs through the SAME Server.SetDynamicCerts).
type SecretRef = ingress.SecretRef

// Result is what the translator produces: the rendered sites, per-element rejects, the
// status bookkeeping, and the BYO TLS Secret refs to inject via Server.SetDynamicCerts.
type Result struct {
	Sites          []ingress.RenderedSite
	Rejects        []Reject
	AttachedRoutes map[string]int
	// AttachedRoutesByListener maps "gwKey\x00listenerName" → the number of routes attached
	// to THAT listener (honoring the listener's hostname / a route's sectionName scoping),
	// used for the per-listener status.attachedRoutes (GW2). The per-Gateway AttachedRoutes
	// total is NOT a correct per-listener count when listeners are hostname-scoped.
	AttachedRoutesByListener map[string]int
	AcceptedRoutes           map[string]bool
	ResolvedRoutes           map[string]bool
	// RefNotPermittedRoutes is the subset of routes whose ResolvedRefs failure was a
	// cross-namespace ref refused for lack of a ReferenceGrant (status reason
	// RefNotPermitted vs the generic BackendNotFound).
	RefNotPermittedRoutes map[string]bool
	// HostOwnedRoutes is the subset of routes rejected because (some of) their hosts'
	// ROUTING is owned by another namespace (Fix #3 cross-ns hijack guard). The status
	// writer reports Accepted=False with reason NotAllowedByListeners for a route that
	// retained no host. (A route that kept at least one host stays Accepted; this set is
	// still recorded for the per-host Event.)
	HostOwnedRoutes map[string]bool
	// ProgrammedGateways is the set of Gateway "ns/name" with at least one programmed
	// listener (an HTTP listener, or an HTTPS listener whose cert was registered).
	ProgrammedGateways map[string]bool
	// ProgrammedListeners maps "gwKey\x00listenerName" → true for each listener that is
	// Programmed (HTTP always; HTTPS only when its BYO cert was registered).
	ProgrammedListeners map[string]bool
	// ListenerRejects maps "gwKey\x00listenerName" → a reason when a listener was NOT
	// programmed (e.g. an HTTPS listener with a missing/mismatched cert), for per-listener
	// status conditions.
	ListenerRejects map[string]string
	// SecretRefs are the BYO TLS Secrets to load (deduped by ns/name, hosts unioned), for
	// the controller's Server.SetDynamicCerts injection — the SAME path Ingress uses.
	SecretRefs []SecretRef
	// TLSHosts is the set of hostnames cadish terminates TLS for (HTTPS listener hosts with
	// a registered cert), so the controller can drive the redirect/Programmed posture.
	TLSHosts []string
}

// Translate emits the concatenated Cadishfile (sites only). Convenience wrapper.
func Translate(in Inputs) (string, []Reject) {
	r := TranslateResult(in)
	var b strings.Builder
	for _, s := range r.Sites {
		b.WriteString(s.Text)
	}
	return b.String(), r.Rejects
}

// TranslateResult is the full translation. SLICE 2 adds, over slice 1: HTTPS/TLS listeners
// with certificateRefs (BYO Secret termination, reusing the Ingress SetDynamicCerts path +
// the F10 SAN gate + host-ownership), advanced HTTPRoute matchers (headers / queryParams /
// method, AND within a match, OR across matches), cross-namespace refs gated by a
// ReferenceGrant, and weighted multi-backend pools. Exotic HTTPRoute filters are surfaced
// with an UnsupportedValue reject rather than silently dropped.
func TranslateResult(in Inputs) Result {
	res := Result{
		AttachedRoutes:           map[string]int{},
		AttachedRoutesByListener: map[string]int{},
		AcceptedRoutes:           map[string]bool{},
		ResolvedRoutes:           map[string]bool{},
		RefNotPermittedRoutes:    map[string]bool{},
		HostOwnedRoutes:          map[string]bool{},
		ProgrammedGateways:       map[string]bool{},
		ProgrammedListeners:      map[string]bool{},
		ListenerRejects:          map[string]string{},
	}

	// 1. Which GatewayClasses do we own?
	ownedClass := map[string]bool{}
	for _, gc := range in.Classes {
		if OwnsClass(gc) {
			ownedClass[gc.Name] = true
		}
	}

	grants := indexGrants(in.Grants)

	// 2. Collect accepted listeners from owned Gateways. HTTP listeners are always
	//    programmed; HTTPS (TLS mode Terminate) listeners are programmed when their
	//    certificateRefs resolve to a usable Secret whose cert covers the listener
	//    hostname (the F10 gate + host-ownership). A registered BYO cert becomes a
	//    SecretRef for Server.SetDynamicCerts.
	secretHosts := map[byoClaim]map[string]bool{} // Secret → hosts it covers
	var secretOrder []byoClaim                    // stable ref order
	tlsHostSet := map[string]bool{}               // hosts cadish terminates TLS for
	listenersByGW := map[string][]httpListener{}  // gateway "ns/name" → its listeners
	listenerHostOwner := map[string]string{}      // host → owning Gateway ns (cross-ns guard)
	// listenerHostOrder records the literal listener hostnames in first-claim (oldest
	// Gateway) order. routingHostOwner walks it to resolve a concrete subdomain to the
	// OLDEST `*.suffix` wildcard listener that admits it, so a wildcard's concrete
	// subdomains share its routing owner (routing+TLS agree under wildcards; Fix B).
	var listenerHostOrder []string

	gateways := append([]*gatewayv1.Gateway(nil), in.Gateways...)
	sort.SliceStable(gateways, func(i, j int) bool {
		ti, tj := gateways[i].CreationTimestamp, gateways[j].CreationTimestamp
		if !ti.Equal(&tj) {
			return ti.Before(&tj)
		}
		return gateways[i].Namespace+"/"+gateways[i].Name < gateways[j].Namespace+"/"+gateways[j].Name
	})

	for _, gw := range gateways {
		gwKey := gw.Namespace + "/" + gw.Name
		if !ownedClass[string(gw.Spec.GatewayClassName)] {
			continue
		}
		var ls []httpListener
		for li := range gw.Spec.Listeners {
			l := &gw.Spec.Listeners[li]
			lkey := gwKey + "\x00" + string(l.Name)
			host := ""
			if l.Hostname != nil {
				host = strings.ToLower(strings.TrimSpace(string(*l.Hostname)))
			}
			if host != "" && !validHost(host) {
				res.Rejects = append(res.Rejects, Reject{Kind: "Gateway", Object: gwKey,
					Reason: fmt.Sprintf("listener %q hostname %q is not a valid DNS hostname; listener ignored", l.Name, host)})
				res.ListenerRejects[lkey] = listenerRejectInvalidHostname
				continue
			}
			allowedFrom := listenerAllowedFrom(l)
			allowedKinds := listenerAllowedKinds(l)
			switch l.Protocol {
			case gatewayv1.HTTPProtocolType:
				ls = append(ls, httpListener{gateway: gwKey, gwNamespace: gw.Namespace, section: string(l.Name), hostname: host, allowedFrom: allowedFrom, allowedKinds: allowedKinds})
				res.ProgrammedListeners[lkey] = true
				claimListenerHost(listenerHostOwner, &listenerHostOrder, host, gw.Namespace)
			case gatewayv1.HTTPSProtocolType:
				programmed, reason, claim := programHTTPSListener(gw, l, host, in, grants, listenerHostOwner, listenerHostOrder)
				if !programmed {
					res.Rejects = append(res.Rejects, Reject{Kind: "Gateway", Object: gwKey, Reason: reason})
					res.ListenerRejects[lkey] = reason
					continue
				}
				ls = append(ls, httpListener{gateway: gwKey, gwNamespace: gw.Namespace, section: string(l.Name), hostname: host, tls: true, allowedFrom: allowedFrom, allowedKinds: allowedKinds})
				res.ProgrammedListeners[lkey] = true
				claimListenerHost(listenerHostOwner, &listenerHostOrder, host, gw.Namespace)
				// Record the BYO cert claim (first-claim wins per host).
				if _, ok := secretHosts[claim]; !ok {
					secretHosts[claim] = map[string]bool{}
					secretOrder = append(secretOrder, claim)
				}
				secretHosts[claim][host] = true
				tlsHostSet[host] = true
			case gatewayv1.TLSProtocolType:
				reason := fmt.Sprintf("listener %q protocol TLS (passthrough/L4) is not supported; only HTTP and HTTPS (Terminate) are served", l.Name)
				res.Rejects = append(res.Rejects, Reject{Kind: "Gateway", Object: gwKey, Reason: reason})
				res.ListenerRejects[lkey] = reason
			default:
				reason := fmt.Sprintf("listener %q protocol %s is unsupported; only HTTP and HTTPS are served", l.Name, l.Protocol)
				res.Rejects = append(res.Rejects, Reject{Kind: "Gateway", Object: gwKey, Reason: reason})
				res.ListenerRejects[lkey] = reason
			}
		}
		if len(ls) > 0 {
			listenersByGW[gwKey] = ls
			res.ProgrammedGateways[gwKey] = true
		}
	}

	// Emit the BYO SecretRefs (deduped, sorted) for Server.SetDynamicCerts.
	sort.Slice(secretOrder, func(i, j int) bool {
		if secretOrder[i].ns != secretOrder[j].ns {
			return secretOrder[i].ns < secretOrder[j].ns
		}
		return secretOrder[i].name < secretOrder[j].name
	})
	for _, c := range secretOrder {
		res.SecretRefs = append(res.SecretRefs, SecretRef{Namespace: c.ns, Name: c.name, Hosts: sortedKeys(secretHosts[c])})
	}
	res.TLSHosts = sortedKeys(tlsHostSet)

	// 3. Attach HTTPRoutes (oldest-first; duplicate (host, signature) won by the older).
	routes := append([]*gatewayv1.HTTPRoute(nil), in.Routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		ti, tj := routes[i].CreationTimestamp, routes[j].CreationTimestamp
		if !ti.Equal(&tj) {
			return ti.Before(&tj)
		}
		return routeKey(routes[i]) < routeKey(routes[j])
	})

	// Cross-namespace ROUTING host-ownership (Fix #3, first-claim lock — mirroring the
	// Ingress controller's D77 routingHostOwners). A host's routing is OWNED by the
	// namespace of the OLDEST Gateway/HTTPRoute that serves it; an HTTPRoute in a DIFFERENT
	// namespace claiming the same hostname is REJECTED for that host and never merged, so a
	// hostile namespace cannot parasitize another namespace's host routing (e.g. add a `/`
	// catch-all to victim.com). The map is seeded from the concrete listener hostnames FIRST
	// (the same listenerHostOwner the TLS-cert guard uses, in the same Gateway creation-time
	// order), so routing and TLS ownership AGREE on the owner per host; then route-derived
	// hosts (wildcard/empty-hostname listeners) are claimed oldest-route-first. Same-namespace
	// routes still merge: a namespace owns its own host.
	routingOwner := routingHostOwner(listenerHostOwner, listenerHostOrder, routes, listenersByGW, grants)

	byHost := map[string][]gwRouteRule{}
	for _, rt := range routes {
		rk := routeKey(rt)

		attached := attachedListeners(rt, listenersByGW, &res.Rejects)
		if len(attached) == 0 {
			continue
		}
		for gwKey := range attachedGateways(attached) {
			res.AttachedRoutes[gwKey]++
		}

		hosts, hostRejects := effectiveHosts(rt, attached)
		res.Rejects = append(res.Rejects, hostRejects...)
		if len(hosts) == 0 {
			continue
		}

		// Per-listener attachedRoutes (GW2): a route counts against a listener only when the
		// listener admits at least one of the route's effective hosts (a hostname-scoped
		// listener attaches only the routes whose hosts it serves; a listener with no hostname
		// admits all). Counted once per distinct listener even if reached via multiple
		// parentRefs. A route with no path/method matches still attached (status-wise), so this
		// is computed before the rule loop — mirroring the per-Gateway AttachedRoutes total.
		for _, lkey := range distinctAttachedListenerKeys(attached, hosts) {
			res.AttachedRoutesByListener[lkey]++
		}

		// Drop the hosts whose routing is owned by ANOTHER namespace (cross-ns hijack
		// guard). A route is Accepted only if it retains at least one host it may serve.
		ownedHosts := hosts[:0:0]
		for _, host := range hosts {
			if ownNs, ok := routingOwner[host]; ok && ownNs != rt.Namespace {
				res.HostOwnedRoutes[rk] = true
				res.Rejects = append(res.Rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("host %q routing is owned by namespace %q (oldest Gateway first-claim); a route for it may only come from that namespace (cross-namespace routing claim rejected)", host, ownNs)})
				continue
			}
			ownedHosts = append(ownedHosts, host)
		}
		hosts = ownedHosts
		if len(hosts) == 0 {
			continue // every host was foreign-owned: route attaches nothing, not Accepted
		}
		res.AcceptedRoutes[rk] = true

		resolvedAll := true
		anyBackend := false
		for ri := range rt.Spec.Rules {
			rule := &rt.Spec.Rules[ri]

			// Filters: support RequestHeaderModifier + RequestRedirect cheaply; an exotic
			// filter is surfaced (UnsupportedValue) rather than silently dropped.
			filterConds, filterRejects := collectFilterRejects(rt, ri, rule)
			res.Rejects = append(res.Rejects, filterRejects...)
			_ = filterConds // (request-header filters fold into directives in a later pass)

			backends, bok, brejects := resolveBackends(rt, ri, rule, grants, in.serviceExists)
			res.Rejects = append(res.Rejects, brejects...)
			for _, br := range brejects {
				if strings.Contains(br.Reason, "RefNotPermitted") {
					res.RefNotPermittedRoutes[rk] = true
				}
			}
			if !bok {
				resolvedAll = false
				continue
			}
			anyBackend = true

			matches, mrejects := ruleMatches(rt, ri, rule)
			res.Rejects = append(res.Rejects, mrejects...)
			if len(matches) == 0 {
				continue
			}
			for _, host := range hosts {
				byHost[host] = append(byHost[host], gwRouteRule{matches: matches, backends: backends, owner: rk})
			}
		}
		if anyBackend && resolvedAll {
			res.ResolvedRoutes[rk] = true
		}
	}

	sites, structuralRejects := renderGatewaySites(byHost)
	res.Sites = sites
	res.Rejects = append(res.Rejects, structuralRejects...)
	return res
}

// routingHostOwner maps each effective hostname to the namespace that OWNS its routing,
// mirroring the Ingress controller's D77 routingHostOwners first-claim lock. It seeds from
// the concrete listener hostnames FIRST (listenerHostOwner — the SAME map and Gateway
// creation-time order the TLS-cert guard uses), so a host with a concrete listener has the
// same owner for routing and TLS. Then route-derived effective hosts (served via a wildcard
// or empty-hostname listener, where listenerHostOwner has no concrete entry) are claimed by
// the oldest HTTPRoute that serves them — UNLESS the host is a CONCRETE subdomain admitted by
// a `*.suffix` wildcard listener, in which case the WILDCARD listener's namespace owns its
// routing too (so a concrete subdomain like app.example.com routes to the same namespace that
// terminates the `*.example.com` TLS, keeping routing and TLS ownership in agreement under
// wildcards; without this a foreign namespace's older route could win a concrete subdomain of
// another namespace's wildcard). listenerHostOrder lists the literal listener hostnames in
// first-claim (oldest) order so the OLDEST matching wildcard wins deterministically. routes
// MUST already be sorted oldest-first.
func routingHostOwner(listenerHostOwner map[string]string, listenerHostOrder []string, routes []*gatewayv1.HTTPRoute, listenersByGW map[string][]httpListener, grants grantIndex) map[string]string {
	owner := make(map[string]string, len(listenerHostOwner))
	// Pass 1: concrete listener hostnames (routing+TLS agree on these).
	for h, ns := range listenerHostOwner {
		owner[h] = ns
	}
	// Pass 2: route-derived effective hosts not already owned by a listener hostname.
	var scratch []Reject // discarded: attach rejects are recorded in the main loop
	for _, rt := range routes {
		attached := attachedListeners(rt, listenersByGW, &scratch)
		if len(attached) == 0 {
			continue
		}
		hosts, _ := effectiveHosts(rt, attached)
		for _, h := range hosts {
			if _, ok := owner[h]; ok {
				continue
			}
			// A concrete subdomain admitted by a `*.suffix` wildcard listener inherits the
			// wildcard listener's owner (routing+TLS agree under wildcards), not the route's
			// namespace. The literal wildcard string itself (h == "*.suffix") is already in
			// the seed map, so this only fires for a CONCRETE host. The oldest matching
			// wildcard wins (listenerHostOrder is oldest-first).
			if ns, ok := wildcardListenerOwner(h, listenerHostOrder, listenerHostOwner); ok {
				owner[h] = ns
				continue
			}
			owner[h] = rt.Namespace
		}
	}
	// Pass 3: a CONCRETE listener hostname seeded in Pass 1 that falls under an OLDER
	// `*.suffix` wildcard listener in a DIFFERENT namespace is reassigned to the wildcard's
	// owner. Pass 2 only resolves route-derived hosts (a concrete listener host is already
	// owned, so it would otherwise bypass the wildcard check) — closing the gap where a
	// tenant's concrete listener for app.example.com captures routing for a subdomain of
	// another namespace's older wildcard. Strict oldest-wins: only an OLDER wildcard
	// (strictly lower first-claim rank) wins, so a younger foreign wildcard cannot steal an
	// already-established concrete listener host. The literal wildcard itself is skipped.
	if len(listenerHostOrder) > 0 {
		rank := make(map[string]int, len(listenerHostOrder))
		for i, h := range listenerHostOrder {
			rank[h] = i
		}
		for h, ns := range owner {
			if strings.HasPrefix(h, "*.") {
				continue
			}
			hr, isListener := rank[h]
			if !isListener {
				continue // route-derived hosts are resolved in Pass 2
			}
			if w, ok := oldestCoveringWildcard(h, listenerHostOrder); ok {
				if wns := listenerHostOwner[w]; wns != ns && rank[w] < hr {
					owner[h] = wns
				}
			}
		}
	}
	return owner
}

// oldestCoveringWildcard returns the literal of the OLDEST `*.suffix` wildcard listener that
// admits the concrete host (listenerHostOrder is oldest-first, so the first match is oldest).
func oldestCoveringWildcard(host string, listenerHostOrder []string) (string, bool) {
	for _, lh := range listenerHostOrder {
		if !strings.HasPrefix(lh, "*.") {
			continue
		}
		suffix := lh[1:]
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return lh, true
		}
	}
	return "", false
}

// wildcardListenerOwner returns the namespace of the OLDEST `*.suffix` wildcard listener that
// admits the concrete host, reusing the same suffix-match semantics as hostMatchesAny.
// listenerHostOrder is the literal listener hostnames in first-claim (oldest Gateway) order;
// listenerHostOwner maps each literal to its owning namespace.
func wildcardListenerOwner(host string, listenerHostOrder []string, listenerHostOwner map[string]string) (string, bool) {
	for _, lh := range listenerHostOrder {
		if !strings.HasPrefix(lh, "*.") {
			continue
		}
		suffix := lh[1:] // ".example.com"
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			return listenerHostOwner[lh], true
		}
	}
	return "", false
}

// claimListenerHost records the first Gateway namespace that owns a listener hostname (the
// cross-namespace cert-hijack guard: a later Gateway in a different namespace must not
// register a cert for a hostname an earlier one already terminates). order, when non-nil,
// accumulates each newly-claimed literal host in claim order (oldest first) so a later pass
// can resolve concrete subdomains to the oldest matching wildcard deterministically.
func claimListenerHost(owner map[string]string, order *[]string, host, ns string) {
	if host == "" {
		return
	}
	if _, ok := owner[host]; !ok {
		owner[host] = ns
		if order != nil {
			*order = append(*order, host)
		}
	}
}

// programHTTPSListener decides whether an HTTPS listener can be TLS-programmed: TLS mode
// must be Terminate, exactly the BYO Secret path is supported (certificateRefs → a
// kubernetes.io/tls Secret), the Secret must be usable, its cert must cover the listener
// hostname (F10), a cross-namespace certificateRef needs a ReferenceGrant, and the listener
// hostname must not already be owned by another namespace. Returns (programmed, reason,
// claim).
func programHTTPSListener(gw *gatewayv1.Gateway, l *gatewayv1.Listener, host string, in Inputs, grants grantIndex, hostOwner map[string]string, hostOrder []string) (bool, string, byoClaim) {
	var none byoClaim
	if host == "" {
		return false, fmt.Sprintf("HTTPS listener %q has no hostname; a terminating listener needs a concrete hostname for its certificate", l.Name), none
	}
	if l.TLS == nil {
		return false, fmt.Sprintf("HTTPS listener %q has no tls config", l.Name), none
	}
	if l.TLS.Mode != nil && *l.TLS.Mode != gatewayv1.TLSModeTerminate {
		return false, fmt.Sprintf("HTTPS listener %q TLS mode %q is unsupported; only Terminate is served", l.Name, *l.TLS.Mode), none
	}
	if len(l.TLS.CertificateRefs) == 0 {
		// No BYO Secret. ACME for a Gateway listener is deferred (documented in D82): a
		// terminating listener must reference a kubernetes.io/tls Secret in this slice.
		return false, fmt.Sprintf("HTTPS listener %q has no certificateRefs; BYO-Secret termination is required (ACME for a Gateway listener is deferred — see docs/gateway-api.md)", l.Name), none
	}
	if in.secretUsable == nil {
		return false, fmt.Sprintf("HTTPS listener %q: TLS Secret injection is not available in this mode", l.Name), none
	}
	// Cross-namespace cert-hijack guard: the listener hostname must not be owned by another
	// namespace's listener already.
	if ownNs, ok := hostOwner[host]; ok && ownNs != gw.Namespace {
		return false, fmt.Sprintf("HTTPS listener %q hostname %q is already terminated by namespace %q; refusing a cross-namespace cert claim", l.Name, host, ownNs), none
	}
	// Wildcard-cover variant of the same guard: a CONCRETE hostname that falls under an
	// OLDER `*.suffix` wildcard listener owned by another namespace must also be refused —
	// an exact-host cert wins over a wildcard at serving time, so without this a tenant could
	// program a (self-signed) cert for app.example.com and hijack TLS for a concrete
	// subdomain of another namespace's wildcard. Listeners are processed oldest-first, so any
	// wildcard already in hostOwner is necessarily older; wildcardListenerOwner returns the
	// OLDEST covering wildcard's namespace. A same-namespace covering wildcard (the tenant's
	// own) is allowed.
	if !strings.HasPrefix(host, "*.") {
		if wns, ok := wildcardListenerOwner(host, hostOrder, hostOwner); ok && wns != gw.Namespace {
			return false, fmt.Sprintf("HTTPS listener %q hostname %q falls under a wildcard listener owned by namespace %q; refusing a cross-namespace cert claim", l.Name, host, wns), none
		}
	}
	ref := l.TLS.CertificateRefs[0]
	if ref.Group != nil && *ref.Group != "" {
		return false, fmt.Sprintf("HTTPS listener %q certificateRef group %q is unsupported; only core Secrets are supported", l.Name, *ref.Group), none
	}
	if ref.Kind != nil && *ref.Kind != "Secret" {
		return false, fmt.Sprintf("HTTPS listener %q certificateRef kind %q is unsupported; only Secret is supported", l.Name, *ref.Kind), none
	}
	secNS := gw.Namespace
	if ref.Namespace != nil && string(*ref.Namespace) != "" && string(*ref.Namespace) != gw.Namespace {
		secNS = string(*ref.Namespace)
		// Cross-namespace certificateRef requires a ReferenceGrant in the Secret's namespace
		// permitting Gateway → Secret.
		if !grants.allows(secNS, "Secret", string(ref.Name), gw.Namespace, "Gateway") {
			return false, fmt.Sprintf("HTTPS listener %q certificateRef to Secret %s/%s is cross-namespace and not permitted by a ReferenceGrant (ResolvedRefs=False, RefNotPermitted)", l.Name, secNS, ref.Name), none
		}
	}
	if !in.secretUsable(secNS, string(ref.Name)) {
		return false, fmt.Sprintf("HTTPS listener %q certificateRef Secret %s/%s is missing or not a usable kubernetes.io/tls keypair", l.Name, secNS, ref.Name), none
	}
	if in.certCovers != nil && !in.certCovers(secNS, string(ref.Name), host) {
		return false, fmt.Sprintf("HTTPS listener %q: Secret %s/%s's certificate does not cover hostname %q (SAN mismatch); refusing to serve a mismatched cert", l.Name, secNS, ref.Name, host), none
	}
	return true, "", byoClaim{ns: secNS, name: string(ref.Name)}
}

// routeKey is the HTTPRoute identity "ns/name".
func routeKey(rt *gatewayv1.HTTPRoute) string { return rt.Namespace + "/" + rt.Name }

// normalizePath trims whitespace and a single trailing slash (keeping root "/").
func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p
}

// sortedKeys returns the sorted keys of a string set (nil-safe).
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validHost reports whether host is a syntactically valid DNS hostname (optionally one
// "*." wildcard prefix). Lowercased/trimmed input assumed.
func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
		if host == "" {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

// validDNSLabel reports whether s is a single DNS-1123 label.
func validDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
