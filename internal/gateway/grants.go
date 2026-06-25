package gateway

import (
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// grantIndex answers cross-namespace reference authorization from the watched
// ReferenceGrant set (the Gateway API trust model: a reference INTO a namespace is
// allowed ONLY when a ReferenceGrant in the TARGET namespace permits the FROM
// (group/kind/namespace) → TO (group/kind[/name]). Without a permitting grant a
// cross-namespace backendRef / certificateRef is refused (ResolvedRefs=False,
// RefNotPermitted).
type grantIndex struct {
	// grants[targetNamespace] = the ReferenceGrants defined IN that namespace.
	grants map[string][]*gatewayv1.ReferenceGrant
}

// indexGrants buckets the ReferenceGrants by their own namespace (the TARGET namespace —
// the namespace whose resources may be referenced).
func indexGrants(gs []*gatewayv1.ReferenceGrant) grantIndex {
	idx := grantIndex{grants: map[string][]*gatewayv1.ReferenceGrant{}}
	for _, g := range gs {
		if g == nil {
			continue
		}
		idx.grants[g.Namespace] = append(idx.grants[g.Namespace], g)
	}
	return idx
}

// allows reports whether a reference is permitted: a resource of (fromKind) in fromNS may
// reference (toKind, named toName) in toNS, per a ReferenceGrant IN toNS whose From admits
// (Gateway-API core group, fromKind, fromNS) and whose To admits (core group, toKind) and
// either names toName or names nothing (all of that kind). The core API group is "" for a
// Secret/Service; the Gateway-API group for an HTTPRoute/Gateway.
func (idx grantIndex) allows(toNS, toKind, toName, fromNS, fromKind string) bool {
	for _, g := range idx.grants[toNS] {
		if !grantFromAdmits(g, fromNS, fromKind) {
			continue
		}
		if grantToAdmits(g, toKind, toName) {
			return true
		}
	}
	return false
}

// grantFromAdmits reports whether any From entry admits (fromNS, fromKind). The From
// group for an HTTPRoute/Gateway is the Gateway-API group; per spec From.Group is matched
// explicitly and an empty group means the CORE group "" (NOT a wildcard). Since an
// HTTPRoute/Gateway lives in the Gateway-API group, an empty From.Group does not admit it
// (Fix #10) — only the explicit Gateway-API group does, with kind + namespace matched
// exactly.
func grantFromAdmits(g *gatewayv1.ReferenceGrant, fromNS, fromKind string) bool {
	for _, f := range g.Spec.From {
		if string(f.Namespace) != fromNS {
			continue
		}
		if string(f.Kind) != fromKind {
			continue
		}
		if string(f.Group) != gatewayv1.GroupName {
			continue // HTTPRoute/Gateway are in the gateway-api group; "" is the core group, not a wildcard
		}
		return true
	}
	return false
}

// grantToAdmits reports whether any To entry admits (toKind, toName). A To with no Name
// admits every resource of that kind; a To with a Name admits only that name. The To group
// for a Secret/Service is the core group (""), so an empty/unset group matches.
func grantToAdmits(g *gatewayv1.ReferenceGrant, toKind, toName string) bool {
	for _, t := range g.Spec.To {
		if string(t.Kind) != toKind {
			continue
		}
		if grp := strings.TrimSpace(string(t.Group)); grp != "" {
			continue // a Secret/Service is in the core group
		}
		if t.Name == nil || string(*t.Name) == "" || string(*t.Name) == toName {
			return true
		}
	}
	return false
}
