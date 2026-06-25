package ingress

import (
	networkingv1 "k8s.io/api/networking/v1"
)

// This file exports a SMALL, neutral rendering seam so a SECOND controller (the Gateway
// API controller, internal/gateway) can emit the SAME Cadishfile + RenderedSite model the
// Ingress translator produces — WITHOUT duplicating the rendering rules (upstream dedup,
// Exact-before-Prefix specificity ordering, the element-wise PathPrefix matcher, the F7
// terminal no-match 404, and the security posture in writeSite/renderSites). The Ingress
// translator keeps OWNING those rules; the Gateway translator maps its own Kubernetes
// types onto RenderRoute and calls RenderHTTPSites. Because RenderHTTPSites funnels into
// the exact same renderSites/writeSite path the Ingress translator uses, the Ingress
// controller's behaviour and tests stay byte-identical.
//
// SLICE 1 scope: only HTTP routing (host + path → Service backend) is exposed here.
// Policy fragments, spec.defaultBackend fan-out, and ACME `tls` directives remain
// Ingress-only (the Gateway slice-2 work — certificateRefs/HTTPS — will extend this seam).

// PathKind is the neutral path-match kind shared by both controllers. It maps onto the
// same Cadishfile matcher semantics regardless of which API surface produced it:
//   - PathExact  → matches ONLY the exact path (Ingress Exact, Gateway Exact);
//   - PathPrefix → element-wise prefix: "/api" matches "/api" and "/api/…" but NOT
//     "/apiother" (Ingress Prefix, Gateway PathPrefix). This is the Kubernetes Prefix
//     semantics both APIs require.
type PathKind int

const (
	// PathPrefix is the element-wise prefix match (the default).
	PathPrefix PathKind = iota
	// PathExact matches only the exact path.
	PathExact
)

// RenderRoute is one (host, path) → Service backend mapping, in neutral terms. The
// Gateway translator builds a slice of these and hands them to RenderHTTPSites; the
// Ingress translator continues to use its richer internal routeEntry directly.
type RenderRoute struct {
	// Host is the lowercased site hostname.
	Host string
	// Path is the normalized request path ("/" for a catch-all). An empty Path marks a
	// host-only entry (the host still becomes a site, with no route).
	Path string
	// Kind is the path-match kind (Prefix or Exact).
	Kind PathKind
	// Namespace/Service/Port name the k8s:// backend (resolved by Layer 1 at apply).
	Namespace string
	Service   string
	Port      string
}

// toRouteEntry maps a neutral RenderRoute onto the Ingress translator's internal
// routeEntry so it flows through the EXACT same rendering path (specRank, pathMatcherArgs,
// isCatchAll, the F7 terminal 404). policy is left empty: policy fragments are Ingress-only
// in slice 1.
func (r RenderRoute) toRouteEntry() routeEntry {
	pt := networkingv1.PathTypePrefix
	if r.Kind == PathExact {
		pt = networkingv1.PathTypeExact
	}
	return routeEntry{
		host:     r.Host,
		path:     r.Path,
		pathType: pt,
		ns:       r.Namespace,
		svc:      r.Service,
		port:     r.Port,
	}
}

// RenderHTTPSites renders the given neutral routes into the same RenderedSite model
// (one `host { … }` block per host) the Ingress translator produces. It reuses
// renderSites/writeSite, so the output carries the identical upstream dedup, specificity
// ordering, element-wise PathPrefix matchers, and the F7 terminal no-match 404 — a
// Gateway-rendered site 404s on an unmatched path exactly like an Ingress-rendered one
// (it never falls through to the first upstream). RenderedSite.Ingresses is left empty
// for the caller to populate with its own attribution (e.g. HTTPRoute keys).
func RenderHTTPSites(routes []RenderRoute) []RenderedSite {
	entries := make([]routeEntry, 0, len(routes))
	for _, r := range routes {
		entries = append(entries, r.toRouteEntry())
	}
	// No policy fragments, no per-host defaultBackend, no ACME directives in slice 1
	// (those stay Ingress-owned; the Gateway slice-2 TLS work will extend this).
	var rejects []Reject
	return renderSites(entries, nil, nil, nil, nil, "", 0, &rejects)
}

// CombineSites is the exported Combine: prepend a base (globals-only) Cadishfile to the
// generated sites. The Gateway controller uses it exactly as the Ingress controller does.
func CombineSites(base, generated string) string { return Combine(base, generated) }

// SanitizeName exposes the Cadishfile-token sanitizer so a sibling controller can build
// matching upstream/identifier names. (Used by the Gateway translator's tests.)
func SanitizeName(s string) string { return sanitize(s) }
