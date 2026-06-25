// Package gateway runs the in-cluster Kubernetes Gateway API controller: it watches
// GatewayClass / Gateway / HTTPRoute objects, translates the HTTP routing they describe
// into a Cadishfile, and hot-swaps cadish's live routing through Server.ApplyConfig — the
// SAME atomic swap the Ingress controller (internal/ingress) uses (D55/D58). It runs
// ALONGSIDE the Ingress controller, mirroring its architecture: a pure translator, a
// debounced reconcile, per-resource graceful degradation, a leader-elected status writer,
// and Kubernetes status conditions instead of Events for accept/reject feedback.
//
// SLICE 1 (this package) delivers: GatewayClass acceptance, Gateway HTTP listeners,
// HTTPRoute host + path (Exact / PathPrefix) routing to a Service backendRef, and the
// Accepted / Programmed / ResolvedRefs status conditions. DEFERRED to slice 2 (clear
// seams + TODOs left in place): HTTPS/TLS listeners + certificateRefs, header/query
// matchers, cross-namespace ReferenceGrant, and backendRef weights/filters.
package gateway

import (
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ControllerName is the value a GatewayClass's spec.controllerName MUST carry for cadish
// to own it (the GatewayClass → controller binding). It mirrors the Ingress controller's
// IngressClass controller name (ingress.ControllerName = "cadi.sh/ingress-controller").
const ControllerName gatewayv1.GatewayController = "cadi.sh/gateway-controller"

// OwnsClass reports whether this controller owns gc: its spec.controllerName must equal
// ControllerName. A GatewayClass naming a DIFFERENT controller is ignored entirely (no
// status is written for it — another controller owns it).
func OwnsClass(gc *gatewayv1.GatewayClass) bool {
	return gc != nil && gc.Spec.ControllerName == ControllerName
}
