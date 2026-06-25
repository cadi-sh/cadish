package gateway

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// gwAllowed builds a Gateway with one HTTP listener carrying the given AllowedRoutes.
func gwAllowed(ns, name string, ar *gatewayv1.AllowedRoutes) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cadish",
			Listeners: []gatewayv1.Listener{{
				Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, AllowedRoutes: ar,
			}},
		},
	}
}

// routeTo builds an HTTPRoute in routeNS whose parentRef names gw in gwNS (cross-ns when set).
func routeTo(routeNS, name, gwNS, gwName, host string) *gatewayv1.HTTPRoute {
	pr := gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gwName)}
	if gwNS != "" {
		pr.Namespace = ptr(gatewayv1.Namespace(gwNS))
	}
	pp := gatewayv1.PathMatchPathPrefix
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: routeNS},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{pr}},
			Hostnames:       []gatewayv1.Hostname{gatewayv1.Hostname(host)},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{Path: &gatewayv1.HTTPPathMatch{Type: &pp, Value: ptr("/")}}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{Name: "web", Port: ptr(gatewayv1.PortNumber(80))},
				}}},
			}},
		},
	}
}

func from(f gatewayv1.FromNamespaces) *gatewayv1.AllowedRoutes {
	return &gatewayv1.AllowedRoutes{Namespaces: &gatewayv1.RouteNamespaces{From: &f}}
}

func renders(t *testing.T, in Inputs, host string) bool {
	t.Helper()
	out, _ := Translate(in)
	return strings.Contains(out, host)
}

// TestAllowedRoutesKindsRejectsOtherKinds: a listener whose AllowedRoutes.Kinds lists only
// TLSRoute must NOT admit an HTTPRoute (the Kinds attachment control was previously ignored).
func TestAllowedRoutesKindsRejectsOtherKinds(t *testing.T) {
	ar := &gatewayv1.AllowedRoutes{Kinds: []gatewayv1.RouteGroupKind{{Kind: "TLSRoute"}}}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gwAllowed("infra", "g", ar)},
		Routes:   []*gatewayv1.HTTPRoute{routeTo("infra", "r", "", "g", "app.example.com")},
	}
	if renders(t, in, "app.example.com") {
		t.Error("an HTTPRoute must NOT attach to a listener whose AllowedRoutes.Kinds lists only TLSRoute")
	}
}

// TestAllowedRoutesFromSameRejectsCrossNamespace: the default (From: Same) must reject a
// cross-namespace route, and From: All must admit it.
func TestAllowedRoutesFromNamespaces(t *testing.T) {
	mk := func(ar *gatewayv1.AllowedRoutes) Inputs {
		return Inputs{
			Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
			Gateways: []*gatewayv1.Gateway{gwAllowed("infra", "g", ar)},
			Routes:   []*gatewayv1.HTTPRoute{routeTo("tenant", "r", "infra", "g", "x.example.com")}, // cross-ns parentRef
		}
	}
	// From: Same (explicit) → cross-namespace route refused.
	if renders(t, mk(from(gatewayv1.NamespacesFromSame)), "x.example.com") {
		t.Error("From: Same must reject a cross-namespace route")
	}
	// Default (no AllowedRoutes) → also Same → refused.
	if renders(t, mk(nil), "x.example.com") {
		t.Error("the default (Same) must reject a cross-namespace route")
	}
	// From: All → cross-namespace route admitted (the Gateway owner opted in).
	if !renders(t, mk(from(gatewayv1.NamespacesFromAll)), "x.example.com") {
		t.Error("From: All must admit a cross-namespace route")
	}
	// From: None → nothing attaches.
	if renders(t, mk(from(gatewayv1.NamespacesFromNone)), "x.example.com") {
		t.Error("From: None must admit no route")
	}
}

// TestAllowedRoutesSameNamespaceStillWorks: a same-namespace route with the default policy
// still attaches (no regression).
func TestAllowedRoutesSameNamespaceStillWorks(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gwAllowed("infra", "g", nil)},
		Routes:   []*gatewayv1.HTTPRoute{routeTo("infra", "r", "", "g", "same.example.com")},
	}
	if !renders(t, in, "same.example.com") {
		t.Error("a same-namespace route must still attach under the default policy")
	}
}
