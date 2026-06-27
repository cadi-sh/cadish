package gateway

import (
	"strings"
	"testing"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestRouteWildcardListenerConcreteIntersects: a listener pins a CONCRETE hostname
// (app.example.com) and the HTTPRoute declares a WILDCARD hostname (*.example.com). Per
// Gateway API the intersection is the more-specific name app.example.com, so the route
// MUST attach and serve app.example.com. (Bug: only listener-side wildcards were honored.)
func TestRouteWildcardListenerConcreteIntersects(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "app.example.com")},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "r", "g", "*.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	out, rejects := Translate(in)
	if !strings.Contains(out, "app.example.com {") {
		t.Fatalf("route *.example.com must intersect listener app.example.com → serve app.example.com:\n%s\nrejects=%+v", out, rejects)
	}
	mustCompile(t, out)
}

// TestUnconstrainedSiblingListenerServes: a Gateway with an unconstrained HTTP listener
// (no hostname → matches any) AND a hostname-scoped HTTPS listener. A route whose hostname
// only matches the unconstrained listener MUST still serve via it. (Bug: any listener
// having a hostname forced the intersection branch, dropping hosts the unconstrained
// listener would serve.)
func TestUnconstrainedSiblingListenerServes(t *testing.T) {
	g := gw("prod", "g", "cadish", "") // listener "http", no hostname
	g.Spec.Listeners = append(g.Spec.Listeners, gatewayv1.Listener{
		Name: "scoped", Port: 81, Protocol: gatewayv1.HTTPProtocolType,
		Hostname: ptr(gatewayv1.Hostname("app.example.com")),
	})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{g},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "r", "g", "other.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	out, rejects := Translate(in)
	if !strings.Contains(out, "other.com {") {
		t.Fatalf("route other.com must serve via the unconstrained listener:\n%s\nrejects=%+v", out, rejects)
	}
	mustCompile(t, out)
}
