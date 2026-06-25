package gateway

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestPerListenerAttachedRoutes (GW2): a Gateway with an HTTP listener (no hostname) and an
// HTTPS listener (hostname secure.example.com). 5 routes attach to the Gateway: 4 pin the
// HTTP listener (sectionName: http) on plain hosts; 1 pins the HTTPS listener on the secure
// host. Each listener's attachedRoutes must reflect only ITS attached routes — http=4,
// https=1. The pre-fix bug assigned the per-Gateway total (5) to BOTH listeners.
func TestPerListenerAttachedRoutes(t *testing.T) {
	mode := gatewayv1.TLSModeTerminate
	g := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "prod"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cadish",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{
					Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: ptr(gatewayv1.Hostname("secure.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{Mode: &mode, CertificateRefs: []gatewayv1.SecretObjectReference{
						{Name: gatewayv1.ObjectName("tls-secret")},
					}},
				},
			},
		},
	}
	pinHTTP := func(rt *gatewayv1.HTTPRoute) *gatewayv1.HTTPRoute {
		rt.Spec.ParentRefs[0].SectionName = ptr(gatewayv1.SectionName("http"))
		return rt
	}
	r5 := httpRoute("prod", "r5", "g", "secure.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	r5.Spec.ParentRefs[0].SectionName = ptr(gatewayv1.SectionName("https"))
	routes := []*gatewayv1.HTTPRoute{
		pinHTTP(httpRoute("prod", "r1", "g", "a.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})),
		pinHTTP(httpRoute("prod", "r2", "g", "b.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})),
		pinHTTP(httpRoute("prod", "r3", "g", "c.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})),
		pinHTTP(httpRoute("prod", "r4", "g", "d.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})),
		r5,
	}
	gate := fakeGate{certs: map[string][]string{"prod/tls-secret": {"secure.example.com"}}}
	in := Inputs{
		Classes:       []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:      []*gatewayv1.Gateway{g},
		Routes:        routes,
		secretUsable:  gate.usable,
		certCovers:    gate.covers,
		serviceExists: func(ns, name string) bool { return true },
	}
	r := TranslateResult(in)

	httpKey := "prod/g\x00http"
	httpsKey := "prod/g\x00https"
	if !r.ProgrammedListeners[httpKey] || !r.ProgrammedListeners[httpsKey] {
		t.Fatalf("both listeners should be programmed; rejects=%+v", r.Rejects)
	}
	// Sanity: the per-Gateway total is 5 (the value the buggy code put on every listener).
	if got := r.AttachedRoutes["prod/g"]; got != 5 {
		t.Fatalf("per-Gateway AttachedRoutes = %d, want 5", got)
	}
	if got := r.AttachedRoutesByListener[httpKey]; got != 4 {
		t.Fatalf("HTTP listener attachedRoutes = %d, want 4 (per-listener, not the per-Gateway total 5)", got)
	}
	if got := r.AttachedRoutesByListener[httpsKey]; got != 1 {
		t.Fatalf("HTTPS listener attachedRoutes = %d, want 1 (per-listener, not the per-Gateway total 5)", got)
	}
}

// TestHostnameScopedAttachedRoutes (GW2): a route attaching to BOTH listeners (no
// sectionName) where the HTTPS listener is hostname-scoped counts against the HTTPS listener
// only when the route's effective host is admitted by that listener's hostname.
func TestHostnameScopedAttachedRoutes(t *testing.T) {
	mode := gatewayv1.TLSModeTerminate
	g := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "prod"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cadish",
			Listeners: []gatewayv1.Listener{
				// Both listeners are hostname-scoped to the SAME host so a no-sectionName route
				// for that host attaches to both (effectiveHosts intersects cleanly).
				{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType, Hostname: ptr(gatewayv1.Hostname("secure.example.com"))},
				{
					Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: ptr(gatewayv1.Hostname("secure.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{Mode: &mode, CertificateRefs: []gatewayv1.SecretObjectReference{
						{Name: gatewayv1.ObjectName("tls-secret")},
					}},
				},
			},
		},
	}
	rt := httpRoute("prod", "r", "g", "secure.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	gate := fakeGate{certs: map[string][]string{"prod/tls-secret": {"secure.example.com"}}}
	in := Inputs{
		Classes:       []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:      []*gatewayv1.Gateway{g},
		Routes:        []*gatewayv1.HTTPRoute{rt},
		secretUsable:  gate.usable,
		certCovers:    gate.covers,
		serviceExists: func(ns, name string) bool { return true },
	}
	r := TranslateResult(in)
	if got := r.AttachedRoutesByListener["prod/g\x00http"]; got != 1 {
		t.Fatalf("http listener attachedRoutes = %d, want 1", got)
	}
	if got := r.AttachedRoutesByListener["prod/g\x00https"]; got != 1 {
		t.Fatalf("https listener attachedRoutes = %d, want 1", got)
	}
}

// TestSectionNameScopedAttachedRoutes (GW2): a route that names a specific listener via
// parentRef.sectionName counts ONLY against that listener.
func TestSectionNameScopedAttachedRoutes(t *testing.T) {
	g := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "g", Namespace: "prod"},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cadish",
			Listeners: []gatewayv1.Listener{
				{Name: "a", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
				{Name: "b", Port: 80, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
	}
	// Route pins sectionName "a": it attaches to listener "a" only.
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	rt.Spec.ParentRefs[0].SectionName = ptr(gatewayv1.SectionName("a"))
	in := Inputs{
		Classes:       []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:      []*gatewayv1.Gateway{g},
		Routes:        []*gatewayv1.HTTPRoute{rt},
		serviceExists: func(ns, name string) bool { return true },
	}
	r := TranslateResult(in)
	if got := r.AttachedRoutesByListener["prod/g\x00a"]; got != 1 {
		t.Fatalf("listener a attachedRoutes = %d, want 1", got)
	}
	if got := r.AttachedRoutesByListener["prod/g\x00b"]; got != 0 {
		t.Fatalf("listener b attachedRoutes = %d, want 0 (the route pinned sectionName a)", got)
	}
}
