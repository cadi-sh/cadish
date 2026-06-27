package gateway

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/pipeline"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// zeroWeight sets every backendRef weight of rt to 0.
func zeroAllWeights(rt *gatewayv1.HTTPRoute) {
	z := int32(0)
	for ri := range rt.Spec.Rules {
		for bi := range rt.Spec.Rules[ri].BackendRefs {
			rt.Spec.Rules[ri].BackendRefs[bi].Weight = &z
		}
	}
}

// TestAllZeroWeightCatchAllServes503: an HTTPRoute whose single catch-all rule has an
// all-zero-weight backend pool must serve 503 (Gateway API spec) — not render an empty,
// uncompilable host block.
func TestAllZeroWeightCatchAllServes503(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	zeroAllWeights(rt)
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")
	for _, path := range []string{"/", "/api", "/x/y"} {
		dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: path})
		if dec.Synthetic == nil || dec.Synthetic.Status != 503 {
			t.Errorf("all-zero-weight catch-all must 503 %q, got %+v", path, dec.Synthetic)
		}
	}
}

// TestAllZeroWeightScopedServes503: an all-zero-weight rule scoped to /api 503s /api but a
// sibling real route to /web still serves, and an unmatched path 404s.
func TestAllZeroWeightScopedServes503(t *testing.T) {
	denyRt := httpRoute("prod", "deny", "g", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}})
	zeroAllWeights(denyRt)
	okRt := httpRoute("prod", "ok", "g", "example.com", "web2", 80, []match{{"/web", gatewayv1.PathMatchPathPrefix}})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{denyRt, okRt},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")

	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/api/x"}); dec.Synthetic == nil || dec.Synthetic.Status != 503 {
		t.Errorf("/api (all-zero) must 503, got %+v", dec.Synthetic)
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/web"}); dec.Synthetic != nil {
		t.Errorf("/web must route to its real backend, got synthetic %+v", dec.Synthetic)
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/other"}); dec.Synthetic == nil || dec.Synthetic.Status != 404 {
		t.Errorf("/other must 404, got %+v", dec.Synthetic)
	}
}

// TestAllZeroWeightDenyDoesNotShadowMoreSpecificRoute: an all-zero-weight rule on a BROAD
// prefix (/api) must not 503 a more-specific real route nested under it (/api/special);
// only the paths the deny covers but no real route serves get 503.
func TestAllZeroWeightDenyDoesNotShadowMoreSpecificRoute(t *testing.T) {
	denyRt := httpRoute("prod", "deny", "g", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}})
	zeroAllWeights(denyRt)
	okRt := httpRoute("prod", "ok", "g", "example.com", "web2", 80, []match{{"/api/special", gatewayv1.PathMatchPathPrefix}})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{denyRt, okRt},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/api/special/x"}); dec.Synthetic != nil {
		t.Errorf("/api/special (more specific real route) must route, not 503: %+v", dec.Synthetic)
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/api/other"}); dec.Synthetic == nil || dec.Synthetic.Status != 503 {
		t.Errorf("/api/other (deny-covered, no real route) must 503, got %+v", dec.Synthetic)
	}
}

// TestAllZeroWeightCatchAllWithRealRoute: a real scoped route must win over an all-zero
// catch-all deny (more-specific real match routes; everything else 503s).
func TestAllZeroWeightCatchAllWithRealRoute(t *testing.T) {
	denyRt := httpRoute("prod", "deny", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	zeroAllWeights(denyRt)
	okRt := httpRoute("prod", "ok", "g", "example.com", "web2", 80, []match{{"/web", gatewayv1.PathMatchPathPrefix}})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{denyRt, okRt},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/web"}); dec.Synthetic != nil {
		t.Errorf("/web must route to its real backend (not 503), got %+v", dec.Synthetic)
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/elsewhere"}); dec.Synthetic == nil || dec.Synthetic.Status != 503 {
		t.Errorf("/elsewhere must 503 via the catch-all deny, got %+v", dec.Synthetic)
	}
}
