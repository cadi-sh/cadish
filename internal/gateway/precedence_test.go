package gateway

import (
	"net/http"
	"testing"

	"github.com/cadi-sh/cadish/internal/pipeline"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestConditionedMatchWinsSamePath: per Gateway API match precedence, a match with more
// qualifiers (a header match) at the SAME path must win over a plain same-path match,
// regardless of the routes' relative ordering. (Bug: the renderer sorted only by path
// type + path length, so the plain route could be emitted first and shadow the qualified
// one.)
func TestConditionedMatchWinsSamePath(t *testing.T) {
	// Name the plain route so it sorts FIRST by the oldest-then-key ordering; without the
	// precedence fix it would be emitted first and win for /foo+header.
	plain := httpRoute("prod", "a-plain", "g", "example.com", "svcB", 80, []match{{"/foo", gatewayv1.PathMatchPathPrefix}})
	canary := httpRoute("prod", "b-canary", "g", "example.com", "svcA", 80, []match{{"/foo", gatewayv1.PathMatchPathPrefix}})
	canary.Spec.Rules[0].Matches[0].Headers = []gatewayv1.HTTPHeaderMatch{{Name: "X-Canary", Value: "yes"}}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{plain, canary},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")

	dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/foo", Header: http.Header{"X-Canary": {"yes"}}})
	if dec.Upstream != "u_prod_svcA_80" {
		t.Errorf("/foo with X-Canary:yes must route to the header-qualified backend svcA, got %q", dec.Upstream)
	}
	dec2 := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/foo"})
	if dec2.Upstream != "u_prod_svcB_80" {
		t.Errorf("/foo without the header must route to the plain backend svcB, got %q", dec2.Upstream)
	}
}
