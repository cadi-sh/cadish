package gateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

// svc builds a minimal core Service (existence is all the BackendNotFound gate checks).
func svc(ns, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}

// TestBackendNotFoundWhenServiceMissing (GW1): a backendRef to a Service that does not
// exist must leave the route NOT ResolvedRefs, with a BackendNotFound (not RefNotPermitted)
// reject, while the existing structural checks still pass. The data plane already fails
// closed; this is the status-conformance fix.
func TestBackendNotFoundWhenServiceMissing(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "does-not-exist", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
		// No Service exists.
		serviceExists: func(ns, name string) bool { return false },
	}
	r := TranslateResult(in)
	if r.ResolvedRoutes["prod/r"] {
		t.Fatalf("a backendRef to a missing Service must NOT be ResolvedRefs")
	}
	if r.RefNotPermittedRoutes["prod/r"] {
		t.Fatalf("a missing Service is BackendNotFound, not RefNotPermitted")
	}
	if !r.AcceptedRoutes["prod/r"] {
		t.Fatalf("the route still attached to the listener, so it is Accepted")
	}
	foundBNF := false
	for _, rj := range r.Rejects {
		if rj.Kind == "HTTPRoute" && strings.Contains(rj.Reason, "BackendNotFound") {
			foundBNF = true
		}
	}
	if !foundBNF {
		t.Fatalf("expected a BackendNotFound reject, got: %+v", r.Rejects)
	}
}

// TestBackendFoundWhenServiceExists (GW1): with the Service present, the route is
// ResolvedRefs=True (no false BackendNotFound).
func TestBackendFoundWhenServiceExists(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	in := Inputs{
		Classes:       []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:      []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:        []*gatewayv1.HTTPRoute{rt},
		serviceExists: func(ns, name string) bool { return ns == "prod" && name == "web" },
	}
	r := TranslateResult(in)
	if !r.ResolvedRoutes["prod/r"] {
		t.Fatalf("a backendRef to an existing Service must be ResolvedRefs; rejects=%+v", r.Rejects)
	}
}

// TestServiceExistsNilGateBackCompatible (GW1): when serviceExists is nil (older tests /
// no informer), existence is NOT enforced — a backendRef resolves on its structural checks
// alone, preserving the pre-fix behavior for the pure translator.
func TestServiceExistsNilGateBackCompatible(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
		// serviceExists nil.
	}
	r := TranslateResult(in)
	if !r.ResolvedRoutes["prod/r"] {
		t.Fatalf("with a nil serviceExists gate, the route must resolve on structural checks; rejects=%+v", r.Rejects)
	}
}

// TestControllerBackendNotFound (GW1, E2E): a real reconcile with a missing Service writes
// ResolvedRefs=False (BackendNotFound) on the route's parent status.
func TestControllerBackendNotFound(t *testing.T) {
	gc := gatewayClass("cadish", ControllerName)
	g := gw("prod", "gw", "cadish", "")
	rt := httpRoute("prod", "api", "gw", "example.com", "does-not-exist", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}})

	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	// The core clientset has NO Service named does-not-exist (and no EndpointSlice).
	cs := k8sfake.NewSimpleClientset()

	applier := applierFunc(func(*config.Config) error { return nil })
	ctrl := New(cs, gwcs, applier, ``, Config{ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().HTTPRoutes("prod").Get(ctx, "api", metav1.GetOptions{})
		if err != nil || len(got.Status.Parents) == 0 {
			return false
		}
		for _, c := range got.Status.Parents[0].Conditions {
			if c.Type == string(gatewayv1.RouteConditionResolvedRefs) {
				return c.Status == metav1.ConditionFalse && c.Reason == string(gatewayv1.RouteReasonBackendNotFound)
			}
		}
		return false
	}, "ResolvedRefs=False BackendNotFound for a missing Service")
}

// TestControllerBackendFoundWhenServiceExists (GW1, E2E): with the Service present the
// route's parent status is ResolvedRefs=True.
func TestControllerBackendFoundWhenServiceExists(t *testing.T) {
	gc := gatewayClass("cadish", ControllerName)
	g := gw("prod", "gw", "cadish", "")
	rt := httpRoute("prod", "api", "gw", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}})

	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	cs := k8sfake.NewSimpleClientset(svc("prod", "web"), sliceFor("web", "prod", "10.0.0.1", 80))

	applier := applierFunc(func(*config.Config) error { return nil })
	ctrl := New(cs, gwcs, applier, ``, Config{ResyncDebounce: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	waitCond(t, func() bool {
		got, err := gwcs.GatewayV1().HTTPRoutes("prod").Get(ctx, "api", metav1.GetOptions{})
		if err != nil || len(got.Status.Parents) == 0 {
			return false
		}
		return condTrue(got.Status.Parents[0].Conditions, string(gatewayv1.RouteConditionResolvedRefs))
	}, "ResolvedRefs=True with the Service present")
}
