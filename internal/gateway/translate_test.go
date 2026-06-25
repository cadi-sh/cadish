package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/ingress"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/pipeline"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// noopResolver lets a k8s:// Cadishfile compile offline (the compile check is the
// translator's correctness guard; real endpoint resolution is Layer 1's concern).
type noopResolver struct{}

func (noopResolver) ResolveEndpoints(context.Context, string, string, string) ([]lb.Endpoint, error) {
	return nil, nil
}
func (noopResolver) Watch(string, string, func()) func() { return nil }

// mustCompile proves the generated Cadishfile compiles through the real config compiler.
func mustCompile(t *testing.T, out string) {
	t.Helper()
	cfg, err := config.LoadStringWithOptions("<gateway>", out, config.LoadOptions{EndpointResolver: noopResolver{}, AllowNoSites: true})
	if err != nil {
		t.Fatalf("generated cadishfile did not compile:\n%s\nerr: %v", out, err)
	}
	_ = cfg.Close()
}

// pipelineFor compiles out and returns the live request pipeline for host (so a test can
// drive real path resolution: a matched path routes; an unmatched path returns a 404
// synthetic). Mirrors the Ingress translator's pipelineFor helper.
func pipelineFor(t *testing.T, out, host string) *pipeline.Pipeline {
	t.Helper()
	cfg, err := config.LoadStringWithOptions("<gateway>", out, config.LoadOptions{EndpointResolver: noopResolver{}})
	if err != nil {
		t.Fatalf("generated cadishfile did not compile:\n%s\nerr: %v", out, err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	for _, s := range cfg.Sites {
		for _, a := range s.Addresses {
			if a == host {
				return s.Pipeline
			}
		}
	}
	t.Fatalf("no site for host %q in:\n%s", host, out)
	return nil
}

func joinSites(sites []ingress.RenderedSite) string {
	var b strings.Builder
	for _, s := range sites {
		b.WriteString(s.Text)
	}
	return b.String()
}

// --- fixtures ----------------------------------------------------------------

func ptr[T any](v T) *T { return &v }

func gatewayClass(name string, controller gatewayv1.GatewayController) *gatewayv1.GatewayClass {
	return &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: controller},
	}
}

// gw builds a Gateway with a single HTTP listener (optional hostname) on port 80.
func gw(ns, name, className, listenerHost string) *gatewayv1.Gateway {
	l := gatewayv1.Listener{Name: "http", Port: 80, Protocol: gatewayv1.HTTPProtocolType}
	if listenerHost != "" {
		l.Hostname = ptr(gatewayv1.Hostname(listenerHost))
	}
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(className),
			Listeners:        []gatewayv1.Listener{l},
		},
	}
}

type match struct {
	path string
	kind gatewayv1.PathMatchType
}

// httpRoute builds an HTTPRoute attaching to gwName with the given hostname and a single
// rule: the path matches → Service svc:port.
func httpRoute(ns, name, gwName, hostname, svc string, port int32, matches []match) *gatewayv1.HTTPRoute {
	var ms []gatewayv1.HTTPRouteMatch
	for _, m := range matches {
		mk := m.kind
		ms = append(ms, gatewayv1.HTTPRouteMatch{Path: &gatewayv1.HTTPPathMatch{Type: &mk, Value: ptr(m.path)}})
	}
	var hostnames []gatewayv1.Hostname
	if hostname != "" {
		hostnames = []gatewayv1.Hostname{gatewayv1.Hostname(hostname)}
	}
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gwName)}},
			},
			Hostnames: hostnames,
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: ms,
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(svc),
							Port: ptr(port),
						},
					},
				}},
			}},
		},
	}
}

// --- tests -------------------------------------------------------------------

func TestOwnsClassAcceptsOnlyOurController(t *testing.T) {
	if !OwnsClass(gatewayClass("cadish", ControllerName)) {
		t.Fatalf("GatewayClass with our controllerName must be owned")
	}
	if OwnsClass(gatewayClass("nginx", "example.com/other-controller")) {
		t.Fatalf("GatewayClass with a foreign controllerName must NOT be owned")
	}
}

// TestForeignClassIgnored: a Gateway using a foreign GatewayClass renders nothing.
func TestForeignClassIgnored(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("nginx", "example.com/other")},
		Gateways: []*gatewayv1.Gateway{gw("default", "g", "nginx", "")},
		Routes:   []*gatewayv1.HTTPRoute{httpRoute("default", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})},
	}
	out, _ := Translate(in)
	if strings.TrimSpace(out) != "" {
		t.Fatalf("a foreign GatewayClass must render no sites, got:\n%s", out)
	}
}

// TestBasicHTTPRoutePrefix is the core happy path.
func TestBasicHTTPRoutePrefix(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "api", "g", "example.com", "web", 8080, []match{{"/api", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	out, rejects := Translate(in)
	if len(rejects) != 0 {
		t.Fatalf("unexpected rejects: %+v", rejects)
	}
	if !strings.Contains(out, "example.com {") {
		t.Fatalf("missing example.com site:\n%s", out)
	}
	if !strings.Contains(out, "path /api /api/*") {
		t.Fatalf("expected element-wise prefix matcher 'path /api /api/*':\n%s", out)
	}
	if !strings.Contains(out, "k8s://web.prod:8080") {
		t.Fatalf("expected k8s://web.prod:8080 upstream:\n%s", out)
	}
	if !strings.Contains(out, "respond !@r0p 404") {
		t.Fatalf("expected terminal no-match 404 (respond !@r0p 404):\n%s", out)
	}
	mustCompile(t, out)
}

// TestPathPrefixElementMatch: PathPrefix /api matches /api and /api/sub but NOT /apiother;
// an unmatched path 404s (F7). Driven through the live router.
func TestPathPrefixElementMatch(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "api", "g", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")

	for _, ok := range []string{"/api", "/api/", "/api/v1/users"} {
		if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: ok}); dec.Synthetic != nil {
			t.Errorf("PathPrefix /api must match %q, got 404: %+v", ok, dec.Synthetic)
		}
	}
	for _, no := range []string{"/apiother", "/ap", "/", "/admin"} {
		dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: no})
		if dec.Synthetic == nil || dec.Synthetic.Status != 404 {
			t.Errorf("PathPrefix /api must NOT match %q (expect 404), got %+v", no, dec.Synthetic)
		}
	}
}

// TestExactPath: Exact /api matches only /api, not /api/sub; unmatched paths 404.
func TestExactPath(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "api", "g", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchExact}}),
		},
	}
	out, _ := Translate(in)
	p := pipelineFor(t, out, "example.com")
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/api"}); dec.Synthetic != nil {
		t.Fatalf("Exact /api should route, not 404: %+v", dec.Synthetic)
	}
	for _, no := range []string{"/api/sub", "/other"} {
		dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: no})
		if dec.Synthetic == nil || dec.Synthetic.Status != 404 {
			t.Errorf("Exact /api must NOT match %q (expect 404), got %+v", no, dec.Synthetic)
		}
	}
}

// TestListenerHostnameSuppliesHost: a route with no hostnames inherits the listener's.
func TestListenerHostnameSuppliesHost(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "shop.example.com")},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "r", "g", "", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	out, _ := Translate(in)
	if !strings.Contains(out, "shop.example.com {") {
		t.Fatalf("route should inherit the listener hostname shop.example.com:\n%s", out)
	}
	mustCompile(t, out)
}

// TestHTTPSListenerWithoutCertNotProgrammed: an HTTPS listener with no certificateRefs is
// acknowledged with a reject (not programmed), while the HTTP listener on the same Gateway
// still serves — per-resource graceful degradation.
func TestHTTPSListenerWithoutCertNotProgrammed(t *testing.T) {
	g := gw("prod", "g", "cadish", "")
	g.Spec.Listeners = append(g.Spec.Listeners, gatewayv1.Listener{
		Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: ptr(gatewayv1.Hostname("example.com")),
		TLS:      &gatewayv1.ListenerTLSConfig{},
	})
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{g},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	r := TranslateResult(in)
	foundHTTPS := false
	for _, rj := range r.Rejects {
		if rj.Kind == "Gateway" && strings.Contains(rj.Reason, "certificateRefs") {
			foundHTTPS = true
		}
	}
	if !foundHTTPS {
		t.Fatalf("an HTTPS listener with no certificateRefs should produce a reject, got: %+v", r.Rejects)
	}
	if !strings.Contains(joinSites(r.Sites), "example.com {") {
		t.Fatalf("HTTP listener should still serve example.com alongside the not-programmed HTTPS one")
	}
}

// TestStatusBookkeeping: the route is Accepted+Resolved and the gateway is Programmed with
// attachedRoutes counted.
func TestStatusBookkeeping(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes: []*gatewayv1.HTTPRoute{
			httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}}),
		},
	}
	r := TranslateResult(in)
	if !r.AcceptedRoutes["prod/r"] {
		t.Fatalf("route prod/r should be Accepted")
	}
	if !r.ResolvedRoutes["prod/r"] {
		t.Fatalf("route prod/r should be ResolvedRefs")
	}
	if !r.ProgrammedGateways["prod/g"] {
		t.Fatalf("gateway prod/g should be Programmed")
	}
	if r.AttachedRoutes["prod/g"] != 1 {
		t.Fatalf("gateway prod/g should have attachedRoutes=1, got %d", r.AttachedRoutes["prod/g"])
	}
}

// TestBackendNotResolved: a backendRef with no port leaves the route NOT ResolvedRefs.
func TestBackendNotResolved(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	rt.Spec.Rules[0].BackendRefs[0].Port = nil
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	r := TranslateResult(in)
	if r.ResolvedRoutes["prod/r"] {
		t.Fatalf("a backendRef with no port must NOT be ResolvedRefs")
	}
	if !r.AcceptedRoutes["prod/r"] {
		t.Fatalf("the route still attached to the listener, so it is Accepted")
	}
}
