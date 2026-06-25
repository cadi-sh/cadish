package gateway

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/pipeline"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// fakeGate is an in-test TLS gate: usable/covers backed by a fixed cert map keyed ns/name.
type fakeGate struct {
	certs map[string][]string // ns/name -> SANs
}

func (g fakeGate) usable(ns, name string) bool { _, ok := g.certs[ns+"/"+name]; return ok }
func (g fakeGate) covers(ns, name, host string) bool {
	for _, s := range g.certs[ns+"/"+name] {
		if s == host || (strings.HasPrefix(s, "*.") && strings.HasSuffix(host, s[1:])) {
			return true
		}
	}
	return false
}

// httpsGW builds a Gateway with an HTTPS listener (hostname + certificateRef to a Secret).
func httpsGW(ns, name, className, listenerHost, secretNS, secretName string) *gatewayv1.Gateway {
	mode := gatewayv1.TLSModeTerminate
	ref := gatewayv1.SecretObjectReference{Name: gatewayv1.ObjectName(secretName)}
	if secretNS != "" {
		ref.Namespace = ptr(gatewayv1.Namespace(secretNS))
	}
	l := gatewayv1.Listener{
		Name: "https", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: ptr(gatewayv1.Hostname(listenerHost)),
		TLS:      &gatewayv1.ListenerTLSConfig{Mode: &mode, CertificateRefs: []gatewayv1.SecretObjectReference{ref}},
	}
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(className),
			Listeners:        []gatewayv1.Listener{l},
		},
	}
}

// --- TLS tests ---------------------------------------------------------------

// TestHTTPSListenerBYOCertProgrammed: an HTTPS listener with a BYO Secret whose cert covers
// the hostname is programmed (Programmed listener + a SecretRef to inject + a TLS host).
func TestHTTPSListenerBYOCertProgrammed(t *testing.T) {
	g := httpsGW("prod", "g", "cadish", "secure.example.com", "", "tls-secret")
	gate := fakeGate{certs: map[string][]string{"prod/tls-secret": {"secure.example.com"}}}
	in := Inputs{
		Classes:      []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:     []*gatewayv1.Gateway{g},
		Routes:       []*gatewayv1.HTTPRoute{httpRoute("prod", "r", "g", "secure.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})},
		secretUsable: gate.usable,
		certCovers:   gate.covers,
	}
	r := TranslateResult(in)
	if !r.ProgrammedListeners["prod/g\x00https"] {
		t.Fatalf("HTTPS listener should be Programmed; rejects=%+v", r.Rejects)
	}
	if len(r.SecretRefs) != 1 || r.SecretRefs[0].Name != "tls-secret" {
		t.Fatalf("expected one SecretRef tls-secret, got %+v", r.SecretRefs)
	}
	if len(r.SecretRefs[0].Hosts) != 1 || r.SecretRefs[0].Hosts[0] != "secure.example.com" {
		t.Fatalf("SecretRef hosts = %v", r.SecretRefs[0].Hosts)
	}
	if len(r.TLSHosts) != 1 || r.TLSHosts[0] != "secure.example.com" {
		t.Fatalf("TLSHosts = %v", r.TLSHosts)
	}
}

// TestHTTPSListenerSANMismatchRefused: a BYO Secret whose cert does NOT cover the listener
// hostname is refused (not programmed) with a SAN-mismatch reject (F10).
func TestHTTPSListenerSANMismatchRefused(t *testing.T) {
	g := httpsGW("prod", "g", "cadish", "secure.example.com", "", "tls-secret")
	gate := fakeGate{certs: map[string][]string{"prod/tls-secret": {"other.example.com"}}}
	in := Inputs{
		Classes:      []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:     []*gatewayv1.Gateway{g},
		secretUsable: gate.usable,
		certCovers:   gate.covers,
	}
	r := TranslateResult(in)
	if r.ProgrammedListeners["prod/g\x00https"] {
		t.Fatalf("a SAN-mismatched HTTPS listener must NOT be programmed")
	}
	if len(r.SecretRefs) != 0 {
		t.Fatalf("no SecretRef should be registered on SAN mismatch, got %+v", r.SecretRefs)
	}
	found := false
	for _, rj := range r.Rejects {
		if strings.Contains(rj.Reason, "SAN mismatch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a SAN-mismatch reject, got %+v", r.Rejects)
	}
}

// TestMultiListenerTLS: two HTTPS listeners on one Gateway, different hostnames + certs,
// both program and yield two SecretRefs.
func TestMultiListenerTLS(t *testing.T) {
	g := httpsGW("prod", "g", "cadish", "a.example.com", "", "cert-a")
	mode := gatewayv1.TLSModeTerminate
	g.Spec.Listeners = append(g.Spec.Listeners, gatewayv1.Listener{
		Name: "https-b", Port: 443, Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: ptr(gatewayv1.Hostname("b.example.com")),
		TLS: &gatewayv1.ListenerTLSConfig{Mode: &mode, CertificateRefs: []gatewayv1.SecretObjectReference{
			{Name: gatewayv1.ObjectName("cert-b")},
		}},
	})
	gate := fakeGate{certs: map[string][]string{
		"prod/cert-a": {"a.example.com"},
		"prod/cert-b": {"b.example.com"},
	}}
	in := Inputs{
		Classes:      []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:     []*gatewayv1.Gateway{g},
		secretUsable: gate.usable,
		certCovers:   gate.covers,
	}
	r := TranslateResult(in)
	if !r.ProgrammedListeners["prod/g\x00https"] || !r.ProgrammedListeners["prod/g\x00https-b"] {
		t.Fatalf("both HTTPS listeners should program; rejects=%+v", r.Rejects)
	}
	if len(r.SecretRefs) != 2 {
		t.Fatalf("expected 2 SecretRefs, got %+v", r.SecretRefs)
	}
	if len(r.TLSHosts) != 2 {
		t.Fatalf("expected 2 TLS hosts, got %v", r.TLSHosts)
	}
}

// --- advanced matcher tests --------------------------------------------------

// TestHeaderMethodMatchAND: a match with a path + header + method is an AND; only a request
// satisfying ALL of them routes; others 404 (F7). Driven through the live router.
func TestHeaderMethodMatchAND(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, nil)
	mk := gatewayv1.PathMatchPathPrefix
	post := gatewayv1.HTTPMethodPost
	hx := gatewayv1.HeaderMatchExact
	rt.Spec.Rules[0].Matches = []gatewayv1.HTTPRouteMatch{{
		Path:    &gatewayv1.HTTPPathMatch{Type: &mk, Value: ptr("/api")},
		Method:  &post,
		Headers: []gatewayv1.HTTPHeaderMatch{{Type: &hx, Name: "X-Env", Value: "prod"}},
	}}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	p := pipelineFor(t, out, "example.com")

	good := &pipeline.Request{Method: "POST", Host: "example.com", Path: "/api/x", Header: map[string][]string{"X-Env": {"prod"}}}
	if dec := p.EvalRequest(good); dec.Synthetic != nil {
		t.Errorf("path+method+header all match should route, got %+v", dec.Synthetic)
	}
	// Wrong method -> 404 (AND not satisfied).
	bad1 := &pipeline.Request{Method: "GET", Host: "example.com", Path: "/api/x", Header: map[string][]string{"X-Env": {"prod"}}}
	if dec := p.EvalRequest(bad1); dec.Synthetic == nil || dec.Synthetic.Status != 404 {
		t.Errorf("GET should 404 (method AND not met), got %+v", dec.Synthetic)
	}
	// Missing header -> 404.
	bad2 := &pipeline.Request{Method: "POST", Host: "example.com", Path: "/api/x"}
	if dec := p.EvalRequest(bad2); dec.Synthetic == nil || dec.Synthetic.Status != 404 {
		t.Errorf("missing header should 404, got %+v", dec.Synthetic)
	}
}

// TestMultipleMatchesOR: two matches in one rule are an OR — either set of criteria routes.
func TestMultipleMatchesOR(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, nil)
	mk := gatewayv1.PathMatchPathPrefix
	rt.Spec.Rules[0].Matches = []gatewayv1.HTTPRouteMatch{
		{Path: &gatewayv1.HTTPPathMatch{Type: &mk, Value: ptr("/a")}},
		{Path: &gatewayv1.HTTPPathMatch{Type: &mk, Value: ptr("/b")}},
	}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	out, _ := Translate(in)
	p := pipelineFor(t, out, "example.com")
	for _, ok := range []string{"/a", "/a/x", "/b", "/b/y"} {
		if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: ok}); dec.Synthetic != nil {
			t.Errorf("OR match should route %q, got %+v", ok, dec.Synthetic)
		}
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/c"}); dec.Synthetic == nil || dec.Synthetic.Status != 404 {
		t.Errorf("/c should 404, got %+v", dec.Synthetic)
	}
}

// TestHeaderRegexMatch: a RegularExpression header match renders header_regex and routes.
func TestHeaderRegexMatch(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, nil)
	mk := gatewayv1.PathMatchPathPrefix
	hr := gatewayv1.HeaderMatchRegularExpression
	rt.Spec.Rules[0].Matches = []gatewayv1.HTTPRouteMatch{{
		Path:    &gatewayv1.HTTPPathMatch{Type: &mk, Value: ptr("/")},
		Headers: []gatewayv1.HTTPHeaderMatch{{Type: &hr, Name: "X-Canary", Value: "^v[0-9]+$"}},
	}}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	out, _ := Translate(in)
	if !strings.Contains(out, "header_regex X-Canary") {
		t.Fatalf("expected header_regex matcher:\n%s", out)
	}
	p := pipelineFor(t, out, "example.com")
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/", Header: map[string][]string{"X-Canary": {"v12"}}}); dec.Synthetic != nil {
		t.Errorf("X-Canary: v12 should match the regex, got %+v", dec.Synthetic)
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/", Header: map[string][]string{"X-Canary": {"beta"}}}); dec.Synthetic == nil {
		t.Errorf("X-Canary: beta should NOT match the regex (expect 404)")
	}
}

// TestQueryParamMatch: a queryParams Exact match renders a `query` matcher and routes.
func TestQueryParamMatch(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "web", 80, nil)
	mk := gatewayv1.PathMatchPathPrefix
	rt.Spec.Rules[0].Matches = []gatewayv1.HTTPRouteMatch{{
		Path:        &gatewayv1.HTTPPathMatch{Type: &mk, Value: ptr("/")},
		QueryParams: []gatewayv1.HTTPQueryParamMatch{{Name: "channel", Value: "beta"}},
	}}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	out, _ := Translate(in)
	if !strings.Contains(out, "query channel beta") {
		t.Fatalf("expected `query channel beta` matcher:\n%s", out)
	}
	p := pipelineFor(t, out, "example.com")
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/", Query: map[string][]string{"channel": {"beta"}}}); dec.Synthetic != nil {
		t.Errorf("channel=beta should route, got %+v", dec.Synthetic)
	}
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "example.com", Path: "/", Query: map[string][]string{"channel": {"stable"}}}); dec.Synthetic == nil {
		t.Errorf("channel=stable should NOT match (expect 404)")
	}
}

// --- ReferenceGrant tests ----------------------------------------------------

// crossNSRoute builds an HTTPRoute in routeNS whose single rule's backendRef targets a
// Service in svcNS.
func crossNSRoute(routeNS, name, gwName, host, svcNS, svc string, port int32) *gatewayv1.HTTPRoute {
	rt := httpRoute(routeNS, name, gwName, host, svc, port, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	rt.Spec.Rules[0].BackendRefs[0].Namespace = ptr(gatewayv1.Namespace(svcNS))
	return rt
}

// grant builds a ReferenceGrant in toNS permitting fromKind/fromNS -> toKind[/toName].
func grant(toNS, fromNS, fromKind, toKind, toName string) *gatewayv1.ReferenceGrant {
	to := gatewayv1.ReferenceGrantTo{Group: "", Kind: gatewayv1.Kind(toKind)}
	if toName != "" {
		to.Name = ptr(gatewayv1.ObjectName(toName))
	}
	return &gatewayv1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: toNS},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{{Group: gatewayv1.GroupName, Kind: gatewayv1.Kind(fromKind), Namespace: gatewayv1.Namespace(fromNS)}},
			To:   []gatewayv1.ReferenceGrantTo{to},
		},
	}
}

// TestCrossNSBackendRefRefusedWithoutGrant: a cross-namespace backendRef without a
// ReferenceGrant is refused (ResolvedRefs=False, RefNotPermitted) and serves nothing.
func TestCrossNSBackendRefRefusedWithoutGrant(t *testing.T) {
	rt := crossNSRoute("team-a", "r", "g", "example.com", "team-b", "web", 80)
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("team-a", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	r := TranslateResult(in)
	if r.ResolvedRoutes["team-a/r"] {
		t.Fatalf("cross-namespace backendRef without a grant must NOT resolve")
	}
	if !r.RefNotPermittedRoutes["team-a/r"] {
		t.Fatalf("expected RefNotPermitted for team-a/r; rejects=%+v", r.Rejects)
	}
}

// TestCrossNSBackendRefAllowedWithGrant: with a permitting ReferenceGrant in the target
// namespace, the cross-namespace backendRef resolves and serves.
func TestCrossNSBackendRefAllowedWithGrant(t *testing.T) {
	rt := crossNSRoute("team-a", "r", "g", "example.com", "team-b", "web", 80)
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("team-a", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
		Grants:   []*gatewayv1.ReferenceGrant{grant("team-b", "team-a", "HTTPRoute", "Service", "")},
	}
	r := TranslateResult(in)
	if !r.ResolvedRoutes["team-a/r"] {
		t.Fatalf("a permitting grant should let the cross-namespace backendRef resolve; rejects=%+v", r.Rejects)
	}
	if !strings.Contains(joinSites(r.Sites), "k8s://web.team-b:80") {
		t.Fatalf("expected the cross-namespace Service in the rendered upstream:\n%s", joinSites(r.Sites))
	}
}

// --- weighted backend test ---------------------------------------------------

// TestWeightedBackendsBuildPool: a rule with two backendRefs builds a multi-target lb pool;
// a zero-weight backend is excluded.
func TestWeightedBackendsBuildPool(t *testing.T) {
	rt := httpRoute("prod", "r", "g", "example.com", "v1", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	rt.Spec.Rules[0].BackendRefs = []gatewayv1.HTTPBackendRef{
		{BackendRef: gatewayv1.BackendRef{Weight: ptr(int32(3)), BackendObjectReference: gatewayv1.BackendObjectReference{Name: "v1", Port: ptr(gatewayv1.PortNumber(80))}}},
		{BackendRef: gatewayv1.BackendRef{Weight: ptr(int32(1)), BackendObjectReference: gatewayv1.BackendObjectReference{Name: "v2", Port: ptr(gatewayv1.PortNumber(80))}}},
		{BackendRef: gatewayv1.BackendRef{Weight: ptr(int32(0)), BackendObjectReference: gatewayv1.BackendObjectReference{Name: "v3", Port: ptr(gatewayv1.PortNumber(80))}}},
	}
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("prod", "g", "cadish", "")},
		Routes:   []*gatewayv1.HTTPRoute{rt},
	}
	out, _ := Translate(in)
	mustCompile(t, out)
	if !strings.Contains(out, "k8s://v1.prod:80") || !strings.Contains(out, "k8s://v2.prod:80") {
		t.Fatalf("both non-zero-weight backends should be in the pool:\n%s", out)
	}
	if strings.Contains(out, "k8s://v3.prod:80") {
		t.Fatalf("a zero-weight backend must be excluded:\n%s", out)
	}
	if !r0Resolved(t, in) {
		t.Fatalf("a weighted multi-backend rule should be ResolvedRefs")
	}
}

func r0Resolved(t *testing.T, in Inputs) bool {
	t.Helper()
	return TranslateResult(in).ResolvedRoutes["prod/r"]
}
