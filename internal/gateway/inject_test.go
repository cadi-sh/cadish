package gateway

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// hostileHeaderRoute builds an HTTPRoute in ns/name attaching to gwName for hostname,
// with a single rule whose match carries one Exact header (hname=hvalue) and routes to
// svc:port. The header name and value are the tenant-controlled, potentially hostile,
// strings concatenated into the generated Cadishfile.
func hostileHeaderRoute(ns, name, gwName, hostname, hname, hvalue, svc string, port int32) *gatewayv1.HTTPRoute {
	exact := gatewayv1.HeaderMatchExact
	prefix := gatewayv1.PathMatchPathPrefix
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gwName)}},
			},
			Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(hostname)},
			Rules: []gatewayv1.HTTPRouteRule{{
				Matches: []gatewayv1.HTTPRouteMatch{{
					Path:    &gatewayv1.HTTPPathMatch{Type: &prefix, Value: ptr("/")},
					Headers: []gatewayv1.HTTPHeaderMatch{{Type: &exact, Name: gatewayv1.HTTPHeaderName(hname), Value: hvalue}},
				}},
				BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{Name: gatewayv1.ObjectName(svc), Port: ptr(port)},
				}}},
			}},
		},
	}
}

// siteAddresses compiles out and returns the flattened set of every site address that
// the generated Cadishfile defines (so a test can prove no foreign host was injected).
func siteAddresses(t *testing.T, out string) []string {
	t.Helper()
	cfg, err := config.LoadStringWithOptions("<gateway>", out, config.LoadOptions{EndpointResolver: noopResolver{}, AllowNoSites: true})
	if err != nil {
		t.Fatalf("generated cadishfile did not compile:\n%s\nerr: %v", out, err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	var addrs []string
	for _, s := range cfg.Sites {
		addrs = append(addrs, s.Addresses...)
	}
	return addrs
}

// TestHTTPRouteMatchValueInjection (R01/R24): a tenant-authored header match VALUE that
// embeds Cadishfile structural characters must be contained inside the tenant's own
// block — it must neither break the generated config nor create a site for a foreign
// host. Mirrors the spec's regression fixtures: `}`, `"x\nevil.com {"`, trailing
// backslash, leading `#`.
func TestHTTPRouteMatchValueInjection(t *testing.T) {
	hostiles := []string{
		"}",
		"} evil.example.com {",
		"x\nevil.example.com {",
		`val\`,
		"#comment",
		"} } }",
	}
	for _, hv := range hostiles {
		in := Inputs{
			Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
			Gateways: []*gatewayv1.Gateway{gw("tenant", "g", "cadish", "")},
			Routes: []*gatewayv1.HTTPRoute{
				hostileHeaderRoute("tenant", "r", "g", "tenant.example.com", "X-Probe", hv, "web", 80),
			},
		}
		out, _ := Translate(in)
		addrs := siteAddresses(t, out)
		if len(addrs) != 1 || addrs[0] != "tenant.example.com" {
			t.Errorf("hostile value %q escaped its block: generated sites = %v\n%s", hv, addrs, out)
		}
	}
}

// TestHTTPRouteMatchNameInjection (R25): a tenant-authored header/query match NAME that
// embeds structural characters (e.g. a leading `#` turning the rest of the line into a
// comment, or a brace) must be quoted/contained, not silently break or drop the site.
func TestHTTPRouteMatchNameInjection(t *testing.T) {
	hostiles := []string{
		"#x",
		"evil.example.com {",
		"}",
		"a b",
	}
	for _, hn := range hostiles {
		in := Inputs{
			Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
			Gateways: []*gatewayv1.Gateway{gw("tenant", "g", "cadish", "")},
			Routes: []*gatewayv1.HTTPRoute{
				hostileHeaderRoute("tenant", "r", "g", "tenant.example.com", hn, "v", "web", 80),
			},
		}
		out, _ := Translate(in)
		addrs := siteAddresses(t, out)
		if len(addrs) != 1 || addrs[0] != "tenant.example.com" {
			t.Errorf("hostile NAME %q escaped its block: generated sites = %v\n%s", hn, addrs, out)
		}
	}
}

// TestHostileRouteCannotHijackForeignHost (R01, the multi-tenant property): even with a
// crafted match value AND name, a tenant whose only access is an own-namespace HTTPRoute
// for tenant.example.com cannot create or contribute a site for victim.example.com.
func TestHostileRouteCannotHijackForeignHost(t *testing.T) {
	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gw("tenant", "g", "cadish", "")},
		Routes: []*gatewayv1.HTTPRoute{
			hostileHeaderRoute("tenant", "r", "g", "tenant.example.com",
				"} victim.example.com { route", "} victim.example.com {", "web", 80),
		},
	}
	out, _ := Translate(in)
	for _, a := range siteAddresses(t, out) {
		if strings.Contains(a, "victim.example.com") {
			t.Fatalf("hostile HTTPRoute hijacked a foreign host %q:\n%s", a, out)
		}
	}
}
