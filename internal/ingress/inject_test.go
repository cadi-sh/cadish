package ingress

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
	networkingv1 "k8s.io/api/networking/v1"
)

// ingressSiteAddresses compiles the generated Cadishfile and returns every site address
// it defines, so a test can prove a hostile path did not break out into a foreign site.
func ingressSiteAddresses(t *testing.T, out string) []string {
	t.Helper()
	cfg, err := config.LoadStringWithOptions("<ingress>", out, config.LoadOptions{EndpointResolver: noopResolver{}})
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

// TestIngressPathInjection (R38): a tenant-authored Ingress path that embeds Cadishfile
// structural characters (e.g. "/a}" to close the host block) must be quoted/contained,
// not structurally injected. The generated config must compile and stay one site for the
// tenant's host.
func TestIngressPathInjection(t *testing.T) {
	hostiles := []struct {
		path string
		pt   networkingv1.PathType
	}{
		{"/a}", prefix},
		{"/a}", exact},
		{"/a} victim.example.com {", prefix},
		{"/p;evil", prefix},
		{"/p\tx", exact},
	}
	for _, h := range hostiles {
		ing := ingress("tenant", "r", "tenant.example.com", []pathRule{{h.path, h.pt, "web", 80}})
		out, _ := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
		addrs := ingressSiteAddresses(t, out)
		if len(addrs) != 1 || addrs[0] != "tenant.example.com" {
			t.Errorf("hostile path %q escaped its block: generated sites = %v\n%s", h.path, addrs, out)
		}
	}
}
