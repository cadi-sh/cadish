package ingress

import (
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

// TestTranslate_ACMEDirective proves a spec.tls host without a Secret gets a
// `tls acme` directive (so it auto-issues), a BYO-Secret host gets NONE (its cert
// arrives via the side-channel), and the generated Cadishfile compiles.
func TestTranslate_ACMEDirective(t *testing.T) {
	acmeIng := ingress("prod", "acme-site", "acme.example.com",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	byoIng := ingress("prod", "byo-site", "byo.example.com",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})

	out, rej := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{acmeIng, byoIng},
		ClassName: "cadish",
		ACMEHosts: map[string]bool{"acme.example.com": true},
		ACMEEmail: "ops@example.com",
	})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects: %v", rej)
	}
	if !strings.Contains(out, "tls acme ops@example.com") {
		t.Fatalf("ACME host should get a `tls acme` directive:\n%s", out)
	}
	// The BYO host's site must NOT carry a tls directive.
	byoBlock := siteBlock(t, out, "byo.example.com")
	if strings.Contains(byoBlock, "tls") {
		t.Fatalf("BYO host must not get a tls directive:\n%s", byoBlock)
	}
	mustCompile(t, out)
}

// TestTranslate_ACMEDirectiveNoEmail proves a `tls acme` directive renders (and
// compiles) even without an ACME email.
func TestTranslate_ACMEDirectiveNoEmail(t *testing.T) {
	ing := ingress("prod", "s", "acme.example.com",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	out, _ := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{ing},
		ClassName: "cadish",
		ACMEHosts: map[string]bool{"acme.example.com": true},
	})
	if !strings.Contains(out, "tls acme\n") {
		t.Fatalf("expected a bare `tls acme` directive:\n%s", out)
	}
	mustCompile(t, out)
}

// TestTranslate_ACMEOnlyHostDropped proves a host named only in spec.tls (no rule,
// no backend) is NOT forced into an unservable, non-compiling site — it drops out of
// the ACME set, keeping the generated config valid.
func TestTranslate_ACMEOnlyHostDropped(t *testing.T) {
	out, _ := Translate(Inputs{
		ClassName: "cadish",
		ACMEHosts: map[string]bool{"tlsonly.example.com": true},
		ACMEEmail: "ops@example.com",
	})
	if strings.Contains(out, "tlsonly.example.com") {
		t.Fatalf("a route-less ACME-only host must not become a site:\n%s", out)
	}
	// (No site is rendered; the controller compiles such output with AllowNoSites.)
}

// siteBlock returns the text of the `host { … }` block for host (for per-site asserts).
func siteBlock(t *testing.T, out, host string) string {
	t.Helper()
	start := strings.Index(out, host+" {")
	if start < 0 {
		t.Fatalf("site %q not found in:\n%s", host, out)
	}
	end := strings.Index(out[start:], "\n}")
	if end < 0 {
		t.Fatalf("unterminated site %q in:\n%s", host, out)
	}
	return out[start : start+end]
}
