package ingress

import (
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ingressTLS builds an Ingress in ns whose spec.tls[] is described by secret->hosts.
func ingressTLS(ns, name string, secretHosts map[string][]string) *networkingv1.Ingress {
	var tls []networkingv1.IngressTLS
	for secret, hosts := range secretHosts {
		tls = append(tls, networkingv1.IngressTLS{Hosts: hosts, SecretName: secret})
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       networkingv1.IngressSpec{TLS: tls},
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestTLSPlan(t *testing.T) {
	ing := ingressTLS("prod", "site", map[string][]string{
		"web-cert": {"example.com"},     // secret exists -> BYO
		"api-cert": {"api.example.com"}, // secret missing -> ACME
	})
	exists := func(ns, name string) bool { return name == "web-cert" }
	acme, refs, rej := TLSPlan([]*networkingv1.Ingress{ing}, exists, nil)
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects: %v", rej)
	}
	if !contains(acme, "api.example.com") {
		t.Fatalf("api host should fall to ACME, got %v", acme)
	}
	if len(refs) != 1 || refs[0].Name != "web-cert" {
		t.Fatalf("web-cert should be a BYO secret ref, got %v", refs)
	}
	if contains(acme, "example.com") {
		t.Fatalf("example.com is covered by an existing secret; must not be in the ACME set: %v", acme)
	}
}

// TestTLSPlanSANMismatch (F10): a single spec.tls entry lists [covered, uncovered] for
// one Secret whose certificate covers ONLY `covered`. The BYO cert must be registered
// for `covered` only; `uncovered` must NOT get the wrong cert — it is rejected (warning
// Event) and falls through to ACME.
func TestTLSPlanSANMismatch(t *testing.T) {
	ing := ingressTLS("prod", "site", map[string][]string{
		"multi-cert": {"covered.example.com", "uncovered.example.com"},
	})
	exists := func(ns, name string) bool { return true }
	// The cert only covers covered.example.com (its single SAN).
	covers := func(ns, name, host string) bool { return host == "covered.example.com" }

	acme, refs, rej := TLSPlan([]*networkingv1.Ingress{ing}, exists, covers)

	// covered.example.com is registered as a BYO cert.
	coveredBYO := false
	for _, ref := range refs {
		if ref.Name == "multi-cert" && contains(ref.Hosts, "covered.example.com") {
			coveredBYO = true
		}
		if contains(ref.Hosts, "uncovered.example.com") {
			t.Fatalf("uncovered host must NOT be registered with the mismatched cert: %v", refs)
		}
	}
	if !coveredBYO {
		t.Fatalf("covered host should get the BYO cert: %v", refs)
	}
	// uncovered.example.com is rejected with a SAN-mismatch reason and falls to ACME.
	mismatchRejected := false
	for _, r := range rej {
		if strings.Contains(r.Reason, "uncovered.example.com") && strings.Contains(strings.ToLower(r.Reason), "san") {
			mismatchRejected = true
		}
	}
	if !mismatchRejected {
		t.Fatalf("uncovered host should be rejected for SAN mismatch; rejects=%v", rej)
	}
	if !contains(acme, "uncovered.example.com") {
		t.Fatalf("uncovered host should fall through to ACME: %v", acme)
	}
	if contains(acme, "covered.example.com") {
		t.Fatalf("covered host must not be in the ACME set: %v", acme)
	}
}

// ingressRuleTLS builds an Ingress in ns that DECLARES a routing rule for host (claiming
// the host's routing) AND a spec.tls[secret] -> [host] entry, with the given creation
// time (older wins the routing claim).
func ingressRuleTLS(ns, name, host, secret string, created metav1.Time) *networkingv1.Ingress {
	in := ingress(ns, name, host, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	in.CreationTimestamp = created
	in.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: secret}}
	return in
}

// TestTLSPlanRejectsCrossNamespaceCert is the FIX-2 confused-deputy guard: namespace B
// owns the routing for b.victim.com (its Ingress is oldest). Namespace A must NOT be able
// to register a BYO cert for that host — that would let A serve traffic for a host B
// routes. A's spec.tls host is rejected (Event), and only B's same-namespace cert is
// registered.
func TestTLSPlanRejectsCrossNamespaceCert(t *testing.T) {
	t0 := metav1.Unix(1000, 0)
	t1 := metav1.Unix(2000, 0)
	owner := ingressRuleTLS("ns-b", "owner", "b.victim.com", "b-cert", t0) // oldest -> owns routing
	attacker := ingressRuleTLS("ns-a", "attacker", "b.victim.com", "a-cert", t1)

	exists := func(ns, name string) bool { return true } // both secrets "exist"
	_, refs, rej := TLSPlan([]*networkingv1.Ingress{owner, attacker}, exists, nil)

	// The attacker's cross-namespace cert must be rejected.
	rejected := false
	for _, r := range rej {
		if strings.Contains(r.Ingress, "ns-a/attacker") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("cross-namespace BYO cert was not rejected; rejects=%v", rej)
	}
	// Only ns-b's cert may terminate b.victim.com.
	for _, ref := range refs {
		if ref.Namespace == "ns-a" && contains(ref.Hosts, "b.victim.com") {
			t.Fatalf("attacker ns-a registered a cert for b.victim.com: %v", refs)
		}
	}
	bOK := false
	for _, ref := range refs {
		if ref.Namespace == "ns-b" && ref.Name == "b-cert" && contains(ref.Hosts, "b.victim.com") {
			bOK = true
		}
	}
	if !bOK {
		t.Fatalf("owner ns-b cert for b.victim.com missing: %v", refs)
	}
}

// TestTLSPlanSameNamespaceBYO proves same-namespace BYO still works after FIX 2.
func TestTLSPlanSameNamespaceBYO(t *testing.T) {
	t0 := metav1.Unix(1000, 0)
	ing := ingressRuleTLS("prod", "site", "example.com", "web-cert", t0)
	exists := func(ns, name string) bool { return true }
	_, refs, rej := TLSPlan([]*networkingv1.Ingress{ing}, exists, nil)
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects for same-namespace BYO: %v", rej)
	}
	ok := false
	for _, ref := range refs {
		if ref.Namespace == "prod" && contains(ref.Hosts, "example.com") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("same-namespace BYO cert missing: %v", refs)
	}
}

// ingressTLSOnly builds an Ingress that has a spec.tls[] entry for host but NO routing
// rule — the host is TLS-only (SNI termination without a route).
func ingressTLSOnly(ns, name, host, secret string, created metav1.Time) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         ns,
			CreationTimestamp: created,
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{
				Hosts:      []string{host},
				SecretName: secret,
			}},
		},
	}
}

// TestTLSPlanRejectsCrossNamespaceTLSOnlyHost is the FIX-B guard: when a host appears
// ONLY in spec.tls (no routing rule) and two Ingresses in DIFFERENT namespaces both
// claim a BYO cert for it, the second/younger namespace's claim must be rejected. The
// first/older namespace's claim must succeed. Within the same namespace (legitimate
// case) the claim must be accepted.
func TestTLSPlanRejectsCrossNamespaceTLSOnlyHost(t *testing.T) {
	t0 := metav1.Unix(1000, 0) // older → first claim
	t1 := metav1.Unix(2000, 0) // newer → must be rejected when cross-namespace

	// Two different namespaces both claim tls-only.victim.com — no routing rule anywhere.
	first := ingressTLSOnly("ns-first", "first", "tls-only.victim.com", "first-cert", t0)
	second := ingressTLSOnly("ns-second", "second", "tls-only.victim.com", "second-cert", t1)

	exists := func(ns, name string) bool { return true }
	_, refs, rej := TLSPlan([]*networkingv1.Ingress{first, second}, exists, nil)

	// ns-second's cert must be rejected (cross-namespace, younger claim).
	secondRejected := false
	for _, r := range rej {
		if strings.Contains(r.Ingress, "ns-second/second") {
			secondRejected = true
		}
	}
	if !secondRejected {
		t.Fatalf("cross-namespace TLS-only cert from ns-second was NOT rejected; rejects=%v refs=%v", rej, refs)
	}
	// ns-second must not own any host.
	for _, ref := range refs {
		if ref.Namespace == "ns-second" && contains(ref.Hosts, "tls-only.victim.com") {
			t.Fatalf("ns-second registered cert for tls-only.victim.com: %v", refs)
		}
	}
	// ns-first's cert must succeed.
	firstOK := false
	for _, ref := range refs {
		if ref.Namespace == "ns-first" && ref.Name == "first-cert" && contains(ref.Hosts, "tls-only.victim.com") {
			firstOK = true
		}
	}
	if !firstOK {
		t.Fatalf("ns-first cert for tls-only.victim.com missing: %v", refs)
	}
}

// TestTLSPlanSameNamespaceTLSOnly proves a single-namespace TLS-only claim is accepted.
func TestTLSPlanSameNamespaceTLSOnly(t *testing.T) {
	t0 := metav1.Unix(1000, 0)
	ing := ingressTLSOnly("prod", "site", "tls-only.example.com", "prod-cert", t0)
	exists := func(ns, name string) bool { return true }
	_, refs, rej := TLSPlan([]*networkingv1.Ingress{ing}, exists, nil)
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects for single-namespace TLS-only: %v", rej)
	}
	ok := false
	for _, ref := range refs {
		if ref.Namespace == "prod" && contains(ref.Hosts, "tls-only.example.com") {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("single-namespace TLS-only cert missing: %v", refs)
	}
}
