package ingress

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestACMEDomainPolicyOffByDefault proves the per-namespace ACME allow-list is OFF when
// unset: every watched ACME host is eligible (single-trust-domain default, unchanged).
func TestACMEDomainPolicyOffByDefault(t *testing.T) {
	owner := map[string]string{"a.example.com": "ns-a", "b.other.com": "ns-b"}
	hosts := []string{"a.example.com", "b.other.com"}

	// nil policy → all eligible.
	kept, rej := FilterACMEDomains(hosts, owner, nil)
	if len(rej) != 0 {
		t.Fatalf("nil policy must reject nothing, got %v", rej)
	}
	if len(kept) != 2 || !contains(kept, "a.example.com") || !contains(kept, "b.other.com") {
		t.Fatalf("nil policy must keep all hosts, got %v", kept)
	}

	// empty (non-nil) policy → still off.
	kept2, rej2 := FilterACMEDomains(hosts, owner, ACMEDomainPolicy{})
	if len(rej2) != 0 || len(kept2) != 2 {
		t.Fatalf("empty policy must keep all hosts with no rejects, kept=%v rej=%v", kept2, rej2)
	}
}

// TestACMEDomainPolicyExcludesDisallowed proves that with a policy set, a host whose
// OWNER namespace is not permitted that domain is dropped from the ACME set (and produces
// a reject Event), while a permitted host stays eligible.
func TestACMEDomainPolicyExcludesDisallowed(t *testing.T) {
	owner := map[string]string{
		"a.example.com":   "ns-a", // ns-a permitted example.com → kept
		"evil.victim.com": "ns-a", // ns-a NOT permitted victim.com → dropped + reject
		"b.other.com":     "ns-b", // ns-b permitted other.com → kept
	}
	hosts := []string{"a.example.com", "evil.victim.com", "b.other.com"}
	policy := ACMEDomainPolicy{
		"ns-a": {"example.com"},
		"ns-b": {"other.com"},
	}

	kept, rej := FilterACMEDomains(hosts, owner, policy)

	if !contains(kept, "a.example.com") {
		t.Fatalf("ns-a's permitted host must stay eligible, kept=%v", kept)
	}
	if !contains(kept, "b.other.com") {
		t.Fatalf("ns-b's permitted host must stay eligible, kept=%v", kept)
	}
	if contains(kept, "evil.victim.com") {
		t.Fatalf("ns-a is not permitted victim.com; evil.victim.com must be dropped, kept=%v", kept)
	}
	rejected := false
	for _, r := range rej {
		if r.Reason != "" && containsSub(r.Reason, "evil.victim.com") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("disallowed ACME host must produce a reject Event, rej=%v", rej)
	}
}

// TestACMEDomainPolicyMatchesSuffix proves suffix matching: an allowed suffix matches the
// apex AND any subdomain, but never a different domain that merely shares a tail token.
func TestACMEDomainPolicyMatchesSuffix(t *testing.T) {
	policy := ACMEDomainPolicy{"ns-a": {"example.com"}}
	cases := map[string]bool{
		"example.com":          true,  // apex
		"www.example.com":      true,  // subdomain
		"deep.www.example.com": true,  // nested subdomain
		"notexample.com":       false, // shares a suffix string but not a label boundary
		"example.com.evil.com": false, // different domain
	}
	for host, want := range cases {
		got := policy.Allowed("ns-a", host)
		if got != want {
			t.Errorf("Allowed(ns-a, %q) = %v, want %v", host, got, want)
		}
	}
	// A namespace with no entry is allowed nothing once the policy is active.
	if policy.Allowed("ns-x", "example.com") {
		t.Errorf("a namespace absent from a non-empty policy must be allowed nothing")
	}
}

// TestParseACMEDomainPolicy proves the operator-curated flag parser: "ns=suffix,suffix"
// entries separated by ';'. An empty string yields a nil (off) policy.
func TestParseACMEDomainPolicy(t *testing.T) {
	if p, err := ParseACMEDomainPolicy(""); err != nil || p != nil {
		t.Fatalf("empty spec must be off (nil, no error), got p=%v err=%v", p, err)
	}
	p, err := ParseACMEDomainPolicy("ns-a=example.com,*.test ; ns-b=other.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Allowed("ns-a", "example.com") || !p.Allowed("ns-a", "x.test") {
		t.Fatalf("ns-a should be permitted example.com and *.test, got %v", p)
	}
	if !p.Allowed("ns-b", "sub.other.com") {
		t.Fatalf("ns-b should be permitted other.com, got %v", p)
	}
	if p.Allowed("ns-a", "other.com") {
		t.Fatalf("ns-a must not be permitted ns-b's domain")
	}
	if _, err := ParseACMEDomainPolicy("bogus-no-equals"); err == nil {
		t.Fatalf("a malformed entry must error")
	}
}

// containsSub is strings.Contains without importing strings into this small test file.
func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestControllerACMEPolicyFiltersHostSet is the controller-level A2 guard: with an ACME
// domain policy set, a watched ACME host whose owner namespace is not permitted the domain
// is NOT rendered with a `tls acme` directive (excluded from the issuer HostPolicy), while
// a permitted host is. With NO policy, both are eligible (unchanged).
func TestControllerACMEPolicyFiltersHostSet(t *testing.T) {
	t0 := metav1.Unix(1000, 0)
	// ns-a owns a.example.com (permitted) and evil.victim.com (not permitted).
	permitted := ingressRuleTLS("ns-a", "permitted", "a.example.com", "", t0)
	evil := ingressRuleTLS("ns-a", "evil", "evil.victim.com", "", t0)

	ings := []*networkingv1.Ingress{permitted, evil}
	// No Secrets exist → both hosts go to ACME.
	exists := func(ns, name string) bool { return false }
	acmeHosts, _, _ := TLSPlan(ings, exists, nil)
	owner := routingHostOwners(ings)

	// Policy off: both eligible.
	kept, _ := FilterACMEDomains(acmeHosts, owner, nil)
	if !contains(kept, "a.example.com") || !contains(kept, "evil.victim.com") {
		t.Fatalf("policy off: both hosts must be ACME-eligible, got %v", kept)
	}

	// Policy on: only the permitted domain stays.
	policy := ACMEDomainPolicy{"ns-a": {"example.com"}}
	kept2, rej := FilterACMEDomains(acmeHosts, owner, policy)
	if !contains(kept2, "a.example.com") {
		t.Fatalf("permitted host must stay ACME-eligible, got %v", kept2)
	}
	if contains(kept2, "evil.victim.com") {
		t.Fatalf("disallowed host must be excluded from ACME, got %v", kept2)
	}
	if len(rej) == 0 {
		t.Fatalf("disallowed host must produce a reject Event")
	}
}
