package ingress

import (
	"strings"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ageIngress sets an Ingress's creationTimestamp so oldest-wins ordering is
// deterministic in the cap tests (smaller offset = older).
func ageIngress(in *networkingv1.Ingress, secondsOld int) *networkingv1.Ingress {
	in.CreationTimestamp = metav1.NewTime(time.Unix(1_700_000_000-int64(secondsOld), 0))
	return in
}

// TestCapsDefaultOffUnchanged proves a zero ResourceCaps (the default) is unlimited:
// many sites/routes/large fragments all render, byte-identical to no-caps behaviour.
func TestCapsDefaultOffUnchanged(t *testing.T) {
	ings := []*networkingv1.Ingress{
		ingress("team", "a", "a.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}),
		ingress("team", "b", "b.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}),
		ingress("team", "c", "c.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}),
	}
	withCaps, rejCaps := TranslateSites(Inputs{Ingresses: ings, ClassName: "cadish", Caps: ResourceCaps{}})
	noCaps, rejNo := TranslateSites(Inputs{Ingresses: ings, ClassName: "cadish"})
	if len(rejCaps) != 0 || len(rejNo) != 0 {
		t.Fatalf("default caps must reject nothing: caps=%v no=%v", rejCaps, rejNo)
	}
	if joinSites(withCaps) != joinSites(noCaps) {
		t.Fatalf("default (zero) caps must be byte-identical to no caps")
	}
	if len(withCaps) != 3 {
		t.Fatalf("want 3 sites, got %d", len(withCaps))
	}
}

// TestMaxSitesPerNamespaceCap proves a namespace exceeding the site cap has its
// EXCESS hosts rejected (oldest-wins keeps the earlier ones) with a per-Ingress
// Event, while EARLIER sites in that namespace render and OTHER namespaces are
// unaffected.
func TestMaxSitesPerNamespaceCap(t *testing.T) {
	noisy1 := ageIngress(ingress("noisy", "i1", "n1.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}), 300)
	noisy2 := ageIngress(ingress("noisy", "i2", "n2.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}), 200)
	noisy3 := ageIngress(ingress("noisy", "i3", "n3.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}), 100)
	other := ageIngress(ingress("quiet", "q1", "q1.example.com", []pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}}), 50)

	in := Inputs{
		Ingresses: []*networkingv1.Ingress{noisy3, noisy1, noisy2, other},
		ClassName: "cadish",
		Caps:      ResourceCaps{MaxSitesPerNamespace: 2},
	}
	sites, rejects := TranslateSites(in)

	hosts := map[string]bool{}
	for _, s := range sites {
		hosts[s.Host] = true
	}
	// Oldest two in "noisy" survive (n1, n2); the newest (n3) is over the cap.
	if !hosts["n1.example.com"] || !hosts["n2.example.com"] {
		t.Fatalf("oldest two noisy sites must render, got hosts=%v", hosts)
	}
	if hosts["n3.example.com"] {
		t.Fatalf("the 3rd noisy site must be rejected over the site cap, got hosts=%v", hosts)
	}
	// The other namespace is untouched.
	if !hosts["q1.example.com"] {
		t.Fatalf("a different namespace must be unaffected by another's cap, got hosts=%v", hosts)
	}
	// A per-Ingress reject Event for the over-cap Ingress.
	if !hasRejectFor(rejects, "noisy/i3", "site") {
		t.Fatalf("want a site-cap reject for noisy/i3, got %v", rejects)
	}
	for _, r := range rejects {
		if r.Ingress == "quiet/q1" {
			t.Fatalf("the quiet namespace must not be rejected: %v", r)
		}
	}
}

// TestMaxRoutesPerNamespaceCap proves a namespace exceeding the route (path) cap has
// the excess routes rejected (oldest-Ingress-first) while earlier routes render and
// another namespace is unaffected.
func TestMaxRoutesPerNamespaceCap(t *testing.T) {
	// noisy declares 3 paths across two Ingresses; cap is 2 routes/namespace.
	a := ageIngress(ingress("noisy", "a", "app.example.com", []pathRule{
		{path: "/one", pathType: prefix, svc: "s", port: 80},
		{path: "/two", pathType: prefix, svc: "s", port: 80},
	}), 200)
	b := ageIngress(ingress("noisy", "b", "app.example.com", []pathRule{
		{path: "/three", pathType: prefix, svc: "s", port: 80},
	}), 100)
	quiet := ageIngress(ingress("quiet", "q", "q.example.com", []pathRule{
		{path: "/x", pathType: prefix, svc: "s", port: 80},
		{path: "/y", pathType: prefix, svc: "s", port: 80},
	}), 50)

	in := Inputs{
		Ingresses: []*networkingv1.Ingress{a, b, quiet},
		ClassName: "cadish",
		Caps:      ResourceCaps{MaxRoutesPerNamespace: 2},
	}
	sites, rejects := TranslateSites(in)
	out := joinSites(sites)

	// The two oldest routes survive; the 3rd is over the cap.
	if !strings.Contains(out, "/one") || !strings.Contains(out, "/two") {
		t.Fatalf("oldest two routes must render:\n%s", out)
	}
	if strings.Contains(out, "/three") {
		t.Fatalf("the 3rd route must be rejected over the route cap:\n%s", out)
	}
	// The quiet namespace keeps both its routes (its own cap budget).
	if !strings.Contains(out, "/x") || !strings.Contains(out, "/y") {
		t.Fatalf("a different namespace must keep its routes:\n%s", out)
	}
	if !hasRejectFor(rejects, "noisy/b", "route") {
		t.Fatalf("want a route-cap reject for noisy/b, got %v", rejects)
	}
}

// TestMaxFragmentBytesCap proves an over-size cadi.sh/policy fragment is rejected
// (with an Event) BEFORE compiling, while a within-cap fragment is layered.
func TestMaxFragmentBytesCap(t *testing.T) {
	big := "header X-Big v\n" + strings.Repeat("# pad padding padding padding\n", 50)
	small := "header X-Small v\n"

	ingBig := ingressWithPolicy("team", "big", "big.example.com", "team/bigcm",
		[]pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}})
	ingSmall := ingressWithPolicy("team", "small", "small.example.com", "team/smallcm",
		[]pathRule{{path: "/", pathType: prefix, svc: "s", port: 80}})

	in := Inputs{
		Ingresses: []*networkingv1.Ingress{ingBig, ingSmall},
		ClassName: "cadish",
		Policies:  map[string]string{"team/bigcm": big, "team/smallcm": small},
		Caps:      ResourceCaps{MaxFragmentBytes: 100},
	}
	sites, rejects := TranslateSites(in)
	out := joinSites(sites)

	if strings.Contains(out, "X-Big") {
		t.Fatalf("an over-size fragment must NOT be layered:\n%s", out)
	}
	if !strings.Contains(out, "X-Small") {
		t.Fatalf("a within-cap fragment must be layered:\n%s", out)
	}
	if !hasRejectFor(rejects, "team/bigcm", "fragment") {
		t.Fatalf("want a fragment-size reject for team/bigcm, got %v", rejects)
	}
	mustCompile(t, joinSites(sites))
}

// hasRejectFor reports whether rejects contains an entry for ingress key k whose
// reason mentions the word w (a coarse intent check for the test).
func hasRejectFor(rejects []Reject, k, w string) bool {
	for _, r := range rejects {
		if r.Ingress == k && strings.Contains(r.Reason, w) {
			return true
		}
	}
	return false
}
