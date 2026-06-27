package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/ingress"
	"github.com/cadi-sh/cadish/internal/pipeline"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// at returns a Gateway/HTTPRoute timestamp helper: sets CreationTimestamp.
func atTime(o metav1.Object, secs int) {
	o.SetCreationTimestamp(metav1.NewTime(time.Unix(int64(secs), 0)))
}

// TestRoutingHostCrossNSHijackRejected pins Fix #3: when team-a's Gateway+HTTPRoute own
// the routing for victim.com (oldest Gateway first-claim), a Gateway+HTTPRoute in a
// DIFFERENT namespace (team-b) that claims the same hostname is REJECTED for that host —
// its rules are NOT merged into victim.com's site, so team-b cannot parasitize team-a's
// routing (e.g. add a `/` catch-all capturing non-/app traffic).
func TestRoutingHostCrossNSHijackRejected(t *testing.T) {
	gA := gw("team-a", "ga", "cadish", "victim.com")
	atTime(gA, 100)
	gB := gw("team-b", "gb", "cadish", "victim.com")
	atTime(gB, 200) // newer

	// team-a: legitimate /app route on victim.com.
	rA := httpRoute("team-a", "ra", "ga", "victim.com", "app", 80, []match{{"/app", gatewayv1.PathMatchPathPrefix}})
	atTime(rA, 101)
	// team-b: hostile catch-all on victim.com -> its own evil backend.
	rB := httpRoute("team-b", "rb", "gb", "victim.com", "evil", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	atTime(rB, 201)

	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gA, gB},
		Routes:   []*gatewayv1.HTTPRoute{rA, rB},
	}
	r := TranslateResult(in)
	out := concatSites(r.Sites)

	// team-b's evil backend must NOT appear in the rendered victim.com site.
	if strings.Contains(out, "evil") {
		t.Fatalf("cross-ns hijack: team-b's evil backend leaked into victim.com routing:\n%s", out)
	}
	// team-a's legitimate route must still render.
	if !strings.Contains(out, "app") {
		t.Fatalf("team-a's own /app route should still render:\n%s", out)
	}
	// team-b's route is rejected (Accepted/ResolvedRefs reason) and not accepted.
	if r.AcceptedRoutes["team-b/rb"] {
		t.Errorf("team-b's cross-ns route to an owned host must NOT be Accepted")
	}
	if !hasRejectFor(r.Rejects, "team-b/rb") {
		t.Errorf("expected a reject for team-b/rb (cross-ns routing claim), got %+v", r.Rejects)
	}

	// Behavioral check: a request to victim.com/other 404s (no team-b catch-all captured it).
	p := pipelineFor(t, out, "victim.com")
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "victim.com", Path: "/other"}); dec.Synthetic == nil || dec.Synthetic.Status != 404 {
		t.Errorf("victim.com/other should 404 (team-b catch-all rejected), got %+v", dec.Synthetic)
	}
}

// TestRoutingHostSameNSStillMerges: two Gateways/Routes in the SAME namespace serving the
// same host still merge (a namespace owns its own host) — ownership only blocks FOREIGN ns.
func TestRoutingHostSameNSStillMerges(t *testing.T) {
	gA := gw("team-a", "ga", "cadish", "shop.com")
	atTime(gA, 100)
	gB := gw("team-a", "gb", "cadish", "shop.com")
	atTime(gB, 200)
	rA := httpRoute("team-a", "ra", "ga", "shop.com", "app", 80, []match{{"/app", gatewayv1.PathMatchPathPrefix}})
	atTime(rA, 101)
	rB := httpRoute("team-a", "rb", "gb", "shop.com", "cart", 80, []match{{"/cart", gatewayv1.PathMatchPathPrefix}})
	atTime(rB, 201)

	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gA, gB},
		Routes:   []*gatewayv1.HTTPRoute{rA, rB},
	}
	r := TranslateResult(in)
	out := concatSites(r.Sites)
	if !strings.Contains(out, "app") || !strings.Contains(out, "cart") {
		t.Fatalf("same-ns routes for the same host must both merge:\n%s", out)
	}
	if !r.AcceptedRoutes["team-a/ra"] || !r.AcceptedRoutes["team-a/rb"] {
		t.Errorf("both same-ns routes should be Accepted; ra=%v rb=%v", r.AcceptedRoutes["team-a/ra"], r.AcceptedRoutes["team-a/rb"])
	}
}

// TestRoutingAndTLSOwnershipAgree: the routing owner and the TLS listener owner of a host
// are the SAME namespace (the oldest Gateway), so a cross-ns Gateway cannot win TLS on a
// host whose routing it cannot win, or vice-versa.
func TestRoutingAndTLSOwnershipAgree(t *testing.T) {
	gate := fakeGate{certs: map[string][]string{
		"team-a/cert": {"secure.com"},
		"team-b/cert": {"secure.com"},
	}}
	gA := httpsGW("team-a", "ga", "cadish", "secure.com", "", "cert")
	atTime(gA, 100)
	gB := httpsGW("team-b", "gb", "cadish", "secure.com", "", "cert")
	atTime(gB, 200)
	rB := httpRoute("team-b", "rb", "gb", "secure.com", "evil", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	atTime(rB, 201)

	in := Inputs{
		Classes:      []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:     []*gatewayv1.Gateway{gA, gB},
		Routes:       []*gatewayv1.HTTPRoute{rB},
		secretUsable: gate.usable,
		certCovers:   gate.covers,
	}
	r := TranslateResult(in)
	// team-a owns the TLS listener for secure.com (oldest); team-b's HTTPS listener is rejected.
	if r.ProgrammedListeners["team-b/gb\x00https"] {
		t.Errorf("team-b's HTTPS listener for an owned host must NOT program")
	}
	// team-b's route is also rejected for routing (ownership agrees: team-a owns the host).
	if r.AcceptedRoutes["team-b/rb"] {
		t.Errorf("team-b's route to a host owned by team-a must NOT be Accepted (routing+TLS agree)")
	}
}

// TestRoutingWildcardConcreteSubdomainOwnership pins Fix B: team-a owns a `*.example.com`
// wildcard HTTP listener (oldest Gateway). team-b has a newer `*.example.com` listener and an
// HTTPRoute for the CONCRETE subdomain app.example.com created before any team-a route for it.
// Without the fix, routingHostOwner's pass 2 would award app.example.com to team-b (the
// concrete host is not in the listener-owner seed, which holds only the literal wildcard),
// re-introducing the routing-vs-TLS cross-ns disagreement Fix #3 prevents under wildcards.
// With the fix, the concrete subdomain's routing owner is team-a (the wildcard owner), so
// team-b's route is REJECTED and team-a owns app.example.com.
func TestRoutingWildcardConcreteSubdomainOwnership(t *testing.T) {
	gA := gw("team-a", "ga", "cadish", "*.example.com")
	atTime(gA, 100)
	gB := gw("team-b", "gb", "cadish", "*.example.com")
	atTime(gB, 200) // newer

	// team-b: route for the CONCRETE subdomain app.example.com -> its own evil backend,
	// created before any team-a route for that concrete host.
	rB := httpRoute("team-b", "rb", "gb", "app.example.com", "evil", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	atTime(rB, 201)

	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gA, gB},
		Routes:   []*gatewayv1.HTTPRoute{rB},
	}
	r := TranslateResult(in)
	out := concatSites(r.Sites)

	if strings.Contains(out, "evil") {
		t.Fatalf("cross-ns wildcard hijack: team-b's evil backend leaked into app.example.com routing:\n%s", out)
	}
	if r.AcceptedRoutes["team-b/rb"] {
		t.Errorf("team-b's route to a concrete subdomain of team-a's wildcard must NOT be Accepted")
	}
	if !hasRejectFor(r.Rejects, "team-b/rb") {
		t.Errorf("expected a reject for team-b/rb (cross-ns concrete-subdomain-of-wildcard routing claim), got %+v", r.Rejects)
	}
}

// TestRoutingWildcardConcreteSubdomainSameNS: a single-namespace wildcard listener + a
// concrete-subdomain route in the SAME namespace still works (ownership only blocks FOREIGN
// ns; a namespace owns the concrete subdomains of its own wildcard).
func TestRoutingWildcardConcreteSubdomainSameNS(t *testing.T) {
	gA := gw("team-a", "ga", "cadish", "*.example.com")
	atTime(gA, 100)
	rA := httpRoute("team-a", "ra", "ga", "app.example.com", "web", 80, []match{{"/app", gatewayv1.PathMatchPathPrefix}})
	atTime(rA, 101)

	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gA},
		Routes:   []*gatewayv1.HTTPRoute{rA},
	}
	r := TranslateResult(in)
	out := concatSites(r.Sites)
	if !strings.Contains(out, "app.example.com {") {
		t.Fatalf("same-ns concrete subdomain of own wildcard must render:\n%s", out)
	}
	if !r.AcceptedRoutes["team-a/ra"] {
		t.Errorf("same-ns concrete-subdomain route must be Accepted")
	}
	if hasRejectFor(r.Rejects, "team-a/ra") {
		t.Errorf("same-ns concrete-subdomain route must NOT be rejected, got %+v", r.Rejects)
	}
}

// TestRoutingConcreteListenerUnderForeignWildcard pins the listener-vs-wildcard gap:
// team-a owns an OLDER `*.example.com` wildcard HTTP listener. team-b declares a YOUNGER
// CONCRETE listener for app.example.com (a subdomain of team-a's wildcard) plus a route to
// its own backend. Because a concrete-subdomain exact host wins over a wildcard at serving
// time, team-b would steal/blackhole app.example.com from team-a. routingHostOwner must
// award app.example.com's routing to team-a (the older covering wildcard), so team-b's
// route is REJECTED — exactly as it is when team-b uses a wildcard listener instead of a
// concrete one (see TestRoutingWildcardConcreteSubdomainOwnership).
func TestRoutingConcreteListenerUnderForeignWildcard(t *testing.T) {
	gA := gw("team-a", "ga", "cadish", "*.example.com")
	atTime(gA, 100)
	gB := gw("team-b", "gb", "cadish", "app.example.com") // concrete listener under team-a's wildcard
	atTime(gB, 200)                                       // newer

	rB := httpRoute("team-b", "rb", "gb", "app.example.com", "evil", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	atTime(rB, 201)

	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gA, gB},
		Routes:   []*gatewayv1.HTTPRoute{rB},
	}
	r := TranslateResult(in)
	out := concatSites(r.Sites)

	if strings.Contains(out, "evil") {
		t.Fatalf("cross-ns hijack: team-b's evil backend leaked into app.example.com routing under team-a's wildcard:\n%s", out)
	}
	if r.AcceptedRoutes["team-b/rb"] {
		t.Errorf("team-b's route to a concrete subdomain of team-a's OLDER wildcard must NOT be Accepted")
	}
	if !hasRejectFor(r.Rejects, "team-b/rb") {
		t.Errorf("expected a reject for team-b/rb (cross-ns concrete-listener-under-wildcard routing claim), got %+v", r.Rejects)
	}
}

// TestTLSConcreteListenerUnderForeignWildcard pins the cert-hijack twin of the routing
// gap: team-a owns an OLDER `*.example.com` HTTPS listener. team-b declares a YOUNGER
// CONCRETE HTTPS listener for app.example.com with its OWN (e.g. self-signed) cert that
// covers app.example.com — passing the SAN gate. The exact-host cert wins over the
// wildcard at serving time, so team-b would terminate TLS for app.example.com. The
// cross-namespace cert-hijack guard must REFUSE to program team-b's listener because the
// concrete host falls under team-a's older covering wildcard listener.
func TestTLSConcreteListenerUnderForeignWildcard(t *testing.T) {
	gate := fakeGate{certs: map[string][]string{
		"team-a/wildcert": {"*.example.com"},
		"team-b/appcert":  {"app.example.com"},
	}}
	gA := httpsGW("team-a", "ga", "cadish", "*.example.com", "", "wildcert")
	atTime(gA, 100)
	gB := httpsGW("team-b", "gb", "cadish", "app.example.com", "", "appcert")
	atTime(gB, 200) // newer

	in := Inputs{
		Classes:      []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:     []*gatewayv1.Gateway{gA, gB},
		secretUsable: gate.usable,
		certCovers:   gate.covers,
	}
	r := TranslateResult(in)
	if r.ProgrammedListeners["team-b/gb\x00https"] {
		t.Errorf("team-b's HTTPS listener for a concrete subdomain of team-a's OLDER wildcard must NOT program (cross-ns cert hijack)")
	}
}

// TestRoutingOlderConcreteSurvivesYoungerForeignWildcard pins the SYMMETRIC oldest-wins
// guard (the routing twin of the Ingress controller's TestTranslateOlderExactSurvivesYounger
// ForeignWildcard): team-a owns the CONCRETE host app.example.com via the OLDER Gateway+route
// (first-claim). team-b LATER declares a `*.example.com` wildcard listener + route in a
// DIFFERENT namespace. Strict oldest-wins must hold: routingHostOwner's Pass 3 reassigns a
// concrete listener host to a covering wildcard's namespace ONLY when that wildcard is strictly
// OLDER (lower first-claim rank). team-b's wildcard is YOUNGER, so it must NOT steal team-a's
// already-established concrete host — team-a keeps routing app.example.com and its route stays
// Accepted. Without the `rank[w] < hr` condition, a single hostile younger wildcard would
// capture every existing concrete subdomain under example.com owned by other namespaces.
func TestRoutingOlderConcreteSurvivesYoungerForeignWildcard(t *testing.T) {
	gA := gw("team-a", "ga", "cadish", "app.example.com") // older concrete listener
	atTime(gA, 100)
	rA := httpRoute("team-a", "ra", "ga", "app.example.com", "web", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	atTime(rA, 101)
	// team-b later declares a *.example.com wildcard listener + a route to its own backend.
	gB := gw("team-b", "gb", "cadish", "*.example.com")
	atTime(gB, 200) // newer
	rB := httpRoute("team-b", "rb", "gb", "*.example.com", "evil", 80, []match{{"/", gatewayv1.PathMatchPathPrefix}})
	atTime(rB, 201)

	in := Inputs{
		Classes:  []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways: []*gatewayv1.Gateway{gA, gB},
		Routes:   []*gatewayv1.HTTPRoute{rA, rB},
	}
	r := TranslateResult(in)
	out := concatSites(r.Sites)

	if !r.AcceptedRoutes["team-a/ra"] {
		t.Errorf("team-a's older concrete route for app.example.com must stay Accepted (not stolen by a younger foreign wildcard)")
	}
	if hasRejectFor(r.Rejects, "team-a/ra") {
		t.Fatalf("team-a's older concrete route was rejected by a younger foreign wildcard; rejects=%+v\n%s", r.Rejects, out)
	}
	if !strings.Contains(out, "app.example.com {") || !strings.Contains(out, "k8s://web.team-a:80") {
		t.Fatalf("team-a's concrete host app.example.com was stolen/dropped by a younger foreign wildcard:\n%s", out)
	}
}

// TestTLSOlderConcreteSurvivesYoungerForeignWildcard is the cert twin: team-a terminates
// app.example.com with its OWN cert via the OLDER HTTPS listener. team-b LATER declares a
// `*.example.com` HTTPS listener in a DIFFERENT namespace. A younger foreign wildcard must NOT
// displace an already-established concrete cert owner — team-a's listener stays programmed
// (and at serving time the exact-host cert wins over the wildcard anyway), keeping routing and
// TLS ownership of app.example.com in the same namespace (team-a).
func TestTLSOlderConcreteSurvivesYoungerForeignWildcard(t *testing.T) {
	gate := fakeGate{certs: map[string][]string{
		"team-a/appcert":  {"app.example.com"},
		"team-b/wildcert": {"*.example.com"},
	}}
	gA := httpsGW("team-a", "ga", "cadish", "app.example.com", "", "appcert")
	atTime(gA, 100)
	gB := httpsGW("team-b", "gb", "cadish", "*.example.com", "", "wildcert")
	atTime(gB, 200) // newer

	in := Inputs{
		Classes:      []*gatewayv1.GatewayClass{gatewayClass("cadish", ControllerName)},
		Gateways:     []*gatewayv1.Gateway{gA, gB},
		secretUsable: gate.usable,
		certCovers:   gate.covers,
	}
	r := TranslateResult(in)
	if !r.ProgrammedListeners["team-a/ga\x00https"] {
		t.Errorf("team-a's older concrete HTTPS listener for app.example.com must stay programmed (not displaced by a younger foreign wildcard)")
	}
}

func concatSites(sites []ingress.RenderedSite) string {
	var b strings.Builder
	for _, s := range sites {
		b.WriteString(s.Text)
	}
	return b.String()
}

func hasRejectFor(rejects []Reject, obj string) bool {
	for _, r := range rejects {
		if r.Object == obj {
			return true
		}
	}
	return false
}
