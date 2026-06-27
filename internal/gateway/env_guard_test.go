package gateway

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestRuleMatchesRejectsEnvPlaceholder (FIX 2) pins the multi-tenant env-exfiltration
// guard: a tenant HTTPRoute match value/name/method/path carrying an unescaped "{$VAR}"
// must be REJECTED, not quoted-and-emitted. QuoteArg quotes but does not neutralize "{$",
// so without the guard such a token would expand against the CONTROLLER POD's environment
// at config load (config.SubstituteEnv), leaking a secret into the matcher operand.
func TestRuleMatchesRejectsEnvPlaceholder(t *testing.T) {
	exact := gatewayv1.PathMatchExact
	hExact := gatewayv1.HeaderMatchExact
	qExact := gatewayv1.QueryParamMatchExact
	method := gatewayv1.HTTPMethod("{$SECRET}")

	rule := &gatewayv1.HTTPRouteRule{
		Matches: []gatewayv1.HTTPRouteMatch{
			{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: ptr("/p/{$SECRET}")}},
			{Headers: []gatewayv1.HTTPHeaderMatch{{Type: &hExact, Name: "X-Tenant", Value: "{$SECRET}"}}},
			{QueryParams: []gatewayv1.HTTPQueryParamMatch{{Type: &qExact, Name: "q", Value: "{$SECRET}"}}},
			{Method: &method},
		},
	}
	rt := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "r"}}

	matches, rejects := ruleMatches(rt, 0, rule)

	if len(rejects) != 4 {
		t.Fatalf("expected 4 env-placeholder rejects (path/header/query/method), got %d: %+v", len(rejects), rejects)
	}
	for _, rj := range rejects {
		if !strings.Contains(rj.Reason, "environment-variable placeholder") {
			t.Errorf("reject reason = %q, want it to mention environment-variable placeholder", rj.Reason)
		}
	}
	// No rendered match may carry the secret span: every tainted match was dropped.
	for _, m := range matches {
		if strings.Contains(m.path, "{$") {
			t.Errorf("rendered match path %q still carries an env placeholder", m.path)
		}
		for _, c := range m.conds {
			for _, a := range c.args {
				if strings.Contains(a, "{$") {
					t.Errorf("rendered matcher arg %q still carries an env placeholder", a)
				}
			}
		}
	}
}

// TestRuleMatchesAllowsBraceNonEnvValues confirms the guard does NOT over-fire: a value or
// path that contains a literal "{" not followed by "$" (a regex quantifier "{1,3}", a
// runtime placeholder "{device}") is legitimate generated content and must pass through.
func TestRuleMatchesAllowsBraceNonEnvValues(t *testing.T) {
	exact := gatewayv1.PathMatchExact
	hRegex := gatewayv1.HeaderMatchRegularExpression
	rule := &gatewayv1.HTTPRouteRule{
		Matches: []gatewayv1.HTTPRouteMatch{
			{Path: &gatewayv1.HTTPPathMatch{Type: &exact, Value: ptr("/x{1,3}")}},
			{Headers: []gatewayv1.HTTPHeaderMatch{{Type: &hRegex, Name: "X-Id", Value: "a{2,4}"}}},
		},
	}
	rt := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "r"}}

	matches, rejects := ruleMatches(rt, 0, rule)
	if len(rejects) != 0 {
		t.Fatalf("legitimate brace (non-env) values must not be rejected, got: %+v", rejects)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches retained, got %d", len(matches))
	}
}
