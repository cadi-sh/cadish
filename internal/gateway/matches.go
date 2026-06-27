package gateway

import (
	"fmt"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/ingress"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ruleMatches maps a rule's matches[] onto gwMatch values (OR across matches; AND within a
// match). A rule with NO matches is a PathPrefix "/" catch-all (Gateway default). Each
// match's path (Exact/PathPrefix) plus its headers / queryParams / method become an
// AND-conjunction of cadish matchers. A RegularExpression path is rejected
// (Implementation-specific); a RegularExpression queryParam is deferred (UnsupportedValue);
// header RegularExpression is supported (header_regex).
func ruleMatches(rt *gatewayv1.HTTPRoute, ri int, rule *gatewayv1.HTTPRouteRule) ([]gwMatch, []Reject) {
	rk := routeKey(rt)
	var rejects []Reject
	if len(rule.Matches) == 0 {
		return []gwMatch{{path: "/", pathKind: ingress.PathPrefix}}, nil
	}
	var out []gwMatch
	for mi := range rule.Matches {
		m := &rule.Matches[mi]
		gm := gwMatch{path: "/", pathKind: ingress.PathPrefix}

		if m.Path != nil {
			if m.Path.Value != nil {
				gm.path = normalizePath(*m.Path.Value)
				// Env-exfiltration guard (parity with the Ingress policy-fragment surface):
				// a tenant path carrying an unescaped "{$VAR}" would, once quoted into the
				// `path` matcher, expand against the CONTROLLER POD's environment when the
				// combined config is loaded (config.SubstituteEnv) — leaking secrets. QuoteArg
				// quotes but does not neutralize "{$", so reject the match rather than emit it.
				if cadishfile.ContainsEnvPlaceholder(gm.path) {
					rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
						Reason: fmt.Sprintf("rule %d match %d path contains an environment-variable placeholder ({$VAR}), which is not allowed", ri, mi)})
					continue
				}
			}
			if m.Path.Type != nil {
				switch *m.Path.Type {
				case gatewayv1.PathMatchExact:
					gm.pathKind = ingress.PathExact
				case gatewayv1.PathMatchPathPrefix:
					gm.pathKind = ingress.PathPrefix
				default:
					rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
						Reason: fmt.Sprintf("rule %d match %d path type %q is unsupported; only Exact and PathPrefix are served", ri, mi, *m.Path.Type)})
					continue
				}
			}
		}

		ok := true
		// Headers: Exact → `header NAME VALUE`; RegularExpression → `header_regex NAME RE`.
		for hi := range m.Headers {
			h := &m.Headers[hi]
			name := strings.TrimSpace(string(h.Name))
			if name == "" {
				continue
			}
			if cadishfile.ContainsEnvPlaceholder(name) || cadishfile.ContainsEnvPlaceholder(h.Value) {
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("rule %d match %d header %q contains an environment-variable placeholder ({$VAR}), which is not allowed", ri, mi, name)})
				ok = false
				continue
			}
			ht := gatewayv1.HeaderMatchExact
			if h.Type != nil {
				ht = *h.Type
			}
			switch ht {
			case gatewayv1.HeaderMatchExact:
				gm.conds = append(gm.conds, matcherSpec{typ: "header", args: []string{cadishfile.QuoteArg(name), cadishfile.QuoteArg(h.Value)}})
			case gatewayv1.HeaderMatchRegularExpression:
				gm.conds = append(gm.conds, matcherSpec{typ: "header_regex", args: []string{cadishfile.QuoteArg(name), cadishfile.QuoteArg(h.Value)}})
			default:
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("rule %d match %d header %q type %q is unsupported", ri, mi, name, ht)})
				ok = false
			}
		}
		// QueryParams: Exact → `query NAME VALUE`; RegularExpression deferred.
		for qi := range m.QueryParams {
			q := &m.QueryParams[qi]
			name := strings.TrimSpace(string(q.Name))
			if name == "" {
				continue
			}
			if cadishfile.ContainsEnvPlaceholder(name) || cadishfile.ContainsEnvPlaceholder(q.Value) {
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("rule %d match %d queryParam %q contains an environment-variable placeholder ({$VAR}), which is not allowed", ri, mi, name)})
				ok = false
				continue
			}
			qt := gatewayv1.QueryParamMatchExact
			if q.Type != nil {
				qt = *q.Type
			}
			switch qt {
			case gatewayv1.QueryParamMatchExact:
				gm.conds = append(gm.conds, matcherSpec{typ: "query", args: []string{cadishfile.QuoteArg(name), cadishfile.QuoteArg(q.Value)}})
			default:
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("rule %d match %d queryParam %q type %q is unsupported (RegularExpression query matching is deferred — UnsupportedValue)", ri, mi, name, qt)})
				ok = false
			}
		}
		// Method.
		if m.Method != nil {
			if cadishfile.ContainsEnvPlaceholder(string(*m.Method)) {
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("rule %d match %d method contains an environment-variable placeholder ({$VAR}), which is not allowed", ri, mi)})
				ok = false
			} else {
				gm.conds = append(gm.conds, matcherSpec{typ: "method", args: []string{cadishfile.QuoteArg(string(*m.Method))}})
			}
		}

		if !ok {
			continue
		}
		out = append(out, gm)
	}
	return out, rejects
}

// resolveBackends resolves a rule's backendRefs into a weighted backend pool. A cross-
// namespace backendRef requires a ReferenceGrant (HTTPRoute → Service). A non-Service ref,
// a missing port, an unpermitted cross-namespace ref, or a reference to a Service that does
// not exist (BackendNotFound, via serviceExists when non-nil) drops that backendRef
// (recorded); ok is false only when NO backend resolved (the rule routes nothing). A
// backendRef with no explicit weight defaults to 1; weight 0 is kept (excluded from serving
// by usableBackends). serviceExists may be nil — then Service existence is NOT enforced.
func resolveBackends(rt *gatewayv1.HTTPRoute, ri int, rule *gatewayv1.HTTPRouteRule, grants grantIndex, serviceExists func(ns, name string) bool) ([]gwBackend, bool, []Reject) {
	rk := routeKey(rt)
	var rejects []Reject
	var pool []gwBackend
	if len(rule.BackendRefs) == 0 {
		return nil, false, nil
	}
	for bi := range rule.BackendRefs {
		be := &rule.BackendRefs[bi]
		if be.Group != nil && *be.Group != "" {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: fmt.Sprintf("rule %d backendRef group %q is unsupported; only core Services are supported", ri, *be.Group)})
			continue
		}
		if be.Kind != nil && *be.Kind != "Service" {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: fmt.Sprintf("rule %d backendRef kind %q is unsupported; only Service backends are supported", ri, *be.Kind)})
			continue
		}
		if be.Name == "" {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk, Reason: fmt.Sprintf("rule %d backendRef has no service name", ri)})
			continue
		}
		bns := rt.Namespace
		if be.Namespace != nil && string(*be.Namespace) != "" && string(*be.Namespace) != rt.Namespace {
			bns = string(*be.Namespace)
			if !grants.allows(bns, "Service", string(be.Name), rt.Namespace, "HTTPRoute") {
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
					Reason: fmt.Sprintf("rule %d cross-namespace backendRef to Service %s/%s is not permitted by a ReferenceGrant (RefNotPermitted)", ri, bns, be.Name)})
				continue
			}
		}
		if be.Port == nil || *be.Port == 0 {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk, Reason: fmt.Sprintf("rule %d backendRef to Service %q has no port", ri, be.Name)})
			continue
		}
		// Existence (GW1): a structurally-valid backendRef whose Service does NOT exist is
		// BackendNotFound — drop it so the rule's ResolvedRefs becomes False. The data plane
		// already fails closed (empty k8s:// upstream → 502); this is the status-conformance
		// fix. Skipped when serviceExists is nil (no informer / older tests).
		if serviceExists != nil && !serviceExists(bns, string(be.Name)) {
			rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
				Reason: fmt.Sprintf("rule %d backendRef to Service %s/%s does not exist (BackendNotFound)", ri, bns, be.Name)})
			continue
		}
		weight := int32(1)
		if be.Weight != nil {
			weight = *be.Weight
		}
		pool = append(pool, gwBackend{ns: bns, svc: string(be.Name), port: fmt.Sprintf("%d", *be.Port), weight: weight})
	}
	if len(pool) == 0 {
		return nil, false, rejects
	}
	if len(pool) > 1 {
		// cadish has no per-backend weight knob: a multi-backend pool is served as an
		// even-weighted round-robin lb pool (D82). Note this once so an operator relying on
		// proportional weights knows the approximation (not a hard failure).
		rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
			Reason: fmt.Sprintf("rule %d has %d weighted backendRefs; served as an even-weighted pool (cadish has no per-backend weight; proportional weights are approximated — see docs/gateway-api.md)", ri, len(pool))})
	}
	return pool, true, rejects
}

// collectFilterRejects inspects a rule's filters and surfaces UnsupportedValue rejects for
// filters this slice does not implement, rather than silently dropping them. (No filter is
// folded into the route yet; this keeps behaviour honest and visible — see D82.)
func collectFilterRejects(rt *gatewayv1.HTTPRoute, ri int, rule *gatewayv1.HTTPRouteRule) ([]matcherSpec, []Reject) {
	rk := routeKey(rt)
	var rejects []Reject
	for fi := range rule.Filters {
		f := &rule.Filters[fi]
		rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: rk,
			Reason: fmt.Sprintf("rule %d filter %q is not implemented in this release (UnsupportedValue); the route still serves its backend", ri, f.Type)})
	}
	return nil, rejects
}

// NOTE: tenant-authored match names, values, methods, and paths are rendered through the
// canonical cadishfile.QuoteArg (force-quoting whitespace/quotes/semicolons/leading-#/
// trailing-backslash AND the block-structural braces) so a hostile HTTPRoute value can
// never break out of its directive or its host block (R01/R24/R25; see ADR D90). The old
// hand-rolled quoteArg that quoted only on space/tab/" has been removed — never add a
// bespoke quoter; always route generated text through cadishfile.QuoteArg.
