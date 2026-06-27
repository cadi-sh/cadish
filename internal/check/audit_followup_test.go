package check

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// TestRouteDeadRule: route is first-match-wins, so a duplicate `@selector` route is
// unreachable and must be flagged (audit 2026-06-24 — route was missing from the
// dead-rule lint that already covered cache_ttl/storage/cache_key/pass).
func TestRouteDeadRule(t *testing.T) {
	src := `example.com {
  upstream a { to http://a:80 }
  upstream b { to http://b:80 }
  @api path /api/*
  route @api -> a
  route @api -> b
}`
	r, err := CheckSource("routes.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["dead-rule"]; n != 1 {
		t.Errorf("dead-rule count = %d, want 1 (the duplicate `route @api`)\n%s", n, render(t, r))
	}
}

// TestCatalogSubsetOfRegistry: every directive the `cadish check` cost/phase catalog
// (directivePhase) knows must also be a known directive in cadishfile.DefaultDirectives,
// so the two source-of-truth lists can't silently diverge (audit 2026-06-24 — `admin`
// was in the catalog but not the registry; `transform` was a no-op ghost in both).
func TestCatalogSubsetOfRegistry(t *testing.T) {
	known := map[string]bool{}
	for _, n := range cadishfile.DefaultDirectives {
		known[n] = true
	}
	for d := range directivePhase {
		if !known[d] {
			t.Errorf("directive %q is in the check catalog (directivePhase) but not in cadishfile.DefaultDirectives — the lists have diverged", d)
		}
	}
}

// TestEveryRegisteredDirectiveHasPhase is the REVERSE of TestCatalogSubsetOfRegistry:
// every directive the runtime accepts (cadishfile.DefaultDirectives — the same list
// pipeline.Compile's knownDirectives is built from) MUST have an explicit
// directivePhase entry. Without one, phaseOf() silently defaults the directive to
// PhaseRECV, so `cadish check` reports a WRONG lifecycle phase and per-request cost
// for a directive `cadish run` actually honors — the "check mis-costs a directive run
// honors" divergence class. A Setup-phase directive defaulted to RECV would be charged
// a phantom per-request cost in the cost breakdown. This makes the missing-phase a
// hard test failure (the operator must classify the new directive's phase explicitly).
func TestEveryRegisteredDirectiveHasPhase(t *testing.T) {
	for _, n := range cadishfile.DefaultDirectives {
		if _, ok := directivePhase[n]; !ok {
			t.Errorf("registered directive %q has no directivePhase entry — phaseOf() silently "+
				"defaults it to PhaseRECV, so `cadish check` mis-reports its phase/cost vs what "+
				"`cadish run` honors. Add an explicit directivePhase entry classifying its lifecycle phase.", n)
		}
	}
}

// wiredDirectives is the curated set of catalogued directives (directivePhase keys)
// that resolve to REAL behavior somewhere in cadish. "Real behavior" is broader than
// "consumed by pipeline.Compile": several are config-/server-layer directives wired
// outside the request pipeline (tls termination, listener setup, the admin dashboard,
// the access-log hub, the security audit-log sink, the PROXY-protocol listener, the
// per-upstream transport knobs). The point of the set is to be an EXPLICIT, reviewed
// inventory: a programmatic "has handler" signal does not exist (compile.go's switch
// is unreachable from a test, and the config layer wires the rest), so this is a
// maintained assertion.
//
// MAINTENANCE CONTRACT: when you add a directive to directivePhase (the check
// catalog), you MUST also add it here — UNLESS it is an intentional no-op, in which
// case add it to intentionalNoOps below with a comment. TestEveryCatalogedDirectiveIsWired
// fails otherwise, which is the whole point: it makes "catalogued but unwired" a
// conscious decision rather than a silent drift (audit 2026-06-24 root-cause fix).
var wiredDirectives = map[string]string{
	// --- setup / config-layer directives (wired outside pipeline.Compile) ---
	"tls":            "TLS termination + ACME (server/config layer)",
	"cache":          "two-tier RAM+NVMe cache config (server/config layer)",
	"upstream":       "origin pool (pipeline pass 1: upstreamNames)",
	"cluster":        "named upstream cluster (pipeline pass 1)",
	"origin":         "upstream alias (pipeline pass 1)",
	"lb":             "load-balancing policy (server/config layer)",
	"sticky":         "sticky-session cookie (cache key {sticky} + LB)",
	"host_header":    "origin Host header override (transport, config layer)",
	"sni":            "per-upstream TLS ServerName (http.Transport, config layer)",
	"http_reuse":     "per-upstream keepalive toggle (http.Transport, config layer)",
	"tls_insecure":   "per-upstream origin TLS skip-verify (http.Transport, config layer)",
	"ca_file":        "per-upstream origin TLS RootCAs pool (http.Transport, config layer)",
	"alpn":           "per-upstream origin TLS ALPN pin (http.Transport, config layer)",
	"resolve":        "per-upstream DNS resolver: re-resolution interval + nameserver(s) (lb pool, config layer)",
	"import":         "splice-time include (resolved before Compile)",
	"device_detect":  "UA classifier (config layer; feeds {device} key token)",
	"geo":            "geo resolution (config layer; feeds {geo}/geo matcher)",
	"trust_proxy":    "trusted-proxy CIDRs (config layer; feeds geo/ip ACL)",
	"tenant":         "tenant resolver (pipeline: p.tenantResolver)",
	"normalize":      "bucket normalizer (pipeline pass 1: p.normalizers)",
	"classify":       "derived-token classifier (pipeline pass 1b: p.classifiers)",
	"admin":          "dashboard/metrics listener (server/config layer, D16)",
	"edge":           "edge worker policy block (pipeline: compileEdgeBlock)",
	"access_log":     "in-memory access-log hub (server/config layer, D44)",
	"strict_host":    "strict-host site selection (config.StrictHost -> server routing 421)",
	"security":       "security audit-log sink (server/config layer, D52)",
	"proxy_protocol": "PROXY-protocol listener (server/config layer)",
	"server":         "inbound maxconn/read_timeout/idle_timeout knobs (config.ServerConfig -> server listener/timeouts)",
	// --- request-pipeline directives (consumed by pipeline.Compile's switch) ---
	"respond":              "compileRespond / compileOnError (RECV / ORIGIN)",
	"redirect":             "compileRedirect (RECV)",
	"purge":                "compilePurge (RECV)",
	"route":                "compileRoute (RECV)",
	"pass":                 "parseScopeAll -> passRules (RECV)",
	"upgrade":              "parseScopeAll -> upgradeRules (RECV); server tunnel in internal/server/upgrade.go",
	"cache_credentialed":   "parseScopeAll -> credentialedRules (RECV, D101); server skips BypassForCredentials + forwards cookies; EvalResponse origin-authoritative store; edge EdgeIR.CacheCredentialed",
	"rewrite":              "compileRewrite (RECV)",
	"allow":                "compileSecurityRule(secAllow) (RECV security gate)",
	"deny":                 "compileSecurityRule(secDeny) (RECV security gate)",
	"block":                "compileSecurityRule(secDeny) (RECV security gate)",
	"monitor":              "compileMonitorToggle -> securityMonitor (setup)",
	"rate_limit":           "compileRateLimit (RECV security gate)",
	"cache_key":            "compileCacheKeyRule (KEY)",
	"cache_ttl":            "compileTTL (ORIGIN/store)",
	"storage":              "compileStorage (ORIGIN/store)",
	"cache_unsafe":         "p.cacheUnsafe flag (response-phase safe-default opt-out)",
	"client_cache_control": "p.ignoreClientRevalidation flag; server gates clientForcesRevalidate at LOOKUP (RFC 9111 §5.2.1.4 opt-out)",
	"header":               "compileHeader (req/resp header ops)",
	"strip_cookies":        "parseScopeAll -> stripRules (DELIVER)",
	"cookie_allow":         "p.cookieAllow nameGlobSet; server FilterRequestCookies strips non-allowed cookies at RECV",
	"cors":                 "compileCORS (DELIVER)",
	"replace":              "compileReplace -> transformRules (DELIVER body transform)",
	"encode":               "compileEncode -> encodeRule (DELIVER)",
}

// intentionalNoOps is the small, explicit allowlist of catalogued directives that
// compile to a NO-OP on purpose. A directive here is exempt from the "must be wired"
// gate. Adding to this set must be a CONSCIOUS decision with a comment explaining why
// the no-op is intentional.
var intentionalNoOps = map[string]string{
	// `transform { … }` is a deprecated no-op alias: `cadish check` warns ("no-op-directive")
	// and tells the operator to use `replace` directly. It is NOT in directivePhase or
	// DefaultDirectives today (it survives only as a check-time diagnostic in analyze.go),
	// but it is listed here as the canonical example so this allowlist is never empty and
	// the intent is documented for the next no-op directive.
	"transform": "deprecated alias for `replace`; check warns no-op-directive (analyze.go)",
}

// TestEveryCatalogedDirectiveIsWired is the META-GATE against directive drift: every
// directive in the check catalog (directivePhase) must resolve to REAL behavior
// (listed in wiredDirectives) OR be an explicit intentional no-op (intentionalNoOps).
//
// WHAT IT CATCHES: if someone adds a directive to directivePhase (so `cadish check`
// reports a phase/cost for it) but forgets to wire a handler, this test FAILS —
// forcing them to either add the wiring inventory entry (after actually wiring it) or
// consciously declare it an intentional no-op. It also catches a stale wiredDirectives
// entry for a directive that was removed from the catalog. This is the root-cause
// guard for "catalogued + registered but compiles to a no-op" drift (audit 2026-06-24).
func TestEveryCatalogedDirectiveIsWired(t *testing.T) {
	for d := range directivePhase {
		_, wired := wiredDirectives[d]
		_, noop := intentionalNoOps[d]
		switch {
		case wired && noop:
			t.Errorf("directive %q is in BOTH wiredDirectives and intentionalNoOps — pick one", d)
		case !wired && !noop:
			t.Errorf("directive %q is in the check catalog (directivePhase) but is NOT wired to behavior "+
				"(not in wiredDirectives) and NOT declared an intentional no-op (not in intentionalNoOps).\n"+
				"If you wired a real handler for it, add it to wiredDirectives with a one-line note of where.\n"+
				"If it is a deliberate no-op, add it to intentionalNoOps with a comment explaining why.", d)
		}
	}
	// Reverse direction: a wiredDirectives entry that is no longer in the catalog is
	// stale and must be removed (keeps the inventory honest as directives are retired).
	for d := range wiredDirectives {
		if _, ok := directivePhase[d]; !ok {
			t.Errorf("wiredDirectives lists %q but it is not in the check catalog (directivePhase) — stale entry, remove it", d)
		}
	}
}
