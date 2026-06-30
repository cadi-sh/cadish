package check

import (
	"strconv"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// directivePhase maps a directive keyword to the lifecycle phase it runs in.
// Setup directives are parse-once and do not contribute to per-request cost.
var directivePhase = map[string]Phase{
	// `tls { … }` is parse-once TLS termination config (acme/cert/key/off/hsts and the
	// `http_redirect_except /path …` :80-redirect exemption). Its sub-options live inside
	// the block — they are NOT top-level directives, so they are never individually
	// cataloged or flagged (the walk only inspects top-level nodes); `http_redirect_except`
	// only shapes the :80 HTTP→HTTPS redirect decision (skip the 301 for named probe/
	// data-plane paths) and adds NO per-request cost on the served path, so the whole `tls`
	// block is Setup. See ADR D89.
	"tls":         PhaseSetup,
	"cache":       PhaseSetup,
	"upstream":    PhaseSetup,
	"cluster":     PhaseSetup,
	"origin":      PhaseSetup,
	"lb":          PhaseSetup,
	"sticky":      PhaseSetup,
	"host_header": PhaseSetup,
	// `sni <server-name>` / `http_reuse never` (gap H6) are per-upstream TRANSPORT
	// knobs parsed once at config load — they shape the origin's http.Transport
	// (TLS ServerName / DisableKeepAlives), never a per-request matcher — so Setup
	// (zero per-request cost).
	"sni":        PhaseSetup,
	"http_reuse": PhaseSetup,
	// TLSVERIFY (per-upstream origin TLS verification): `tls_insecure` (skip
	// verification = HAProxy `ssl verify none`), `ca_file <path>` (verify against a
	// private CA), `alpn <proto…>` (pin the origin ALPN). All are parsed once at
	// config load and shape the origin's http.Transport TLS config — never a
	// per-request matcher — so they are Setup (zero per-request cost). `tls_insecure`
	// additionally raises a security warning (see detectInsecureOriginTLS).
	"tls_insecure": PhaseSetup,
	"ca_file":      PhaseSetup,
	"alpn":         PhaseSetup,
	// `resolve [<interval>] [nameserver <ip:port>…]` (RESOLVER, sound subset) is a
	// per-upstream DNS knob: it picks the nameserver(s) a dns:// pool queries and the
	// re-resolution interval. Parsed once at config load and applied to the pool's
	// resolver + ticker — never a per-request matcher — so Setup (zero per-request cost).
	"resolve":       PhaseSetup,
	"import":        PhaseSetup,
	"device_detect": PhaseSetup,
	"geo":           PhaseSetup,
	// `trust_proxy <CIDR…>` is the standalone site-level trusted-proxy declaration
	// (decoupled from the geo block). It is parsed once at config load to populate
	// Site.TrustedProxies for {geo} resolution and the security `ip` ACL — no
	// per-request matcher cost — so it is Setup.
	"trust_proxy": PhaseSetup,
	"tenant":      PhaseSetup,
	"normalize":   PhaseSetup,
	"classify":    PhaseSetup,
	"admin":       PhaseSetup,
	// `edge {}` configures the Cadish Edge worker (deploy identity + cache-tier
	// policies); it adds no per-request cost on the cadish SERVER, so it is Setup.
	"edge": PhaseSetup,
	// `access_log off` is a global option that disables the in-memory access-log
	// fan-out hub (D44). It is read once at startup and changes only whether the hot
	// path's idle atomic check is ever non-zero — it adds no per-request matcher
	// cost — so it is Setup.
	"access_log": PhaseSetup,
	// global `strict_host` option: reject a request whose Host matches no declared
	// site address with 421 (instead of the lenient single-site fallback). Read once
	// at routing-build time; it only changes site selection for an UNDECLARED Host and
	// adds no per-request matcher cost on the served path, so it is Setup.
	"strict_host": PhaseSetup,
	// global `security { audit_log … }` block (WAF v1c, D52): security observability.
	// The audit-log target is read once at startup and only governs whether ENFORCED/
	// MONITORED gate events are written to an async, off-hot-path sink — it adds no
	// per-request matcher cost (and OFF by default = zero cost), so it is Setup.
	"security": PhaseSetup,
	// global `proxy_protocol { trust … }` block: the opt-in PROXY-protocol listener
	// (recover the real client IP behind an L4/TCP-passthrough LB). It is read once at
	// startup and only governs whether the inbound listener reads a PROXY v1/v2 header
	// on accept — it adds no per-request matcher cost (and is OFF by default = the bare
	// listener, zero cost), so it is Setup.
	"proxy_protocol": PhaseSetup,
	// global `server { maxconn N; read_timeout D; idle_timeout D }` block: the inbound
	// data-plane connection knobs. Read once at startup — it shapes the inbound
	// http.Server timeouts and installs an optional LimitListener — and adds no
	// per-request matcher cost (and is OFF by default = the shipped defaults, zero
	// cost), so it is Setup.
	"server": PhaseSetup,

	"respond":  PhaseRECV,
	"redirect": PhaseRECV,
	"purge":    PhaseRECV,
	"route":    PhaseRECV,
	"pass":     PhaseRECV,
	// `upgrade @scope` enables a WebSocket / `Connection: Upgrade` passthrough tunnel
	// in RECV (before LOOKUP/ORIGIN). COST: it bypasses the cache entirely (implies
	// pass) AND opens a long-lived, hijacked bidirectional connection per matching
	// upgrade request — far more expensive than a normal request, so use a tight scope.
	"upgrade": PhaseRECV,
	// `rewrite` edits the origin-bound path/query in RECV (before LOOKUP/ORIGIN).
	// Its per-request cost is its optional matcher scope plus a cheap string op on
	// the request line (a regex path replace, a query name scan), never the body.
	"rewrite": PhaseRECV,
	// SECURITY GATE (WAF v1a, native primitives — server-only, never at the edge).
	// `allow`/`deny`/`block` are the FIRST step of RECV: evaluated before the cache
	// key / cache lookup / origin, so an enforced deny touches neither. Their
	// per-request cost is the gate's matcher conjunction (an `ip` CIDR test, a `geo`
	// lookup, a `path` glob) — cheap request-phase checks, charged once via the
	// named-matcher pass. `monitor` is a global toggle (parse-once), so it is Setup.
	"allow":   PhaseRECV,
	"deny":    PhaseRECV,
	"block":   PhaseRECV,
	"monitor": PhaseSetup,
	// `rate_limit` is the THIRD step of the security gate (after allow/deny), the
	// stateful native primitive (WAF v1b, server-only). Its per-request cost is its
	// optional matcher scope (charged via the named-matcher pass) plus a cheap token-
	// bucket consult keyed on the resolved client IP / a header / global — a constant-
	// time map+lock op, no regex, no body. RECV (before cache key / cache / origin).
	"rate_limit": PhaseRECV,

	// `cookie_allow NAME…` strips every request cookie not on the allowlist, at RECV —
	// before the cache key and the origin fetch. It is the explicit opt-in to caching
	// cookie-bearing traffic (the controlled cookies survive; the rest, incl. any
	// session, are removed). Parse-once name set, no per-request matcher cost.
	"cookie_allow": PhaseRECV,

	"cache_key": PhaseKEY,

	"cache_ttl": PhaseORIGIN,
	"storage":   PhaseORIGIN,
	// `cache_unsafe` is the site-level opt-out of safe-by-default caching: a parse-once
	// toggle read at compile that flips whether EvalResponse refuses to cache a
	// Set-Cookie / private / uncovered-Vary response. It carries no matcher scope and
	// adds no per-request cost (the response-header inspection it disables runs only on
	// already-cacheable responses), so it is Setup.
	"cache_unsafe": PhaseSetup,
	// `cache_credentialed @scope` makes caching ORIGIN-AUTHORITATIVE for the matching
	// credentialed requests (D101): a RECV-phase decision (it gates the request-time credential
	// bypass — skip it + forward the original cookies to origin), with the actual store/refuse
	// precedence applied in EvalResponse. Like `pass` it is a request-phase OR-scope; its
	// per-request cost is one scope evaluation on a site that declares it (zero otherwise). Its
	// matcher uses are counted via the `pass`/`strip_cookies`/`upgrade` scope-usage case so a
	// matcher used only to scope it is not flagged unused.
	"cache_credentialed": PhaseRECV,
	// `client_cache_control ignore` is the site-level opt-out of honoring a request's
	// client-forced revalidation (`Cache-Control: no-cache`/`max-age=0`, `Pragma:
	// no-cache`; RFC 9111 §5.2.1.4). A parse-once toggle read at compile that flips one
	// boolean checked on the LOOKUP hot path — when set, the server SKIPS the cheap
	// client-revalidation header scan entirely (zero per-request cost) and serves the
	// fresh/stale entry instead of forcing a MISS. It carries no matcher scope, so it is
	// Setup. (Hot-path note: it gates, and can short-circuit, a per-request header scan.)
	"client_cache_control": PhaseSetup,

	"header":        PhaseDELIVER,
	"strip_cookies": PhaseDELIVER,
	"cors":          PhaseDELIVER,
	"replace":       PhaseDELIVER,
	// `encode` compresses the response body on delivery (negotiated on
	// Accept-Encoding, post-cache). It runs in the DELIVER phase; its per-request
	// cost is the per-HIT compression CPU, not a matcher evaluation (it carries no
	// matcher scope in v1), so it adds no matcher-class cost to the breakdown.
	"encode": PhaseDELIVER,
}

// phaseOf returns the phase for a directive, defaulting to RECV for unknown
// directives (they still execute somewhere on the request path).
func phaseOf(name string) Phase {
	if p, ok := directivePhase[name]; ok {
		return p
	}
	return PhaseRECV
}

// phaseOfDirective returns the lifecycle phase for a directive INSTANCE, accounting
// for sub-forms whose phase differs from the bare directive. `respond on_error` is
// the origin-error fallback (D57): it runs on the ORIGIN path (after the cache/origin
// bottoms out), not in RECV like the bare `respond PATH STATUS BODY` short-circuit.
func phaseOfDirective(d *cadishfile.Directive) Phase {
	if d.Name == "respond" && len(d.Args) >= 1 && d.Args[0].Raw == "on_error" {
		return PhaseORIGIN
	}
	return phaseOf(d.Name)
}

// knownMatcherTypes / knownDirectives are sets derived from the cadishfile
// catalog, used to flag unknown names.
var (
	knownMatcherTypes = sliceSet(cadishfile.DefaultMatcherTypes)
	defaultDirectives = sliceSet(cadishfile.DefaultDirectives)
)

func sliceSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func isMatcherType(s string) bool { return knownMatcherTypes[s] }

// matcherClass is the weight class of an evaluated matcher.
type matcherClass int

const (
	classExact matcherClass = iota
	classGlob
	classRegex
)

// classifyMatcher returns the weight class of a matcher of the given type and
// args. The second result reports whether it is a regex evaluation (counted
// separately as the headline "regex evals / request" metric).
//
// Rules:
//   - path:        glob if any arg contains '*', else exact (one trie/set lookup).
//   - host:        glob if any arg uses a '*.' wildcard, else exact.
//   - path_regex,
//     host_regex:  always regex.
//   - header:      regex if a value arg looks like a regex (best-effort), else
//     exact (presence/equality compare).
//   - method,
//     upstream:    exact.
//   - unknown:     exact (cost is unknown; treated as a cheap compare).
func classifyMatcher(typ string, args []cadishfile.Arg) (matcherClass, bool) {
	switch typ {
	case "path_regex", "host_regex":
		return classRegex, true
	case "header_regex":
		// A request-phase RE2 regex applied to a header value (the Accept-Language
		// language gate). It IS a real regex evaluation — charge it at the regex tier
		// and count it in the "regex evals / request" headline, exactly like
		// path_regex/host_regex.
		return classRegex, true
	case "path", "host":
		// glob if any pattern uses a wildcard ('/a/*', '*.example.com'), else a
		// single trie/set lookup.
		return globOrExact(anyArgContains(args, "*"))
	case "header":
		// args[0] is the header name; args[1:] (if any) is the value to match.
		if len(args) >= 2 && looksLikeRegex(args[1].Raw) {
			return classRegex, true
		}
		return classExact, false
	case "header_present":
		// A request-header existence test — a single raw-map lookup, cheapest tier.
		return classExact, false
	case "content_type":
		// A response-phase substring scan over a short Content-Type — a cheap
		// compare, like an exact match for cost purposes.
		return classExact, false
	case "resp_header":
		// A response-phase test of a named origin response header value. args[0] is the
		// header NAME; args[1:] (if any) are exact-or-`*`-glob value patterns. A glob
		// value scans via the name-glob engine (like `query_present`), so a `*` value makes
		// it a glob-class evaluation; otherwise it is a cheap exact compare. Never a regex.
		var values []cadishfile.Arg
		if len(args) > 1 {
			values = args[1:]
		}
		return globOrExact(anyArgContains(values, "*"))
	case "set_cookie":
		// A response-phase scan of the Set-Cookie header(s) for presence or a
		// named cookie — a cheap compare, like an exact match for cost purposes.
		return classExact, false
	case "cookie":
		// A request-phase cookie test. A bare `cookie NAME` is an exact lookup; a
		// `cookie NAME*` prefix glob scans every cookie name, so it is counted as a
		// glob (like a `path`/`host` wildcard) rather than a cheap exact compare.
		return globOrExact(len(args) >= 1 && strings.HasSuffix(args[0].Raw, "*"))
	case "cookie_json", "header_json":
		// A request-phase bounded JSON field test inside a cookie/header value (D54).
		// It costs a small, size/depth-capped JSON parse on ONE header value — pricier
		// than a plain `cookie` exact compare, so it is charged at the regex cost tier
		// (weight 10). It is NOT an RE2 evaluation, so the second result is false: it
		// must not inflate the "regex evals / request" headline (which counts real
		// regex matchers). The 8 KiB size cap and depth-32 nesting cap bound the parse.
		return classRegex, false
	case "geo":
		// A request-phase test of a server-resolved geo class (country/continent/
		// region) against a small OR set — a cheap map lookup, like an exact compare.
		return classExact, false
	case "ip":
		// A request-phase IP/CIDR ACL test of the resolved client IP against a small
		// OR set of prefixes — a handful of netip prefix-contains compares, like an
		// exact match for cost purposes (no regex, no body).
		return classExact, false
	case "query_present":
		// A request-phase presence-OR over the query params. Exact names are a hash
		// lookup, but a `*` glob name forces a scan over every param name, so any
		// glob arg makes it a glob-class evaluation (like `cookie NAME*`).
		return globOrExact(anyArgContains(args, "*"))
	case "query":
		// A request-phase exact-value test of ONE named query param against an OR set
		// of values — a single map lookup plus a small equality scan, like an exact
		// compare (no regex, no glob).
		return classExact, false
	case "all":
		// AND-composite: the cost is its sub-matchers' costs (charged when THEY are
		// referenced/counted). The composite itself adds only a cheap conjunction walk,
		// so it is exact-class here (its sub-matchers carry the real per-class cost).
		return classExact, false
	case "upstream_healthy":
		// A request-phase liveness probe over one or more named pools: an O(1) read of
		// the maintained health/ejection state (lb nbsrv()>0), no dial, no regex, no body.
		// A handful of cheap pointer/map reads — charge it like an exact compare.
		return classExact, false
	default: // method, upstream, unknown
		return classExact, false
	}
}

// anyArgContains reports whether any arg's raw text contains sub.
func anyArgContains(args []cadishfile.Arg, sub string) bool {
	for _, a := range args {
		if strings.Contains(a.Raw, sub) {
			return true
		}
	}
	return false
}

// globOrExact returns the (class, isRegex) pair for a non-regex matcher: classGlob
// when isGlob, else classExact. Neither is a regex evaluation.
func globOrExact(isGlob bool) (matcherClass, bool) {
	if isGlob {
		return classGlob, false
	}
	return classExact, false
}

// looksLikeRegex is a conservative heuristic for whether a header match value is
// a regular expression rather than a literal. It treats common RE2 metacharacters
// as the signal. Placeholders ("{$VAR}", "{http.X}") are not regexes.
func looksLikeRegex(s string) bool {
	if strings.HasPrefix(s, "{") {
		return false
	}
	return strings.ContainsAny(s, "^$|()[]+*?\\")
}

// addClass accumulates a class into a CostBreakdown.
func (c *CostBreakdown) addClass(cl matcherClass) {
	switch cl {
	case classExact:
		c.Exact++
	case classGlob:
		c.Glob++
	case classRegex:
		c.Regex++
	}
}

// inlineUse is an anonymous matcher written directly in a directive (e.g.
// `strip_cookies path_regex \.css$`).
type inlineUse struct {
	typ  string
	args []cadishfile.Arg
	pos  cadishfile.Pos
}

// usages is what a single directive evaluates: named-matcher references, inline
// (anonymous) matchers, and bare selectors (`status`, `default`).
type usages struct {
	refs      []refUse
	inlines   []inlineUse
	selectors []string
}

// refUse is a reference to a named matcher at a source position.
type refUse struct {
	name string
	pos  cadishfile.Pos
}

// directiveUsages extracts the matcher scope a directive is conditioned on. It
// understands the v1 directive catalog's argument shapes. Directives with no
// matcher scope return an empty usages.
func directiveUsages(d *cadishfile.Directive) usages {
	switch d.Name {
	case "respond":
		// The bare `respond PATH STATUS BODY` short-circuit carries no matcher scope
		// (PATH is an exact path string, not a matcher).
		//   - `respond on_error [@scope] STATUS BODY` (D57) carries a leading @matcher
		//     scope; count it so a matcher used only to scope an on_error page is NOT
		//     flagged unused.
		//   - `respond @scope… STATUS BODY` (the ingress terminal no-match handler) is a
		//     conjunction of (optionally `!`-negated) @matcher refs — the security-gate
		//     grammar — so count each ref as a USE (mirrors allow/deny).
		if len(d.Args) >= 1 && d.Args[0].Raw == "on_error" {
			return scopeUsages(d.Args[1:])
		}
		if len(d.Args) >= 1 && (d.Args[0].Kind == cadishfile.ArgMatcherRef || strings.HasPrefix(d.Args[0].Raw, "!@")) {
			return securityUsages(d.Args)
		}
		return usages{}
	case "route":
		// route SCOPE -> TARGET. The scope is the OR form (a run of leading @refs, or one
		// inline matcher) — consistent with `pass`. A multi-criteria (AND) route references
		// a single `all` composite matcher (`route @gw -> u`); the `all` def itself counts
		// its sub-refs as uses. Count every leading @ref here as a USE so a matcher
		// referenced only by a route is not flagged unused.
		cond := argsBefore(d.Args, "->")
		if len(cond) > 0 && cond[0].Kind == cadishfile.ArgMatcherRef {
			return scopeUsages(cond)
		}
		return scopeUsages(cond)
	case "storage":
		// scope -> TARGET
		return scopeUsages(argsBefore(d.Args, "->"))
	case "pass", "strip_cookies", "upgrade", "cache_credentialed":
		// the whole arg list is the scope (possibly empty = catch-all)
		return scopeUsages(d.Args)
	case "allow", "deny", "block":
		// SECURITY GATE: `ACTION <terms> [monitor]`, where <terms> is a conjunction of
		// (optionally `!`-negated) @matcher refs OR one inline matcher. Every ref is a
		// USE (so a matcher referenced only by allow/deny is NOT flagged unused — the
		// `ip` matcher used by allow/deny mirrors the `replace` regression guard). A
		// trailing `monitor` keyword is a flag, not a matcher.
		return securityUsages(d.Args)
	case "rate_limit":
		// rate_limit [@scope… | INLINE-MATCHER] RATE [burst N] [key …] [monitor]: only
		// the leading matcher scope is a USE (so a matcher used only to scope a
		// rate_limit rule is NOT flagged unused). The rate spec / burst / key / monitor
		// tokens are not matchers.
		return rateLimitUsages(d.Args)
	case "cache_ttl":
		// selector [ttl DUR | from_header HEADER | hit_for_miss DUR] followed (on ttl /
		// from_header) by an optional tail of grace / max_stale windows — each either a
		// literal (`grace DUR` / `max_stale DUR`) or origin-header-sourced
		// (`grace_from_header NAME` / `max_stale_from_header NAME`). grace_from_header /
		// max_stale_from_header are TAIL sub-keywords of cache_ttl, NOT standalone
		// directives, so they need no directive registration and do not shift the
		// selector boundary. Only the leading selector is a matcher usage; the durations /
		// header names after the action keyword are not matchers.
		return scopeUsages(argsBeforeAny(d.Args, "ttl", "from_header", "hit_for_miss"))
	case "cache_key":
		// cache_key [SELECTOR] TOKEN… (scoped cache_key): an OPTIONAL leading selector
		// (a run of @matcher refs, or the `default`/`status` keyword) picks the recipe.
		// Count the selector refs as USES so a matcher used only to scope a cache_key
		// recipe is NOT flagged unused. The key TOKENS that follow (host/path/url/
		// header:NAME/{…}) are the key vocabulary, never matchers.
		return keyUsages(d.Args)
	case "header":
		return headerUsages(d.Args)
	case "purge":
		// purge when <cond> [regex EXPR | regex-path EXPR]
		rest := argsAfter(d.Args, "when")
		return scopeUsages(argsBeforeAny(rest, "regex", "regex-path"))
	case "redirect":
		// Four forms, disambiguated by the first arg:
		//   - `redirect @scope… CODE TARGET` — a leading @matcher is a SCOPED form;
		//     the leading run of refs is the matcher scope (so they count as
		//     referenced, not unused). The scope's own cost is charged once via the
		//     named-matcher pass.
		//   - `redirect @scope… PATH_REGEX CODE TARGET` — the combined form: the
		//     leading refs are the scope AND a path regex follows (≥3 args after the
		//     refs), so it adds one regex eval/request on top of the scope-match.
		//   - `redirect PATH_REGEX CODE TARGET` — a non-@, non-digit first arg is the
		//     implicit path_regex match (one regex eval/request).
		//   - `redirect CODE map { … }` — Args[0] is the status code; it compiles to
		//     one regex per map entry, counted as one representative regex eval.
		var u usages
		switch {
		case len(d.Args) >= 1 && d.Args[0].Kind == cadishfile.ArgMatcherRef:
			i := 0
			for i < len(d.Args) && d.Args[i].Kind == cadishfile.ArgMatcherRef {
				u.refs = append(u.refs, refUse{name: strings.TrimPrefix(d.Args[i].Raw, "@"), pos: d.Args[i].Pos})
				i++
			}
			// Combined form: a path regex precedes `CODE TARGET` (≥3 trailing args AND
			// the first arg is NOT a valid 3xx redirect code), so it costs one regex
			// eval/request like the bare regex form. The `!isRedirectCodeToken` guard
			// mirrors the parser's disambiguation (compileRedirectScoped): the scope-only
			// form with a trailing `no_store` modifier (`@scope CODE TARGET no_store`) also
			// leaves 3 trailing args, but its first is the CODE — without this guard the
			// catalog would wrongly register the status code as an inline path_regex cost.
			// Keying on a valid code (not merely "all digits") keeps the catalog in lockstep
			// with the parser for an all-digit PATH_REGEX combined form (e.g. `@scope 12 …`).
			if rest := d.Args[i:]; len(rest) >= 3 && !isRedirectCodeToken(rest[0].Raw) {
				u.inlines = append(u.inlines, inlineUse{typ: "path_regex", args: rest[:1], pos: rest[0].Pos})
			}
		case len(d.Args) >= 1 && !isAllDigits(d.Args[0].Raw):
			u.inlines = append(u.inlines, inlineUse{typ: "path_regex", args: d.Args[:1], pos: d.Args[0].Pos})
		case len(d.Args) >= 2 && d.Args[1].Raw == "map":
			// map form: one regex eval (representative).
			u.inlines = append(u.inlines, inlineUse{typ: "path_regex", args: nil, pos: d.Pos})
		}
		return u
	case "replace":
		// replace [@matcher…] OLD NEW — only the leading matcher-refs are a scope;
		// OLD/NEW are literal strings (don't misread one as an inline matcher type).
		var u usages
		for _, a := range d.Args {
			if a.Kind != cadishfile.ArgMatcherRef {
				break
			}
			u.refs = append(u.refs, refUse{name: strings.TrimPrefix(a.Raw, "@"), pos: a.Pos})
		}
		return u
	case "rewrite":
		// rewrite [@matcher…] OP … — the leading matcher-refs are the scope (so a
		// matcher used only by rewrite is NOT flagged unused). The `path` op carries
		// a regex (one regex eval/request); strip_query/set_query are cheap string
		// ops (no matcher eval). The OP keyword + its args are literals, never
		// inline matchers.
		var u usages
		i := 0
		for i < len(d.Args) && d.Args[i].Kind == cadishfile.ArgMatcherRef {
			u.refs = append(u.refs, refUse{name: strings.TrimPrefix(d.Args[i].Raw, "@"), pos: d.Args[i].Pos})
			i++
		}
		if i < len(d.Args) && d.Args[i].Raw == "path" && i+1 < len(d.Args) {
			u.inlines = append(u.inlines, inlineUse{typ: "path_regex", args: d.Args[i+1 : i+2], pos: d.Args[i+1].Pos})
		}
		return u
	default:
		return usages{}
	}
}

// classifyMatcherRefs returns the named-matcher references used in the `when`
// rows of a `classify {TOKEN} { … }` block. A row's matchers form a conjunction
// (AND); an inline matcher type (no leading @) is not a named reference and is
// skipped here. A bare `and`/`AND` readability connector is ignored.
func classifyMatcherRefs(d *cadishfile.Directive) []refUse {
	var out []refUse
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "when" {
			continue
		}
		for _, a := range argsBefore(bd.Args, "->") {
			if a.Kind == cadishfile.ArgMatcherRef {
				out = append(out, refUse{name: strings.TrimPrefix(a.Raw, "@"), pos: a.Pos})
			}
		}
	}
	return out
}

// classifyTokenOf returns the {TOKEN} name a `classify` block defines (without
// the braces), or "?" when it is malformed — used only for diagnostics.
func classifyTokenOf(d *cadishfile.Directive) string {
	if len(d.Args) >= 1 {
		raw := d.Args[0].Raw
		if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") && len(raw) > 2 {
			return raw[1 : len(raw)-1]
		}
		return raw
	}
	return "?"
}

// keyUsages extracts the selector matcher-uses of a `cache_key [SELECTOR] TOKEN…`
// directive. The selector is an OPTIONAL leading run of @matcher refs, or a single
// `default`/`status` keyword. Only that leading scope is a matcher usage; the key
// TOKENS after it (host/path/url/query/header:NAME/{…}) are never matchers, so the
// scan stops at the first non-ref arg. An unscoped line (no leading selector)
// returns no uses.
func keyUsages(args []cadishfile.Arg) usages {
	var u usages
	if len(args) > 0 && (args[0].Raw == "default" || args[0].Raw == "status") {
		u.selectors = append(u.selectors, args[0].Raw)
		return u
	}
	for _, a := range args {
		if a.Kind != cadishfile.ArgMatcherRef {
			break
		}
		u.refs = append(u.refs, refUse{name: strings.TrimPrefix(a.Raw, "@"), pos: a.Pos})
	}
	return u
}

// securityUsages extracts the matcher uses of an `allow`/`deny`/`block` rule:
// a conjunction of (optionally `!`-negated) @matcher refs, or one inline matcher.
// A plain `@x` arrives as ArgMatcherRef; a negated `!@x` arrives as an ArgLiteral
// whose text starts with `!@`, so both are counted as references. A trailing
// `monitor` keyword (and any `and` connector) is not a matcher. Counting the refs
// here is what keeps a matcher used only by the security gate from being flagged
// "unused".
func securityUsages(args []cadishfile.Arg) usages {
	// Drop a trailing `monitor` flag.
	if n := len(args); n > 0 && args[n-1].Raw == "monitor" {
		args = args[:n-1]
	}
	if len(args) == 0 {
		return usages{}
	}
	// Ref-conjunction form: the first term is a @ref or a !@ref.
	if args[0].Kind == cadishfile.ArgMatcherRef || strings.HasPrefix(args[0].Raw, "!@") {
		var u usages
		for _, a := range args {
			switch {
			case a.Raw == "and" || a.Raw == "AND":
				// readability connector
			case a.Kind == cadishfile.ArgMatcherRef:
				u.refs = append(u.refs, refUse{name: strings.TrimPrefix(a.Raw, "@"), pos: a.Pos})
			case strings.HasPrefix(a.Raw, "!@"):
				u.refs = append(u.refs, refUse{name: strings.TrimPrefix(a.Raw, "!@"), pos: a.Pos})
			}
		}
		return u
	}
	// Inline single matcher form: `deny ip 10.0.0.0/8`.
	if isMatcherType(args[0].Raw) {
		var u usages
		u.inlines = append(u.inlines, inlineUse{typ: args[0].Raw, args: args[1:], pos: args[0].Pos})
		return u
	}
	return usages{}
}

// rateLimitUsages extracts the matcher scope of a `rate_limit` rule: leading
// @matcher refs, or a single inline `TYPE arg` matcher before the rate spec. The
// rate spec (e.g. `100r/s`) is not a matcher type, so it is never mistaken for one.
// Counting the leading scope here keeps a matcher used only to scope a rate_limit
// rule from being flagged "unused" (mirrors the security/replace regression guards).
func rateLimitUsages(args []cadishfile.Arg) usages {
	var u usages
	if len(args) == 0 {
		return u
	}
	if args[0].Kind == cadishfile.ArgMatcherRef {
		i := 0
		for i < len(args) && args[i].Kind == cadishfile.ArgMatcherRef {
			u.refs = append(u.refs, refUse{name: strings.TrimPrefix(args[i].Raw, "@"), pos: args[i].Pos})
			i++
		}
		return u
	}
	// Inline single-arg matcher scope: `rate_limit path /api/* 100r/s …`. A rate spec
	// (`100r/s`) is not a matcher type, so only a real matcher type is taken as scope.
	if isMatcherType(args[0].Raw) && len(args) >= 2 {
		u.inlines = append(u.inlines, inlineUse{typ: args[0].Raw, args: args[1:2], pos: args[0].Pos})
	}
	return u
}

// scopeUsages classifies a leading matcher scope: any number of leading
// matcher-refs, then optionally one inline matcher or a bare selector.
func scopeUsages(args []cadishfile.Arg) usages {
	var u usages
	i := 0
	for i < len(args) && args[i].Kind == cadishfile.ArgMatcherRef {
		u.refs = append(u.refs, refUse{name: strings.TrimPrefix(args[i].Raw, "@"), pos: args[i].Pos})
		i++
	}
	if i >= len(args) {
		return u
	}
	switch first := args[i].Raw; {
	case first == "default", first == "status":
		u.selectors = append(u.selectors, first)
	case isMatcherType(first):
		u.inlines = append(u.inlines, inlineUse{typ: first, args: args[i+1:], pos: args[i].Pos})
	}
	return u
}

// headerUsages handles the `header [scope] [+/-]NAME [VALUE]` shape. A leading
// matcher-ref scope is taken verbatim; a leading inline matcher type consumes
// exactly one following arg as its value (the rest is the header spec).
func headerUsages(args []cadishfile.Arg) usages {
	var u usages
	if len(args) == 0 {
		return u
	}
	if args[0].Kind == cadishfile.ArgMatcherRef {
		i := 0
		for i < len(args) && args[i].Kind == cadishfile.ArgMatcherRef {
			u.refs = append(u.refs, refUse{name: strings.TrimPrefix(args[i].Raw, "@"), pos: args[i].Pos})
			i++
		}
		return u
	}
	if isMatcherType(args[0].Raw) {
		var ma []cadishfile.Arg
		if len(args) >= 2 {
			ma = args[1:2]
		}
		u.inlines = append(u.inlines, inlineUse{typ: args[0].Raw, args: ma, pos: args[0].Pos})
	}
	return u
}

// argsBefore returns the prefix of args up to (not including) the first arg whose
// raw text equals sep. If sep is absent it returns all args.
func argsBefore(args []cadishfile.Arg, sep string) []cadishfile.Arg {
	for i, a := range args {
		if a.Raw == sep {
			return args[:i]
		}
	}
	return args
}

// argsBeforeAny is argsBefore for any of several separators.
func argsBeforeAny(args []cadishfile.Arg, seps ...string) []cadishfile.Arg {
	for i, a := range args {
		for _, s := range seps {
			if a.Raw == s {
				return args[:i]
			}
		}
	}
	return args
}

// argsAfter returns the suffix of args following the first arg equal to sep, or
// nil if sep is absent.
func argsAfter(args []cadishfile.Arg, sep string) []cadishfile.Arg {
	for i, a := range args {
		if a.Raw == sep {
			return args[i+1:]
		}
	}
	return nil
}

// isAllDigits reports whether s is a non-empty run of ASCII digits (used to tell
// a `redirect` status code from a leading PATH_REGEX arg).
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isRedirectCodeToken reports whether raw is a literal valid 3xx redirect code cadish
// emits (301/302/303/307/308). It backs the scoped-redirect disambiguation in the cost
// catalog, kept in lockstep with the pipeline parser (pipeline.isRedirectCodeToken): a
// leading CODE marks the scope-only form, a non-code first arg marks the combined form's
// PATH_REGEX — so an all-digit PATH_REGEX (e.g. "12") is not misread as a status code.
func isRedirectCodeToken(raw string) bool {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	switch n {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// hasArg reports whether any arg's raw text equals s.
func hasArg(args []cadishfile.Arg, s string) bool {
	for _, a := range args {
		if a.Raw == s {
			return true
		}
	}
	return false
}
