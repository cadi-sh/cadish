package pipeline

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// edgeview.go exposes a READ-ONLY, serialization-friendly projection of a compiled
// Pipeline for the edge IR projector (internal/edgeir). It adds only accessor
// methods that read existing fields — it changes no behavior, no compile path, and
// no AST. It exists so internal/edgeir can stay a separate consumer package without
// reaching into Pipeline's unexported fields, and so the lossy compiled forms
// (pathSet/hostSet/glob, which factor away their source patterns) can be
// reconstructed to faithful pattern strings the JS interpreter will mirror.
//
// Everything here returns plain Go values (no internal types leak), so the IR
// contract in internal/edgeir is fully decoupled from these internals.

// EdgeMatcher is the neutral, serialization-ready view of one compiled matcher.
// Kind mirrors the matcher type keyword (path/host/header/…); exactly the fields
// relevant to that kind are populated. It is the projection the IR's `{kind,
// fields}` shape is built from — the JS matcher switch mirrors these 1:1.
type EdgeMatcher struct {
	Kind string // matcher type keyword: path|path_regex|host|host_regex|header|method|upstream|content_type|cookie|cookie_json|header_json|set_cookie|classify|geo|query_present

	// Pattern-style kinds.
	Patterns []string // path/host: reconstructed glob/suffix patterns (OR set)
	Regex    string   // path_regex/host_regex/header_regex: the RE2 source

	// header / cookie.
	Name   string   // header name (header/header_regex); cookie name (or prefix when Glob)
	Values []string // header/cookie accepted values (OR); empty => presence-only
	Glob   bool     // cookie: Name is a name prefix (`cookie NAME*`)

	// method / upstream / content_type / set_cookie.
	Methods      []string // method: upper-cased OR set
	Upstreams    []string // upstream: OR set
	ContentTypes []string // content_type: lower-cased media-type substrings (OR)
	CookieNames  []string // set_cookie: OR set of cookie names (empty => any Set-Cookie)

	// classify matcher (`@x classify {tok}==val`).
	ClassifyToken  string // the classifier token name
	ClassifyValue  string // the compared value
	ClassifyNegate bool   // true for `!=`

	// geo.
	GeoGranularity string   // country|continent|region
	GeoValues      []string // upper-cased OR set

	// query_present.
	QueryNames []string // param-name patterns (exact + `*` globs)

	// cookie_json / header_json (D54): a bounded dotted field test inside a JSON
	// cookie/header value. Name carries the cookie/header name; JSONPath is the
	// dotted PATH (e.g. "user.verified", "flags.0.kind") the JS interpreter splits
	// the same way; Values is the OR set of accepted scalar string forms (empty =>
	// presence/non-null only — mirrors the cookie matcher).
	JSONPath string

	// ResponsePhase is true for content_type/set_cookie (needs the origin response).
	ResponsePhase bool
}

// EdgeClassifier is the neutral view of a classify table: ordered rows (each an
// AND-conjunction of matcher names) plus the default value.
//
// Synthetic carries the matchers SYNTHESIZED for inline (unnamed) matchers in
// `when` rows, keyed by the synthetic name that appears in the rows' Conj. The
// pipeline's own classifier resolves an inline matcher by object identity; the edge
// IR has only the matcher map, so an inline matcher must be given a name and emitted
// (BUG-2) — otherwise its Conj entry would be the empty string the runtime can never
// satisfy. The projector merges Synthetic into EdgeIR.Matchers.
type EdgeClassifier struct {
	Rows      []EdgeClassifyRow
	Default   string
	Synthetic map[string]EdgeMatcher
	// DerivesFrom names the request cookies this axis consumes (`derives_from cookie
	// NAME…`). The edge worker keeps them through cookie_allow so the classifier reads
	// the original value and the key is built from it, then strips them post-key before
	// the credential bypass + origin fetch — the SAME derive→strip the server performs,
	// so the two runtimes collapse cardinality identically. nil when none declared.
	DerivesFrom []string
	// DerivesForward is the SUBSET of DerivesFrom declared `forward` (alias `keep`): the
	// worker FORWARDS these to origin unchanged (does NOT strip) and treats them as covered
	// by {TOKEN} in the credential bypass — the same forward-mode the server applies, so the
	// edge and origin agree. nil when no row uses the modifier.
	DerivesForward []string
}

// EdgeClassifyRow is one `when @a @b -> VALUE` row: the matcher names (AND) and the
// value. An inline matcher in the row contributes a SYNTHETIC name here (see
// EdgeClassifier.Synthetic) rather than an empty string.
type EdgeClassifyRow struct {
	Conj  []string // matcher names that must ALL match
	Value string
}

// EdgeNormalizer is the neutral view of a normalize bucket map.
type EdgeNormalizer struct {
	Source     string            // header|cookie|query
	SourceName string            // the header/cookie/param name
	Map        map[string]string // raw value -> bucket
	Default    string
}

// EdgeTenant is the neutral view of a request-derived `tenant { … }` resolver.
type EdgeTenant struct {
	FromHeader string          // "" => derive from Host; else the header name
	Rules      []EdgeTenantMap // ordered pattern -> name
	Default    string
}

// EdgeTenantMap is one tenant rule (an exact host or `*.suffix` wildcard).
type EdgeTenantMap struct {
	Pattern string
	Name    string
}

// EdgeKeyRecipe is the neutral view of one scoped cache_key recipe: a request-phase
// selector scope plus the ordered token list it produces. The catch-all
// (`cache_key default …` or an unscoped line) has Always=true. The edge worker
// evaluates the recipes first-match-wins, exactly like the Go pipeline's
// selectKeyTokens loop, so a scoped site keys byte-identically on the edge (D70).
type EdgeKeyRecipe struct {
	Selector EdgeScope
	Tokens   []EdgeKeyToken
}

// EdgeKeyToken is the neutral view of one cache_key token.
type EdgeKeyToken struct {
	// Kind is a stable string token name the JS interpreter switches on:
	//   method|host|path|url|query|query_allow|query_strip|header|sticky|device|geo|
	//   geo.continent|geo.region|normalize|classify|tenant|literal
	Kind  string
	Arg   string   // header name (header), literal text (literal), constant tenant
	Ref   string   // normalize/classify: the referenced definition name
	Allow []string // query_allow: the param-name allowlist (exact + globs)
	Deny  []string // query_strip: the param-name denylist (exact + globs)
}

// EdgeScope is the neutral view of a directive scope: an OR set of matcher NAMES.
// A nil EdgeScope (Always=true) means the directive is unscoped (always matches).
// Inline (anonymous) matchers are surfaced as Inline so the projector can still
// render them; named refs are in Names.
type EdgeScope struct {
	Always bool          // true => unconditional (nil scope)
	Names  []string      // referenced @matcher names
	Inline []EdgeMatcher // anonymous inline matchers in the scope (name == "")
}

// EdgeHeaderOp is the neutral view of one header edit.
type EdgeHeaderOp struct {
	Op          string // set|append|remove|cache_status
	Name        string
	Value       string
	ValueIsTmpl bool // the Value carries a template placeholder (dynamic header value)
}

// EdgeHeaderRule is a scoped group of header ops.
type EdgeHeaderRule struct {
	Scope EdgeScope
	Ops   []EdgeHeaderOp
}

// EdgeRespond is a `respond PATH STATUS BODY` rule.
type EdgeRespond struct {
	Path   string
	Status int
	Body   string
}

// EdgeRedirect is a compiled redirect rule. Regex and/or Scope select: the
// regex-only and scope-only forms set exactly one; the combined scope+regex form
// sets BOTH (HasScope true AND a non-empty Regex), and the rule fires only when the
// scope matches AND the regex matches the path.
type EdgeRedirect struct {
	Regex    string    // path-regex selector: the RE2 source ("" when there is no path regex)
	HasScope bool      // true when Scope is a real selector (scope-only or combined form)
	Scope    EdgeScope // the selecting scope (valid only when HasScope)
	Status   int
	Target   string // template: {host}/{path}/{query}/{uri} (+ $0..$9 when Regex is set)
}

// EdgePurge is a compiled purge guard.
type EdgePurge struct {
	Guard      EdgeScope
	RegexToken string // literal regex or "{http.NAME}" placeholder; "" if none
}

// EdgeRoute is a compiled route rule.
type EdgeRoute struct {
	Scope    EdgeScope
	Upstream string
}

// EdgeTTL is a compiled cache_ttl rule. Selector is a status set OR a scope OR default.
type EdgeTTL struct {
	SelKind    string    // status_in|status_not_in|scope|default
	Codes      []int     // status_in/status_not_in
	Scope      EdgeScope // scope selector
	TTL        time.Duration
	Grace      time.Duration
	MaxStale   time.Duration // max_stale (D60): stale-on-error window beyond ttl+grace
	HitForMiss time.Duration
	IsHFM      bool
	FromHeader string // origin response header to read the TTL from ("" => static TTL)
	// GraceFromHeader / MaxStaleFromHeader name origin response headers the grace /
	// max_stale window is read from per-response ("" => the static Grace / MaxStale
	// above is used). The literal stays as the fallback when the header is
	// absent/unparseable; the worker mirrors the server's resolveGraceMaxStale.
	GraceFromHeader    string
	MaxStaleFromHeader string
	// RespHeader is an optional RESPONSE-phase `resp_header NAME VALUE` term ANDed in
	// front of the selector (SelKind/Codes/Scope): the rule applies only when the origin
	// response carries the named header value. nil for every rule that does not name
	// resp_header. The worker evaluates it before the kind selector, mirroring the server.
	RespHeader *EdgeMatcher
	// StripHeaders names the from_header-family control headers this rule CONSUMES from
	// the origin response (X-Cache-Ttl/X-Cache-Grace/X-Cache-Max-Stale, whichever are
	// configured). The worker removes them before store + deliver, exactly as the server
	// does (handler.go), so the internal origin↔cache contract never leaks to the client.
	// nil for a plain rule that sources nothing from a header (the common case).
	StripHeaders []string
}

// EdgeStorage is a compiled storage tier rule.
type EdgeStorage struct {
	SelKind    string // status_in|status_not_in|scope|default
	Codes      []int
	Scope      EdgeScope
	Tier       string       // ram|disk
	RespHeader *EdgeMatcher // optional response-phase resp_header AND-term (see EdgeTTL.RespHeader)
}

// EdgeCORS is the neutral view of a cors rule.
type EdgeCORS struct {
	Scope           EdgeScope
	AllowAllOrigins bool
	Origins         []string
	Methods         []string
	Headers         []string
}

// EdgeTransform is one `replace OLD NEW` deliver-phase body substitution.
type EdgeTransform struct {
	Scope EdgeScope
	Old   string
	New   string
}

// --- Pipeline-level accessors ---------------------------------------------------

// EdgeHosts returns the site's address tokens (e.g. "example.com", "*.example.com").
func (p *Pipeline) EdgeHosts() []string { return append([]string(nil), p.addresses...) }

// EdgeRedirectHosts returns the NORMALIZED trusted-host allowlist a `redirect`
// TARGET's {host} placeholder is checked against — the edge projection of the
// server's trustedHosts (see Pipeline.redirectHost / normalizeRedirectHost). Each
// entry is a bare lower-cased host or a preserved `*.suffix` wildcard (scheme/port/
// path already stripped). The worker uses it with the SAME semantics as
// hostSet.Match (exact OR HasSuffix for a wildcard — a `*.suffix` does NOT trust the
// apex). Returns nil when the site declares no address (trustedHosts == nil): the
// worker then reflects the request Host verbatim, exactly as the server does. The
// list is deterministically ordered (exacts then wildcards, each sorted).
func (p *Pipeline) EdgeRedirectHosts() []string {
	return hostSetPatterns(p.trustedHosts)
}

// EdgeCanonicalHost returns the site's canonical host (first non-wildcard configured
// address, scheme/port stripped, lower-cased) — the safe {host} the edge substitutes
// into a redirect Location when the inbound Host is not trusted. Mirrors
// Pipeline.canonicalHost; "" when the site declares no address.
func (p *Pipeline) EdgeCanonicalHost() string { return p.canonicalHost }

// EdgeDefaultUpstream returns the site's default upstream `to` name ("" if none).
func (p *Pipeline) EdgeDefaultUpstream() string { return p.defaultUpstream }

// EdgeStickyCookie returns the configured sticky cookie name ("" if none).
func (p *Pipeline) EdgeStickyCookie() string { return p.stickyCookie }

// EdgeCacheUnsafe reports whether the site set `cache_unsafe` (opts out of the
// safe-by-default refusal of Set-Cookie / private Cache-Control / uncovered Vary).
// The edge interpreter reads this to decide whether to apply the same downgrade.
func (p *Pipeline) EdgeCacheUnsafe() bool { return p.cacheUnsafe }

// EdgeCookieAllow returns the `cookie_allow` allowlist patterns and whether the
// directive is present. The edge worker strips every request cookie not matching a
// pattern (an empty list with active=true strips ALL cookies), so the edge can cache
// the controlled cookie-bearing traffic the server does — mirroring FilterRequestCookies.
func (p *Pipeline) EdgeCookieAllow() ([]string, bool) {
	if p.cookieAllow == nil {
		return nil, false
	}
	return nameGlobPatterns(p.cookieAllow), true
}

// EdgeKeyHeaderNames returns the lower-cased set of request header names the cache
// key varies on (every `header:NAME` token across all key recipes). The edge IR is
// static, so it uses the union over recipes; the edge interpreter reads it to decide
// whether a `Vary` field is already covered by the cache key.
func (p *Pipeline) EdgeKeyHeaderNames() []string {
	var out []string
	seen := map[string]bool{}
	for i := range p.keyRules {
		for name := range keyHeaderNamesForTokens(p.keyRules[i].toks) {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// EdgeTenantConstant returns the per-site constant {tenant} value ("" if the site
// is not a bare-tenant site).
func (p *Pipeline) EdgeTenantConstant() string { return p.tenant }

// EdgeMatchers returns every NAMED matcher, keyed by name, as a neutral view.
// Anonymous inline matchers (name == "") are not included here — they surface
// inside the scope that owns them.
//
// The `ip` ACL matcher resolves the trusted-proxy real client IP (decision #16), which the
// edge has no concept of, so it is projected as a SERVER-ONLY matcher (Kind "ip" → projectMatcher
// marks ServerOnly) rather than SKIPPED (R02). It was previously dropped on the assumption it is
// "only referenced by the security gate" — but `ip` is a GENERAL request-phase matcher that can
// scope ANY directive (`pass @internal_ips`, `cache_key @internal …`, `route @office …`). Skipping
// it left a DANGLING name in the projected scope (scopeView still emits it) that the runtime
// silently treats as a non-match → e.g. `pass @internal_ips` became an edge cache STORE while the
// server passes it. Projecting it ServerOnly routes every ip-scoped directive through the same
// fail-closed delegation/fail-open machinery as `upstream_healthy`, so it can never silently
// mis-project; a security-gate-only `ip` is simply delegated (the gate is already server-only).
func (p *Pipeline) EdgeMatchers() map[string]EdgeMatcher {
	out := make(map[string]EdgeMatcher, len(p.matchers))
	for name, m := range p.matchers {
		out[name] = m.edgeView()
	}
	return out
}

// EdgeClassifiers returns every classify table, keyed by token name.
func (p *Pipeline) EdgeClassifiers() map[string]EdgeClassifier {
	out := make(map[string]EdgeClassifier, len(p.classifiers))
	for name, cl := range p.classifiers {
		rows := make([]EdgeClassifyRow, 0, len(cl.rows))
		var synth map[string]EdgeMatcher
		for ri, r := range cl.rows {
			conj := make([]string, 0, len(r.conj))
			for mi, m := range r.conj {
				if m.name != "" {
					conj = append(conj, m.name)
					continue
				}
				// BUG-2: an inline (unnamed) matcher in a classify `when` row. Give it a
				// deterministic synthetic name and emit it so the edge IR can resolve it the
				// same way the Go classifier does (which matches by object identity). The
				// name is namespaced under the token + row + position to avoid colliding with
				// a user matcher or another synthetic one.
				sn := syntheticClassifyMatcherName(name, ri, mi)
				if synth == nil {
					synth = map[string]EdgeMatcher{}
				}
				synth[sn] = m.edgeView()
				conj = append(conj, sn)
			}
			rows = append(rows, EdgeClassifyRow{Conj: conj, Value: r.value})
		}
		var derives []string
		if len(cl.derivesFrom) > 0 {
			derives = append(derives, cl.derivesFrom...)
		}
		var derivesFwd []string
		if len(cl.derivesForward) > 0 {
			derivesFwd = append(derivesFwd, cl.derivesForward...)
		}
		out[name] = EdgeClassifier{Rows: rows, Default: cl.def, Synthetic: synth, DerivesFrom: derives, DerivesForward: derivesFwd}
	}
	return out
}

// syntheticClassifyMatcherName builds the stable name for an inline matcher in a
// classify row. The `__edge.` prefix (a dot is not a legal user matcher name char)
// guarantees it cannot collide with a user-declared @matcher.
func syntheticClassifyMatcherName(token string, row, idx int) string {
	return "__edge.classify." + token + "." + strconv.Itoa(row) + "." + strconv.Itoa(idx)
}

// EdgeNormalizers returns every normalize bucket map, keyed by name.
func (p *Pipeline) EdgeNormalizers() map[string]EdgeNormalizer {
	out := make(map[string]EdgeNormalizer, len(p.normalizers))
	for name, n := range p.normalizers {
		m := make(map[string]string, len(n.mapping))
		for k, v := range n.mapping {
			m[k] = v
		}
		out[name] = EdgeNormalizer{Source: normSourceName(n.source), SourceName: n.sourceName, Map: m, Default: n.def}
	}
	return out
}

// EdgeTenantResolver returns the request-derived tenant resolver view, and ok=false
// when the site uses no such block (a bare `tenant NAME` constant or no tenant).
func (p *Pipeline) EdgeTenantResolver() (EdgeTenant, bool) {
	if p.tenantResolver == nil {
		return EdgeTenant{}, false
	}
	tr := p.tenantResolver
	rules := make([]EdgeTenantMap, 0, len(tr.rules))
	for _, r := range tr.rules {
		rules = append(rules, EdgeTenantMap{Pattern: r.pattern, Name: r.name})
	}
	return EdgeTenant{FromHeader: tr.fromHeader, Rules: rules, Default: tr.def}, true
}

// EdgeKeyTokens returns the compiled cache_key tokens for edge projection: the
// catch-all (`default`/unscoped) recipe, or the built-in method/host/path when the
// site declares no cache_key. v1 projects a single recipe — a site with one
// unscoped cache_key (the 100%-backward-compatible case) is unaffected. Projecting
// the FULL scoped recipe list + selectors to the edge worker is v2 (see the spec's
// phasing); HasScopedCacheKey lets the edge build plane detect and refuse a scoped
// site until then, so the edge never silently computes a divergent key.
func (p *Pipeline) EdgeKeyTokens() []EdgeKeyToken {
	toks := defaultKeyTokens
	for i := range p.keyRules {
		if p.keyRules[i].sel.kind == selDefault {
			toks = p.keyRules[i].toks
			break
		}
	}
	out := make([]EdgeKeyToken, 0, len(toks))
	for _, t := range toks {
		out = append(out, t.edgeView())
	}
	return out
}

// HasScopedCacheKey reports whether the site uses a scoped cache_key (more than one
// recipe, or a single non-default selector). As of D70 the edge projects the FULL
// ordered recipe list + selectors (EdgeKeyRecipes) and evaluates the same
// first-match-wins selection in the worker, so a scoped site is edge-native — this
// accessor is retained for callers that still want to know whether the site uses
// scoping (e.g. `cadish check` / build-report wording) but no longer gates edge
// projection.
func (p *Pipeline) HasScopedCacheKey() bool {
	if len(p.keyRules) > 1 {
		return true
	}
	return len(p.keyRules) == 1 && p.keyRules[0].sel.kind != selDefault
}

// EdgeKeyRecipes returns the FULL ordered cache_key recipe list for edge projection:
// one EdgeKeyRecipe per `cache_key [SELECTOR] TOKEN…` line, in source order, each
// carrying its request-phase selector scope (Always=true for `default`/unscoped) and
// its compiled tokens. The worker iterates these first-match-wins, mirroring
// pipeline.selectKeyTokens, so the edge keys byte-identically to the server even for
// a scoped site (D70). Returns nil when the site declares no cache_key (the worker
// then falls back to the built-in method/host/path key, exactly like buildKey).
//
// Selectors are request-phase only (compile rejects a response-phase selector), so
// every matcher referenced here is already projected for the worker.
func (p *Pipeline) EdgeKeyRecipes() []EdgeKeyRecipe {
	if len(p.keyRules) == 0 {
		return nil
	}
	out := make([]EdgeKeyRecipe, 0, len(p.keyRules))
	for i := range p.keyRules {
		r := &p.keyRules[i]
		var sc EdgeScope
		if r.sel.kind == selDefault {
			sc = EdgeScope{Always: true}
		} else {
			sc = scopeView(r.sel.scope)
		}
		toks := make([]EdgeKeyToken, 0, len(r.toks))
		for _, t := range r.toks {
			toks = append(toks, t.edgeView())
		}
		out = append(out, EdgeKeyRecipe{Selector: sc, Tokens: toks})
	}
	return out
}

// EdgeDeviceRule is the neutral view of one UA→class rule (substrings/excludes
// already lower-cased), evaluated first-match-wins by the worker.
type EdgeDeviceRule struct {
	Class      string
	Substrings []string
	Exclude    []string
}

// EdgeDeviceFold is one class remap applied after rule matching (FROM -> INTO).
type EdgeDeviceFold struct {
	From string
	Into string
}

// EdgeDeviceClassifier is the neutral view of the {device} UA classifier: an ordered
// ruleset (first match wins) + a default class + optional folds. The worker ports the
// identical scan (substring contains, OR over substrings, NONE of excludes, then
// fold) so the same User-Agent yields the same {device} bucket Go↔JS (D70).
type EdgeDeviceClassifier struct {
	Rules   []EdgeDeviceRule
	Default string
	Folds   []EdgeDeviceFold
}

// EdgeDeviceClassifier returns the projected device classifier and ok=false when the
// site does NOT use the {device} cache-key token (zero-cost-when-unused: a site that
// never keys on device ships no UA ruleset to the worker). When the {device} token is
// present the FULL ruleset is projected (even the built-in default) so the worker
// classifies from an explicit IR and never relies on a JS-side default that could
// drift from Go.
func (p *Pipeline) EdgeDeviceClassifier() (EdgeDeviceClassifier, bool) {
	if !p.UsesDeviceToken() || p.deviceClassifier == nil {
		return EdgeDeviceClassifier{}, false
	}
	c := p.deviceClassifier
	var rules []EdgeDeviceRule
	for _, r := range c.Rules() {
		rules = append(rules, EdgeDeviceRule{
			Class:      r.Class,
			Substrings: append([]string(nil), r.Substrings...),
			Exclude:    append([]string(nil), r.Exclude...),
		})
	}
	var folds []EdgeDeviceFold
	for _, f := range c.Folds() {
		folds = append(folds, EdgeDeviceFold{From: f.From, Into: f.Into})
	}
	return EdgeDeviceClassifier{Rules: rules, Default: c.DefaultClass(), Folds: folds}, true
}

// EdgePassRules returns the `pass` scopes, in order.
func (p *Pipeline) EdgePassRules() []EdgeScope {
	out := make([]EdgeScope, 0, len(p.passRules))
	for _, sc := range p.passRules {
		out = append(out, scopeView(sc))
	}
	return out
}

// EdgeCredentialedRules returns the `cache_credentialed @scope` scopes, in order (D101).
// The projector runs each through the fail-closed chokepoint: a scope referencing a
// ServerOnly/untranslatable matcher fails CLOSED at the edge (fail-open site-wide pass +
// ForcedPass++), and a translatable scope is projected into EdgeIR.CacheCredentialed so the
// worker applies the SAME origin-authoritative precedence the server does.
func (p *Pipeline) EdgeCredentialedRules() []EdgeScope {
	out := make([]EdgeScope, 0, len(p.credentialedRules))
	for _, sc := range p.credentialedRules {
		out = append(out, scopeView(sc))
	}
	return out
}

// EdgeRespondRules returns the exact-path `respond PATH STATUS BODY` rules, in order.
// The scoped form (`respond @scope STATUS BODY`, e.g. the ingress terminal no-match
// 404) is NOT projected: the edge IR's EdgeRespond models only an exact path, and the
// scoped form expresses a matcher conjunction that has no exact-path representation.
// Projecting it with the empty path would make the edge worker 404 the path "" (or
// behave inconsistently with the server), so it is skipped — the server enforces the
// terminal no-match behavior; the edge tier defers to origin for an uncovered path.
//
// The skipped scoped rules are NOT silently dropped: EdgeScopedRespondCount reports
// them so the caller records a Delegate, keeping them in the coverage report and tripping
// `-strict` (E2 — "never silently dropped").
func (p *Pipeline) EdgeRespondRules() []EdgeRespond {
	out := make([]EdgeRespond, 0, len(p.respondRules))
	for _, r := range p.respondRules {
		if r.terms != nil {
			continue // scoped form: server-only, not representable in the edge IR (counted by EdgeScopedRespondCount)
		}
		out = append(out, EdgeRespond{Path: r.path, Status: r.status, Body: r.body})
	}
	return out
}

// EdgeScopedRespondCount returns the number of scoped `respond @scope STATUS BODY` rules
// that EdgeRespondRules deliberately skips (they have no exact-path edge representation).
// The edge projector records one Delegate per scoped respond so it is counted in the
// coverage report and fails `cadish edge build -strict` instead of vanishing from the IR
// and worker bundle (E2).
func (p *Pipeline) EdgeScopedRespondCount() int {
	n := 0
	for _, r := range p.respondRules {
		if r.terms != nil {
			n++
		}
	}
	return n
}

// EdgeRedirectRules returns the `redirect` rules, in order.
func (p *Pipeline) EdgeRedirectRules() []EdgeRedirect {
	out := make([]EdgeRedirect, 0, len(p.redirectRules))
	for i := range p.redirectRules {
		r := &p.redirectRules[i]
		er := EdgeRedirect{Status: r.status, Target: r.target}
		if r.re != nil {
			er.Regex = r.re.String()
		}
		if r.sc != nil {
			er.HasScope = true
			er.Scope = scopeView(r.sc)
		}
		out = append(out, er)
	}
	return out
}

// EdgePurgeRules returns the `purge` guards, in order.
func (p *Pipeline) EdgePurgeRules() []EdgePurge {
	out := make([]EdgePurge, 0, len(p.purgeRules))
	for _, r := range p.purgeRules {
		out = append(out, EdgePurge{Guard: scopeView(r.guard), RegexToken: r.regexToken})
	}
	return out
}

// EdgeRouteRules returns the `route` rules, in order.
func (p *Pipeline) EdgeRouteRules() []EdgeRoute {
	out := make([]EdgeRoute, 0, len(p.routeRules))
	for _, r := range p.routeRules {
		out = append(out, EdgeRoute{Scope: scopeView(r.scope), Upstream: r.upstream})
	}
	return out
}

// EdgeReqHeaderRules returns the request-phase header rules, in order.
func (p *Pipeline) EdgeReqHeaderRules() []EdgeHeaderRule { return headerRuleViews(p.reqHeaderRules) }

// EdgeRespHeaderRules returns the response/deliver-phase header rules, in order.
func (p *Pipeline) EdgeRespHeaderRules() []EdgeHeaderRule { return headerRuleViews(p.respHeaderRules) }

// EdgeTTLRules returns the cache_ttl rules, in order.
func (p *Pipeline) EdgeTTLRules() []EdgeTTL {
	out := make([]EdgeTTL, 0, len(p.ttlRules))
	for _, r := range p.ttlRules {
		k, codes, sc := selectorView(r.sel)
		out = append(out, EdgeTTL{
			SelKind: k, Codes: codes, Scope: sc,
			TTL: r.ttl, Grace: r.grace, MaxStale: r.maxStale, HitForMiss: r.hfm, IsHFM: r.isHFM,
			FromHeader:      r.fromHeader,
			GraceFromHeader: r.graceFromHeader, MaxStaleFromHeader: r.maxStaleFromHeader,
			RespHeader:   selRespHeaderView(r.sel),
			StripHeaders: r.consumedHeaders(),
		})
	}
	return out
}

// EdgeStorageRules returns the storage tier rules, in order.
func (p *Pipeline) EdgeStorageRules() []EdgeStorage {
	out := make([]EdgeStorage, 0, len(p.storageRules))
	for _, r := range p.storageRules {
		k, codes, sc := selectorView(r.sel)
		out = append(out, EdgeStorage{SelKind: k, Codes: codes, Scope: sc, Tier: r.tier, RespHeader: selRespHeaderView(r.sel)})
	}
	return out
}

// EdgeStripRules returns the `strip_cookies` scopes, in order.
func (p *Pipeline) EdgeStripRules() []EdgeScope {
	out := make([]EdgeScope, 0, len(p.stripRules))
	for _, sc := range p.stripRules {
		out = append(out, scopeView(sc))
	}
	return out
}

// EdgeCORSRule returns the cors rule and ok=false when the site has none.
func (p *Pipeline) EdgeCORSRule() (EdgeCORS, bool) {
	if p.corsRule == nil {
		return EdgeCORS{}, false
	}
	c := p.corsRule
	return EdgeCORS{
		Scope:           scopeView(c.scope),
		AllowAllOrigins: c.cors.AllowAllOrigins,
		Origins:         append([]string(nil), c.cors.Origins...),
		Methods:         append([]string(nil), c.cors.Methods...),
		Headers:         append([]string(nil), c.cors.Headers...),
	}, true
}

// EdgeTransformRules returns the `replace` body-substitution rules, in order.
func (p *Pipeline) EdgeTransformRules() []EdgeTransform {
	out := make([]EdgeTransform, 0, len(p.transformRules))
	for _, tr := range p.transformRules {
		out = append(out, EdgeTransform{Scope: scopeView(tr.scope), Old: tr.repl.Old, New: tr.repl.New})
	}
	return out
}

// EdgeUpgradeScopes returns one scope per `upgrade @scope` rule. `upgrade` is
// inherently server-only: it opens a live, hijacked connection-upgrade (WebSocket)
// tunnel to the origin, which a stateless edge worker cannot host. The projector
// delegates each so it surfaces in the coverage report (and trips `-strict`) instead
// of being silently dropped.
func (p *Pipeline) EdgeUpgradeScopes() []EdgeScope {
	out := make([]EdgeScope, 0, len(p.upgradeRules))
	for _, sc := range p.upgradeRules {
		out = append(out, scopeView(sc))
	}
	return out
}

// EdgeRewriteScopes returns one scope per `rewrite` rule. `rewrite` is server-only in
// edge v1 (origin-request URL rewrite); the projector delegates each so it surfaces in
// the coverage report instead of being silently dropped.
func (p *Pipeline) EdgeRewriteScopes() []EdgeScope {
	out := make([]EdgeScope, 0, len(p.rewriteRules))
	for _, r := range p.rewriteRules {
		out = append(out, scopeView(r.scope))
	}
	return out
}

// EdgeOnErrorScopes returns one scope per `respond on_error` rule. The origin-error
// synthetic is server-only in edge v1; the projector delegates each.
func (p *Pipeline) EdgeOnErrorScopes() []EdgeScope {
	out := make([]EdgeScope, 0, len(p.onErrorRules))
	for _, r := range p.onErrorRules {
		out = append(out, scopeView(r.scope))
	}
	return out
}

// EdgeTransformMaxBytes is the body-size ceiling the edge worker buffers to apply a
// `replace` body transform (D75). It mirrors the server's maxTransformBody (1 MiB,
// internal/server/transform.go): a body at or below it is transformed; a larger one
// passes through untransformed (the over-cap path stays a permanent server-only
// non-goal). Kept here (not imported from internal/server) to avoid an import cycle;
// both constants are 1<<20 and a comment in each points at the other.
const EdgeTransformMaxBytes int64 = 1 << 20

// EdgeOnError is the neutral view of one `respond on_error [@scope] STATUS BODY`
// origin-error synthetic (D57/D76). Body is the resolved body bytes as a string.
type EdgeOnError struct {
	Scope       EdgeScope
	Status      int
	Body        string
	ContentType string
}

// EdgeOnErrorRules returns the `respond on_error` synthetics, in source order, with
// their resolved status/body/content_type. The edge worker serves the FIRST whose
// request-phase scope matches on the outage path (no servable cached object),
// mirroring Pipeline.EvalOnError. Edge-native as of D76 (was delegated).
func (p *Pipeline) EdgeOnErrorRules() []EdgeOnError {
	out := make([]EdgeOnError, 0, len(p.onErrorRules))
	for _, r := range p.onErrorRules {
		out = append(out, EdgeOnError{
			Scope:       scopeView(r.scope),
			Status:      r.status,
			Body:        string(r.body),
			ContentType: r.contentType,
		})
	}
	return out
}

// EdgeHasEncode reports whether the site declares `encode` (on-the-fly response-body
// compression). Server-only in edge v1; the projector delegates it.
func (p *Pipeline) EdgeHasEncode() bool { return p.encodeRule != nil }

// --- internal helpers (read-only) -----------------------------------------------

func headerRuleViews(rules []headerRule) []EdgeHeaderRule {
	out := make([]EdgeHeaderRule, 0, len(rules))
	for _, r := range rules {
		ops := make([]EdgeHeaderOp, 0, len(r.ops))
		for _, op := range r.ops {
			ops = append(ops, EdgeHeaderOp{Op: op.Op.String(), Name: op.Name, Value: op.Value, ValueIsTmpl: op.ValueTpl})
		}
		out = append(out, EdgeHeaderRule{Scope: scopeView(r.scope), Ops: ops})
	}
	return out
}

func selectorView(s selector) (kind string, codes []int, sc EdgeScope) {
	switch s.kind {
	case selStatusIn:
		return "status_in", sortedCodes(s.codes), EdgeScope{}
	case selStatusNotIn:
		return "status_not_in", sortedCodes(s.codes), EdgeScope{}
	case selScope:
		return "scope", nil, scopeView(s.scope)
	default:
		return "default", nil, EdgeScope{}
	}
}

// selRespHeaderView projects a selector's optional `resp_header` AND-term to its
// neutral EdgeMatcher view, or nil when the selector has none. The worker evaluates
// it before the kind selector (status/scope/default), mirroring selector.matches.
func selRespHeaderView(s selector) *EdgeMatcher {
	if s.respHeader == nil {
		return nil
	}
	em := s.respHeader.edgeView()
	return &em
}

func sortedCodes(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Ints(out)
	return out
}

// scopeView projects a *scope into the neutral EdgeScope. A nil scope is
// unconditional (Always). Named matchers go into Names (sorted for stability);
// anonymous inline matchers (name == "") surface in Inline.
func scopeView(s *scope) EdgeScope {
	if s == nil {
		return EdgeScope{Always: true}
	}
	var names []string
	var inline []EdgeMatcher
	for _, m := range s.matchers {
		if m.name != "" {
			names = append(names, m.name)
		} else {
			inline = append(inline, m.edgeView())
		}
	}
	sort.Strings(names)
	return EdgeScope{Names: names, Inline: inline}
}

func normSourceName(s normSourceKind) string {
	switch s {
	case normHeader:
		return "header"
	case normCookie:
		return "cookie"
	case normQuery:
		return "query"
	}
	return ""
}

func geoGranularityName(g geoGranularity) string {
	switch g {
	case geoContinent:
		return "continent"
	case geoRegion:
		return "region"
	default:
		return "country"
	}
}

// edgeKindName maps a matcherKind to its Cadishfile type keyword (the inverse of
// matcherType). It is a dedicated, exhaustive mapping — distinct from
// matcherKindName, which is only an error-message helper for the two response-phase
// kinds.
func edgeKindName(k matcherKind) string {
	switch k {
	case kindPath:
		return "path"
	case kindPathRegex:
		return "path_regex"
	case kindHost:
		return "host"
	case kindHostRegex:
		return "host_regex"
	case kindHeader:
		return "header"
	case kindHeaderPresent:
		// Projects as a values-less `header` matcher — the edge `header` case treats
		// empty values as presence, so no new edge kind is needed.
		return "header"
	case kindHeaderRegex:
		return "header_regex"
	case kindMethod:
		return "method"
	case kindUpstream:
		return "upstream"
	case kindContentType:
		return "content_type"
	case kindRespHeader:
		return "resp_header"
	case kindCookie:
		return "cookie"
	case kindCookieJSON:
		return "cookie_json"
	case kindHeaderJSON:
		return "header_json"
	case kindSetCookie:
		return "set_cookie"
	case kindClassify:
		return "classify"
	case kindGeo:
		return "geo"
	case kindQueryPresent:
		return "query_present"
	case kindQuery:
		return "query"
	case kindAll:
		// `all` (AND-composite) and `query` are slice-2 server-side Gateway matchers
		// with no JavaScript runtime case yet; the edge projector (edgeir.Project)
		// detects these kinds and DELEGATES any site that uses them to the Cadish server
		// behind (fail-closed), so they never silently mis-project. Naming the kind
		// explicitly (not "unknown") keeps that detection precise.
		return "all"
	case kindIP:
		// SERVER-ONLY: the `ip` ACL resolves the trusted-proxy real client IP, which the edge
		// has no concept of (decision #16). The kind name is in serverOnlyEdgeKinds, so the
		// projector marks it ServerOnly and DELEGATES (or fails open) every directive that
		// references it — fail-closed at the edge — rather than silently mis-projecting an
		// ip-scoped pass/route/cache_key into a wrong native decision (R02).
		return "ip"
	case kindUpstreamHealthy:
		// SERVER-ONLY: live upstream-pool health is a property of the Cadish server's lb
		// state and does not exist at the edge (like the security gate, D49). The kind name
		// is in serverOnlyEdgeKinds, so the projector marks it ServerOnly and DELEGATES every
		// directive that references it (fail-closed at the edge) rather than mis-projecting.
		return "upstream_healthy"
	}
	return "unknown"
}

// edgeView projects one compiled keyToken to the neutral view.
func (t keyToken) edgeView() EdgeKeyToken {
	switch t.kind {
	case tokMethod:
		return EdgeKeyToken{Kind: "method"}
	case tokHost:
		return EdgeKeyToken{Kind: "host"}
	case tokPath:
		return EdgeKeyToken{Kind: "path"}
	case tokURL:
		return EdgeKeyToken{Kind: "url"}
	case tokQuery:
		return EdgeKeyToken{Kind: "query"}
	case tokQueryAllow:
		return EdgeKeyToken{Kind: "query_allow", Allow: nameGlobPatterns(t.allow)}
	case tokQueryStrip:
		return EdgeKeyToken{Kind: "query_strip", Deny: nameGlobPatterns(t.deny)}
	case tokHeader:
		return EdgeKeyToken{Kind: "header", Arg: t.arg}
	case tokCookie:
		return EdgeKeyToken{Kind: "cookie", Arg: t.arg}
	case tokSticky:
		return EdgeKeyToken{Kind: "sticky"}
	case tokDevice:
		return EdgeKeyToken{Kind: "device"}
	case tokGeo:
		return EdgeKeyToken{Kind: "geo"}
	case tokGeoContinent:
		return EdgeKeyToken{Kind: "geo.continent"}
	case tokGeoRegion:
		return EdgeKeyToken{Kind: "geo.region"}
	case tokNormalize:
		return EdgeKeyToken{Kind: "normalize", Ref: t.norm.name}
	case tokClassify:
		return EdgeKeyToken{Kind: "classify", Ref: t.clsf.name}
	case tokTenant:
		// Request-derived resolver vs per-site constant: the JS side reads the
		// site's tenant definition either way; surface the constant in Arg when set.
		return EdgeKeyToken{Kind: "tenant", Arg: t.arg}
	default: // tokLiteral
		return EdgeKeyToken{Kind: "literal", Arg: t.arg}
	}
}

// edgeView projects one compiled matcher to the neutral EdgeMatcher view,
// reconstructing the original pattern source for the factored set kinds. A kindIP
// matcher projects to a fields-less `ip` view (no IP/CIDR data leaks to the worker);
// projectMatcher then marks it ServerOnly so the projector delegates / fails open every
// directive that references it (R02) — it is no longer a panic, so an inline `ip`
// (`pass ip 10.0.0.0/8`) never crashes `cadish edge build`.
func (m *matcher) edgeView() EdgeMatcher {
	em := EdgeMatcher{Kind: edgeKindName(m.kind), ResponsePhase: isResponsePhaseKind(m.kind)}
	switch m.kind {
	case kindPath:
		em.Patterns = pathSetPatterns(m.paths)
	case kindHost:
		em.Patterns = hostSetPatterns(m.hosts)
	case kindPathRegex, kindHostRegex:
		em.Regex = m.re.String()
	case kindHeader:
		em.Name = m.headerName
		em.Values = append([]string(nil), m.headerValues...)
	case kindHeaderPresent:
		// Project as a `header` matcher with NO values: the edge interpreter's
		// `header` case treats empty values as presence (interpreter.js line ~580),
		// exactly like the server, so this reuses the existing edge machinery with no
		// new IR/runtime concept. (edgeKindName maps the kind to "header" too.)
		em.Name = m.headerName
	case kindHeaderRegex:
		// Request-phase, edge-expressible: the JS runtime applies the same RegExp to
		// the header value. The RE2 inline-flag lift (splitRE2Flags) happens in the
		// projector (projectMatcher), exactly like path_regex/host_regex.
		em.Name = m.headerName
		em.Regex = m.re.String()
	case kindMethod:
		em.Methods = sortedSetKeys(m.methods)
	case kindUpstream:
		em.Upstreams = sortedSetKeys(m.upstreams)
	case kindContentType:
		em.ContentTypes = append([]string(nil), m.contentTypes...)
	case kindRespHeader:
		// Response-phase, edge-expressible: the worker reads the named origin response
		// header and value-matches it with the SAME name-glob engine (nameGlobMatch) the
		// server uses (respValues). Name is the header; Values carries the exact-or-`*`-glob
		// value patterns (empty => presence). ResponsePhase=true gates it to the response walk.
		em.Name = m.headerName
		em.Values = append([]string(nil), m.respValuePatterns...)
	case kindCookie:
		em.Name = m.cookieName
		em.Glob = m.cookieGlob
		em.Values = append([]string(nil), m.cookieValues...)
	case kindCookieJSON, kindHeaderJSON:
		// Request-phase, edge-expressible: a bounded JSON field test the JS runtime
		// mirrors 1:1 (length cap + try/catch JSON.parse + depth-guarded descent).
		em.Name = m.jsonName
		em.JSONPath = jsonPathString(m.jsonPath)
		em.Values = append([]string(nil), m.jsonValues...)
	case kindSetCookie:
		em.CookieNames = append([]string(nil), m.setCookieNames...)
	case kindClassify:
		em.ClassifyToken = m.classifier.name
		em.ClassifyValue = m.classifyValue
		em.ClassifyNegate = m.classifyNegate
	case kindGeo:
		em.GeoGranularity = geoGranularityName(m.geoGran)
		em.GeoValues = sortedSetKeys(m.geoValues)
	case kindQueryPresent:
		em.QueryNames = nameGlobPatterns(m.queryNames)
	case kindQuery:
		// One named query param tested against an OR set of exact values (server-side
		// Gateway routing). Reuse Name + Values (no new IR field); an edge site that uses
		// it would need a JS `query` case, but Gateway routing is server-only so this is
		// projected for completeness only.
		em.Name = m.queryName
		em.Values = append([]string(nil), m.queryValues...)
	}
	return em
}

func sortedSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pathSetPatterns reconstructs the original `path` matcher pattern strings from the
// factored pathSet (exact names, prefix trie, glob part-lists, matchAll). The set
// is reassembled into faithful glob strings the JS interpreter can compile.
func pathSetPatterns(s *pathSet) []string {
	if s == nil {
		return nil
	}
	var out []string
	if s.matchAll {
		out = append(out, "*")
	}
	for k := range s.exact {
		out = append(out, k)
	}
	for _, pfx := range s.prefixes.collect() {
		out = append(out, pfx+"*")
	}
	for _, g := range s.globs {
		out = append(out, g.source())
	}
	sort.Strings(out)
	return out
}

// hostSetPatterns reconstructs the original `host` matcher pattern strings (exact
// hosts + `*.suffix` wildcards) from the factored hostSet.
func hostSetPatterns(h *hostSet) []string {
	if h == nil {
		return nil
	}
	var out []string
	for k := range h.exact {
		out = append(out, k)
	}
	for _, suf := range h.suffixes {
		out = append(out, "*"+suf) // suf already includes the leading dot
	}
	sort.Strings(out)
	return out
}

func nameGlobPatterns(s *nameGlobSet) []string {
	if s == nil {
		return nil
	}
	var out []string
	if s.matchAll {
		out = append(out, "*")
	}
	for k := range s.exact {
		out = append(out, k)
	}
	for _, g := range s.globs {
		out = append(out, g.source())
	}
	sort.Strings(out)
	return out
}

// source reconstructs the original glob pattern string from the compiled part-list
// + leading/trailing star flags. `*a*b*` round-trips faithfully (the projector is
// only ever fed patterns this engine itself compiled).
func (g *glob) source() string {
	var b strings.Builder
	if g.leadingStar {
		b.WriteByte('*')
	}
	for i, p := range g.parts {
		if i > 0 {
			b.WriteByte('*')
		}
		b.WriteString(p)
	}
	if g.trailingStar {
		b.WriteByte('*')
	}
	if b.Len() == 0 {
		return "*"
	}
	return b.String()
}

// collect returns every stored prefix in the trie (depth-first), in deterministic
// byte order, so a `path /a/* /b/*` matcher round-trips to its prefix patterns.
func (t *trieNode) collect() []string {
	var out []string
	var walk func(n *trieNode, acc []byte)
	walk = func(n *trieNode, acc []byte) {
		if n.terminal {
			out = append(out, string(acc))
		}
		keys := make([]int, 0, len(n.children))
		for b := range n.children {
			keys = append(keys, int(b))
		}
		sort.Ints(keys)
		for _, k := range keys {
			b := byte(k)
			walk(n.children[b], append(acc, b))
		}
	}
	walk(t, nil)
	return out
}
