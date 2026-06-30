package edgeir

import (
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// exclusions.go computes the STRICT, fail-safe set of CF worker-route EXCLUSIONS
// (D105 / 2026-06-29-edge-pass-route-exclusion, refined 2026-06-30): the path patterns
// the edge worker would ONLY ever `pass`, projected as Cloudflare routes that match but
// run no worker so CF proxies them straight to origin (skipping a wasted worker
// invocation). The honest excludable set is ALWAYS surfaced in the coverage report; it is
// only projected into the IR (and turned into real CF routes by the deploy plane) when the
// operator opts in with `edge { bypass_passes }`.
//
// THE ADDITIVE-SERVER INSIGHT (why most directives do NOT disqualify a pure-pass path).
// cadish edge is ADDITIVE: every request the operator route-excludes from the worker still
// reaches the cadish server BEHIND the worker (the worker's origin — a passthrough or a
// real cadish server), which runs the SAME compiled config and reproduces ALL of: request-
// header ops, response/deliver-header ops, routing (`route`), `cors`, body `replace`, and
// `strip_cookies` for that request. So those operations being present on a path do NOT
// disqualify it from exclusion — excluding the path loses NOTHING, because the server
// behind does exactly what the worker would have done (minus the edge's unique value). The
// `edge { bypass_passes }` opt-in IS the operator's assertion that this server-behind
// topology holds.
//
// The ONLY things a route-exclusion actually loses are EDGE-UNIQUE:
//   - serving P from the EDGE CACHE (a path the edge would CACHE → keep it in the worker;
//     excluding loses POP caching), and
//   - an edge-served SHORT-CIRCUIT `redirect`/`respond` that avoids an origin hop (keep it
//     in the worker to preserve the latency win).
// Only those two disqualify. A wrong exclusion can therefore at worst forgo an edge-cache
// hit or a saved hop — never strip behaviour the path needed.
//
// A path pattern P is excludable iff ALL of:
//
//  1. An unconditional, PATH-ONLY `pass` covers P. The pass selector is built solely
//     from `path` / `path_regex` matchers, each reducible to a `<host>/<prefix>*`
//     CF glob (a literal prefix/exact, or an anchored-literal regex `^/lit` with no
//     RE2 metacharacters). ANY other matcher in the scope (cookie/header/method/geo/
//     query/classify/`all`/`ip`/host/…) — i.e. a CONDITIONAL pass — disqualifies it:
//     the worker has to evaluate the condition, and route-exclusion is all-or-nothing per
//     path, so the path must stay in the worker.
//  2. NO higher-or-equal-priority rule would CACHE P or SHORT-CIRCUIT P at the edge. P is
//     disqualified ONLY by a SCOPED cache_ttl / cache_key recipe / storage that stores it,
//     or a `redirect` / `respond` that serves it without an origin hop, overlapping P.
//     Request-header ops, response/deliver-header ops, `route`, `cors`, `replace`,
//     `strip_cookies`, `on_error`, and edge-tier policies are NOT disqualifying — the
//     additive server behind reproduces them all (see touchFootprints). The always-on
//     default store recipe/ttl is not disqualifying either (a passed request is never
//     cached).
//  3. P reduces to a CF route glob inside the worker's configured route zone(s). A
//     `path_regex` that is not reducible to a host+prefix glob (an alternation, a
//     char class, a quantifier) is NOT excludable — CF routes are glob, not regex.
//
// CF mechanism (confirmed against Cloudflare docs, 2026-06-29): a Workers route whose
// `script` is omitted "can be specified without being associated with a Worker. This
// will act to negate any less specific patterns" (developers.cloudflare.com/workers/
// configuration/routing/routes — "Routes Without Workers"), and the routes API's
// `script` body field is documented OPTIONAL (developers.cloudflare.com/api …
// workers/routes create). So `brand-a.example/transmit*` with no script carves
// `brand-a.example/transmit…` out of the worker's `brand-a.example/*` (more-specific pattern wins)
// and CF proxies it straight to origin.

// pathGlob is a reduced path pattern: a literal prefix (with a leading '/') that is
// either an exact path (isPrefix=false) or a trailing-'*' prefix glob (isPrefix=true).
type pathGlob struct {
	prefix   string
	isPrefix bool
}

// edgeDeployRoutes returns the CF route patterns the worker attaches to — the
// `edge { route … }` patterns, or the derived `<host>/*` per site address when the
// block lists none. These bound where an exclusion route may be created (a carve-out
// must sit inside, and be more specific than, a worker route).
func edgeDeployRoutes(p *pipeline.Pipeline) []string {
	d := p.EdgeDeployConfig()
	if len(d.Routes) > 0 {
		return append([]string(nil), d.Routes...)
	}
	var out []string
	for _, h := range p.EdgeHosts() {
		if h != "" {
			out = append(out, h+"/*")
		}
	}
	return out
}

// computeExplicitExclusions projects the operator-DECLARED `edge { bypass PATTERN… }`
// patterns (D105 explicit companion) into host-crossed CF route globs, and computes a
// loud overlap WARNING for any pattern that shadows a path the edge would CACHE.
//
// Unlike the auto-derived set, these are NOT subject to the excludability gate — the
// operator has asserted "these paths are pure pass-through", so they are taken at their
// word (the HAProxy `acl … path_beg /prefix` bypass analog). Declaring `bypass …` is
// itself the opt-in, so the patterns are always projected (independent of bypass_passes).
//
// Safety (warn, never fail): a passed path is never edge-CACHED, so a `bypass` pattern that
// overlaps a path the edge would store (a SCOPED cache_ttl / cache_key recipe / storage rule
// reducible to a literal path prefix) silently forgoes POP caching for that path. We surface
// that as a WARNING (operator-declared ⇒ warn, don't fail) naming the pattern and the cached
// path it shadows, reusing the cache-store footprint sources (cacheStorePathGlobs). The
// pattern is STILL included — the warning is advisory, not a veto.
func computeExplicitExclusions(p edgeBypassSource, ir EdgeIR, routes []string) (patterns, warnings []string) {
	raw := p.EdgeBypassPatterns()
	if len(raw) == 0 {
		return nil, nil
	}
	var globs []pathGlob
	for _, r := range raw {
		g, ok := literalPathGlob(r)
		if !ok {
			// The compiler already validated each pattern (validateBypassPattern); an
			// unreducible one cannot reach here. Skip defensively rather than panic.
			continue
		}
		globs = append(globs, g)
	}
	if len(globs) == 0 {
		return nil, nil
	}

	// Overlap warnings: name each cached path a bypass pattern would shadow.
	cacheGlobs := cacheStorePathGlobs(ir)
	for _, g := range globs {
		for _, cg := range cacheGlobs {
			if pathGlobsOverlap(g, cg) {
				warnings = append(warnings, "bypass "+globString(g)+" would skip the worker for "+globString(cg)+" which is cached — POP caching lost for it")
			}
		}
	}
	// next#2: a SCOPED cache rule names a specific path (handled above), but an
	// UNCONDITIONAL `cache_ttl default` (or an Always cache_key recipe / default storage)
	// caches EVERY path, so cacheStorePathGlobs — which skips non-scope selectors —
	// reports nothing and a `bypass /static*` silently forgoes POP caching with no
	// warning. When the site has a default/unconditional cache-store rule, every bypass
	// pattern shadows cached content: warn per pattern.
	if hasDefaultCacheStore(ir) {
		for _, g := range globs {
			warnings = append(warnings, "bypass "+globString(g)+" would skip the worker for a path the edge caches by default (`cache_ttl default`) — POP caching lost for it")
		}
	}
	// next#1: a bypassed path is served origin-direct, so any DELIVER-phase op the edge
	// would have applied to it (here: `strip_cookies`) is NOT applied by the worker. This
	// is safe ONLY when a full cadish server sits behind the worker (it re-applies the op);
	// against a non-cadish origin the op is silently lost. Warn on the overlap so the
	// operator confirms a cadish server is behind (`bypass` requires one).
	deliverGlobs, deliverAll := deliverOpPathGlobs(ir)
	for _, g := range globs {
		if deliverAll {
			warnings = append(warnings, "bypass "+globString(g)+" skips the worker for a path carrying a deliver-phase op (e.g. strip_cookies) — the op is applied ONLY by a cadish server behind the worker; ensure one is, or the op is lost")
			continue
		}
		for _, dg := range deliverGlobs {
			if pathGlobsOverlap(g, dg) {
				warnings = append(warnings, "bypass "+globString(g)+" skips the worker for "+globString(dg)+" which carries a deliver-phase op (e.g. strip_cookies) — applied ONLY by a cadish server behind the worker; ensure one is, or the op is lost")
			}
		}
	}
	sort.Strings(warnings)
	warnings = dedupeStrings(warnings)

	// Cross each pattern with every catch-all worker route host, exactly like the
	// auto-derived set, so a pattern becomes `<host><pattern>` per worker route.
	globs = collapsePathGlobs(globs)
	seen := map[string]bool{}
	for _, route := range routes {
		host, ok := routeHostCatchAll(route)
		if !ok {
			continue
		}
		for _, g := range globs {
			pat := host + g.prefix
			if g.isPrefix {
				pat += "*"
			}
			if !seen[pat] {
				seen[pat] = true
				patterns = append(patterns, pat)
			}
		}
	}
	sort.Strings(patterns)
	return patterns, warnings
}

// edgeBypassSource is the slice of the pipeline the explicit-exclusion computation needs
// (the operator-declared `bypass` patterns). Narrowed to an interface so the unit tests
// can drive it without a full pipeline.
type edgeBypassSource interface {
	EdgeBypassPatterns() []string
}

// globString renders a pathGlob back to its CF-route path form (a trailing '*' for a
// prefix glob, the bare literal for an exact). Used in the overlap warning messages.
func globString(g pathGlob) string {
	if g.isPrefix {
		return g.prefix + "*"
	}
	return g.prefix
}

// cacheStorePathGlobs returns the path-reducible footprints of the SCOPED edge cache-STORE
// rules (cache_ttl / cache_key recipe / storage) — the paths the edge would CACHE. It is the
// overlap source for the explicit-`bypass` safety warning: a bypass that overlaps one of
// these forgoes POP caching for it. A cache scope that is unconditional or bound to a
// non-path matcher cannot name a specific shadowed path, so it is skipped here (the warning
// is best-effort/advisory; the strict auto-derive gate in touchFootprints handles blockAll).
func cacheStorePathGlobs(ir EdgeIR) []pathGlob {
	var out []pathGlob
	add := func(sc Scope) {
		ba, gs := scopeFootprint(sc, ir.Matchers)
		if ba {
			return
		}
		out = append(out, gs...)
	}
	for _, t := range ir.Response.TTL {
		if t.SelKind == "scope" && t.Scope != nil {
			add(*t.Scope)
		}
	}
	for _, s := range ir.Response.Storage {
		if s.SelKind == "scope" && s.Scope != nil {
			add(*s.Scope)
		}
	}
	for _, rc := range ir.Key.Recipes {
		if !rc.Selector.Always {
			add(rc.Selector)
		}
	}
	return out
}

// hasDefaultCacheStore reports whether the site caches paths UNCONDITIONALLY — a
// `cache_ttl default` (SelKind "default"), an Always `cache_key` recipe, or a default
// storage tier. Such a rule caches every path, so cacheStorePathGlobs (scoped-only)
// cannot name the shadowed path and any explicit `bypass` silently forgoes POP caching
// for it. Used to emit the next#2 overlap warning.
func hasDefaultCacheStore(ir EdgeIR) bool {
	// A rule caches an UNBOUNDED set of PATHS when its selector is the unconditional
	// default OR a status selector (`cache_ttl status 200 …` caches every path that
	// returns that status). cacheStorePathGlobs (scoped-only) cannot name those paths,
	// so any explicit bypass shadows cached content (F-D2-r2: status_in/status_not_in
	// were previously missed).
	pathUnconditional := func(selKind string) bool {
		return selKind == "default" || selKind == "status_in" || selKind == "status_not_in"
	}
	for _, t := range ir.Response.TTL {
		// A hit-for-miss default stores no servable content, so a bypass forgoes
		// nothing — do not let it fire a false "POP caching lost" warning (F-D2-r2).
		if t.IsHFM {
			continue
		}
		if pathUnconditional(t.SelKind) {
			return true
		}
	}
	for _, s := range ir.Response.Storage {
		if pathUnconditional(s.SelKind) {
			return true
		}
	}
	for _, rc := range ir.Key.Recipes {
		if rc.Selector.Always {
			return true
		}
	}
	return false
}

// deliverOpPathGlobs returns the path footprints of DELIVER-phase ops the edge would
// apply but a bypassed (origin-direct) path would skip: `strip_cookies`, `cors`,
// response-phase `header` ops, and `replace` body transforms (F-D3-r2 extends this
// beyond strip_cookies to every deliver-phase op the source finding named). A scope
// reducible to a path glob contributes its glob; an unconditional one sets
// blockAll=true (it applies to every path). Used for the next#1 deliver-op overlap
// warning (advisory: a cadish server behind re-applies the op).
func deliverOpPathGlobs(ir EdgeIR) (globs []pathGlob, blockAll bool) {
	add := func(sc Scope) {
		ba, gs := scopeFootprint(sc, ir.Matchers)
		if ba {
			blockAll = true
			return
		}
		globs = append(globs, gs...)
	}
	for _, sc := range ir.Response.StripCookies {
		add(sc)
	}
	for _, h := range ir.Response.HeaderResp {
		add(h.Scope)
	}
	for _, tr := range ir.Response.Transforms {
		add(tr.Scope)
	}
	if ir.Response.CORS != nil {
		add(ir.Response.CORS.Scope)
	}
	return globs, blockAll
}

// dedupeStrings returns s with adjacent duplicates removed; callers sort first so this
// removes ALL duplicates. Keeps the overlap-warning set clean when several sources
// (scoped + default cache, deliver ops) name the same bypass pattern.
func dedupeStrings(s []string) []string {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// mergeRouteExclusions dedups + collapses the union of the auto-derived and explicit
// host-crossed CF route patterns: an exact/prefix pattern fully covered by a broader prefix
// pattern for the SAME host is dropped (so an explicit `/v3*` subsumes an auto `/v3/x*`, and
// vice-versa). Returns a deterministic (sorted) set. Operates on the already-host-crossed
// strings so the two sources collapse against each other.
func mergeRouteExclusions(auto, explicit []string) []string {
	type hg struct {
		host string
		glob pathGlob
	}
	var all []hg
	seen := map[string]bool{}
	for _, s := range append(append([]string(nil), auto...), explicit...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		host, g, ok := splitRoutePattern(s)
		if !ok {
			continue
		}
		all = append(all, hg{host: host, glob: g})
	}
	var kept []hg
	for _, c := range all {
		covered := false
		for i, k := range kept {
			if k.host != c.host {
				continue
			}
			if coversGlob(k.glob, c.glob) {
				covered = true
				break
			}
			if coversGlob(c.glob, k.glob) {
				kept[i] = c // c is broader — replace
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, c)
		}
	}
	out := make([]string, 0, len(kept))
	for _, k := range kept {
		out = append(out, k.host+globString(k.glob))
	}
	sort.Strings(out)
	return out
}

// splitRoutePattern splits a host-crossed CF route pattern `<host>/<path>[*]` into its host
// and the reduced path glob. ok=false for a malformed pattern (no '/', empty path).
func splitRoutePattern(s string) (string, pathGlob, bool) {
	i := strings.IndexByte(s, '/')
	if i <= 0 {
		return "", pathGlob{}, false
	}
	host := s[:i]
	g, ok := literalPathGlob(s[i:])
	if !ok {
		return "", pathGlob{}, false
	}
	return host, g, true
}

// computeRouteExclusions returns the host+prefix CF route glob patterns that are
// safe to exclude from the worker (run no worker → origin direct). It is the single
// entry point used by Project for both the always-on coverage report and the opt-in
// IR field. Returns nil when nothing is safely excludable (the fail-safe default).
func computeRouteExclusions(ir EdgeIR, routes []string) []string {
	cands := excludablePassPaths(ir)
	if len(cands) == 0 {
		return nil
	}
	blockAll, footprints := touchFootprints(ir)
	if blockAll {
		// Some edge-UNIQUE directive (an unconditional redirect/respond short-circuit, or
		// a cache-store rule scoped on a non-path matcher) can cache or short-circuit ANY
		// path, so no path can be safely carved out. Exclude nothing.
		return nil
	}
	var safe []pathGlob
	for _, c := range cands {
		touched := false
		for _, f := range footprints {
			if pathGlobsOverlap(c, f) {
				touched = true
				break
			}
		}
		if !touched {
			safe = append(safe, c)
		}
	}
	if len(safe) == 0 {
		return nil
	}
	safe = collapsePathGlobs(safe)

	seen := map[string]bool{}
	var out []string
	for _, r := range routes {
		host, ok := routeHostCatchAll(r)
		if !ok {
			continue
		}
		for _, g := range safe {
			pat := host + g.prefix
			if g.isPrefix {
				pat += "*"
			}
			if !seen[pat] {
				seen[pat] = true
				out = append(out, pat)
			}
		}
	}
	sort.Strings(out)
	return out
}

// routeHostCatchAll parses a `<host>/*` catch-all worker route into its host. It
// returns ok=false for any non-catch-all route (e.g. an explicit `<host>/sub/*`),
// so an exclusion is only ever carved out of a whole-host worker route.
func routeHostCatchAll(route string) (string, bool) {
	if !strings.HasSuffix(route, "/*") {
		return "", false
	}
	host := strings.TrimSuffix(route, "/*")
	if host == "" || strings.Contains(host, "/") {
		return "", false
	}
	return host, true
}

// excludablePassPaths collects the path-only unconditional `pass` candidates from the
// projected RECV pass scopes. The site-wide fail-open `pass` (Always) and any
// conditional (non-path) pass scope contribute nothing.
func excludablePassPaths(ir EdgeIR) []pathGlob {
	var out []pathGlob
	for _, sc := range ir.Recv.Pass {
		gs, ok := scopePathGlobs(sc, ir.Matchers)
		if !ok {
			continue
		}
		out = append(out, gs...)
	}
	return out
}

// scopePathGlobs returns the reduced path globs for a scope iff EVERY matcher in the
// scope is a path/path_regex matcher reducible to a host+prefix glob. An Always
// scope, an empty scope, or any non-path / non-reducible matcher returns ok=false
// (the scope is then not safely path-bound).
func scopePathGlobs(sc Scope, matchers map[string]Matcher) ([]pathGlob, bool) {
	if sc.Always {
		return nil, false
	}
	ms := scopeMatchers(sc, matchers)
	if len(ms) == 0 {
		return nil, false
	}
	var out []pathGlob
	for _, m := range ms {
		gs, ok := matcherPathGlobs(m)
		if !ok {
			return nil, false
		}
		out = append(out, gs...)
	}
	return out, true
}

// scopeMatchers resolves a scope's named refs (via the projected matcher map) plus
// its inline anonymous matchers into a flat matcher slice.
func scopeMatchers(sc Scope, matchers map[string]Matcher) []Matcher {
	var out []Matcher
	for _, n := range sc.Names {
		if m, ok := matchers[n]; ok {
			out = append(out, m)
		}
	}
	out = append(out, sc.Inline...)
	return out
}

// matcherPathGlobs reduces one matcher to its path globs, or ok=false when it is not
// a path/path_regex matcher OR cannot be reduced to a host+prefix CF glob.
func matcherPathGlobs(m Matcher) ([]pathGlob, bool) {
	switch m.Kind {
	case "path":
		if len(m.Patterns) == 0 {
			return nil, false
		}
		var out []pathGlob
		for _, p := range m.Patterns {
			g, ok := literalPathGlob(p)
			if !ok {
				return nil, false
			}
			out = append(out, g)
		}
		return out, true
	case "path_regex":
		// An untranslatable / stripped regex carries no source to reduce.
		if m.RegexUntranslatable || m.Regex == "" {
			return nil, false
		}
		g, ok := regexLiteralPathGlob(m.Regex)
		if !ok {
			return nil, false
		}
		return []pathGlob{g}, true
	}
	return nil, false
}

// literalPathGlob reduces one `path` matcher pattern string to a pathGlob. An exact
// path (no '*') or a pure trailing-'*' prefix reduces; a bare '*', or any leading/
// interior glob, does NOT (it has no host+prefix form). A pattern must start with '/'.
func literalPathGlob(p string) (pathGlob, bool) {
	if p == "" || p == "*" {
		return pathGlob{}, false
	}
	switch strings.Count(p, "*") {
	case 0:
		if !strings.HasPrefix(p, "/") {
			return pathGlob{}, false
		}
		return pathGlob{prefix: p, isPrefix: false}, true
	case 1:
		if !strings.HasSuffix(p, "*") {
			return pathGlob{}, false
		}
		prefix := p[:len(p)-1]
		if !strings.HasPrefix(prefix, "/") {
			return pathGlob{}, false
		}
		return pathGlob{prefix: prefix, isPrefix: true}, true
	default:
		return pathGlob{}, false
	}
}

// regexLiteralPathGlob reduces an anchored-literal `path_regex` source (inline flags
// already lifted off by projectMatcher) to a pathGlob. It accepts ONLY `^/literal`
// (a prefix) or `^/literal$` (an exact), where `literal` is a plain path with no RE2
// metacharacter. Anything else (an alternation `^/(a|b)`, a char class `^/v[23]/`, a
// quantifier, a `.`) is NOT reducible — CF routes are glob, not regex — so ok=false.
func regexLiteralPathGlob(src string) (pathGlob, bool) {
	if !strings.HasPrefix(src, "^") {
		return pathGlob{}, false
	}
	rest := src[1:]
	exact := false
	if strings.HasSuffix(rest, "$") {
		exact = true
		rest = rest[:len(rest)-1]
	}
	if rest == "" || !strings.HasPrefix(rest, "/") || !isPlainPathLiteral(rest) {
		return pathGlob{}, false
	}
	return pathGlob{prefix: rest, isPrefix: !exact}, true
}

// isPlainPathLiteral reports whether s is a path made only of characters that carry no
// special meaning in a RE2 source AND no '*' (so it round-trips to a literal prefix).
// Conservative on purpose: any other byte (`.`, `\`, `(`, `[`, `|`, `+`, `?`, `{`, a
// space, …) means the source is not a pure literal and the regex is not reducible.
func isPlainPathLiteral(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_' || r == '~':
		default:
			return false
		}
	}
	return true
}

// touchFootprints gathers the path footprints of the only directives that, on an
// ADDITIVE edge, a route-exclusion would actually LOSE — rule (b). It returns
// blockAll=true when such a directive can touch ANY path (an unconditional one, or one
// scoped on a non-path matcher), in which case NOTHING is excludable.
//
// Only EDGE-UNIQUE behaviour disqualifies (see the file doc comment): a rule that would
// (1) STORE P in the edge cache (a SCOPED cache_ttl / storage / cache_key recipe — the
// always-on DEFAULT store recipe is dead for a fully-passed path and is NOT counted), or
// (2) SHORT-CIRCUIT P at the edge with a `redirect` / `respond` (saving an origin hop).
// Request-header ops, response/deliver-header ops, `route`, `cors`, `replace`,
// `strip_cookies`, `on_error`, and edge-tier policies are deliberately NOT footprint
// sources: the cadish server BEHIND the worker (its origin) runs the same compiled config
// and reproduces every one of them for an excluded request, so excluding the path loses
// nothing they would have done.
func touchFootprints(ir EdgeIR) (bool, []pathGlob) {
	blockAll := false
	var globs []pathGlob
	add := func(ba bool, gs []pathGlob) {
		if ba {
			blockAll = true
		}
		globs = append(globs, gs...)
	}

	// Short-circuit (2): a redirect or respond serves P at the edge with NO origin hop.
	// The server behind would reproduce it, but the worker keeps the latency win — so
	// keep such a path in the worker.
	for _, r := range ir.Recv.Redirect {
		matched := false
		if r.Regex != "" {
			matched = true
			if g, ok := regexLiteralPathGlob(r.Regex); ok {
				globs = append(globs, g)
			} else {
				blockAll = true
			}
		}
		if r.Scope != nil {
			matched = true
			add(scopeFootprint(*r.Scope, ir.Matchers))
		}
		if !matched {
			// An unconditional redirect selects everything.
			blockAll = true
		}
	}
	for _, rs := range ir.Recv.Respond {
		if rs.Path == "" {
			blockAll = true
			continue
		}
		globs = append(globs, pathGlob{prefix: rs.Path})
	}
	// Store (1): a SCOPED cache_ttl / storage / cache_key recipe would CACHE P at the
	// edge POP — the one thing route-exclusion gives up (a passed path is never cached,
	// but a path the edge would store should stay in the worker to keep POP caching). The
	// always-on default recipe (SelKind "default" / Always selector) is excluded — it is
	// dead for a fully-passed path.
	for _, t := range ir.Response.TTL {
		if t.SelKind == "scope" && t.Scope != nil {
			add(scopeFootprint(*t.Scope, ir.Matchers))
		}
	}
	for _, s := range ir.Response.Storage {
		if s.SelKind == "scope" && s.Scope != nil {
			add(scopeFootprint(*s.Scope, ir.Matchers))
		}
	}
	for _, rc := range ir.Key.Recipes {
		if !rc.Selector.Always {
			add(scopeFootprint(rc.Selector, ir.Matchers))
		}
	}
	return blockAll, globs
}

// scopeFootprint returns the path footprint of a directive scope. An Always scope, or
// a scope that contains any non-path / non-reducible matcher, can match ANY path →
// blockAll. A purely path-bound scope returns its reduced globs.
func scopeFootprint(sc Scope, matchers map[string]Matcher) (bool, []pathGlob) {
	if sc.Always {
		return true, nil
	}
	gs, ok := scopePathGlobs(sc, matchers)
	if !ok {
		return true, nil
	}
	return false, gs
}

// pathGlobsOverlap reports whether two path globs can match a common path (used to
// test whether a candidate exclusion is touched by another directive's footprint).
func pathGlobsOverlap(a, b pathGlob) bool {
	switch {
	case a.isPrefix && b.isPrefix:
		return strings.HasPrefix(a.prefix, b.prefix) || strings.HasPrefix(b.prefix, a.prefix)
	case a.isPrefix:
		return strings.HasPrefix(b.prefix, a.prefix)
	case b.isPrefix:
		return strings.HasPrefix(a.prefix, b.prefix)
	default:
		return a.prefix == b.prefix
	}
}

// collapsePathGlobs removes redundant globs: an exact or prefix glob fully covered by
// a broader prefix glob in the set is dropped (overlapping prefixes collapse). The
// result is deterministic (sorted).
func collapsePathGlobs(in []pathGlob) []pathGlob {
	cp := append([]pathGlob(nil), in...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].prefix != cp[j].prefix {
			return cp[i].prefix < cp[j].prefix
		}
		// A prefix glob is broader than an exact of the same string — keep it first.
		return cp[i].isPrefix && !cp[j].isPrefix
	})
	var kept []pathGlob
	for _, c := range cp {
		covered := false
		for _, k := range kept {
			if coversGlob(k, c) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, c)
		}
	}
	return kept
}

// coversGlob reports whether k matches every path c matches (k ⊇ c). A prefix glob
// covers any glob whose prefix it begins; an exact covers only an identical exact.
func coversGlob(k, c pathGlob) bool {
	if !k.isPrefix {
		return !c.isPrefix && k.prefix == c.prefix
	}
	return strings.HasPrefix(c.prefix, k.prefix)
}
