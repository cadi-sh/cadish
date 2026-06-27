package gateway

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/ingress"
)

// This file renders Gateway HTTPRoutes into the Cadishfile site model. The Ingress
// neutral seam (ingress.RenderHTTPSites) handles path-only routing to a SINGLE backend;
// Gateway slice 2 adds richer routes (header/method/query matcher conjunctions and
// WEIGHTED multi-backend pools) that the path-only seam cannot express, so the Gateway
// renderer is a parallel emitter that REUSES the same conventions the Ingress renderer
// established (and exports via the seam):
//   - upstream naming via ingress.SanitizeName (so names are valid Cadishfile tokens),
//   - the element-wise PathPrefix matcher (`path /api /api/*`, so /api never matches
//     /apiother) and the Exact matcher (`path /api`),
//   - the F7 terminal no-match 404 (`respond !@r0 !@r1 … 404`) so an unmatched path 404s
//     instead of silently falling through to the first upstream,
//   - one `host { … }` block per host, sites sorted, deterministic output.
//
// A Gateway route carries an AND-conjunction of matcher conditions (path AND headers AND
// method AND query) which compiles to the route's AND form (`route @r0p @r0h … -> u`,
// the security-gate grammar taught to `route` for this slice). Multiple matches in one
// rule are an OR: each renders its own route line to the same upstream.

// gwBackend is one resolved Service backend with its Gateway weight.
type gwBackend struct {
	ns, svc, port string
	weight        int32 // Gateway backendRef weight (default 1); 0 ⇒ excluded
}

// gwMatch is one HTTPRoute match: a path (Exact/Prefix) plus an AND-conjunction of
// header/method/query conditions. All conditions must hold (AND) for the match to fire.
type gwMatch struct {
	path     string
	pathKind ingress.PathKind
	// conds are the non-path conditions, each an inline matcher spec (type + args) that
	// becomes a named `@matcher` def AND'd into the route line.
	conds []matcherSpec
}

// matcherSpec is one inline matcher definition (`<type> <args…>`) to emit as a named
// matcher and reference (optionally negated) from a route's AND conjunction.
type matcherSpec struct {
	typ    string   // cadishfile matcher type: header, header_regex, method, query
	args   []string // matcher args (already sanitized for safe tokenization)
	negate bool     // emit as `!@name` in the conjunction (unused in slice 2; reserved)
}

// gwRouteRule is one collected routing rule for a host: a set of matches (OR) → a
// weighted backend pool. owner is the HTTPRoute "ns/name" for attribution/status.
type gwRouteRule struct {
	matches  []gwMatch
	backends []gwBackend
	owner    string
}

// renderGatewaySites renders the per-host rules into RenderedSite blocks. byHost maps a
// host to its rules (in collection order); the output mirrors ingress conventions:
// upstream dedup, specificity ordering (Exact before Prefix, longer path first), and the
// terminal no-match 404. Each site's Ingresses field is the sorted contributing route
// keys.
func renderGatewaySites(byHost map[string][]gwRouteRule) ([]ingress.RenderedSite, []Reject) {
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	sites := make([]ingress.RenderedSite, 0, len(hosts))
	var rejects []Reject
	for _, host := range hosts {
		text, owners := writeGatewaySite(host, byHost[host])
		// Structural breakout guard (mirrors the Ingress policy-fragment validateFragment):
		// a defense-in-depth backstop to the canonical quoting. Re-parse the rendered block
		// and require it to be EXACTLY one site for THIS host with no globals and no top-level
		// body. If anything escaped (a quoting regression, a future renderer bug), DROP the
		// site and surface a reject rather than apply a config that could serve a foreign host.
		if err := validateRenderedSite(host, text); err != nil {
			for _, owner := range owners {
				rejects = append(rejects, Reject{Kind: "HTTPRoute", Object: owner,
					Reason: fmt.Sprintf("generated site for host %q failed the structural breakout guard and was dropped: %v", host, err)})
			}
			continue
		}
		sites = append(sites, ingress.RenderedSite{Host: host, Text: text, Ingresses: owners})
	}
	return sites, rejects
}

// validateRenderedSite re-parses a rendered host block and confirms nothing escaped it:
// exactly one site, addressed to host alone, with no global block and no top-level body.
// This is the Gateway twin of the Ingress validateFragment structural check — the canonical
// quoter is the primary defense; this guard catches any breakout the quoter might miss.
func validateRenderedSite(host, text string) error {
	f, err := cadishfile.Parse("<gateway-site>", []byte(text))
	if err != nil {
		return err
	}
	if f.Global != nil || len(f.Body) != 0 || len(f.Sites) != 1 {
		return fmt.Errorf("rendered block did not stay within its site (unbalanced braces or extra blocks)")
	}
	addrs := f.Sites[0].Addresses
	if len(addrs) != 1 || addrs[0] != host {
		return fmt.Errorf("rendered site addresses %v, expected exactly [%q]", addrs, host)
	}
	return nil
}

// routeLine is one rendered route: its matcher defs, the route directive, and a
// specificity rank for ordering.
type routeLine struct {
	defs      []string // `@name <type> <args>` lines (no leading tab)
	route     string   // `route @a @b -> upstream` (no leading tab)
	rank      int      // 0 = Exact, 1 = Prefix (Exact wins)
	pathLen   int      // longer path first within a rank
	path      string   // for lexical tiebreak
	hasMethod bool     // a method match (precedence: method-qualified before unqualified)
	headerN   int      // number of header matches (more wins)
	queryN    int      // number of query-param matches (more wins)
	catchAll  bool     // a bare Prefix "/" with no extra conditions: terminal fallback
	deny      bool     // a `respond @ref 503` line (all-zero-weight rule), not a route
	refNames  []string // the @names this route references (for the no-match 404)
}

// writeGatewaySite emits one `host { … }` block plus the sorted contributing route keys.
func writeGatewaySite(host string, rules []gwRouteRule) (string, []string) {
	type up struct{ name, target string }
	upByName := map[string]string{}
	var upNames []string
	owners := map[string]bool{}

	// addPool returns the upstream name for a weighted backend pool, deduplicating by the
	// full pool identity so two rules with the same pool share one `upstream` block.
	addPool := func(bes []gwBackend) string {
		name, target := poolNameAndTarget(bes)
		if _, ok := upByName[name]; !ok {
			upByName[name] = target
			upNames = append(upNames, name)
		}
		return name
	}

	var lines []routeLine
	catchAllDeny := false // an all-zero-weight catch-all rule ⇒ the terminal fallback is 503
	mi := 0               // global matcher-name counter for @r<mi> uniqueness
	for _, rr := range rules {
		owners[rr.owner] = true
		usable := usableBackends(rr.backends)
		if len(usable) == 0 {
			// Every backendRef has weight 0 ⇒ Gateway API: serve 503 for this rule's matches
			// (NOT a silent fall-through, and NOT an empty/uncompilable site). A scoped match
			// emits `respond @ref 503`; a catch-all ("/" prefix, no conds) becomes the 503
			// terminal so more-specific real routes still win. The pool upstream is still
			// declared so a deny-only site keeps ≥1 upstream and compiles.
			addPool(rr.backends)
			for _, m := range rr.matches {
				if m.pathKind == ingress.PathPrefix && m.path == "/" && len(m.conds) == 0 {
					catchAllDeny = true
					continue
				}
				lines = append(lines, buildRouteLine(m, "", &mi, true))
			}
			continue
		}
		upName := addPool(usable)
		for _, m := range rr.matches {
			rl := buildRouteLine(m, upName, &mi, false)
			lines = append(lines, rl)
		}
	}

	// Specificity sort (Gateway API match precedence): Exact before Prefix; longer path
	// first; then a more-qualified match wins a same-path tie — a method match, then more
	// header matches, then more query-param matches — before the lexical tiebreak. Without
	// the qualifier tiers a plain `/foo` route could shadow a more-specific `/foo`+header
	// route purely by collection order. catch-alls sort last among prefixes (path "/" is
	// shortest).
	sort.SliceStable(lines, func(i, j int) bool {
		a, b := lines[i], lines[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.pathLen != b.pathLen {
			return a.pathLen > b.pathLen
		}
		if a.hasMethod != b.hasMethod {
			return a.hasMethod // method-qualified match is more specific
		}
		if a.headerN != b.headerN {
			return a.headerN > b.headerN
		}
		if a.queryN != b.queryN {
			return a.queryN > b.queryN
		}
		return a.path < b.path
	})

	var b strings.Builder
	b.WriteString(host)
	b.WriteString(" {\n")

	// Upstreams (sorted for determinism).
	sort.Strings(upNames)
	for _, n := range upNames {
		fmt.Fprintf(&b, "\tupstream %s { to %s }\n", n, upByName[n])
	}

	// Real scoped route refs (not deny responds, not catch-alls), in specificity order — the
	// matchers the terminal fallback negates, and the matchers a deny respond must negate so a
	// more-specific real route nested under the deny still routes (a `respond` fires in RECV
	// before any route, so without the negation a broad all-zero deny would 503 a nested real
	// path).
	var matcherNames []string
	hasCatchAll := false
	for _, l := range lines {
		if l.catchAll || l.deny {
			continue
		}
		matcherNames = append(matcherNames, l.refNames...)
	}

	// Routes: matcher defs then the route/deny line.
	for _, l := range lines {
		if l.catchAll {
			hasCatchAll = true
			continue // emitted after the scoped routes
		}
		for _, d := range l.defs {
			fmt.Fprintf(&b, "\t%s\n", d)
		}
		if l.deny {
			// Serve 503 for this rule's match — except where a more-specific real route
			// (one whose path-set the deny contains) handles the request: negate those.
			b.WriteString("\t")
			b.WriteString(l.route) // `respond @denyRef`
			for _, rl := range lines {
				if rl.catchAll || rl.deny {
					continue
				}
				if denyCovers(l, rl) {
					for _, rn := range rl.refNames {
						b.WriteString(" !")
						b.WriteString(rn)
					}
				}
			}
			b.WriteString(" 503\n")
			continue
		}
		fmt.Fprintf(&b, "\t%s\n", l.route)
	}
	// Bare catch-all routes after the scoped ones (the terminal fallback).
	for _, l := range lines {
		if l.catchAll {
			fmt.Fprintf(&b, "\t%s\n", l.route)
		}
	}

	// Terminal fallback for paths matching none of the REAL scoped routes:
	//   - a real catch-all route already serves them (nothing to emit);
	//   - else an all-zero-weight catch-all ⇒ 503 them (Gateway API), negating the real
	//     routes so a more-specific real match still wins; with no real route, 503 every path;
	//   - else F7: 404 them (instead of silently falling back to the first upstream).
	switch {
	case hasCatchAll:
		// real catch-all route is the fallback
	case catchAllDeny:
		if len(matcherNames) > 0 {
			b.WriteString("\trespond")
			for _, m := range matcherNames {
				b.WriteString(" !")
				b.WriteString(m)
			}
			b.WriteString(" 503\n")
		} else {
			b.WriteString("\t@__deny_all path *\n\trespond @__deny_all 503\n")
		}
	case len(matcherNames) > 0:
		b.WriteString("\trespond")
		for _, m := range matcherNames {
			b.WriteString(" !")
			b.WriteString(m)
		}
		b.WriteString(" 404\n")
	}
	b.WriteString("}\n")

	return b.String(), sortedBoolKeys(owners)
}

// buildRouteLine renders one match into a route line. The path becomes a `@rNp` matcher
// (element-wise prefix or exact); each non-path condition becomes its own `@rN…` matcher.
// When a match has extra conditions, they are ANDed into ONE composite `@rN all …` matcher
// so the route is a single ref (`route @rN -> u`) — which keeps the terminal no-match 404
// (`respond !@rN … 404`, a conjunction of NEGATED route matchers = matched none) CORRECT.
// A bare Prefix "/" with no extra conditions is a catch-all (no matcher, the terminal
// fallback). When deny is true the rule has an all-zero-weight backend pool, so the line
// is a `respond @ref 503` (Gateway API) instead of a route to upstream; deny is only ever
// passed for a NON-catch-all match (the caller folds a catch-all deny into the 503
// terminal). *mi is the running matcher-name counter.
func buildRouteLine(m gwMatch, upstream string, mi *int, deny bool) routeLine {
	id := *mi
	*mi++

	bareCatchAll := m.pathKind == ingress.PathPrefix && m.path == "/" && len(m.conds) == 0
	if bareCatchAll {
		return routeLine{
			route:    fmt.Sprintf("route -> %s", upstream),
			rank:     1,
			pathLen:  len(m.path),
			path:     m.path,
			catchAll: true,
		}
	}

	var defs []string
	rank := 1
	if m.pathKind == ingress.PathExact {
		rank = 0
	}
	hasMethod, headerN, queryN := condSpecificity(m.conds)

	// Path matcher (always present; defaults to a "/" prefix when a match omits a path).
	pname := fmt.Sprintf("@r%dp", id)
	defs = append(defs, fmt.Sprintf("%s %s", pname, pathMatcherArgs(m.path, m.pathKind)))

	// No extra conditions: the path matcher IS the route/deny ref.
	if len(m.conds) == 0 {
		return routeLine{
			defs:     defs,
			route:    routeOrDeny(deny, pname, upstream),
			rank:     rank,
			pathLen:  len(m.path),
			path:     m.path,
			refNames: []string{pname},
			deny:     deny,
		}
	}

	// Extra conditions: emit each as its own matcher, then an `all` composite ANDing the
	// path + conditions into a single ref.
	var subRefs []string
	subRefs = append(subRefs, pname)
	for ci, c := range m.conds {
		cname := fmt.Sprintf("@r%dc%d", id, ci)
		defs = append(defs, fmt.Sprintf("%s %s %s", cname, c.typ, strings.Join(c.args, " ")))
		if c.negate {
			subRefs = append(subRefs, "!"+cname)
		} else {
			subRefs = append(subRefs, cname)
		}
	}
	aname := fmt.Sprintf("@r%d", id)
	defs = append(defs, fmt.Sprintf("%s all %s", aname, strings.Join(subRefs, " ")))
	return routeLine{
		defs:      defs,
		route:     routeOrDeny(deny, aname, upstream),
		rank:      rank,
		pathLen:   len(m.path),
		path:      m.path,
		hasMethod: hasMethod,
		headerN:   headerN,
		queryN:    queryN,
		refNames:  []string{aname},
		deny:      deny,
	}
}

// condSpecificity counts a match's non-path qualifiers for Gateway API precedence: whether
// it carries a method match, and how many header / query-param matches it has.
func condSpecificity(conds []matcherSpec) (hasMethod bool, headerN, queryN int) {
	for _, c := range conds {
		switch c.typ {
		case "method":
			hasMethod = true
		case "header", "header_regex":
			headerN++
		case "query":
			queryN++
		}
	}
	return hasMethod, headerN, queryN
}

// routeOrDeny renders either a complete `route @ref -> upstream` line or, for an
// all-zero-weight rule, the `respond @ref` PREFIX of a deny line — writeGatewaySite appends
// the (negated) more-specific real-route refs and the trailing ` 503`.
func routeOrDeny(deny bool, ref, upstream string) string {
	if deny {
		return fmt.Sprintf("respond %s", ref)
	}
	return fmt.Sprintf("route %s -> %s", ref, upstream)
}

// denyCovers reports whether the all-zero-weight deny line d's matched path-set CONTAINS the
// real route line r's matched path-set, so r (equal-or-more specific) should still route
// rather than be 503'd by d. Prefix d covers r when r's path is d's path or nests under it at
// a segment boundary (root "/" covers everything); Exact d covers only an Exact r on the same
// path. Conditions on d only narrow when its respond fires, so ignoring them here stays safe.
func denyCovers(d, r routeLine) bool {
	dExact := d.rank == 0
	if dExact {
		return r.rank == 0 && r.path == d.path
	}
	if d.path == "/" {
		return true
	}
	return r.path == d.path || strings.HasPrefix(r.path, d.path+"/")
}

// pathMatcherArgs renders the `path` matcher args: Exact "/p" → `path /p`; Prefix "/p" →
// `path /p /p/*` (the element-wise prefix the Ingress seam uses, so /p never matches
// /prefix). Mirrors ingress.pathMatcherArgs exactly.
func pathMatcherArgs(path string, kind ingress.PathKind) string {
	// Each path token is rendered through the canonical quoter as a COMPLETE token
	// (the "/*" suffix is folded in before quoting), so a hostile path like "/a}"
	// cannot close the host block (R38's Gateway twin). A normal "/api" has no special
	// characters and renders verbatim.
	if kind == ingress.PathExact {
		return "path " + cadishfile.QuoteArg(path)
	}
	return fmt.Sprintf("path %s %s", cadishfile.QuoteArg(path), cadishfile.QuoteArg(path+"/*"))
}

// poolNameAndTarget builds the upstream name + `to` target list for a weighted backend
// pool. A single backend → `to k8s://svc.ns:port` (the trivial origin). Multiple backends
// → a multi-target `to` line (a round-robin lb pool); the Gateway weight is approximated
// by even distribution across the listed backends (cadish has no per-backend weight knob;
// see D82), with zero-weight backends already excluded by usableBackends. The name encodes
// every member so two distinct pools never collide.
func poolNameAndTarget(bes []gwBackend) (string, string) {
	// Sort members for a deterministic name + target order.
	sorted := append([]gwBackend(nil), bes...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].svc != sorted[j].svc {
			return sorted[i].svc < sorted[j].svc
		}
		if sorted[i].ns != sorted[j].ns {
			return sorted[i].ns < sorted[j].ns
		}
		return sorted[i].port < sorted[j].port
	})
	var nameParts, targets []string
	for _, be := range sorted {
		nameParts = append(nameParts, ingress.SanitizeName(be.ns)+"_"+ingress.SanitizeName(be.svc)+"_"+ingress.SanitizeName(be.port))
		targets = append(targets, fmt.Sprintf("k8s://%s.%s:%s", be.svc, be.ns, be.port))
	}
	name := "u_" + strings.Join(nameParts, "__")
	return name, strings.Join(targets, " ")
}

// usableBackends drops zero-weight backends (Gateway: weight 0 ⇒ no traffic). When every
// backend is zero-weight the rule has no servable backend and is skipped by the caller.
func usableBackends(bes []gwBackend) []gwBackend {
	var out []gwBackend
	for _, be := range bes {
		if be.weight == 0 {
			continue
		}
		out = append(out, be)
	}
	return out
}

// sortedBoolKeys returns the sorted keys of a string set (nil-safe).
func sortedBoolKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
