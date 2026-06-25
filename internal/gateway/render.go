package gateway

import (
	"fmt"
	"sort"
	"strings"

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
func renderGatewaySites(byHost map[string][]gwRouteRule) []ingress.RenderedSite {
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	sites := make([]ingress.RenderedSite, 0, len(hosts))
	for _, host := range hosts {
		text, owners := writeGatewaySite(host, byHost[host])
		sites = append(sites, ingress.RenderedSite{Host: host, Text: text, Ingresses: owners})
	}
	return sites
}

// routeLine is one rendered route: its matcher defs, the route directive, and a
// specificity rank for ordering.
type routeLine struct {
	defs     []string // `@name <type> <args>` lines (no leading tab)
	route    string   // `route @a @b -> upstream` (no leading tab)
	rank     int      // 0 = Exact, 1 = Prefix (Exact wins)
	pathLen  int      // longer path first within a rank
	path     string   // for lexical tiebreak
	catchAll bool     // a bare Prefix "/" with no extra conditions: terminal fallback
	refNames []string // the @names this route references (for the no-match 404)
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
	mi := 0 // global matcher-name counter for @r<mi> uniqueness
	for _, rr := range rules {
		owners[rr.owner] = true
		usable := usableBackends(rr.backends)
		if len(usable) == 0 {
			continue // no servable backend (all zero-weight / unresolved) — skip the rule
		}
		upName := addPool(usable)
		for _, m := range rr.matches {
			rl := buildRouteLine(m, upName, &mi)
			lines = append(lines, rl)
		}
	}

	// Specificity sort (mirrors ingress writeSite): Exact before Prefix; longer path
	// first; lexical tiebreak. catch-alls sort last among prefixes (path "/" is shortest).
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].rank != lines[j].rank {
			return lines[i].rank < lines[j].rank
		}
		if lines[i].pathLen != lines[j].pathLen {
			return lines[i].pathLen > lines[j].pathLen
		}
		return lines[i].path < lines[j].path
	})

	var b strings.Builder
	b.WriteString(host)
	b.WriteString(" {\n")

	// Upstreams (sorted for determinism).
	sort.Strings(upNames)
	for _, n := range upNames {
		fmt.Fprintf(&b, "\tupstream %s { to %s }\n", n, upByName[n])
	}

	// Routes: matcher defs then the route line. Track scoped (conditioned) route refs for
	// the terminal no-match 404; a catch-all route is the terminal fallback instead.
	var matcherNames []string
	hasCatchAll := false
	for _, l := range lines {
		if l.catchAll {
			hasCatchAll = true
			continue // emitted after the scoped routes
		}
		for _, d := range l.defs {
			fmt.Fprintf(&b, "\t%s\n", d)
		}
		fmt.Fprintf(&b, "\t%s\n", l.route)
		matcherNames = append(matcherNames, l.refNames...)
	}
	// Bare catch-all routes after the scoped ones (the terminal fallback).
	for _, l := range lines {
		if l.catchAll {
			fmt.Fprintf(&b, "\t%s\n", l.route)
		}
	}

	// F7 terminal no-match 404: a site with scoped routes and NO catch-all 404s any path
	// matching none of the route matchers, instead of falling back to the first upstream.
	if !hasCatchAll && len(matcherNames) > 0 {
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
// fallback). *mi is the running matcher-name counter.
func buildRouteLine(m gwMatch, upstream string, mi *int) routeLine {
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

	// Path matcher (always present; defaults to a "/" prefix when a match omits a path).
	pname := fmt.Sprintf("@r%dp", id)
	defs = append(defs, fmt.Sprintf("%s %s", pname, pathMatcherArgs(m.path, m.pathKind)))

	// No extra conditions: the path matcher IS the route ref.
	if len(m.conds) == 0 {
		return routeLine{
			defs:     defs,
			route:    fmt.Sprintf("route %s -> %s", pname, upstream),
			rank:     rank,
			pathLen:  len(m.path),
			path:     m.path,
			refNames: []string{pname},
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
		defs:     defs,
		route:    fmt.Sprintf("route %s -> %s", aname, upstream),
		rank:     rank,
		pathLen:  len(m.path),
		path:     m.path,
		refNames: []string{aname},
	}
}

// pathMatcherArgs renders the `path` matcher args: Exact "/p" → `path /p`; Prefix "/p" →
// `path /p /p/*` (the element-wise prefix the Ingress seam uses, so /p never matches
// /prefix). Mirrors ingress.pathMatcherArgs exactly.
func pathMatcherArgs(path string, kind ingress.PathKind) string {
	if kind == ingress.PathExact {
		return "path " + path
	}
	return fmt.Sprintf("path %s %s/*", path, path)
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
