package check

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// suggest produces optimization suggestions for a site: cheap, high-signal
// rewrites the report nudges the user toward. Returns a stable-ordered slice.
func suggest(body []cadishfile.Node, defs map[string]*cadishfile.MatcherDef) []string {
	var out []string

	out = append(out, suggestCollapsePass(body, defs)...)
	out = append(out, suggestRegexToGlob(body, defs)...)
	out = append(out, suggestGoodCollapse(defs)...)
	out = append(out, suggestBoundedNormalizer(body)...)

	return out
}

// suggestBoundedNormalizer notes when a cache_key varies on the {device} or
// {geo} normalizers. Unlike keying on a raw request header (unbounded cardinality
// → cache fragmentation), these resolve to a small, bounded class set, so they
// vary the cache safely. The note confirms the good practice.
func suggestBoundedNormalizer(body []cadishfile.Node) []string {
	device, geo, tenant := false, false, false
	tenantCount := -1           // distinct tenant ids from a `tenant { … }` block; -1 = not a block
	buckets := map[string]int{} // user-defined `normalize NAME` -> bucket count
	usedNorm := map[string]bool{}
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		if d.Name == "normalize" && len(d.Args) == 1 {
			buckets[d.Args[0].Raw] = normalizeBucketCount(d)
			continue
		}
		if d.Name == "tenant" && d.HasBlock {
			tenantCount = tenantIDCount(d)
			continue
		}
		if d.Name != "cache_key" {
			continue
		}
		for _, a := range d.Args {
			switch a.Raw {
			case "{device}":
				device = true
			case "{geo}":
				geo = true
			case "{tenant}":
				tenant = true
			default:
				if strings.HasPrefix(a.Raw, "{") && strings.HasSuffix(a.Raw, "}") && len(a.Raw) > 2 {
					usedNorm[a.Raw[1:len(a.Raw)-1]] = true
				}
			}
		}
	}
	var out []string
	if device {
		out = append(out, "cache_key {device} varies on a bounded device class (desktop/mobile/tablet/bot) — low cardinality, safe for hit-rate; customize the classes with a `device_detect { … }` block")
	}
	if geo {
		out = append(out, "cache_key {geo} varies on a bounded geo class (country code) — low cardinality, safe for hit-rate; configure the source with a `geo { … }` block")
	}
	if tenant {
		if tenantCount >= 0 {
			out = append(out, fmt.Sprintf("cache_key {tenant} varies on the %d bounded tenant ids of the `tenant { … }` block — low cardinality, brands get isolated cache entries", tenantCount))
		} else {
			out = append(out, "cache_key {tenant} varies on the site's tenant id (a per-site constant) — brands get isolated cache entries")
		}
	}
	names := make([]string, 0, len(usedNorm))
	for name := range usedNorm {
		if _, ok := buckets[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, fmt.Sprintf("cache_key {%s} varies on the %d bounded buckets of `normalize %s` — low cardinality, safe for hit-rate", name, buckets[name], name))
	}
	return out
}

// normalizeBucketCount counts the distinct buckets a `normalize` directive can
// emit (every `map … -> BUCKET` target plus the `default`), from its AST block.
func normalizeBucketCount(d *cadishfile.Directive) int {
	seen := map[string]bool{}
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "map":
			if n := len(bd.Args); n >= 1 { // bucket is the last token (after `->`)
				seen[bd.Args[n-1].Raw] = true
			}
		case "default":
			if len(bd.Args) == 1 {
				seen[bd.Args[0].Raw] = true
			}
		}
	}
	return len(seen)
}

// tenantIDCount counts the distinct tenant ids a request-derived `tenant { … }`
// block can emit (every `map … -> NAME` target plus the `default`).
func tenantIDCount(d *cadishfile.Directive) int {
	seen := map[string]bool{}
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "map":
			if n := len(bd.Args); n >= 1 {
				seen[bd.Args[n-1].Raw] = true
			}
		case "default":
			if len(bd.Args) == 1 {
				seen[bd.Args[0].Raw] = true
			}
		}
	}
	return len(seen)
}

// suggestCollapsePass detects multiple separate `pass`-by-path rules that could
// be one matcher with many args (one set lookup, not N).
func suggestCollapsePass(body []cadishfile.Node, defs map[string]*cadishfile.MatcherDef) []string {
	single := 0
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "pass" {
			continue
		}
		u := directiveUsages(d)
		// A pass that scopes exactly one path (inline single path, or a named
		// path matcher with a single arg) is a collapse candidate.
		if len(u.inlines) == 1 && len(u.refs) == 0 && u.inlines[0].typ == "path" && len(u.inlines[0].args) == 1 {
			single++
		} else if len(u.refs) == 1 && len(u.inlines) == 0 {
			if m := defs[u.refs[0].name]; m != nil && m.Type == "path" && len(m.Args) == 1 {
				single++
			}
		}
	}
	if single >= 2 {
		return []string{fmt.Sprintf(
			"%d separate `pass path …` rules → collapse into one matcher with %d args (one set lookup, not %d)",
			single, single, single)}
	}
	return nil
}

// suggestRegexToGlob detects path_regex matchers that are an anchored literal
// prefix (`^/foo`) where a `path /foo*` glob — a cheap trie lookup, not a regex —
// would suffice.
func suggestRegexToGlob(body []cadishfile.Node, defs map[string]*cadishfile.MatcherDef) []string {
	var out []string
	seen := map[string]bool{}
	consider := func(pat string) {
		if seen[pat] {
			return
		}
		if lit, ok := anchoredLiteralPrefix(pat); ok {
			seen[pat] = true
			out = append(out, fmt.Sprintf(
				"`path_regex %s` is an anchored literal → use `path %s*` (a trie lookup, weight 2, not a regex, weight 10)",
				pat, lit))
		}
	}
	for _, name := range sortedKeys(defs) {
		if m := defs[name]; m.Type == "path_regex" {
			for _, a := range m.Args {
				consider(a.Raw)
			}
		}
	}
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		for _, in := range directiveUsages(d).inlines {
			if in.typ == "path_regex" {
				for _, a := range in.args {
					consider(a.Raw)
				}
			}
		}
	}
	return out
}

// suggestGoodCollapse positively acknowledges a path matcher that already
// collapses many paths into one set lookup — reinforcing the pattern the report
// promotes.
func suggestGoodCollapse(defs map[string]*cadishfile.MatcherDef) []string {
	var out []string
	for _, name := range sortedKeys(defs) {
		if m := defs[name]; m.Type == "path" && len(m.Args) >= 8 {
			out = append(out, fmt.Sprintf(
				"good: @%s collapses %d paths into one matcher (a single set/trie lookup, not %d compares)",
				name, len(m.Args), len(m.Args)))
		}
	}
	return out
}

// sortedKeys returns the matcher-def names in deterministic (sorted) order.
func sortedKeys(defs map[string]*cadishfile.MatcherDef) []string {
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// anchoredLiteralPrefix reports whether pat is `^<literal>` with no further regex
// metacharacters, returning the literal. `^static`, `^/foo/bar` qualify;
// `^foo$`, `^a|b`, `\.css$` do not.
func anchoredLiteralPrefix(pat string) (string, bool) {
	if !strings.HasPrefix(pat, "^") {
		return "", false
	}
	rest := pat[1:]
	if rest == "" {
		return "", false
	}
	if strings.ContainsAny(rest, "^$.*+?()[]{}|\\") {
		return "", false
	}
	return rest, true
}
