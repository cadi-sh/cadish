package check

import "github.com/cadi-sh/cadish/internal/cadishfile"

// detectDeadRules flags selection directives that can never be reached because an
// earlier rule of the same kind always matches first. cadish evaluates selection
// directives (pass, cache_ttl, storage, route) first-match-wins, so anything after a
// catch-all — or a duplicate/subset of an earlier rule — is dead.
func detectDeadRules(body []cadishfile.Node, defs map[string]*cadishfile.MatcherDef, sr *SiteReport) {
	detectSelectorDead(body, "cache_ttl", sr)
	detectSelectorDead(body, "storage", sr)
	detectSelectorDead(body, "route", sr)
	detectKeyDead(body, sr)
	detectPassDead(body, defs, sr)
}

// detectKeyDead handles scoped cache_key. It mirrors detectSelectorDead but with
// two cache_key-specific rules: an UNSCOPED line (`cache_key TOKENS`, no selector)
// is itself a catch-all default (so anything after it is dead), and a scoped recipe
// set with NO catch-all is a hard error (the required-default rule — a request
// matching no scope would otherwise silently fall back to the built-in key).
func detectKeyDead(body []cadishfile.Node, sr *SiteReport) {
	seenDefault := false
	seenRef := map[string]bool{}
	hasScoped := false
	var firstScopedPos cadishfile.Pos
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "cache_key" {
			continue
		}
		key := selectorKey(d) // "" (unscoped), "default", "status", or "@name"
		if seenDefault {
			sr.add(SevWarning, d.Pos, "dead-rule",
				"unreachable cache_key: an earlier catch-all cache_key always matches first")
			continue
		}
		switch {
		case key == "" || key == "default":
			// An unscoped line or the explicit `default` keyword is the catch-all.
			seenDefault = true
		case key == "status":
			// A response-phase selector; the compiler rejects it. Treat as scoped so a
			// recipe set built only of it still demands a catch-all.
			hasScoped = true
			if firstScopedPos.Line == 0 {
				firstScopedPos = d.Pos
			}
		case len(key) > 0 && key[0] == '@':
			hasScoped = true
			if firstScopedPos.Line == 0 {
				firstScopedPos = d.Pos
			}
			if seenRef[key] {
				sr.add(SevWarning, d.Pos, "dead-rule",
					"unreachable cache_key: selector %s already matched by an earlier rule (first-match-wins)", key)
			}
			seenRef[key] = true
		}
	}
	if hasScoped && !seenDefault {
		sr.add(SevError, firstScopedPos, "cache-key-no-default",
			"scoped cache_key needs a catch-all: add a `cache_key default TOKENS` (or one unscoped `cache_key TOKENS`) line so every request resolves to a recipe")
	}
}

// selectorKey reduces a cache_ttl/storage directive to its selector identity:
// "default", "@name", "status", "inline", or "" (none).
func selectorKey(d *cadishfile.Directive) string {
	u := directiveUsages(d)
	if len(u.refs) > 0 {
		return "@" + u.refs[0].name
	}
	if len(u.selectors) > 0 {
		return u.selectors[0]
	}
	if len(u.inlines) > 0 {
		return "inline"
	}
	return ""
}

// detectSelectorDead handles cache_ttl / storage: a `default` selector is a
// catch-all (everything after it is dead); a repeated `@name` selector is a
// duplicate (the later one never wins).
func detectSelectorDead(body []cadishfile.Node, name string, sr *SiteReport) {
	seenDefault := false
	seenRef := map[string]bool{}
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != name {
			continue
		}
		key := selectorKey(d)
		if seenDefault {
			sr.add(SevWarning, d.Pos, "dead-rule",
				"unreachable %s: an earlier `%s default` always matches first", name, name)
			continue
		}
		switch {
		case key == "default":
			seenDefault = true
		case len(key) > 0 && key[0] == '@':
			if seenRef[key] {
				sr.add(SevWarning, d.Pos, "dead-rule",
					"unreachable %s: selector %s already matched by an earlier rule (first-match-wins)", name, key)
			}
			seenRef[key] = true
		}
	}
}

// detectPassDead handles pass: an unconditioned `pass` is a catch-all (everything
// after is dead); a later pass whose path scope is a strict subset of an earlier
// pass is shadowed.
func detectPassDead(body []cadishfile.Node, defs map[string]*cadishfile.MatcherDef, sr *SiteReport) {
	catchAll := false
	var prior [][]string // path globs of earlier pass rules
	for _, n := range body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "pass" {
			continue
		}
		if catchAll {
			sr.add(SevWarning, d.Pos, "dead-rule",
				"unreachable pass: an earlier unconditioned `pass` already bypasses every request")
			continue
		}
		if len(d.Args) == 0 {
			catchAll = true
			continue
		}
		globs := pathGlobsOf(d, defs)
		if len(globs) > 0 && subsumedBy(globs, prior) {
			sr.add(SevWarning, d.Pos, "dead-rule",
				"redundant pass: its paths are already covered by an earlier pass rule")
		}
		if len(globs) > 0 {
			prior = append(prior, globs)
		}
	}
}

// subsumedBy reports whether every glob in cand is subsumed by some glob in any
// earlier rule's glob set. Conservative: requires full coverage.
func subsumedBy(cand []string, prior [][]string) bool {
	for _, c := range cand {
		covered := false
		for _, set := range prior {
			for _, p := range set {
				if globSubsumes(p, c) {
					covered = true
					break
				}
			}
			if covered {
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
