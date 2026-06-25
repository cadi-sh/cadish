package edgeir

import "strings"

// splitRE2Flags normalizes a Go RE2 regex SOURCE into a (pattern, jsFlags) pair
// the JavaScript `RegExp` constructor can compile faithfully.
//
// Go's `regexp` (RE2) accepts inline flag groups like `(?i)`, `(?is)`, `(?im)`
// anchored at the START of the source (and `(?i)` mid-source). JavaScript's
// `RegExp` does NOT support inline `(?flags)` groups and throws
// `SyntaxError: Invalid group` on them — so the worker 500s on every request that
// touches such a pattern (BUG-1). We lift the LEADING inline flag group out of the
// source and emit it as a separate `flags` string, mapping each RE2 flag to its JS
// equivalent:
//
//	i  -> i   (case-insensitive)
//	m  -> m   (multiline ^ $)
//	s  -> s   (dotall: . matches \n; RE2 `s` and JS `s` are the same)
//
// Any other RE2 flag has NO faithful JS equivalent and is reported untranslatable
// so the caller DELEGATES the directive (loud) rather than shipping a pattern that
// either crashes or silently means something different:
//
//	U  (ungreedy / swap-greediness)         — no JS flag
//	-  (negation, e.g. `(?-i)`)             — no JS per-scope toggle
//	a non-leading / scoped flag group `(?i:…)` or a mid-pattern `(?i)` — left in the
//	   source; JS still cannot compile it, so it is reported untranslatable.
//
// ok=false means: do not ship this regex to the edge — delegate the directive.
// When ok=true, pattern+jsFlags compile to the SAME match as the RE2 source.
func splitRE2Flags(src string) (pattern string, jsFlags string, ok bool) {
	// Only a SINGLE leading GLOBAL inline flag group `(?flags)` (no `:`) is liftable.
	// A leading group is a flag group ONLY when the chars between `(?` and its `)` (or
	// `:`) terminator are actual RE2 flags. A leading NON-flag group — `(?:…)`
	// non-capturing, `(?=…)`/`(?!…)` lookahead, `(?<name>…)` named capture, `(?<=…)`/
	// `(?<!…)` lookbehind — is identical in RE2 and JS and must project edge-native,
	// not be mistaken for a flag group and delegated (finding 3).
	if !strings.HasPrefix(src, "(?") || !isLeadingFlagGroup(src) {
		// No LIFTABLE leading flag group. The pattern may still contain a mid-source
		// inline flag group (e.g. `^/a(?i)b`, or a leading scoped `(?i:…)`) that JS
		// cannot compile — detect and delegate. A leading non-flag group is left for
		// hasInlineFlagGroup, which correctly does NOT flag JS-supported constructs.
		if hasInlineFlagGroup(src) {
			return "", "", false
		}
		return src, "", true
	}
	end := strings.IndexByte(src, ')')
	// end >= 0 is guaranteed by isLeadingFlagGroup.
	flagsPart := src[2:end] // between `(?` and `)`; all flag chars (no `:`)
	rest := src[end+1:]
	js, ok := re2FlagsToJS(flagsPart)
	if !ok {
		return "", "", false
	}
	// The remainder must not itself carry another inline flag group JS can't handle.
	if hasInlineFlagGroup(rest) {
		return "", "", false
	}
	return rest, js, true
}

// isLeadingFlagGroup reports whether src OPENS with a global inline flag group
// `(?flags)` — i.e. `(?` followed by one or more actual flag chars (i/m/s/U/-) and
// then a closing `)`, with NO `:` (a `:` makes it a scoped `(?flags:…)` group, which
// is not liftable). It returns false for any leading NON-flag group (`(?:`, `(?=`,
// `(?!`, `(?<…`), so those project edge-native instead of being delegated.
func isLeadingFlagGroup(src string) bool {
	if !strings.HasPrefix(src, "(?") {
		return false
	}
	for i := 2; i < len(src); i++ {
		switch src[i] {
		case ')':
			return i > 2 // `(?)` (empty) is not a flag group
		case 'i', 'm', 's', 'U', '-':
			// flag char — keep scanning
		default:
			// `:` (scoped group), a group-construct char (`<`, `=`, `!`, letters of a
			// name, `:` of `(?:`), or anything else: not a global flag group.
			return false
		}
	}
	return false // unterminated `(?…`
}

// re2FlagsToJS maps the chars of a leading RE2 flag group to a JS flag string.
// Returns ok=false on any flag without a faithful JS equivalent.
func re2FlagsToJS(flags string) (string, bool) {
	var b strings.Builder
	seen := map[rune]bool{}
	for _, r := range flags {
		switch r {
		case 'i', 'm', 's':
			if !seen[r] {
				b.WriteRune(r)
				seen[r] = true
			}
		default:
			// U (ungreedy), - (negation), or anything else: no faithful JS mapping.
			return "", false
		}
	}
	return b.String(), true
}

// hasInlineFlagGroup reports whether s contains an inline flag group `(?flags)` or
// `(?flags:…)` that JavaScript's RegExp cannot compile. It scans for `(?` not
// followed by a construct JS DOES support: `(?:`  (non-capturing), `(?=`/`(?!`
// (lookahead), `(?<=`/`(?<!` (lookbehind), and `(?<name>` (named capture). A `(?`
// followed by a flag letter (i/m/s/U/-/etc.) is an inline flag group → true.
func hasInlineFlagGroup(s string) bool {
	inClass := false // inside a `[...]` character class, where `(?` is two literals
	for i := 0; i+1 < len(s); i++ {
		// Track character-class boundaries so a `(?` inside `[...]` is not read as a
		// group. An unescaped `[` opens a class, an unescaped `]` closes it.
		if !isEscaped(s, i) {
			if !inClass && s[i] == '[' {
				inClass = true
				continue
			}
			if inClass && s[i] == ']' {
				inClass = false
				continue
			}
		}
		if inClass {
			continue
		}
		if s[i] != '(' || s[i+1] != '?' {
			continue
		}
		// An escaped paren `\(` is a literal, not a group opener. `isEscaped` counts
		// the run of preceding backslashes: ODD ⇒ the `(` is escaped (skip), EVEN ⇒
		// the backslashes are literal and the `(` opens a real group (e.g. `\\(?i)`).
		if isEscaped(s, i) {
			continue
		}
		rest := s[i+2:]
		if rest == "" {
			return true // dangling `(?`
		}
		c := rest[0]
		switch c {
		case ':', '=', '!':
			continue // (?:  (?=  (?!  — JS supports these
		case '<':
			// (?<name>  (?<=  (?<!  — JS supports lookbehind + named capture.
			continue
		default:
			// (?i) (?ms) (?U) (?-i) (?P<…> etc. — an inline flag group (or RE2-only
			// named-capture syntax JS doesn't share). Treat as untranslatable.
			return true
		}
	}
	return false
}

// isEscaped reports whether the char at index i is escaped by a backslash — i.e.
// preceded by an ODD number of consecutive backslashes. An even run (e.g. `\\(`)
// means the backslashes are themselves literal and the char is NOT escaped.
func isEscaped(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}
