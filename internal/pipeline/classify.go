package pipeline

import (
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// classifier is a compiled `classify {TOKEN} { when … -> VALUE ; default -> VALUE }`
// directive: a first-match-wins rule table that derives a NAMED enum token from
// the request. Each row is a CONJUNCTION (AND) of matchers; the first row whose
// matchers ALL match yields that row's literal value, else the default.
//
// It is the conditional generalization of {device}/{geo}/normalize (D7): unlike
// normalize (which reads ONE request value and maps it), a classifier reduces
// SEVERAL matchers to one bounded enum. It is PURE — its matchers read only the
// Request, so the {TOKEN} cache-key token resolves entirely in the pipeline with
// no server pre-pass, exactly like normalize.
//
// The values are LITERALS (never computed); the conditions are named/inline
// matchers combined only by AND (within a row) and OR (across rows). There is no
// expression language, no control flow beyond the first-match table — it is a
// switch/lookup, not a program.
type classifier struct {
	name string
	pos  cadishfile.Pos
	rows []classifyRow
	def  string // default value ("" if no default row)
	// derivesFrom names the request COOKIES this axis consumes (`derives_from cookie
	// NAME…`). When this token is in the SELECTED cache_key recipe these cookies (a)
	// survive `cookie_allow` so the classifier reads the ORIGINAL value and the key is
	// built from it, then (b) are STRIPPED from the request after the key is captured
	// and before the credential check + origin fetch (the Varnish derive→unset Cookie→
	// key-normalized collapse). nil/empty when the classify declares no derives_from.
	// It is the SINGLE fail-closed mechanism: a kept-but-undeclared cookie still
	// bypasses (no coverage-extension), so an axis must list ALL its inputs.
	derivesFrom []string
	// derivesForward is the SUBSET of derivesFrom declared with the trailing `forward`
	// (alias `keep`) modifier (`derives_from cookie NAME… forward`). These cookies are
	// read + keyed like every derives_from cookie, but instead of being STRIPPED post-key
	// they are FORWARDED to origin unchanged and treated as COVERED by {TOKEN} for the
	// credential bypass — the loud opt-in for backends that personalize from the raw
	// cookie. Membership here is the only thing that flips a derives_from cookie from
	// strip-mode (the safe default) to forward-mode. nil when no row uses the modifier.
	derivesForward []string
}

// isForwardCookie reports whether cookie name is a `forward`/`keep` derives_from input of
// this axis (so it must be forwarded — not stripped — and treated as covered when keyed).
func (cl *classifier) isForwardCookie(name string) bool {
	for _, c := range cl.derivesForward {
		if c == name {
			return true
		}
	}
	return false
}

// classifyRow is one `when @a @b -> VALUE` row: a conjunction of matchers (ALL
// must match) yielding value.
type classifyRow struct {
	conj  []*matcher // AND: every matcher must match for the row to fire
	value string
}

// resolve evaluates the classifier against the match context and returns the
// derived token value: the first row whose conjunction fully matches, else the
// default. Matcher results are memoized via the context, so a matcher shared with
// other directives is evaluated once per request.
func (cl *classifier) resolve(c *matchContext) string {
	for _, r := range cl.rows {
		if c.conjMatches(r.conj) {
			return r.value
		}
	}
	return cl.def
}

// values returns the bounded set of values this classifier can emit (row values
// plus the default), so tooling can confirm {TOKEN} is low-cardinality.
func (cl *classifier) values() []string {
	seen := make(map[string]bool, len(cl.rows)+1)
	out := make([]string, 0, len(cl.rows)+1)
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range cl.rows {
		add(r.value)
	}
	add(cl.def)
	return out
}

// conjMatches reports whether EVERY matcher in the conjunction matches (AND). An
// empty conjunction is vacuously true. Results are memoized via the context.
func (c *matchContext) conjMatches(conj []*matcher) bool {
	for _, m := range conj {
		if !c.matches(m) {
			return false
		}
	}
	return true
}

// classifyDirMatcherRefs returns the set of @matcher names referenced in the `when`
// rows of a `classify {}` directive. These are the directive's dependencies: a
// referenced name that is a classify-equality matcher must be built before this
// classifier can compile. Inline matchers (`when path /x -> …`) carry no dependency
// and are skipped. It does not validate — that is compileClassify's job once the
// dependencies are satisfied.
func classifyDirMatcherRefs(d *cadishfile.Directive) []string {
	var refs []string
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "when" {
			continue
		}
		for _, a := range bd.Args {
			if a.Kind == cadishfile.ArgMatcherRef {
				refs = append(refs, strings.TrimPrefix(a.Raw, "@"))
			}
		}
	}
	return refs
}

// classifyMatcherToken returns the classifier token a `@x classify {tok}==v` matcher
// def depends on, or "" if the def is malformed (left to compileClassifyMatcher to
// report). It only reads the dependency; it does not validate the test.
func classifyMatcherToken(args []cadishfile.Arg) string {
	if len(args) != 1 {
		return ""
	}
	token, _, ok := strings.Cut(args[0].Raw, "==")
	if !ok {
		token, _, ok = strings.Cut(args[0].Raw, "!=")
		if !ok {
			return ""
		}
	}
	name, ok := classifyTokenName(token)
	if !ok {
		return ""
	}
	return name
}

// compileClassify parses a `classify {TOKEN} { when … -> VALUE ; default -> VALUE }`
// directive into a classifier. Matchers in `when` rows are resolved against the
// site's named matchers (an inline matcher type is also accepted). The defined
// token name must not collide with a built-in or normalizer token.
func compileClassify(d *cadishfile.Directive, matchers map[string]*matcher) (*classifier, error) {
	if len(d.Args) != 1 {
		return nil, &CompileError{Pos: d.Pos, Msg: "classify needs a token name: `classify {TOKEN} { … }`"}
	}
	name, ok := classifyTokenName(d.Args[0].Raw)
	if !ok {
		return nil, &CompileError{Pos: d.Args[0].Pos, Msg: "classify token must be a {NAME} placeholder, got " + quote(d.Args[0].Raw)}
	}
	if reservedNormalizerNames[name] {
		return nil, &CompileError{Pos: d.Pos, Msg: "classify token " + quote(name) + " is reserved (built-in {" + name + "} token)"}
	}
	if !d.HasBlock {
		return nil, &CompileError{Pos: d.Pos, Msg: "classify " + quote(name) + " needs a { } block"}
	}
	cl := &classifier{name: name, pos: d.Pos}
	haveDefault := false
	// stripCookies / fwdCookies track, PER COOKIE NAME, whether this block declared it
	// on a bare (strip-mode) derives_from row and/or on a `forward`/`keep` row. A cookie
	// in BOTH is a contradiction the classifier cannot honor: it would key+forward the
	// cookie while the operator also asked to strip it (the safe default). isForwardCookie
	// collapses to a single line-level set, so the recipe-scoped guard cannot see this
	// same-block case — catch it here at classify-compile time (R35).
	stripCookies := map[string]cadishfile.Pos{}
	fwdCookies := map[string]bool{}
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "when":
			conj, value, err := compileClassifyRow(bd, matchers)
			if err != nil {
				return nil, err
			}
			cl.rows = append(cl.rows, classifyRow{conj: conj, value: value})
		case "default":
			if haveDefault {
				return nil, &CompileError{Pos: bd.Pos, Msg: "classify " + quote(name) + ": duplicate `default`"}
			}
			value, err := classifyArrowValue(bd.Args, bd.Pos, "default")
			if err != nil {
				return nil, err
			}
			cl.def = value
			haveDefault = true
		case "derives_from":
			cookies, forward, err := compileDerivesFrom(bd, name)
			if err != nil {
				return nil, err
			}
			cl.derivesFrom = append(cl.derivesFrom, cookies...)
			if forward {
				cl.derivesForward = append(cl.derivesForward, cookies...)
				for _, c := range cookies {
					fwdCookies[c] = true
				}
			} else {
				for _, c := range cookies {
					if _, seen := stripCookies[c]; !seen {
						stripCookies[c] = bd.Pos
					}
				}
			}
		default:
			return nil, &CompileError{Pos: bd.Pos, Msg: "classify " + quote(name) + ": unknown row " + quote(bd.Name) + " (want `when … -> VALUE`, `default -> VALUE`, or `derives_from cookie NAME…`)"}
		}
	}
	// A cookie declared BOTH strip (bare) and forward within this one block is a
	// contradiction — it cannot be simultaneously stripped (safe default) and forwarded
	// to origin. Reject it loudly so the safe-default strip is never silently downgraded
	// to forward (R35). Forward-only and strip-only declarations are unaffected.
	for c, pos := range stripCookies {
		if fwdCookies[c] {
			return nil, &CompileError{Pos: pos, Msg: "classify " + quote(name) + ": cookie " + quote(c) + " is declared both `derives_from cookie " + c + " forward` and `derives_from cookie " + c + "` (strip) in the same block — a cookie cannot be both; pick one (`forward` to expose it to origin, or bare for the safe-default strip)"}
		}
	}
	if len(cl.rows) == 0 {
		return nil, &CompileError{Pos: d.Pos, Msg: "classify " + quote(name) + " needs at least one `when … -> VALUE` row"}
	}
	if !haveDefault {
		return nil, &CompileError{Pos: d.Pos, Msg: "classify " + quote(name) + " needs a `default -> VALUE` row"}
	}
	return cl, nil
}

// compileDerivesFrom parses a `derives_from cookie NAME… [forward|keep]` classify row
// into the list of request cookie names the axis consumes plus whether the row is
// FORWARD-mode. The first arg MUST be the source keyword `cookie` (the only source today;
// a leading keyword keeps room for `header`/`query` later without a grammar break),
// followed by at least one cookie name. A trailing `forward` (alias `keep`) keyword marks
// the WHOLE line forward-mode: those cookies are forwarded to origin (not stripped) and
// covered by {TOKEN}. The modifier is recognized only when a cookie name precedes it, so a
// cookie literally named `forward`/`keep` on a strip line (`derives_from cookie forward`)
// is still a name. Per-cookie granularity is by separate lines (one strip, one forward).
// Cookie names are RFC 6265 case-sensitive and used verbatim by the survive/strip/forward
// machinery.
func compileDerivesFrom(bd *cadishfile.Directive, token string) ([]string, bool, error) {
	if len(bd.Args) < 2 || bd.Args[0].Raw != "cookie" {
		return nil, false, &CompileError{Pos: bd.Pos, Msg: "classify " + quote(token) + ": derives_from needs `cookie NAME…` (the request cookies this axis consumes)"}
	}
	rest := bd.Args[1:]
	forward := false
	// A trailing `forward`/`keep` modifier applies to all names on the line, but only when
	// at least one cookie name precedes it (len(rest) >= 2) — otherwise the single token IS
	// the cookie name (strip-mode), never the modifier (fail-closed: ambiguity stays strip).
	if len(rest) >= 2 {
		if last := rest[len(rest)-1].Raw; last == "forward" || last == "keep" {
			forward = true
			rest = rest[:len(rest)-1]
		}
	}
	out := make([]string, 0, len(rest))
	for _, a := range rest {
		if a.Raw == "" {
			return nil, false, &CompileError{Pos: a.Pos, Msg: "classify " + quote(token) + ": derives_from cookie name must be non-empty"}
		}
		out = append(out, a.Raw)
	}
	return out, forward, nil
}

// compileClassifyRow parses a `when <matchers> -> VALUE` row. The matchers before
// the arrow form a CONJUNCTION (AND): the row fires iff ALL match. They may be
// @matcher references or a single inline `TYPE arg…` matcher. The value after the
// arrow is a literal.
func compileClassifyRow(bd *cadishfile.Directive, matchers map[string]*matcher) ([]*matcher, string, error) {
	arrow := -1
	for i, a := range bd.Args {
		if a.Raw == "->" {
			arrow = i
			break
		}
	}
	if arrow < 0 {
		return nil, "", &CompileError{Pos: bd.Pos, Msg: "classify row needs `when <matchers> -> VALUE`"}
	}
	condArgs := bd.Args[:arrow]
	if len(condArgs) == 0 {
		return nil, "", &CompileError{Pos: bd.Pos, Msg: "classify `when` needs at least one matcher before `->`"}
	}
	conj, err := compileConjunction(condArgs, matchers, bd.Pos)
	if err != nil {
		return nil, "", err
	}
	value, err := classifyArrowValue(bd.Args[arrow:], bd.Pos, "when")
	if err != nil {
		return nil, "", err
	}
	// A classify token feeds the cache key / request-phase scopes, so a
	// response-phase matcher (content_type/set_cookie) can never be evaluated in
	// time — reject it up front rather than silently never firing.
	for _, m := range conj {
		if isResponsePhaseKind(m.kind) {
			return nil, "", &CompileError{Pos: bd.Pos, Msg: "classify cannot use a response-phase matcher (" + matcherKindName(m.kind) + " needs the origin response; a classify token resolves in the request phase)"}
		}
	}
	return conj, value, nil
}

// compileConjunction turns a `when` row's leading args into an AND-list of
// matchers: any number of @matcher refs, OR exactly one inline `TYPE arg…`
// matcher. This is the only place matchers combine with AND (existing directives
// keep their OR scope); within a row every matcher must match.
func compileConjunction(args []cadishfile.Arg, matchers map[string]*matcher, pos cadishfile.Pos) ([]*matcher, error) {
	if args[0].Kind == cadishfile.ArgMatcherRef {
		// `when @a @b @c` — a conjunction of named matchers. A bare `and` keyword is
		// tolerated as a readability connector between refs (`@a and @b`).
		out := make([]*matcher, 0, len(args))
		for _, a := range args {
			if a.Raw == "and" || a.Raw == "AND" {
				continue // optional readability connector
			}
			if a.Kind != cadishfile.ArgMatcherRef {
				return nil, &CompileError{Pos: a.Pos, Msg: "expected a @matcher reference in a classify `when` row, got " + quote(a.Raw)}
			}
			name := strings.TrimPrefix(a.Raw, "@")
			m, ok := matchers[name]
			if !ok {
				return nil, &CompileError{Pos: a.Pos, Msg: "undefined matcher @" + name}
			}
			out = append(out, m)
		}
		if len(out) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "classify `when` needs at least one matcher"}
		}
		return out, nil
	}
	if isMatcherType(args[0].Raw) {
		m, err := compileMatcher("", args[0].Raw, rawArgs(args[1:]), pos)
		if err != nil {
			return nil, err
		}
		return []*matcher{m}, nil
	}
	return nil, &CompileError{Pos: pos, Msg: "classify `when` expects @matcher refs or one inline matcher, got " + quote(args[0].Raw)}
}

// classifyArrowValue extracts the single literal VALUE after a `->` in a classify
// row. args is the slice STARTING at (when) or BEFORE the arrow depending on the
// caller; it locates the arrow and returns the token after it.
func classifyArrowValue(args []cadishfile.Arg, pos cadishfile.Pos, what string) (string, error) {
	arrow := -1
	for i, a := range args {
		if a.Raw == "->" {
			arrow = i
			break
		}
	}
	if arrow < 0 {
		return "", &CompileError{Pos: pos, Msg: "classify `" + what + "` needs `-> VALUE`"}
	}
	rest := args[arrow+1:]
	if len(rest) != 1 {
		return "", &CompileError{Pos: pos, Msg: "classify `" + what + "` needs exactly one literal VALUE after `->`"}
	}
	v := rest[0].Raw
	if v == "" {
		return "", &CompileError{Pos: rest[0].Pos, Msg: "classify value must be non-empty"}
	}
	return v, nil
}

// classifyTokenName extracts NAME from a `{NAME}` placeholder, reporting ok=false
// for anything that is not a simple `{NAME}` token.
func classifyTokenName(raw string) (string, bool) {
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") && len(raw) > 2 {
		name := raw[1 : len(raw)-1]
		if name != "" && !strings.ContainsAny(name, "{}") {
			return name, true
		}
	}
	return "", false
}

// compileClassifyMatcher builds a classify-equality matcher from a `classify
// {TOKEN}==VALUE` (or `!=`) matcher definition, resolving {TOKEN} against the
// site's classifiers. This is how a derived token is used AS A SCOPE: a named
// matcher `@gated classify {age}==gate` is then usable anywhere a matcher is
// (pass/header/route/…).
func compileClassifyMatcher(name string, args []string, pos cadishfile.Pos, classifiers map[string]*classifier) (*matcher, error) {
	if len(args) != 1 {
		return nil, &CompileError{Pos: pos, Msg: "classify matcher needs one `{TOKEN}==VALUE` (or `!=`) test"}
	}
	token, value, negate, err := parseClassifyTest(args[0], pos)
	if err != nil {
		return nil, err
	}
	cl, ok := classifiers[token]
	if !ok {
		return nil, &CompileError{Pos: pos, Msg: "classify matcher references unknown token {" + token + "} (define it with `classify {" + token + "} { … }`)"}
	}
	return &matcher{
		name:           name,
		kind:           kindClassify,
		pos:            pos,
		idx:            -1,
		classifier:     cl,
		classifyValue:  value,
		classifyNegate: negate,
	}, nil
}

// parseClassifyTest splits a `{TOKEN}==VALUE` / `{TOKEN}!=VALUE` test into its
// token name, the compared literal value, and whether the test is negated.
func parseClassifyTest(s string, pos cadishfile.Pos) (token, value string, negate bool, err error) {
	op := "=="
	if i := strings.Index(s, "!="); i >= 0 {
		op = "!="
		negate = true
	} else if i := strings.Index(s, "=="); i < 0 {
		return "", "", false, &CompileError{Pos: pos, Msg: "classify matcher must be `{TOKEN}==VALUE` or `{TOKEN}!=VALUE`, got " + quote(s)}
	}
	i := strings.Index(s, op)
	left, right := s[:i], s[i+len(op):]
	name, ok := classifyTokenName(left)
	if !ok {
		return "", "", false, &CompileError{Pos: pos, Msg: "classify matcher left side must be a {TOKEN} placeholder, got " + quote(left)}
	}
	if right == "" {
		return "", "", false, &CompileError{Pos: pos, Msg: "classify matcher needs a non-empty VALUE after " + op}
	}
	return name, right, negate, nil
}
