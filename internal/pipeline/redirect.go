package pipeline

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// redirectRule is one compiled `redirect` directive. It selects matching requests
// in one of two ways and emits a status + target template that builds the Location:
//
//   - path-regex form: re matches the request path; submatches feed $1..$9.
//   - scoped form: sc is a matcher scope (OR of @matchers / one inline matcher,
//     incl. a classify token matcher); re is nil and there are no $N captures.
//
// Evaluated in RECV, first-match-wins; a match short-circuits the lifecycle with
// a synthetic 3xx (no cache, no origin) — the redirect sibling of `respond`.
type redirectRule struct {
	re     *regexp.Regexp // path-regex form: matched against the request path; nil in the scoped form
	sc     *scope         // scoped form: the matcher scope that fires this redirect; nil in the path-regex form
	status int            // 301/302/303/307/308
	target string         // template: {host}/{path}/{query}/{uri} (+ $0..$9 captures, path-regex form only)
}

// eval returns a *Redirect if the rule fires for the request, or nil. For the
// path-regex form, the target template is expanded with the regex submatches and
// the request's host/path/query. For the scoped form, it fires when the scope
// matches and the target may interpolate {host}/{path}/{query}/{uri} but has no
// $N captures (there is no path regex).
//
// The {host} placeholder is resolved through p.redirectHost — NOT the raw request
// Host — so an attacker-supplied, undeclared Host cannot be reflected verbatim into
// the Location (open-redirect defense, F12). See Pipeline.redirectHost.
func (r *redirectRule) eval(c *matchContext, p *Pipeline) *Redirect {
	req := c.req
	env := &TemplateEnv{
		Host:  p.redirectHost(req),
		Path:  req.Path,
		Query: canonicalQuery(req),
	}
	if r.re != nil {
		m := r.re.FindStringSubmatch(req.Path)
		if m == nil {
			return nil
		}
		env.Capture = m
	} else if !c.scopeMatches(r.sc) {
		return nil
	}
	return &Redirect{Status: r.status, Location: expandTemplate(r.target, env, classifyResolver{})}
}

// validRedirectCode reports whether code is a redirect status cadish emits.
func validRedirectCode(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

// compileRedirect parses a `redirect` directive in one of three forms:
//
//	redirect PATH_REGEX CODE TARGET      # regex form (capture groups -> $1..$9)
//	redirect @scope CODE TARGET          # scoped form (fires when @scope matches)
//	redirect CODE map { PFX -> NEWPFX }  # translation-map form (prefix preserved)
//
// Disambiguation: a leading `@name` arg means the SCOPED form (the @scope is a
// matcher ref — incl. a classify token matcher `@x classify {tok}==val`); a
// non-`@` first arg is the PATH_REGEX form. This removes the old footgun where
// `redirect @x …` silently parsed `@x` as a path regex (never matching).
//
// The regex form matches PATH_REGEX against the request path; TARGET is a template
// interpolating {host}/{path}/{query}/{uri} and the regex submatches $0..$9. The
// scoped form's TARGET interpolates the same scalars but has no $N captures (there
// is no path regex). The map form is sugar for one regex rule per entry that
// rewrites a leading path prefix while preserving the remainder of the path.
func compileRedirect(d *cadishfile.Directive, matchers map[string]*matcher) ([]redirectRule, error) {
	if d.HasBlock || (len(d.Args) >= 2 && d.Args[1].Raw == "map") {
		return compileRedirectMap(d)
	}
	if len(d.Args) >= 1 && d.Args[0].Kind == cadishfile.ArgMatcherRef {
		return compileRedirectScoped(d, matchers)
	}
	if len(d.Args) < 3 {
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect needs `PATH_REGEX CODE TARGET` (or `@scope CODE TARGET`, or `CODE map { … }`)"}
	}
	re, err := regexp.Compile(d.Args[0].Raw)
	if err != nil {
		return nil, &CompileError{Pos: d.Args[0].Pos, Msg: "redirect: invalid path regex " + quote(d.Args[0].Raw) + ": " + err.Error()}
	}
	code, err := strconv.Atoi(d.Args[1].Raw)
	if err != nil {
		return nil, &CompileError{Pos: d.Args[1].Pos, Msg: "redirect status must be a number, got " + quote(d.Args[1].Raw)}
	}
	if !validRedirectCode(code) {
		return nil, &CompileError{Pos: d.Args[1].Pos, Msg: "redirect status must be 301/302/303/307/308, got " + strconv.Itoa(code)}
	}
	target := d.Args[2].Raw
	if target == "" {
		return nil, &CompileError{Pos: d.Args[2].Pos, Msg: "redirect: TARGET must be non-empty"}
	}
	return []redirectRule{{re: re, status: code, target: target}}, nil
}

// compileRedirectScoped parses the `redirect @scope… CODE TARGET` form: one or more
// leading @matcher refs (OR'd into a scope) followed by the status and target. The
// scope is the only selector — no path regex — so the TARGET interpolates the
// request scalars ({host}/{path}/{query}/{uri}) but never $N captures.
func compileRedirectScoped(d *cadishfile.Directive, matchers map[string]*matcher) ([]redirectRule, error) {
	// Consume the leading run of @matcher refs as the scope.
	sc, rest, err := leadingRefScope(d.Args, matchers)
	if err != nil {
		return nil, err
	}
	if sc == nil { // unreachable (caller checked Args[0] is a ref), but defensive.
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect scoped form needs a matcher scope"}
	}
	if err := ensureNotResponsePhase(sc, "redirect", d.Pos); err != nil {
		return nil, err
	}
	if len(rest) < 2 {
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect scoped form needs `@scope CODE TARGET`"}
	}
	code, err := strconv.Atoi(rest[0].Raw)
	if err != nil {
		return nil, &CompileError{Pos: rest[0].Pos, Msg: "redirect status must be a number, got " + quote(rest[0].Raw)}
	}
	if !validRedirectCode(code) {
		return nil, &CompileError{Pos: rest[0].Pos, Msg: "redirect status must be 301/302/303/307/308, got " + strconv.Itoa(code)}
	}
	target := rest[1].Raw
	if target == "" {
		return nil, &CompileError{Pos: rest[1].Pos, Msg: "redirect: TARGET must be non-empty"}
	}
	return []redirectRule{{sc: sc, status: code, target: target}}, nil
}

// compileRedirectMap parses the `redirect CODE map { PFX -> NEWPFX … }` form.
// Each entry becomes a regex rule anchored on the prefix: `^PFX(/.*|)$` rewriting
// to `https://{host}NEWPFX$1`, so a longer matching path keeps its suffix
// (`/registro/step2` -> `/register/step2`). Map targets are paths (the scheme +
// host are supplied), matching the language-redirect idiom.
func compileRedirectMap(d *cadishfile.Directive) ([]redirectRule, error) {
	if len(d.Args) < 1 {
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect map needs a status: `redirect CODE map { … }`"}
	}
	code, err := strconv.Atoi(d.Args[0].Raw)
	if err != nil {
		return nil, &CompileError{Pos: d.Args[0].Pos, Msg: "redirect status must be a number, got " + quote(d.Args[0].Raw)}
	}
	if !validRedirectCode(code) {
		return nil, &CompileError{Pos: d.Args[0].Pos, Msg: "redirect status must be 301/302/303/307/308, got " + strconv.Itoa(code)}
	}
	if len(d.Args) < 2 || d.Args[1].Raw != "map" {
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect map form is `redirect CODE map { PFX -> NEWPFX … }`"}
	}
	if !d.HasBlock || len(d.Block) == 0 {
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect map needs a non-empty `{ PFX -> NEWPFX … }` block"}
	}
	var rules []redirectRule
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		// A block line `/registro -> /register` parses as Name="/registro",
		// Args=["->", "/register"].
		if len(bd.Args) != 2 || bd.Args[0].Raw != "->" {
			return nil, &CompileError{Pos: bd.Pos, Msg: "redirect map entry must be `PFX -> NEWPFX`, got " + quote(bd.Name)}
		}
		from := bd.Name
		to := bd.Args[1].Raw
		if from == "" || to == "" {
			return nil, &CompileError{Pos: bd.Pos, Msg: "redirect map entry needs a non-empty PFX and NEWPFX"}
		}
		// Anchor on the prefix and capture an optional trailing path segment so the
		// remainder is preserved across the translation.
		re, err := regexp.Compile("^" + regexp.QuoteMeta(from) + "(/.*|)$")
		if err != nil { // QuoteMeta output always compiles; defensive.
			return nil, &CompileError{Pos: bd.Pos, Msg: "redirect map: " + err.Error()}
		}
		rules = append(rules, redirectRule{re: re, status: code, target: "https://{host}" + to + "$1"})
	}
	return rules, nil
}

// redirectHost resolves the {host} placeholder for a `redirect` TARGET safely. A
// redirect Location drives a browser navigation, so reflecting an arbitrary,
// attacker-controlled request Host into it is an open redirect (F12). The request
// Host is echoed ONLY when it is one of the site's configured addresses (exact or
// "*." wildcard); otherwise the site's canonical (first configured) host is used.
//
// When the site declares no address (trustedHosts nil — e.g. some tests), there is
// no trusted identity to fall back to, so the request host is used as before.
func (p *Pipeline) redirectHost(req *Request) string {
	h := req.normHost()
	if p.trustedHosts == nil {
		return h
	}
	if p.trustedHosts.Match(h) {
		return h
	}
	return p.canonicalHost
}

// normalizeRedirectHost reduces a raw site address token ("example.com",
// "*.cdn.example.com", or one carrying a "scheme://" prefix and/or ":port") to a
// bare, lower-cased host for the trusted-host allowlist and the canonical host. A
// "*." wildcard prefix is preserved (hostSet.add interprets it); any scheme and
// trailing port are stripped.
func normalizeRedirectHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+len("://"):]
	}
	// Trim any path/query that might trail an addr token, keeping only the authority.
	if i := strings.IndexAny(addr, "/?#"); i >= 0 {
		addr = addr[:i]
	}
	wildcard := strings.HasPrefix(addr, "*.")
	if wildcard {
		addr = addr[len("*."):]
	}
	addr = normalizeHost(addr) // lower-case + strip :port
	if addr == "" {
		return ""
	}
	if wildcard {
		return "*." + addr
	}
	return addr
}

// canonicalQuery renders req's query params canonically (the same ordering
// buildKey uses) for the {query}/{uri} template placeholders, without the leading
// '?'; it is "" when there are none.
func canonicalQuery(req *Request) string {
	if len(req.Query) == 0 {
		return ""
	}
	var b strings.Builder
	writeCanonicalQuery(&b, req, false, nil)
	return b.String()
}
