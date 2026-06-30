package pipeline

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// redirectRule is one compiled `redirect` directive. It selects matching requests
// via a path regex and/or a matcher scope, and emits a status + target template
// that builds the Location:
//
//   - path-regex form: re matches the request path; submatches feed $1..$9.
//   - scoped form: sc is a matcher scope (OR of @matchers / one inline matcher,
//     incl. a classify token matcher); re is nil and there are no $N captures.
//   - scoped path-regex (combined) form: BOTH sc and re are set — the rule fires
//     only when the scope matches AND the regex matches the path; the submatches
//     feed $1..$9 in the Location (Part B). This expresses "rewrite this path
//     segment only when language=X" in a single rule.
//
// Evaluated in RECV, first-match-wins; a match short-circuits the lifecycle with
// a synthetic 3xx (no cache, no origin) — the redirect sibling of `respond`.
//
// noStore, when true, carries the `no_store` modifier: the server (and edge)
// attaches Cache-Control: no-store, no-cache, must-revalidate, private to the
// short-circuit response so no intermediary or browser caches the redirect.
type redirectRule struct {
	re      *regexp.Regexp // path-regex selector: matched against the request path; nil when absent
	sc      *scope         // scope selector: the matcher scope that fires this redirect; nil when absent
	status  int            // 301/302/303/307/308
	target  string         // template: {host}/{path}/{query}/{uri} (+ $0..$9 captures when re is set)
	noStore bool           // true when the directive carried a trailing `no_store` modifier
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
	// Populate the request-scoped sources for the derived tokens — {http.NAME},
	// {client_ip}, {geo}/{geo.continent}/{geo.region} — so they resolve in a redirect
	// Location, the same way header/cache_key values do. We borrow ONLY these field
	// values, NOT fillHeaderTemplateEnv, because that helper sets Host = req.normHost()
	// and would defeat the F12 open-redirect defense: {host} must stay the VALIDATED
	// redirect host (p.redirectHost), never the raw attacker-supplied Host.
	// Scheme is set inline from req.TLS (Finding 3): a redirect on a TLS-terminated
	// listener must emit {proto}/{scheme} = "https", not the bare "http" default — else a
	// `{proto}://…` Location downgrades the scheme (and a force-https rule loops). Unlike
	// {host}, Scheme carries no open-redirect concern, so setting it here does not weaken
	// the F12 defense (we still must NOT route Host through fillHeaderTemplateEnv).
	scheme := "http"
	if req.TLS {
		scheme = "https"
	}
	env := &TemplateEnv{
		Host:         p.redirectHost(req),
		Path:         req.Path,
		Query:        canonicalQuery(req),
		QueryParams:  req.Query,
		Header:       req.Header,
		ClientIP:     req.ClientIP,
		Geo:          req.Geo,
		GeoContinent: req.GeoContinent,
		GeoRegion:    req.GeoRegion,
		Device:       req.Device,
		Scheme:       scheme,
	}
	// Scope and regex are ANDed: in the combined form (both set) the rule fires only
	// when the scope matches AND the regex matches the path. The scope-only and
	// regex-only forms degenerate (one selector nil) to a single condition.
	if r.sc != nil && !c.scopeMatches(r.sc) {
		return nil
	}
	if r.re != nil {
		m := r.re.FindStringSubmatch(req.Path)
		if m == nil {
			return nil
		}
		env.Capture = m
	}
	// Pass the LIVE resolver (the one header/cache_key use) so {classify.NAME} resolves
	// to its computed value instead of expanding empty. It is built inline and passed
	// by value — the per-request matchContext is never stored on env.
	loc := normalizeRedirectLocation(expandTemplate(r.target, env, classifyResolver{ctx: c, classifiers: p.classifiers}))

	// Open-redirect RUNTIME defense (the robust backstop to the compile-time
	// redirectTargetUnsafeAuthorityToken guard). That guard treats a $N regex backref and
	// literal text in the authority span as safe, so a target like
	// `https://{host}$1$2?{query}` compiles — yet at RUNTIME a request such as
	// `/index.php@evil.example.com/` can drive a capture into the authority, turning the
	// validated {host} into mere USERINFO and the attacker string into the real navigation
	// origin (and a relative target like {query.next} can expand to an absolute off-origin
	// Location). After expanding the Location, re-derive its authority with EVERY
	// request-sourced input neutralized (captures + request tokens → "", validated host
	// family + scheme KEPT). If the live authority differs from that reference authority, the
	// request injected an off-origin host → SUPPRESS the redirect (return nil) so the request
	// falls through to normal handling. Only computed for an absolute/protocol-relative
	// Location (gotHas) — a relative result has no authority and is always safe; the redirect
	// path is a short-circuit, not the hot path, so this is not on the critical path.
	if gotAuth, gotHas := locationAuthority(loc); gotHas {
		ref := *env
		ref.Capture = nil
		ref.Path = ""
		ref.Query = ""
		ref.QueryParams = nil
		ref.Header = nil
		ref.ClientIP = ""
		ref.Geo = ""
		ref.GeoContinent = ""
		ref.GeoRegion = ""
		ref.Device = ""
		// Host and Scheme are KEPT — the validated host family and scheme are trusted.
		refLoc := normalizeRedirectLocation(expandTemplate(r.target, &ref, classifyResolver{}))
		refAuth, refHas := locationAuthority(refLoc)
		if !refHas || refAuth != gotAuth {
			return nil
		}
	}
	return &Redirect{Status: r.status, Location: loc, NoStore: r.noStore}
}

// redirectAuthorityRest strips a redirect target/Location down to the remainder that BEGINS
// its AUTHORITY span, returning that remainder and whether an authority is present at all. A
// SPECIAL scheme (http/https) introduces the authority right after the ':' regardless of the
// slash count or direction (browsers fold '\'→'/'), so it folds '\'→'/' and trims ALL leading
// slashes after the boundary; a bare protocol-relative "//" (or "\\", "/\", "\/") likewise
// introduces an authority. A relative URL (no scheme, no leading "//") has none → ("", false).
// Shared by the compile-time guard (redirectTargetUnsafeAuthorityToken) and the runtime
// authority extractor (locationAuthority) so both apply identical boundary logic.
func redirectAuthorityRest(s string) (string, bool) {
	if m := redirectSchemePrefix.FindString(s); m != "" {
		rest := strings.ReplaceAll(s[len(m):], "\\", "/")
		return strings.TrimLeft(rest, "/"), true
	}
	norm := strings.ReplaceAll(s, "\\", "/")
	if !strings.HasPrefix(norm, "//") {
		return "", false
	}
	return strings.TrimLeft(norm, "/"), true
}

// locationAuthority extracts the AUTHORITY span (host[:port], INCLUDING any leading userinfo
// before an '@') of a CONCRETE, already-expanded Location string, reusing the exact
// scheme/slash boundary logic the static guard relies on (redirectAuthorityRest). The span
// runs to the first '/', '?' or '#' (or the whole remainder). It returns ("", false) for a
// relative result (no authority). Keeping the full span — userinfo included — is what makes
// `brand-a.example@evil.example.com` compare UNEQUAL to the reference `brand-a.example`, catching the
// userinfo open-redirect trick.
func locationAuthority(s string) (string, bool) {
	rest, has := redirectAuthorityRest(s)
	if !has {
		return "", false
	}
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return rest[:j], true
	}
	return rest, true
}

// normalizeRedirectLocation reduces an expanded Location to EXACTLY the bytes the HTTP
// layer will put on the wire, so the open-redirect authority inspection examines the same
// value a user agent will navigate to (and so the emitted Location cannot smuggle an
// authority past the inspector). Go's net/http Header.Set trims leading/trailing optional
// whitespace (OWS) before transmission, and user agents IGNORE control bytes embedded in a
// URL — so a Location such as "  //evil.example.com/" (leading OWS) or one carrying an
// embedded TAB/CR/LF would report NO authority to a naive inspector yet resolve off-origin
// once the wire/UA strips those bytes (and an embedded CR/LF is a header-splitting vector).
// We therefore (1) remove every byte a UA ignores or that mangles a header — TAB (0x09),
// LF (0x0A), CR (0x0D), FF (0x0C), NUL (0x00) — anywhere in the string, then (2) trim EVERY
// leading/trailing byte <= 0x20 (ASCII space + the whole C0 control range). Step (2) is the
// critical one: per the WHATWG URL spec a user agent strips ALL leading C0-control-or-space
// before parsing, so a Location like "\x0b//evil.example.com/" (leading vertical tab, or any
// 0x01-0x08/0x0B/0x0E-0x1F) would report NO authority to a naive inspector yet navigate
// off-origin once the UA strips the byte — the open-redirect class the runtime guard exists
// to close. Trimming only space+tab (the old behaviour) left those C0 bytes in place and let
// the authority check be skipped. The normalized result is used BOTH for the authority check
// AND as the emitted Location, and is applied identically to the JS edge (interpreter.js
// normalizeRedirectLocation) so Go and the worker stay byte-identical.
func normalizeRedirectLocation(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\n', '\r', '\f', 0x00:
			return -1 // drop
		}
		return r
	}, s)
	return strings.TrimFunc(s, func(r rune) bool { return r <= 0x20 })
}

// redirectSchemePrefix matches a leading URL scheme followed by its ':' separator
// (RFC 3986 scheme grammar). It anchors the R26 authority extraction: a SPECIAL scheme
// (http/https) introduces an authority after the ':' regardless of how many — or which
// direction of — slashes follow (browsers fold '\' to '/'), so the colon, not "://", is
// the real boundary.
var redirectSchemePrefix = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// redirectAuthorityAllowedToken reports whether a template token NAME may appear in a
// redirect Location AUTHORITY (host position). ONLY the validated host family is
// permitted: {host}/{host.base}/{host.sub} all derive from Pipeline.redirectHost — the
// site's allowlist, the F12 open-redirect defense — so they can never become an
// attacker-controlled origin. Every OTHER token ({query.*}, {http.*}, {client_ip},
// {geo*}, {classify.*}, {device}, {currency}, …) is request-sourced and host-unvalidated.
func redirectAuthorityAllowedToken(name string) bool {
	switch name {
	case "host", "host.base", "host.sub":
		return true
	default:
		return false
	}
}

// redirectAuthorityTerminatesToken reports whether a template token's runtime expansion
// BEGINS with a path separator and therefore ENDS the authority, exactly like a literal
// '/'. {uri} (request path + query) and {path} (request path) are always rooted at '/',
// so `https://{host.base}{uri}` is the validated host {host.base} with the path supplied
// by {uri}: the token is the authority/path boundary, not part of the host.
func redirectAuthorityTerminatesToken(name string) bool {
	switch name {
	case "uri", "path":
		return true
	default:
		return false
	}
}

// redirectTargetUnsafeAuthorityToken reports whether a redirect TARGET template places a
// request-sourced template token in the AUTHORITY (host[:port], incl. any userinfo) of an
// absolute or protocol-relative Location, returning the offending token. The authority is
// a navigation origin, so reflecting ANY unvalidated, attacker-influenceable value there
// is an open redirect (R26 of the 2026-06-26 review battery; Fix B extends the original
// {http.*}-only guard to ALL non-host tokens, e.g. the {query.NAME} token).
//
// Whitelist (robust, future-proof): in the authority span the ONLY permitted template
// tokens are the validated host family ({host}/{host.base}/{host.sub}); literal text is
// fine. Any OTHER {…} token is rejected. A $N regex backref is permitted only when a
// validated {host} token already anchors the authority (e.g. `https://{host}$1` rebuilds
// the path from a capture); an UNANCHORED $N forms an unvalidated host and is rejected,
// because the runtime authority guard would otherwise suppress such a redirect on every
// request — a directive that compiles but is permanently dead (F-D2). A token whose
// expansion is rooted at '/' ({uri}/{path}) terminates the authority — everything after
// it is PATH, where request reflection can never become the navigation origin, so it is
// unrestricted.
//
// Browsers treat a SPECIAL scheme (http/https) as introducing the authority immediately
// after the ':', independent of the slash count or direction, so the classic filter-
// bypass variants — `https:/{query.next}/x`, `https:{query.next}/x`, `https:\{…}`,
// `https:/\{…}` — all reflect the token into the navigation origin exactly like the naive
// `https://{query.next}`. We therefore detect a leading `scheme:`, fold backslashes to
// forward slashes, and strip ALL leading slashes after the scheme before scanning the
// authority. A relative target (no scheme, no leading "//"/"\\") has no authority — a
// leading {token} there renders as a path segment, not a host — so it is allowed.
//
// The whole authority span (including any userinfo before an '@') is whitelisted: a token
// in userinfo is harmless for the navigation origin but conservatively rejected, while a
// token AFTER the '@' is the real host and MUST be rejected — scanning the full span
// covers both without parsing the '@' boundary.
func redirectTargetUnsafeAuthorityToken(target string) (string, bool) {
	// Reduce to the authority span using the SAME scheme/slash boundary logic the runtime
	// extractor uses (so `https:`, `https:/`, `https://`, `https:\\`, `https:/\`, and a bare
	// protocol-relative "//" all reduce alike). A relative target has no authority → safe.
	rest, has := redirectAuthorityRest(target)
	if !has {
		return "", false
	}
	// Walk the authority. It ends at the first literal '/', '?' or '#', or at a
	// path-introducing token ({uri}/{path}). Any other {…} token in this span is an
	// unvalidated, request-sourced host — reject it. Literal text passes.
	//
	// A $N regex backref forming the host is special (F-D2): when it is NOT anchored by
	// a preceding validated-host token it always builds an unvalidated authority, and
	// the runtime authority guard (which neutralizes captures to derive the reference
	// authority) then suppresses the redirect on EVERY request — so the directive
	// compiles but is permanently dead. Reject an UNANCHORED $N in the host position so
	// the misconfiguration is loud at `check` instead of silently never firing. A $N
	// that follows a validated {host} token (e.g. `https://{host}$1$2` rebuilding a
	// path from captures) is left to the runtime guard, which fires it when the capture
	// is a rooted path and suppresses it if it escapes the host.
	sawHost := false
	for i := 0; i < len(rest); {
		c := rest[i]
		if c == '/' || c == '?' || c == '#' {
			return "", false // authority ended cleanly
		}
		if c == '{' {
			end := strings.IndexByte(rest[i:], '}')
			if end < 0 {
				// Unterminated '{' in host position: no legitimate host carries a literal
				// '{', so treat the dangling token as unsafe (conservative).
				return rest[i:], true
			}
			name := rest[i+1 : i+end]
			if redirectAuthorityTerminatesToken(name) {
				return "", false // {uri}/{path}: authority ends here, rest is PATH
			}
			if !redirectAuthorityAllowedToken(name) {
				return "{" + name + "}", true
			}
			sawHost = true // a validated {host}/{host.base}/{host.sub} anchors the authority
			i += end + 1
			continue
		}
		if c == '$' && i+1 < len(rest) && rest[i+1] >= '0' && rest[i+1] <= '9' && !sawHost {
			// Unanchored capture in the host position → a config that compiles but the
			// runtime guard suppresses on every request. Reject it loudly.
			return rest[i : i+2], true
		}
		i++
	}
	return "", false
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

// isRedirectCodeToken reports whether raw is a literal valid 3xx redirect code (e.g.
// "301"). It backs the scoped-redirect disambiguation: it tells a leading CODE from a
// leading PATH_REGEX more precisely than "all digits", so an all-digit PATH_REGEX
// (e.g. "12") in the combined form is not misread as a status code.
func isRedirectCodeToken(raw string) bool {
	n, err := strconv.Atoi(raw)
	return err == nil && validRedirectCode(n)
}

// compileRedirect parses a `redirect` directive in one of four forms:
//
//	redirect PATH_REGEX CODE TARGET            # regex form (capture groups -> $1..$9)
//	redirect @scope CODE TARGET                # scoped form (fires when @scope matches)
//	redirect @scope PATH_REGEX CODE TARGET     # scoped path-regex form (scope AND regex; $1..$9)
//	redirect CODE map { PFX -> NEWPFX }        # translation-map form (prefix preserved)
//
// Disambiguation: a leading `@name` arg means a SCOPED form (the @scope is a
// matcher ref — incl. a classify token matcher `@x classify {tok}==val`); a
// non-`@` first arg is the PATH_REGEX form. Within the scoped forms the arg count
// after the leading run of refs tells them apart: exactly two trailing args
// (`CODE TARGET`) is scope-only, three (`PATH_REGEX CODE TARGET`) is the combined
// scope+regex form. This removes the old footgun where `redirect @x …` silently
// parsed `@x` as a path regex (never matching).
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
	if bad, unsafe := redirectTargetUnsafeAuthorityToken(target); unsafe {
		return nil, &CompileError{Pos: d.Args[2].Pos, Msg: "redirect: the request-sourced token " + quote(bad) + " in the Location host is an open redirect — only the validated {host}/{host.base}/{host.sub} may appear in the authority: " + quote(target)}
	}
	// The only allowed token after TARGET is `no_store` (a caching modifier). Any
	// other token is almost certainly a typo and is surfaced as an error.
	var noStore bool
	if len(d.Args) > 3 {
		if d.Args[3].Raw == "no_store" {
			noStore = true
		} else {
			return nil, &CompileError{Pos: d.Args[3].Pos, Msg: "redirect: unexpected extra argument(s) after TARGET: " + quote(d.Args[3].Raw)}
		}
	}
	if len(d.Args) > 4 {
		return nil, &CompileError{Pos: d.Args[4].Pos, Msg: "redirect: unexpected extra argument(s) after TARGET: " + quote(d.Args[4].Raw)}
	}
	return []redirectRule{{re: re, status: code, target: target, noStore: noStore}}, nil
}

// compileRedirectScoped parses the two `@scope`-led redirect forms: one or more
// leading @matcher refs (OR'd into a scope) followed EITHER by `CODE TARGET`
// (scope-only — the scope is the sole selector, no $N captures) OR by
// `PATH_REGEX CODE TARGET` (the combined form — the rule fires only when the scope
// matches AND the path regex matches, and the submatches feed $1..$9 in TARGET).
// The two are told apart by the count of args remaining after the leading refs.
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
		return nil, &CompileError{Pos: d.Pos, Msg: "redirect scoped form needs `@scope CODE TARGET` (or `@scope PATH_REGEX CODE TARGET`)"}
	}
	// Combined form: a path regex precedes the CODE TARGET (≥3 trailing args and
	// the first arg is NOT a valid 3xx redirect code). The scope-only form starts
	// directly with the numeric CODE. We disambiguate on a VALID redirect code (not
	// merely "all digits") so a combined form whose PATH_REGEX first token is itself
	// all-digits (e.g. `@scope 12 301 /x` — a redirect matching a numeric path) is
	// NOT misread as the scope-only `@scope CODE TARGET` form. We must also not confuse
	// `no_store` in position 2 of the scope-only form (`CODE TARGET no_store`) with a
	// combined form's PATH_REGEX (which would also yield len(rest)==3): there the first
	// arg IS a valid code, so it stays scope-only.
	var re *regexp.Regexp
	if len(rest) >= 3 && !isRedirectCodeToken(rest[0].Raw) {
		re, err = regexp.Compile(rest[0].Raw)
		if err != nil {
			return nil, &CompileError{Pos: rest[0].Pos, Msg: "redirect: invalid path regex " + quote(rest[0].Raw) + ": " + err.Error()}
		}
		rest = rest[1:]
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
	if bad, unsafe := redirectTargetUnsafeAuthorityToken(target); unsafe {
		return nil, &CompileError{Pos: rest[1].Pos, Msg: "redirect: the request-sourced token " + quote(bad) + " in the Location host is an open redirect — only the validated {host}/{host.base}/{host.sub} may appear in the authority: " + quote(target)}
	}
	// The only allowed token after TARGET (in either the scope-only or the combined
	// form) is `no_store` (a caching modifier). Any other token is surfaced as a typo.
	var noStore bool
	if len(rest) > 2 {
		if rest[2].Raw == "no_store" {
			noStore = true
		} else {
			return nil, &CompileError{Pos: rest[2].Pos, Msg: "redirect: unexpected extra argument(s) after TARGET: " + quote(rest[2].Raw)}
		}
	}
	if len(rest) > 3 {
		return nil, &CompileError{Pos: rest[3].Pos, Msg: "redirect: unexpected extra argument(s) after TARGET: " + quote(rest[3].Raw)}
	}
	return []redirectRule{{re: re, sc: sc, status: code, target: target, noStore: noStore}}, nil
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
	writeCanonicalQuery(&b, req, false, nil, nil)
	return b.String()
}
