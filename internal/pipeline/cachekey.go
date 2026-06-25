package pipeline

import (
	"net/url"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// keyTokenKind enumerates the cache_key token types.
type keyTokenKind int

const (
	tokMethod keyTokenKind = iota
	tokHost
	tokPath
	tokURL
	tokQuery
	tokQueryAllow   // query_allow NAME… -> only the listed params (globs ok), canonicalized
	tokHeader       // header:NAME -> req.Header.Get(NAME)
	tokCookie       // cookie:NAME -> the value of request cookie NAME (per-user keying)
	tokSticky       // {sticky} -> sticky cookie value or ClientIP
	tokDevice       // {device} -> req.Device (server pre-pass)
	tokGeo          // {geo}    -> req.Geo (server pre-pass)
	tokGeoContinent // {geo.continent} -> req.GeoContinent (server pre-pass)
	tokGeoRegion    // {geo.region}    -> req.GeoRegion (server pre-pass)
	tokNormalize    // {NAME}   -> a user-defined `normalize` bucket (pure, in-pipeline)
	tokClassify     // {NAME}   -> a `classify` derived enum token (pure, needs the matchContext)
	tokTenant       // {tenant} -> the site's tenant name (per-site constant)
	tokLiteral      // any other literal, used verbatim
)

// keyToken is one compiled cache_key component.
type keyToken struct {
	kind    keyTokenKind
	arg     string          // header name for tokHeader; literal text for tokLiteral / constant tenant
	norm    *normalizer     // tokNormalize: the compiled normalizer to resolve
	clsf    *classifier     // tokClassify: the compiled classifier to resolve
	tenantR *tenantResolver // tokTenant: request-derived resolver (nil => use arg as a constant)
	allow   *nameGlobSet    // tokQueryAllow: the param-name allowlist (exact + globs)
}

// keyTokenSep separates rendered tokens in the composed key. It is the ASCII unit
// separator (0x1f). Header/path/host values do not legitimately contain control
// bytes, and the server sanitizes ASCII control bytes (0x00-0x1f, 0x7f) out of the
// request path in normalizePath before any token is rendered (Fix #8), so a token
// value can never carry 0x1f and distinct token lists never collide.
const keyTokenSep = "\x1f"

// compileCacheKey turns the cache_key directive args into compiled tokens. When
// args is empty the default key (method host path) is used by the caller.
func compileCacheKey(args []cadishfile.Arg, pos cadishfile.Pos, normalizers map[string]*normalizer, classifiers map[string]*classifier, tenant string, tenantR *tenantResolver) ([]keyToken, error) {
	toks := make([]keyToken, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a.Raw == "query_allow" {
			// query_allow NAME… is the only multi-arg token: it greedily consumes the
			// following param names (exact or `*` glob) up to the next recognized token
			// keyword/placeholder, so it can sit before other tokens
			// (`query_allow genre age {publi}`).
			j := i + 1
			var names []string
			for j < len(args) && !isKeyTokenStart(args[j].Raw) {
				names = append(names, args[j].Raw)
				j++
			}
			if len(names) == 0 {
				return nil, &CompileError{Pos: pos, Msg: "query_allow needs at least one param name (e.g. `query_allow genre age camLang`)"}
			}
			toks = append(toks, keyToken{kind: tokQueryAllow, allow: newNameGlobSet(names)})
			i = j - 1
			continue
		}
		t, err := compileKeyToken(a, pos, normalizers, classifiers, tenant, tenantR)
		if err != nil {
			return nil, err
		}
		toks = append(toks, t)
	}
	return toks, nil
}

// compileCacheKeyRule compiles one `cache_key [SELECTOR] TOKEN…` directive into a
// keyRule. The optional leading SELECTOR is `@matcher…` (OR'd refs), the keyword
// `default`, or absent (⇒ catch-all). Because cache_key runs in the KEY phase —
// before the origin response — a response-phase selector (`status …`,
// `content_type`/`set_cookie` matchers) is a compile error, mirroring the existing
// rule for `pass`/`route`. Everything after the selector is the unchanged token
// vocabulary parsed by compileCacheKey.
func compileCacheKeyRule(d *cadishfile.Directive, normalizers map[string]*normalizer, classifiers map[string]*classifier, tenant string, tenantR *tenantResolver, matchers map[string]*matcher) (keyRule, error) {
	args := d.Args
	sel := selector{kind: selDefault}
	start := 0
	if len(args) > 0 && looksLikeKeySelector(args[0]) {
		s, i, err := parseSelector(args, matchers, d.Pos)
		if err != nil {
			return keyRule{}, err
		}
		switch s.kind {
		case selStatusIn, selStatusNotIn:
			return keyRule{}, &CompileError{Pos: d.Pos, Msg: "cache_key runs in the KEY phase before the origin response; a `status` selector is response-phase only (use `cache_ttl` for status-based rules)"}
		case selScope:
			if err := ensureNotResponsePhase(s.scope, "cache_key", d.Pos); err != nil {
				return keyRule{}, err
			}
		}
		sel = s
		start = i
	}
	toks, err := compileCacheKey(args[start:], d.Pos, normalizers, classifiers, tenant, tenantR)
	if err != nil {
		return keyRule{}, err
	}
	return keyRule{sel: sel, toks: toks, pos: d.Pos}, nil
}

// validateKeyRules enforces the scoped-cache_key invariants after all directives
// are compiled: a scoped recipe set MUST end in a catch-all. When any rule carries
// a selector other than `default`, at least one selDefault (an unscoped line or the
// `default` keyword) must be present — otherwise a request matching no scope would
// silently fall back to the built-in method/host/path key, a surprise. With zero
// rules the built-in default applies (unchanged) and there is nothing to validate.
func validateKeyRules(rules []keyRule) error {
	hasScoped, hasDefault := false, false
	for i := range rules {
		if rules[i].sel.kind == selDefault {
			hasDefault = true
		} else {
			hasScoped = true
		}
	}
	if hasScoped && !hasDefault {
		return &CompileError{Pos: rules[0].pos, Msg: "a scoped cache_key needs a catch-all: add a `cache_key default TOKENS` (or one unscoped `cache_key TOKENS`) line so every request resolves to a recipe"}
	}
	return nil
}

// looksLikeKeySelector reports whether the first cache_key arg opens a SELECTOR
// rather than a key TOKEN. `@matcher` refs and the `default`/`status` keywords are
// selectors; every key token (`host`, `path`, `url`, `query`, `header:…`, a `{…}`
// placeholder, or any literal) is not. `status` is recognized here only so
// compileCacheKeyRule can reject it with a clear phase error rather than silently
// keying on a literal "status".
func looksLikeKeySelector(a cadishfile.Arg) bool {
	return a.Kind == cadishfile.ArgMatcherRef || a.Raw == "default" || a.Raw == "status"
}

// isKeyTokenStart reports whether raw begins a NEW cache_key token (rather than
// continuing a query_allow param list). It recognizes the built-in keywords, the
// `header:` prefix, and any `{…}` placeholder. A bare word is treated as a param
// name (query_allow's argument), matching how the rest of the grammar treats bare
// words as token arguments.
func isKeyTokenStart(raw string) bool {
	switch raw {
	case "method", "host", "path", "url", "query", "query_allow":
		return true
	}
	if strings.HasPrefix(raw, "header:") || strings.HasPrefix(raw, "cookie:") {
		return true
	}
	return strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") && len(raw) > 2
}

func compileKeyToken(a cadishfile.Arg, pos cadishfile.Pos, normalizers map[string]*normalizer, classifiers map[string]*classifier, tenant string, tenantR *tenantResolver) (keyToken, error) {
	raw := a.Raw
	switch raw {
	case "method":
		return keyToken{kind: tokMethod}, nil
	case "host":
		return keyToken{kind: tokHost}, nil
	case "path":
		return keyToken{kind: tokPath}, nil
	case "url":
		return keyToken{kind: tokURL}, nil
	case "query":
		return keyToken{kind: tokQuery}, nil
	case "{sticky}":
		return keyToken{kind: tokSticky}, nil
	case "{device}":
		return keyToken{kind: tokDevice}, nil
	case "{geo}":
		return keyToken{kind: tokGeo}, nil
	case "{geo.continent}":
		return keyToken{kind: tokGeoContinent}, nil
	case "{geo.region}":
		return keyToken{kind: tokGeoRegion}, nil
	case "{tenant}":
		// {tenant} is either request-derived (a `tenant { from … ; map … }` block)
		// or a per-site constant (a bare `tenant NAME`, e.g. from site-group
		// expansion; "" for a non-tenant site). The resolver, when present, wins.
		if tenantR != nil {
			return keyToken{kind: tokTenant, tenantR: tenantR}, nil
		}
		return keyToken{kind: tokTenant, arg: tenant}, nil
	}
	if strings.HasPrefix(raw, "header:") {
		name := raw[len("header:"):]
		if name == "" {
			return keyToken{}, &CompileError{Pos: pos, Msg: "cache_key header: needs a header name"}
		}
		return keyToken{kind: tokHeader, arg: name}, nil
	}
	// `cookie:NAME` keys on the value of a single request cookie — the explicit,
	// leak-proof way to cache per-user (per-session) content: each distinct cookie
	// value gets its own cache entry. It is ALSO what lifts the safe-default bypass of
	// credentialed requests (see Pipeline.BypassForCredentials): a request carrying a
	// Cookie is only cached when the key captures it.
	if strings.HasPrefix(raw, "cookie:") {
		name := raw[len("cookie:"):]
		if name == "" {
			return keyToken{}, &CompileError{Pos: pos, Msg: "cache_key cookie: needs a cookie name"}
		}
		return keyToken{kind: tokCookie, arg: name}, nil
	}
	// A {NAME} placeholder: resolve against the site's `normalize NAME { … }` and
	// `classify {NAME} { … }` definitions; an unknown one is a likely typo we
	// surface.
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") && len(raw) > 2 {
		name := raw[1 : len(raw)-1]
		if n := normalizers[name]; n != nil {
			return keyToken{kind: tokNormalize, norm: n}, nil
		}
		if cl := classifiers[name]; cl != nil {
			return keyToken{kind: tokClassify, clsf: cl}, nil
		}
		return keyToken{}, &CompileError{Pos: pos, Msg: "unknown cache_key token " + quote(raw) + " (define it with `normalize " + name + " { … }` or `classify " + raw + " { … }`)"}
	}
	return keyToken{kind: tokLiteral, arg: raw}, nil
}

// defaultKeyTokens is the cache key used when no cache_key directive is present.
var defaultKeyTokens = []keyToken{{kind: tokMethod}, {kind: tokHost}, {kind: tokPath}}

// buildKey renders the cache key for a request from compiled tokens. stickyCookie
// is the configured sticky cookie name ("" if the site declares no sticky). ctx is
// the request's match context, needed only to resolve a {classify} token (it
// evaluates matchers); it may be nil when no key token is a classify token (the
// common case and every test that builds a key without one).
//
// Tokens are written straight into one strings.Builder (the query is rendered in
// place, no intermediate strings), so a typical key costs a single allocation —
// the builder's backing array, which Builder.String() returns without a copy.
func buildKey(toks []keyToken, req *Request, stickyCookie string, ctx *matchContext) string {
	if len(toks) == 0 {
		toks = defaultKeyTokens
	}
	var b strings.Builder
	b.Grow(64) // most keys fit in one allocation; longer ones grow once
	for i, t := range toks {
		if i > 0 {
			b.WriteString(keyTokenSep)
		}
		writeToken(&b, t, req, stickyCookie, ctx)
	}
	return b.String()
}

// keyTokenSepByte is the keyTokenSep delimiter as a byte, for the in-value scan below.
const keyTokenSepByte = 0x1f

// writeKeyValue writes a request-derived token value with the 0x1f key SEPARATOR byte
// removed. That byte must never appear INSIDE a token value, or two different (value,
// value) splits would render to the same key and collide (WB-S1). It is a control byte
// illegitimate in a path / header / cookie value anyway (the server already strips it
// from the path), so dropping it is safe defense-in-depth for ANY caller that reaches
// buildKey without the server's input sanitization (e.g. the edge IR path). The common
// case (no separator byte present) writes verbatim after a single cheap scan.
func writeKeyValue(b *strings.Builder, s string) {
	if strings.IndexByte(s, keyTokenSepByte) < 0 {
		b.WriteString(s)
		return
	}
	for i := 0; i < len(s); i++ {
		if s[i] != keyTokenSepByte {
			b.WriteByte(s[i])
		}
	}
}

// writeToken renders one token directly into b.
func writeToken(b *strings.Builder, t keyToken, req *Request, stickyCookie string, ctx *matchContext) {
	switch t.kind {
	case tokMethod:
		b.WriteString(req.method())
	case tokHost:
		b.WriteString(req.normHost())
	case tokPath:
		writeKeyValue(b, req.Path)
	case tokURL:
		writeKeyValue(b, req.Path)
		writeCanonicalQuery(b, req, true, nil) // leading '?' when the query is non-empty
	case tokQuery:
		writeCanonicalQuery(b, req, false, nil)
	case tokQueryAllow:
		// Keep only the allowlisted params, canonicalized + sorted exactly like the
		// whole-query token. Unlisted params (utm_*, anything not named) are dropped,
		// so they cannot fragment the cache key.
		writeCanonicalQuery(b, req, false, t.allow)
	case tokHeader:
		writeKeyValue(b, req.headerCombined(t.arg))
	case tokCookie:
		writeKeyValue(b, req.cookie(t.arg))
	case tokSticky:
		if stickyCookie != "" {
			if v := req.cookie(stickyCookie); v != "" {
				writeKeyValue(b, v)
				return
			}
		}
		b.WriteString(req.ClientIP)
	case tokDevice:
		// The server resolves the device class from the User-Agent via the site's
		// classifier (a pre-pass) and sets req.Device before EvalRequest.
		b.WriteString(req.Device)
	case tokGeo:
		// The server resolves the geo class from the real client IP / a CDN
		// country header via the site's geo source and sets req.Geo before
		// EvalRequest.
		b.WriteString(req.Geo)
	case tokGeoContinent:
		// Derived from the country via an in-tree table (no GeoIP dep); the server
		// sets req.GeoContinent in the geo pre-pass.
		b.WriteString(req.GeoContinent)
	case tokGeoRegion:
		// Read from a configurable upstream CDN region header; the server sets
		// req.GeoRegion in the geo pre-pass.
		b.WriteString(req.GeoRegion)
	case tokNormalize:
		// Pure: resolve the user-defined normalizer directly from the request
		// (header/cookie/query value → bounded bucket). No server pre-pass.
		b.WriteString(t.norm.resolve(req))
	case tokClassify:
		// Pure: resolve the classify table (first matching row's value, else the
		// default) against the request's match context so its matchers memoize with
		// the rest of the phase. No server pre-pass. ctx is always non-nil when a
		// classify token is present (EvalRequest builds it); guard defensively.
		if ctx != nil {
			b.WriteString(t.clsf.resolve(ctx))
		} else {
			b.WriteString(t.clsf.resolve(newMatchContext(req, "")))
		}
	case tokTenant:
		if t.tenantR != nil {
			b.WriteString(t.tenantR.resolve(req)) // request-derived (host/header → tenant)
		} else {
			b.WriteString(t.arg) // per-site constant baked at compile time
		}
	case tokLiteral:
		b.WriteString(t.arg)
	}
}

// queryKeyStack / queryValStack size the stack-backed scratch slices used to
// sort query keys/values without a heap allocation for the common small-query
// case. A larger query simply grows the slice on the heap.
const (
	queryKeyStack = 16
	queryValStack = 8
)

// writeCanonicalQuery renders the query string with keys and values sorted (so
// semantically identical queries map to one key) directly into b. When prefix is
// true a leading '?' is emitted iff at least one key=value pair is written
// (matching the old `path + "?" + query` shape for the `url` token).
//
// Each key and value is re-encoded with url.QueryEscape so reserved delimiters
// ('&', '=', '%') inside a decoded field cannot bleed across params and collide
// two distinct queries onto one cache key (security review #4). For example
// `?a=x%26b=y` (one param a="x&b=y") and `?a=x&b=y` (two params) decode to
// different url.Values and render to different canonical strings.
// When allow is non-nil only param names it matches are kept (the rest, including
// utm_*, are dropped) — this is the `query_allow` token. A nil allow keeps every
// param (the whole-`query`/`url` tokens).
func writeCanonicalQuery(b *strings.Builder, req *Request, prefix bool, allow *nameGlobSet) {
	if len(req.Query) == 0 {
		return
	}
	var keyArr [queryKeyStack]string
	keys := keyArr[:0]
	for k := range req.Query {
		if allow != nil && !allow.match(k) {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	first := true
	for _, k := range keys {
		// Copy the value slice before sorting so the request's url.Values is not
		// mutated (it may be reused by the caller).
		var valArr [queryValStack]string
		vals := append(valArr[:0], req.Query[k]...)
		sort.Strings(vals)
		ek := url.QueryEscape(k)
		for _, v := range vals {
			if first && prefix {
				b.WriteByte('?')
			}
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(ek)
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
}

// nameGlobSet is an OR set of query-param NAME patterns: exact names (a hash-set
// lookup) plus `*`-glob names (the existing glob engine). It backs both the
// `query_allow` cache-key token and the `query_present` matcher. A bare `*` keeps
// (matches) every name. Param names are matched case-sensitively, like url.Values
// keys.
type nameGlobSet struct {
	exact    map[string]struct{}
	globs    []*glob
	matchAll bool
}

// newNameGlobSet compiles a list of param-name patterns, sorting each into the
// cheapest structure that can answer it (mirrors pathSet.add). Names without a
// '*' go to the exact set; the rest compile to a glob.
func newNameGlobSet(names []string) *nameGlobSet {
	s := &nameGlobSet{exact: make(map[string]struct{}, len(names))}
	for _, n := range names {
		switch {
		case n == "*":
			s.matchAll = true
		case !strings.Contains(n, "*"):
			s.exact[n] = struct{}{}
		default:
			s.globs = append(s.globs, compileGlob(n))
		}
	}
	return s
}

// match reports whether a param name matches any pattern in the set (OR).
func (s *nameGlobSet) match(name string) bool {
	if s.matchAll {
		return true
	}
	if _, ok := s.exact[name]; ok {
		return true
	}
	for _, g := range s.globs {
		if g.match(name) {
			return true
		}
	}
	return false
}
