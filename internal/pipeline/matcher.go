package pipeline

import (
	"crypto/subtle"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// matcherKind enumerates the matcher types from the design's matcher catalog.
type matcherKind int

const (
	kindPath matcherKind = iota
	kindPathRegex
	kindHost
	kindHostRegex
	kindHeader
	kindHeaderPresent // request-phase: matches if a named request header is present (any value)
	kindHeaderRegex   // request-phase: matches a named request header's value against an RE2 regex
	kindMethod
	kindUpstream
	kindContentType  // response-phase: matches the response Content-Type
	kindCookie       // request-phase: matches a named cookie in the Cookie header
	kindSetCookie    // response-phase: matches a Set-Cookie header in the response
	kindClassify     // request-phase: matches a classify token value ({TOKEN}==VALUE)
	kindGeo          // request-phase: matches a resolved geo class at a granularity
	kindQueryPresent // request-phase: matches if ANY named query param is present (globs)
	kindQuery        // request-phase: matches a named query param's value (exact, OR set)
	kindIP           // request-phase: matches the resolved real client IP against IP/CIDRs
	kindCookieJSON   // request-phase: matches a dotted field inside a JSON cookie value
	kindHeaderJSON   // request-phase: matches a dotted field inside a JSON header value
	kindAll          // AND-composite: matches when EVERY referenced sub-matcher matches
)

// geoGranularity selects which resolved geo field a `geo` matcher tests.
type geoGranularity int

const (
	geoCountry   geoGranularity = iota // req.Geo (country code)
	geoContinent                       // req.GeoContinent
	geoRegion                          // req.GeoRegion (subdivision)
)

// isResponsePhaseKind reports whether a matcher kind evaluates against the
// RESPONSE rather than the request. Such a matcher needs the origin response
// headers, so it may scope the origin-response directives (cache_ttl, storage) and
// the DELIVER directives (header, strip_cookies, cors), but NOT request-phase
// directives (pass, purge, route, cache_key, a pre-cache_key header) — the response
// isn't known in RECV/KEY. The request-matching kinds work in every phase.
func isResponsePhaseKind(k matcherKind) bool {
	return k == kindContentType || k == kindSetCookie
}

// matcher is a compiled named predicate over a request. Exactly one of the
// kind-specific fields is populated. Args within a matcher are OR'd (handled by
// the per-kind structures: pathSet/hostSet are OR sets, methods/upstreams are sets,
// header values are OR'd).
type matcher struct {
	name string
	kind matcherKind
	pos  cadishfile.Pos
	// idx is a stable per-Pipeline index assigned at the end of Compile (see
	// indexMatchers). It is the slot this matcher uses in matchContext.memo, which
	// lets per-request evaluation memoize results in a stack-backed slice instead of
	// a per-call map. -1 until assigned — a matcher never referenced by any scope
	// keeps -1 and is never evaluated, so it never indexes the memo.
	idx int

	paths *pathSet       // kindPath
	hosts *hostSet       // kindHost
	re    *regexp.Regexp // kindPathRegex, kindHostRegex, kindHeaderRegex

	headerName   string   // kindHeader, kindHeaderPresent, kindHeaderRegex
	headerValues []string // kindHeader: OR of accepted values; empty => presence only

	methods   map[string]struct{} // kindMethod (upper-cased)
	upstreams map[string]struct{} // kindUpstream

	contentTypes []string // kindContentType: OR of lower-cased media-type substrings

	cookieName   string   // kindCookie: exact cookie name (unused when cookieGlob)
	cookieGlob   bool     // kindCookie: cookieName is a name prefix (`cookie NAME*`); presence-only
	cookieValues []string // kindCookie: OR of accepted values; empty => presence only

	setCookieNames []string // kindSetCookie: OR of cookie names; empty => any Set-Cookie present

	classifier     *classifier // kindClassify: the derived-token classifier to resolve
	classifyValue  string      // kindClassify: the value the token must (not) equal
	classifyNegate bool        // kindClassify: true for {TOKEN}!=VALUE

	geoGran   geoGranularity      // kindGeo: which resolved geo field to test
	geoValues map[string]struct{} // kindGeo: OR set of accepted classes (upper-cased)

	queryNames *nameGlobSet // kindQueryPresent: OR set of param names (exact + `*` globs)

	queryName   string   // kindQuery: the param name whose value is tested
	queryValues []string // kindQuery: OR of accepted exact values; empty => presence only

	ipPrefixes []netip.Prefix // kindIP: OR set of IP/CIDR prefixes (bare IP => /32 or /128)

	// kindCookieJSON / kindHeaderJSON: a bounded dotted field test inside a JSON
	// cookie/header value. jsonName is the cookie/header name; jsonPath is the
	// compiled PATH segments; jsonValues is the OR set of accepted scalar string
	// forms (empty => presence/non-null only). See cookie_json.go.
	jsonName   string
	jsonPath   []jsonPathSeg
	jsonValues []string

	// kindAll: the AND-conjunction of (optionally negated) sub-matchers. The composite
	// matches when EVERY term matches (XOR its negate flag). Resolved after all plain
	// matchers are compiled (forward references allowed).
	subTerms []secTerm
}

// matcherType maps a matcher type keyword to its kind. ok is false for unknown
// types.
func matcherType(t string) (matcherKind, bool) {
	switch t {
	case "path":
		return kindPath, true
	case "path_regex":
		return kindPathRegex, true
	case "host":
		return kindHost, true
	case "host_regex":
		return kindHostRegex, true
	case "header":
		return kindHeader, true
	case "header_present":
		return kindHeaderPresent, true
	case "header_regex":
		return kindHeaderRegex, true
	case "method":
		return kindMethod, true
	case "upstream":
		return kindUpstream, true
	case "content_type":
		return kindContentType, true
	case "cookie":
		return kindCookie, true
	case "cookie_json":
		return kindCookieJSON, true
	case "header_json":
		return kindHeaderJSON, true
	case "set_cookie":
		return kindSetCookie, true
	case "geo":
		return kindGeo, true
	case "query_present":
		return kindQueryPresent, true
	case "query":
		return kindQuery, true
	case "ip":
		return kindIP, true
	default:
		return 0, false
	}
}

// isMatcherType reports whether t is a known matcher type keyword (used to detect
// inline matcher scopes in directives like `header path_regex ... NAME VALUE`).
func isMatcherType(t string) bool {
	_, ok := matcherType(t)
	return ok
}

// compileMatcher builds a matcher from a name, type keyword, and arg list. Pos is
// used in error messages.
func compileMatcher(name, typ string, args []string, pos cadishfile.Pos) (*matcher, error) {
	kind, ok := matcherType(typ)
	if !ok {
		return nil, &CompileError{Pos: pos, Msg: "unknown matcher type " + quote(typ)}
	}
	m := &matcher{name: name, kind: kind, pos: pos, idx: -1}
	switch kind {
	case kindPath:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "path matcher needs at least one pattern"}
		}
		m.paths = newPathSet()
		for _, a := range args {
			m.paths.add(a)
		}
	case kindHost:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "host matcher needs at least one host"}
		}
		m.hosts = newHostSet()
		for _, a := range args {
			m.hosts.add(a)
		}
	case kindPathRegex, kindHostRegex:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: typ + " matcher needs a regex"}
		}
		// A regex split across continuation lines arrives as several tokens (the
		// lexer separates on whitespace even across a `\` continuation). They are
		// concatenated back into the single intended RE2 pattern.
		expr := strings.Join(args, "")
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, &CompileError{Pos: pos, Msg: "invalid regex " + quote(expr) + ": " + err.Error()}
		}
		m.re = re
	case kindHeader:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "header matcher needs a header name"}
		}
		m.headerName = args[0]
		m.headerValues = append(m.headerValues, args[1:]...)
	case kindHeaderPresent:
		// header_present NAME: matches when the named request header is present at
		// all (any value, including empty) — the most general "only when header X is
		// present" guard. It takes exactly the header name; value args are a
		// mistake (use `header NAME VALUE` to test a value).
		if len(args) != 1 {
			return nil, &CompileError{Pos: pos, Msg: "header_present matcher takes exactly one header name"}
		}
		m.headerName = args[0]
	case kindHeaderRegex:
		// header_regex NAME PATTERN: applies an RE2 regex to the value of request
		// header NAME (the canonical `req.http.Accept-Language ~ "^es"` language gate).
		// This is a SUBSTRING-style RE2 test (unanchored unless the pattern anchors with
		// ^/$), exactly like Varnish's `~`, NOT q-value parsing — so it reproduces the
		// VCL behavior verbatim. NAME is required; the remaining args are the regex,
		// concatenated (a continuation-split regex arrives as several tokens — mirror
		// path_regex/host_regex).
		if len(args) < 2 {
			return nil, &CompileError{Pos: pos, Msg: "header_regex matcher needs a NAME and a PATTERN: `header_regex NAME PATTERN`"}
		}
		if args[0] == "" {
			return nil, &CompileError{Pos: pos, Msg: "header_regex matcher needs a non-empty NAME"}
		}
		m.headerName = args[0]
		expr := strings.Join(args[1:], "")
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, &CompileError{Pos: pos, Msg: "invalid regex " + quote(expr) + ": " + err.Error()}
		}
		m.re = re
	case kindCookie:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "cookie matcher needs a cookie name"}
		}
		name := args[0]
		if strings.HasSuffix(name, "*") {
			// Prefix glob (`cookie NAME*`): matches any cookie whose name starts
			// with NAME — the WordPress wordpress_logged_in_<md5> case. It is
			// presence-only: a glob name cannot be combined with value args, since
			// a value would be ambiguous across the matched set and constant-time
			// value comparison is reserved for an exact, single-named cookie.
			if len(args) > 1 {
				return nil, &CompileError{Pos: pos, Msg: "a glob cookie name (" + quote(name) + ") is presence-only and cannot take value args"}
			}
			m.cookieGlob = true
			m.cookieName = strings.TrimSuffix(name, "*") // the prefix

		} else {
			m.cookieName = name
			m.cookieValues = append(m.cookieValues, args[1:]...)
		}
	case kindCookieJSON, kindHeaderJSON:
		// `cookie_json NAME PATH [VALUE…]` / `header_json NAME PATH [VALUE…]` (D54):
		// mirror the `cookie` matcher (name + OR-of-values + presence), reaching one
		// dotted field inside a JSON value. NAME and PATH are required; any further
		// args are the OR set of accepted scalar string forms (empty => presence).
		// The `{$ENV}` macro in NAME is resolved pre-compile, so NAME is a literal.
		if len(args) < 2 {
			return nil, &CompileError{Pos: pos, Msg: typ + " matcher needs a NAME and a PATH: `" + typ + " NAME PATH [VALUE…]`"}
		}
		if args[0] == "" {
			return nil, &CompileError{Pos: pos, Msg: typ + " matcher needs a non-empty NAME"}
		}
		segs, err := compileJSONPath(args[1], pos)
		if err != nil {
			return nil, err
		}
		m.jsonName = args[0]
		m.jsonPath = segs
		m.jsonValues = append(m.jsonValues, args[2:]...)
	case kindMethod:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "method matcher needs at least one method"}
		}
		m.methods = map[string]struct{}{}
		for _, a := range args {
			m.methods[strings.ToUpper(a)] = struct{}{}
		}
	case kindUpstream:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "upstream matcher needs at least one upstream name"}
		}
		m.upstreams = map[string]struct{}{}
		for _, a := range args {
			m.upstreams[a] = struct{}{}
		}
	case kindContentType:
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "content_type matcher needs at least one media type"}
		}
		for _, a := range args {
			m.contentTypes = append(m.contentTypes, strings.ToLower(a))
		}
	case kindSetCookie:
		// Zero args is valid: it matches any Set-Cookie present. Named args restrict
		// to Set-Cookie headers that set a cookie of that name (OR).
		m.setCookieNames = append(m.setCookieNames, args...)
	case kindGeo:
		// `geo GRANULARITY VALUE…` — GRANULARITY is country|continent|region; the
		// remaining args are the OR set of accepted classes (upper-cased to match the
		// server-resolved, upper-cased class). The granularity selects which resolved
		// field the matcher reads, mirroring the {geo}/{geo.continent}/{geo.region}
		// tokens.
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "geo matcher needs a granularity: `geo country|continent|region VALUE…`"}
		}
		switch args[0] {
		case "country":
			m.geoGran = geoCountry
		case "continent":
			m.geoGran = geoContinent
		case "region":
			m.geoGran = geoRegion
		default:
			return nil, &CompileError{Pos: pos, Msg: "geo granularity must be country, continent, or region, got " + quote(args[0])}
		}
		values := args[1:]
		if len(values) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "geo " + args[0] + " needs at least one value (e.g. `geo " + args[0] + " " + geoExample(args[0]) + "`)"}
		}
		m.geoValues = make(map[string]struct{}, len(values))
		for _, v := range values {
			m.geoValues[strings.ToUpper(v)] = struct{}{}
		}
	case kindQueryPresent:
		// `query_present NAME…` — matches if ANY named query param is present
		// (presence-OR), with `*` globs (`query_present adult_content t a ff-* pub-*`).
		// It reads only the request, so it is request-phase and usable anywhere a
		// matcher is, including a classify `when` row (the `publi` boolean).
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "query_present matcher needs at least one param name (e.g. `query_present adult_content t a ff-* pub-*`)"}
		}
		m.queryNames = newNameGlobSet(args)
	case kindQuery:
		// `query NAME [VALUE…]` — matches a named query param's value against an OR set
		// of exact values (`query env prod staging`); with no VALUE it is a presence test
		// of that one param. Request-phase. The Gateway translator emits this for an
		// HTTPRoute `queryParams` Exact match (NAME=VALUE). Distinct from query_present
		// (presence-OR over several names): `query` tests ONE name's value.
		if len(args) == 0 {
			return nil, &CompileError{Pos: pos, Msg: "query matcher needs a param name (e.g. `query env prod staging`)"}
		}
		m.queryName = args[0]
		m.queryValues = append([]string(nil), args[1:]...)
	case kindIP:
		// `ip IP|CIDR…` — an IP/CIDR ACL matcher (the WAF native primitive, decision
		// #9/#16). Parsed into masked prefixes; matched against the trusted-proxy-
		// resolved REAL client IP. compileIP owns the netip parsing; delegate to it so
		// inline (`allow ip 10.0.0.0/8`) and named (`@office ip …`) forms agree.
		ipm, err := compileIP(name, args, pos)
		if err != nil {
			return nil, err
		}
		return ipm, nil
	}
	return m, nil
}

// geoExample returns a representative value for a geo granularity, for error hints.
func geoExample(gran string) string {
	switch gran {
	case "continent":
		return "EU"
	case "region":
		return "US-UT"
	default:
		return "US"
	}
}

// match evaluates the matcher against the request context.
func (m *matcher) match(c *matchContext) bool {
	switch m.kind {
	case kindPath:
		return m.paths.Match(c.req.Path)
	case kindPathRegex:
		return m.re.MatchString(c.req.Path)
	case kindHost:
		return m.hosts.Match(c.req.Host)
	case kindHostRegex:
		return m.re.MatchString(c.req.normHost())
	case kindHeaderPresent:
		// Presence-only: the header exists in the request (any value, incl. empty).
		return headerPresent(c.req, m.headerName)
	case kindHeaderRegex:
		// Apply the compiled RE2 to the request header value. A header may carry
		// multiple values (separate header lines): we match if ANY value matches —
		// the natural generalization of the single-value VCL test, and the same
		// "any value" OR convention the edge runtime uses. An absent header (no
		// values) matches nothing. Note: a single comma-joined header line (the
		// browser's `Accept-Language: es-ES,es;q=0.9,en;q=0.8`) is one value, so
		// `^es` matches its prefix exactly as `req.http.Accept-Language ~ "^es"` does.
		for _, v := range headerValues(c.req, m.headerName) {
			if m.re.MatchString(v) {
				return true
			}
		}
		return false
	case kindHeader:
		if len(m.headerValues) == 0 {
			// Presence test: a present header has a non-empty canonical value, but
			// a header set to "" is still present. Check the raw header map.
			return headerPresent(c.req, m.headerName)
		}
		// OR across ALL header values (a header may carry multiple lines), matching the
		// `header_regex` "any value" convention. A `header NAME VALUE` matcher matches if
		// ANY value equals a configured value — otherwise a benign first line would HIDE
		// a blocked second line and bypass a `deny`/`block` access-control rule (WAF1, a
		// security bypass). Constant-time value compare (security review #12): the matcher
		// is also the documented purge-token guard, so equality must not leak the token
		// via timing — compare every (value, want) pair with no early return
		// (crypto/subtle), so neither the match position nor count is timing-observable.
		// The number of values is attacker-controlled but reveals no secret.
		match := 0
		for _, v := range headerValues(c.req, m.headerName) {
			vb := []byte(v)
			for _, want := range m.headerValues {
				match |= subtle.ConstantTimeCompare(vb, []byte(want))
			}
		}
		return match == 1
	case kindMethod:
		_, ok := m.methods[c.req.method()]
		return ok
	case kindUpstream:
		_, ok := m.upstreams[c.upstream]
		return ok
	case kindContentType:
		// Matches the RESPONSE Content-Type (case-insensitive substring, so
		// "text/css" matches "text/css; charset=utf-8"). c.respHeader is nil in
		// the request/origin phases, where a content_type matcher never fires —
		// and Compile rejects scoping a request/origin directive with one.
		if c.respHeader == nil {
			return false
		}
		ct := strings.ToLower(c.respHeader.Get("Content-Type"))
		if ct == "" {
			return false
		}
		for _, want := range m.contentTypes {
			if strings.Contains(ct, want) {
				return true
			}
		}
		return false
	case kindCookie:
		if m.cookieGlob {
			// Glob name (`cookie NAME*`): presence-only prefix test over every
			// cookie name. A bare `cookie *` compiles to an empty prefix, which
			// matches any cookie present.
			return cookieNamePrefixPresent(c.req, m.cookieName)
		}
		if len(m.cookieValues) == 0 {
			// Presence test: the cookie exists (even with an empty value).
			return cookiePresent(c.req, m.cookieName)
		}
		// Value compare (OR), constant-time: a cookie value can be a session token
		// (a secret), so equality must not leak it via timing. Mirrors the header
		// matcher: compare every configured value with no early return.
		v := c.req.cookie(m.cookieName)
		match := 0
		vb := []byte(v)
		for _, want := range m.cookieValues {
			match |= subtle.ConstantTimeCompare(vb, []byte(want))
		}
		return match == 1
	case kindCookieJSON:
		// A bounded JSON field test inside a named cookie value. Fail-closed on a
		// missing cookie, malformed/over-size/too-deep JSON, a missing path, a
		// non-scalar/null leaf — none of which can flip a gate open (see cookie_json.go).
		// Value compares are NOT constant-time: unlike a plain `cookie` value (which may
		// be a whole session token), a JSON field tested here is a low-cardinality
		// flag/enum (needVerify=true, plan.tier=pro), not a secret.
		raw, present := cookieRaw(c.req, m.jsonName)
		return jsonMatch(raw, present, m.jsonPath, m.jsonValues)
	case kindHeaderJSON:
		// Same engine over a named header value, OR-matched across ALL field-lines (like
		// header_regex / the all-lines cookieRaw) — NOT just headerGet's first line. A client
		// can split a header across lines with an empty/benign first line to hide a malicious
		// JSON value on a later line from a deny/respond gate (the header_json twin of the
		// cookie_json evasion); checking every line closes it. An empty/absent value is never
		// valid JSON, so a presence-only test still fails closed.
		for _, raw := range c.req.Header.Values(m.jsonName) {
			if jsonMatch(raw, true, m.jsonPath, m.jsonValues) {
				return true
			}
		}
		return false
	case kindSetCookie:
		// Matches the RESPONSE Set-Cookie header(s). c.respHeader is nil in the
		// request/origin phases where a set_cookie matcher never fires — and Compile
		// rejects scoping a request-phase directive with one.
		if c.respHeader == nil {
			return false
		}
		cookies := (&http.Response{Header: c.respHeader}).Cookies()
		if len(cookies) == 0 {
			return false
		}
		if len(m.setCookieNames) == 0 {
			return true // presence: any Set-Cookie at all
		}
		for _, ck := range cookies {
			for _, want := range m.setCookieNames {
				if ck.Name == want { // cookie names are case-sensitive (RFC 6265)
					return true
				}
			}
		}
		return false
	case kindClassify:
		// Resolve the derived token (first-match over the classifier's rows, using
		// the same memoized context so shared matchers cost nothing extra) and
		// compare it to the configured value. {TOKEN}==VALUE / {TOKEN}!=VALUE.
		got := m.classifier.resolve(c)
		eq := got == m.classifyValue
		if m.classifyNegate {
			return !eq
		}
		return eq
	case kindGeo:
		// Test the server-resolved geo class at the matcher's granularity against the
		// OR set. The fields are upper-cased by the geo source; the matcher values were
		// upper-cased at compile, so the compare is case-insensitive by construction.
		var got string
		switch m.geoGran {
		case geoCountry:
			got = c.req.Geo
		case geoContinent:
			got = c.req.GeoContinent
		case geoRegion:
			got = c.req.GeoRegion
		}
		if got == "" {
			return false
		}
		_, ok := m.geoValues[got]
		return ok
	case kindQueryPresent:
		// Presence-OR over the request's query params: true as soon as one param name
		// matches a configured name/glob. Presence only — a param set to an empty
		// value ("?a=") still counts, matching how a normalize `from query` source
		// reads a present-but-empty param.
		if len(c.req.Query) == 0 {
			return false
		}
		for name := range c.req.Query {
			if m.queryNames.match(name) {
				return true
			}
		}
		return false
	case kindQuery:
		// Exact-value test of ONE named query param (OR over the accepted values). With
		// no configured values it is a presence test of that param. A repeated param
		// (?a=1&a=2) matches if ANY of its values is accepted.
		if len(c.req.Query) == 0 {
			return false
		}
		vals, ok := c.req.Query[m.queryName]
		if !ok {
			return false
		}
		if len(m.queryValues) == 0 {
			return true // presence only
		}
		for _, got := range vals {
			for _, want := range m.queryValues {
				if got == want {
					return true
				}
			}
		}
		return false
	case kindAll:
		// AND-composite: every sub-term must match (XOR its negate flag). Reuses the
		// security-gate conjunction evaluator so the semantics cannot drift.
		return respondTermsMatch(c, m.subTerms)
	case kindIP:
		// Match the resolved REAL client IP (trusted-proxy/XFF aware, decision #16 —
		// the SAME resolution {geo} uses, set by the server before EvalSecurity) against
		// the OR set of IP/CIDR prefixes. An invalid/unset client IP matches nothing.
		ip := c.req.RealClientIP
		if !ip.IsValid() {
			return false
		}
		ip = ip.Unmap()
		for _, p := range m.ipPrefixes {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	return false
}

// cookieRaw returns the named cookie's raw value and whether it is present at all.
// It distinguishes "absent" from "present with an empty value" (the JSON matcher
// treats an empty value as present-but-not-valid-JSON, failing closed at the parse).
//
// Unlike net/http's strict Cookie() parser, this is LENIENT: net/http rejects a
// cookie whose value contains JSON octets ('{', '"', ':', …) as invalid, but a JSON
// cookie is exactly that (commonly percent-encoded, but not always). It mirrors the
// edge JS interpreter's parseCookies (split on ';', then on the first '=', trim,
// strip surrounding quotes) so the Go and JS runtimes read the same value — the
// cross-runtime conformance contract.
func cookieRaw(req *Request, name string) (string, bool) {
	// Uses the SINGLE lenient cookie reader (request.go lenientCookies) shared with the
	// credential gate and the cache key, so the value this matcher sees can never diverge from
	// the value the bypass/key see or the bytes the origin gets. Lenient (split on ';'/'=',
	// strip surrounding quotes, all header lines) because net/http's strict parser drops a JSON
	// cookie value — exactly the kind cookie_json matches.
	for _, c := range lenientCookies(req.Header) {
		if c.name == name {
			return c.value, true
		}
	}
	return "", false
}

// cookiePresent reports whether the named cookie exists in the request's Cookie header at all
// (even with an empty value), read LENIENTLY (see lenientCookies) so a JSON-valued cookie is
// not invisibly dropped by the strict net/http parser.
func cookiePresent(req *Request, name string) bool {
	for _, c := range lenientCookies(req.Header) {
		if c.name == name {
			return true
		}
	}
	return false
}

// cookieNamePrefixPresent reports whether the request carries any cookie whose name starts
// with prefix (the `cookie NAME*` glob matcher). An empty prefix matches any cookie at all.
// Read LENIENTLY (the shared lenientCookies, like cookiePresent) — NOT net/http's strict
// parser, which DROPS a JSON-valued cookie so a `deny cookie admin*` / `allow cookie session*`
// gate would not see it (gate evasion) and would diverge from the lenient edge. Cookie names
// are case-sensitive (RFC 6265), so the prefix compare is case-sensitive too.
func cookieNamePrefixPresent(req *Request, prefix string) bool {
	for _, c := range lenientCookies(req.Header) {
		if strings.HasPrefix(c.name, prefix) {
			return true
		}
	}
	return false
}

// headerValues returns all values of the named header (canonicalized). An absent
// header yields nil. Used by the header_regex matcher, which OR-matches across
// every value of a multi-valued header.
func headerValues(req *Request, name string) []string {
	if req.Header == nil {
		return nil
	}
	return req.Header[http.CanonicalHeaderKey(name)]
}

// headerPresent reports whether the named header exists in the request at all
// (even with an empty value).
func headerPresent(req *Request, name string) bool {
	if req.Header == nil {
		return false
	}
	_, ok := req.Header[http.CanonicalHeaderKey(name)]
	return ok
}

// scope is a set of matchers combined with OR (a directive referencing multiple
// @matchers matches if ANY matches). A nil *scope means "always matches" (an
// unscoped directive).
type scope struct {
	matchers []*matcher
}

// memo tri-state cell values, indexed by matcher.idx. 0 (zero value) means "not
// yet evaluated", so a freshly zeroed slice needs no initialization.
const (
	memoUnknown int8 = iota
	memoFalse
	memoTrue
)

// matchContext is the per-evaluation state: the request, the resolved upstream
// (for `upstream` matchers), and a memo of matcher results so a matcher
// referenced by several directives in one phase is evaluated once.
//
// memo is a tri-state slice indexed by matcher.idx (a stable per-Pipeline index
// assigned at Compile time), not a map: the caller backs it with a stack array
// sized to the Pipeline's matcher count, so building a context and memoizing
// matcher results is allocation-free on the per-request hot path.
type matchContext struct {
	req      *Request
	upstream string
	memo     []int8
	// respHeader is the response header set, populated only in the DELIVER phase
	// so content_type matchers can resolve against the real response Content-Type.
	// It is nil in the request/origin phases.
	respHeader http.Header
}

// newMatchContext builds a match context with an empty memo. It is used by
// standalone callers (tests) that evaluate raw matchers not assigned a memo slot
// by indexMatchers; such matchers carry idx -1 and so are evaluated uncached. The
// per-request hot path does NOT use this — the Eval* methods build the context
// inline with a stack-backed memo (see pipeline.go).
func newMatchContext(req *Request, upstream string) *matchContext {
	return &matchContext{req: req, upstream: upstream}
}

// matches evaluates a single matcher, memoizing the result by its stable index.
func (c *matchContext) matches(m *matcher) bool {
	if m.idx >= 0 && m.idx < len(c.memo) {
		switch c.memo[m.idx] {
		case memoTrue:
			return true
		case memoFalse:
			return false
		}
		v := m.match(c)
		if v {
			c.memo[m.idx] = memoTrue
		} else {
			c.memo[m.idx] = memoFalse
		}
		return v
	}
	// A matcher without a memo slot (idx unassigned, or the slice is too small —
	// neither happens for compiled pipelines) is evaluated without caching.
	return m.match(c)
}

// scopeMatches reports whether the scope matches (OR over its matchers). A nil
// scope is unconditional.
func (c *matchContext) scopeMatches(s *scope) bool {
	if s == nil {
		return true
	}
	for _, m := range s.matchers {
		if c.matches(m) {
			return true
		}
	}
	return false
}
