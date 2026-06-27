package pipeline

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/classify"
)

// CompileError is a configuration error discovered while compiling a site into a
// Pipeline. It carries the offending source position.
type CompileError struct {
	Pos cadishfile.Pos
	Msg string
}

func (e *CompileError) Error() string {
	return e.Pos.String() + ": " + e.Msg
}

// selectorKind classifies a cache_ttl / storage selector.
type selectorKind int

const (
	selStatusIn selectorKind = iota
	selStatusNotIn
	selScope
	selDefault
)

// selector is a compiled cache_ttl / storage selector. Status selectors branch on
// the response status; scope selectors on the request matchers; default always
// matches.
type selector struct {
	kind  selectorKind
	codes map[int]struct{}
	scope *scope
	// respHeader is an optional RESPONSE-phase `resp_header NAME VALUE` term ANDed in
	// FRONT of the kind selector (status/scope/default): the rule applies only when the
	// origin response carries the named header value AND the kind selector matches. It
	// is nil for every rule that does not name resp_header, so the fast path is
	// untouched. resp_header is response-phase-only and the cache_ttl/storage selectors
	// run at EvalResponse, where the origin response is in scope.
	respHeader *matcher
}

func (s selector) matches(c *matchContext, status int) bool {
	// A resp_header term (when present) is ANDed with the rest of the selector. nil for
	// every non-resp_header rule, so this is a single nil-check on the hot path.
	if s.respHeader != nil && !c.matches(s.respHeader) {
		return false
	}
	switch s.kind {
	case selStatusIn:
		_, ok := s.codes[status]
		return ok
	case selStatusNotIn:
		_, ok := s.codes[status]
		return !ok
	case selScope:
		return c.scopeMatches(s.scope)
	case selDefault:
		return true
	}
	return false
}

type respondRule struct {
	// path is the EXACT request path the rule fires on (`respond PATH STATUS BODY`).
	// Empty when the rule is the scoped form (terms != nil).
	path string
	// terms is the matcher conjunction for the scoped `respond @scope STATUS BODY`
	// form (each term AND-ed, with optional `!` negation — the same grammar as the
	// security gate). nil for the exact-path form. The ingress translator emits the
	// scoped form `respond !@r0 !@r1 … 404` as a terminal no-match handler: it fires
	// for any path matching NONE of the route matchers, so an unmatched path 404s
	// instead of falling back to the site's default upstream.
	terms  []secTerm
	status int
	body   string
}

// onErrorRule is one compiled `respond on_error [@scope] STATUS BODY` directive: an
// origin-error-phase synthetic served when the origin HARD-fails with no servable
// object (D57). scope is the optional request-phase matcher OR-set (nil =
// unconditional). The body+status+content-type are fixed at compile.
type onErrorRule struct {
	scope       *scope
	status      int
	body        []byte
	contentType string
}

type purgeRule struct {
	guard      *scope
	regexToken string // literal regex or "{http.NAME}" placeholder; "" if none
	// regexPath, when true, anchors regexToken against the PATH component of the
	// cache key only (Varnish-compatible `^/foo`), rather than the whole key
	// (`host path …`). Set by the `regex-path EXPR` form.
	regexPath bool
}

type routeRule struct {
	// scope is the OR-set form (`route @a @b -> u` matches if ANY of @a/@b matches, or
	// one inline matcher) — consistent with `pass @a @b` and the rest of the language.
	// A multi-criteria (AND) route is expressed by referencing a single `all`
	// AND-composite matcher (`route @gw -> u`), which the Gateway translator emits; that
	// keeps the route ref single (so the terminal no-match `respond !@gw … 404` stays
	// correct) without a route-specific AND form.
	scope    *scope
	upstream string
}

// matches reports whether the route rule's condition (its OR scope) holds for the
// request context. A multi-criteria route references a single `all` composite matcher.
func (r *routeRule) matches(c *matchContext) bool {
	return c.scopeMatches(r.scope)
}

type ttlRule struct {
	sel        selector
	ttl, grace time.Duration
	hfm        time.Duration
	isHFM      bool
	// maxStale is the optional third freshness window (D60): a past-grace object
	// stays servable for this additional duration, but ONLY as a fallback when the
	// origin fetch fails (cache-status HIT-STALE-ERROR). Zero = disabled (the entry
	// behaves exactly as today past grace). Accepted only on the `ttl` and
	// `from_header` actions; rejected on `hit_for_miss`. Must be >= grace.
	maxStale time.Duration
	// fromHeader, when non-empty, names an origin RESPONSE header whose value is
	// parsed as the TTL at EvalResponse (`cache_ttl from_header X-Cache-Ttl`). When
	// set, ttl is ignored and the TTL is read per-response; grace still applies as a
	// static window. If the header is absent or unparseable the rule does NOT apply
	// (it falls through to the next cache_ttl rule), so a static `default` rule after
	// it can supply a fallback.
	fromHeader string
	// graceFromHeader / maxStaleFromHeader, when non-empty, name origin RESPONSE
	// headers whose values are parsed (via the same headerTTL helper as fromHeader) as
	// the grace / max_stale window per-response (`grace_from_header X-Cache-Grace`,
	// `max_stale_from_header X-Cache-Max-Stale`). They are valid on the `ttl` and
	// `from_header` actions (rejected on `hit_for_miss`). Unlike a header TTL, a
	// missing/unparseable value does NOT make the rule fall through — it falls back to
	// the literal `grace` / `max_stale` in the SAME rule (matching the VCL
	// `std.duration(hdr, default)` idiom). When a from_header-family rule APPLIES, the
	// server strips every configured control header (fromHeader + graceFromHeader +
	// maxStaleFromHeader) from the delivered response (Varnish's `unset beresp.http.*`).
	graceFromHeader    string
	maxStaleFromHeader string
}

// consumedHeaders returns the from_header-family control header names this rule reads
// from the origin response (TTL + grace + max_stale, whichever are configured), so the
// server can strip them from the delivered response. Returns nil when the rule sources
// nothing from a header (the common case), keeping the response fast path untouched.
func (r *ttlRule) consumedHeaders() []string {
	var out []string
	if r.fromHeader != "" {
		out = append(out, r.fromHeader)
	}
	if r.graceFromHeader != "" {
		out = append(out, r.graceFromHeader)
	}
	if r.maxStaleFromHeader != "" {
		out = append(out, r.maxStaleFromHeader)
	}
	return out
}

type storageRule struct {
	sel  selector
	tier string
}

// keyRule is one compiled `cache_key [SELECTOR] TOKEN…` directive: a cache-key
// recipe guarded by an optional request-phase selector. The KEY phase evaluates the
// rules first-match-wins (same model as cache_ttl), and the first rule whose
// selector matches the request supplies the recipe. An unscoped line (or the
// `default` keyword) compiles to a selDefault catch-all. A site with a single
// unscoped rule behaves exactly as a pre-scoping `cache_key TOKENS` line.
type keyRule struct {
	sel  selector
	toks []keyToken
	pos  cadishfile.Pos // source position of the directive (for lint/error reporting)
}

type corsRule struct {
	scope *scope
	cors  CORSDecision
}

// transformRule is one compiled `replace [@scope] OLD NEW` deliver-phase body
// substitution. The scope (often a content_type matcher) gates applicability.
type transformRule struct {
	scope *scope
	repl  Replacement
}

// encodeRule is the compiled `encode [codecs…]` deliver-phase response-body
// compression policy: a codec preference order, a Content-Type include list, and
// a minimum body size. It is unconditional (no matcher scope) in v1 — a single
// site-wide policy, mirroring Caddy's global `encode`.
type encodeRule struct {
	codecs    []string
	types     []string
	minLength int
}

// Default codecs / type list / size floor for a bare `encode` (and the defaults a
// codec/type subset is validated against).
var (
	// defaultEncodeCodecs is the preference order for a bare `encode`: strongest
	// ratio first. The server picks the first one the client accepts.
	defaultEncodeCodecs = []string{"zstd", "br", "gzip"}
	// encodeCodecAliases normalizes the accepted spelling of each codec token to
	// its wire Content-Encoding name. "brotli" is accepted as a friendly alias.
	encodeCodecAliases = map[string]string{
		"gzip":   "gzip",
		"br":     "br",
		"brotli": "br",
		"zstd":   "zstd",
	}
	// defaultEncodeTypes is the text-like Content-Type include list compressed by a
	// bare `encode`. Already-compressed formats (images, video, fonts, archives)
	// are intentionally absent.
	defaultEncodeTypes = []string{
		"text/*",
		"application/json",
		"application/javascript",
		"application/xml",
		"application/xhtml+xml",
		"application/rss+xml",
		"application/atom+xml",
		"application/wasm",
		"image/svg+xml",
	}
	// defaultEncodeMinLength is the size floor (bytes): below this, compression
	// overhead is not worth the CPU.
	defaultEncodeMinLength = 1024
)

// Pipeline is the compiled, immutable evaluation plan for one site. It is safe for
// concurrent use by the per-request Eval* methods.
type Pipeline struct {
	addresses []string
	// trustedHosts is the compiled set of this site's configured addresses (exact +
	// "*." wildcard suffixes, scheme/port stripped). It is the allowlist a {host}
	// placeholder in a `redirect` TARGET is checked against: only a request Host that
	// is one of the site's own hosts may be echoed into the Location, otherwise the
	// canonical host is substituted (open-redirect defense, F12). nil when the site
	// declares no address (e.g. some tests) — then {host} falls back to the request
	// host as before.
	trustedHosts *hostSet
	// canonicalHost is the site's primary host (first configured address, scheme/port
	// stripped, lower-cased). It is the safe {host} value substituted into a redirect
	// Location when the inbound Host is NOT a trusted host. "" when no address is
	// configured.
	canonicalHost string
	matchers      map[string]*matcher
	normalizers   map[string]*normalizer
	classifiers   map[string]*classifier
	// numMatchers is the count of distinct matchers that carry a memo slot (a
	// stable idx assigned by indexMatchers). It sizes the per-request memo slice
	// the Eval* methods stack-allocate, so per-request matching is map-free.
	numMatchers int
	// usesGeo is true iff the site references any geo granularity — a geo key token
	// ({geo}/{geo.continent}/{geo.region}) or a `geo` matcher — so the server runs
	// the geo pre-pass. Computed once at the end of Compile; read by UsesGeoToken.
	usesGeo bool
	// needsPoolHealth is true iff the site references an `upstream_healthy` matcher
	// anywhere (named or inline). When true the server injects a per-request pool-health
	// view (Request.PoolHealthy) from config.Pools() before EvalRequest; when false the
	// fast path pays nothing. Computed once at the end of Compile; read by NeedsPoolHealth.
	needsPoolHealth bool

	respondRules  []respondRule
	onErrorRules  []onErrorRule
	redirectRules []redirectRule
	purgeRules    []purgeRule
	routeRules    []routeRule
	passRules     []*scope
	upgradeRules  []*scope
	// credentialedRules are the compiled `cache_credentialed @scope` directives. A request
	// matching ANY of them makes caching ORIGIN-AUTHORITATIVE (D101): the SERVER skips
	// BypassForCredentials (and forwards the original cookies to origin for auth), and
	// EvalResponse applies the in-scope precedence — a positive in-scope cache_ttl signal is the
	// SOLE storage gate: it force-stores under the SHARED key and FORCE-OVERRIDES + STRIPS the
	// per-user Set-Cookie + weak Cache-Control/Pragma/Expires (the VCL exactly), and absence of
	// the signal does NOT store (fail-closed). Like passRules it is an OR-set of request-phase scopes; empty
	// on a site without the directive (zero per-request cost). Server+edge serving-tier policy
	// — never baked into EvalRequest's snapshot (mirrors BypassForCredentials).
	credentialedRules []*scope
	reqHeaderRules    []headerRule
	rewriteRules      []rewriteRule

	// SECURITY GATE (server-only; never projected to the edge — see secgate.go).
	// allowRules short-circuit the gate; denyRules yield a 403. Both are evaluated
	// FIRST in RECV (EvalSecurity), before the cache key / cache / origin. Empty on a
	// site with no security rules, so the server skips the gate entirely.
	allowRules []secRule
	denyRules  []secRule
	// rateLimitRules are the compiled `rate_limit` directives (WAF v1b). They are the
	// THIRD step of the gate, after allow/deny. The PURE gate identifies the
	// applicable rule + computes the bucket key (see ratelimit.go); the server's
	// in-memory token bucket (internal/ratelimit) does the stateful counting. Empty
	// on a site with no rate_limit rule. Server-only — never projected to the edge.
	rateLimitRules []rateLimitRule
	// securityMonitor is the global `monitor` toggle: when true every deny logs a
	// "would-block" and PASSES instead of enforcing the 403, and every rate_limit hit
	// records a would-429 and PASSES instead of throttling (decision #19).
	securityMonitor bool

	keyRules        []keyRule
	stickyCookie    string
	defaultUpstream string
	tenant          string          // {tenant} constant (from a bare `tenant NAME`; "" if none)
	tenantResolver  *tenantResolver // request-derived {tenant} (from a `tenant { … }` block); nil if none

	ttlRules     []ttlRule
	storageRules []storageRule

	// cacheUnsafe is the site-level `cache_unsafe` opt-out. When false (the default),
	// EvalResponse refuses to cache a response that is not safely shareable — one
	// carrying Set-Cookie, a private/no-store/no-cache Cache-Control, or a Vary not
	// covered by the cache key (matching RFC 9111 shared-cache / CDN behavior). When
	// true, the operator has explicitly accepted that risk and the refusal is disabled.
	cacheUnsafe bool
	// ignoreClientRevalidation is the site-level `client_cache_control ignore` opt-out.
	// When false (the default) the server honors a request `Cache-Control: no-cache` /
	// `max-age=0` (or HTTP/1.0 `Pragma: no-cache`) by revalidating with origin before
	// serving a stored response (RFC 9111 §5.2.1.4). When true the server treats that
	// client-forced revalidation as absent and serves the fresh/stale entry as normal —
	// the equivalent of Varnish's `unset req.http.Cache-Control`, closing the cache-bust /
	// DoS vector of a browser hard-refresh forcing a MISS on every reload. It ONLY
	// suppresses the CLIENT-forced revalidation; normal TTL/grace revalidation and all
	// Set-Cookie / credential / no-store safety are unchanged.
	ignoreClientRevalidation bool
	// keyCanCoverCred is true when SOME cache_key recipe captures a per-user credential
	// — a `cookie:NAME` token, or a `header:Cookie`/`header:Authorization` token. When
	// false (the common case), no recipe can ever isolate a credentialed request, so the
	// credential safe-default (BypassForCredentials) short-circuits to "bypass" without
	// selecting the per-request key recipe. Built once at Compile.
	keyCanCoverCred bool
	// cookieAllow is the `cookie_allow NAME…` request-cookie allowlist (nil when the
	// directive is absent). When set, the server strips every request cookie whose name
	// is NOT matched before building the key / forwarding to origin, and the surviving
	// (operator-controlled) cookies are exempt from the credential bypass. An EMPTY
	// allowlist (`cookie_allow` with no names) strips ALL cookies.
	cookieAllow *nameGlobSet
	// derivedSurviveCookies is the static union of every `derives_from cookie NAME`
	// declared by a classify token that appears in AT LEAST ONE cache_key recipe. These
	// cookies must SURVIVE `cookie_allow` stripping so the classifier reads the original
	// value and the key (incl. {TOKEN}) is built from it; they are then stripped per the
	// SELECTED recipe by StripDerivedCookies (post-key, pre-credential/origin). It is a
	// superset of any one request's active set (which is recipe-scoped) — surviving a
	// cookie that turns out inactive is fail-closed (StripDerivedCookies reconciles it to
	// cookie_allow's would-be behavior). nil when no derives_from feeds any recipe, so a
	// site without the feature keeps the fast path byte-for-byte unchanged.
	derivedSurviveCookies map[string]bool

	respHeaderRules []headerRule
	stripRules      []*scope
	corsRule        *corsRule
	transformRules  []transformRule
	encodeRule      *encodeRule

	// edge is the parsed `edge { … }` block: Cloudflare deploy identity (consumed by
	// the management plane, `cadish edge deploy`) + edge cache-tier policies
	// (projected into the worker IR). nil when the site declares no edge block.
	edge *edgeConfig

	// deviceClassifier is the site's compiled User-Agent → device-class ruleset (the
	// `device_detect { … }` block, or the built-in default). The server reads it for
	// the {device} pre-pass (config.Site.Device = p.DeviceClassifier()); the edge
	// projector emits the ruleset so the worker self-classifies the same way (D70). It
	// is always non-nil after Compile (classify.FromSite returns the default when the
	// site declares no block).
	deviceClassifier *classify.Classifier
}

// DeviceClassifier returns the site's compiled User-Agent → device-class classifier
// (from `device_detect { … }`, or the built-in default). Always non-nil. The config
// layer reads it for the server's {device} pre-pass; the edge projector emits its
// ruleset so the worker classifies identically (D70).
func (p *Pipeline) DeviceClassifier() *classify.Classifier { return p.deviceClassifier }

// Addresses returns the site's address tokens (e.g. "example.com").
func (p *Pipeline) Addresses() []string { return p.addresses }

// Tenant returns the site's tenant name (from a `tenant NAME` directive or a
// site-group expansion), or "" when the site is not tenant-scoped.
func (p *Pipeline) Tenant() string { return p.tenant }

// UsesDeviceToken reports whether the compiled cache key includes the {device}
// normalizer, so the server can skip the UA-classification pre-pass entirely
// when no key varies on it.
func (p *Pipeline) UsesDeviceToken() bool {
	for i := range p.keyRules {
		for _, t := range p.keyRules[i].toks {
			if t.kind == tokDevice {
				return true
			}
		}
	}
	return false
}

// UsesGeoToken reports whether the site needs the server's geo pre-pass — i.e. the
// compiled cache key includes a geo token ({geo}/{geo.continent}/{geo.region}) OR a
// `geo` matcher is referenced anywhere. The server skips the geo pre-pass entirely
// when this is false (zero hot-path cost on sites that do not vary on geo).
func (p *Pipeline) UsesGeoToken() bool {
	return p.usesGeo
}

// NeedsPoolHealth reports whether the site references an `upstream_healthy` matcher,
// so the server must inject a per-request pool-health view (Request.PoolHealthy) from
// config.Pools() before EvalRequest. It is false on every site that does not use the
// matcher, keeping the request fast path zero-cost (no pool snapshot). Computed once
// at Compile (computeNeedsPoolHealth).
func (p *Pipeline) NeedsPoolHealth() bool {
	return p.needsPoolHealth
}

// IgnoreClientRevalidation reports whether the site set `client_cache_control ignore`:
// when true, the server does NOT honor a request `Cache-Control: no-cache` / `max-age=0`
// (or `Pragma: no-cache`) and serves the fresh/stale entry as normal, instead of forcing
// a MISS (RFC 9111 §5.2.1.4). False (the default) preserves the standard honor behavior,
// and lets the server skip the client-revalidation header scan only when set. Computed
// once at Compile from a SETUP-phase parse-once toggle.
func (p *Pipeline) IgnoreClientRevalidation() bool {
	return p.ignoreClientRevalidation
}

// isGeoKeyToken reports whether a key-token kind reads a server-resolved geo field.
func isGeoKeyToken(k keyTokenKind) bool {
	return k == tokGeo || k == tokGeoContinent || k == tokGeoRegion
}

// globalOnlyDirectives are the options parsed EXCLUSIVELY from the leading global-options
// block ({ … } at the top of the file) by the config layer's *FromFile constructors
// (serverConfigFromFile, adminFromFile, accessLogOffFromFile, strictHostFromFile,
// securityFromFile, proxyProtocolFromFile). They have no per-site meaning, so a copy
// written inside a SITE body is never read at runtime — silently ignored. Compile rejects
// them in a site body (Finding 2) so the check≡run invariant holds; see registry.go.
var globalOnlyDirectives = map[string]bool{
	"server":         true,
	"admin":          true,
	"access_log":     true,
	"strict_host":    true,
	"security":       true,
	"proxy_protocol": true,
}

// knownDirectives is the set of directive keywords Compile recognizes. Unknown
// names are a compile error.
var knownDirectives = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range cadishfile.DefaultDirectives {
		m[n] = true
	}
	return m
}()

// Compile turns a parsed site into an executable Pipeline. Matchers are compiled
// once; directives are validated and bucketed into per-phase rule lists. Imports
// must be spliced first (see SpliceImports); a leftover `import` is an error.
func Compile(site *cadishfile.Site) (*Pipeline, error) {
	if site == nil {
		return nil, &CompileError{Msg: "nil site"}
	}
	p := &Pipeline{
		addresses:   append([]string(nil), site.Addresses...),
		matchers:    map[string]*matcher{},
		normalizers: map[string]*normalizer{},
		classifiers: map[string]*classifier{},
	}
	// Build the trusted-host allowlist + canonical host used to keep a {host}
	// placeholder in a `redirect` TARGET from reflecting an arbitrary, attacker-set
	// Host header (open redirect, F12). Addresses are raw site tokens
	// ("example.com", "*.cdn.example.com", possibly with a scheme/port); normalize
	// each to a bare host before adding.
	if len(site.Addresses) > 0 {
		ts := newHostSet()
		for _, addr := range site.Addresses {
			h := normalizeRedirectHost(addr)
			if h == "" {
				continue
			}
			ts.add(h)
			if p.canonicalHost == "" && !strings.HasPrefix(h, "*.") {
				p.canonicalHost = h
			}
		}
		// If every configured address is a wildcard, fall back to the first one's
		// suffix-derived host so canonicalHost is never empty when addresses exist.
		if p.canonicalHost == "" {
			p.canonicalHost = normalizeRedirectHost(site.Addresses[0])
		}
		p.trustedHosts = ts
	}
	upstreamNames := map[string]bool{}

	// classify-type matcher defs (`@x classify {tok}==v`) and `classify { … }`
	// directives are deferred: a classifier references matchers and a classify
	// matcher references a classifier, so both are resolved after Pass 1 has
	// collected every plain matcher (regardless of source order).
	var deferredClassifyMatchers []*cadishfile.MatcherDef
	var deferredClassifyDirs []*cadishfile.Directive
	// `all` (AND-composite) matchers reference OTHER named matchers, so they are resolved
	// after Pass 1 has collected every plain matcher (forward references allowed).
	var deferredAllMatchers []*cadishfile.MatcherDef

	// Pass 1: compile matcher definitions and collect upstream/cluster names and
	// the sticky cookie, so directives can reference them regardless of order.
	for _, n := range site.Body {
		switch v := n.(type) {
		case *cadishfile.MatcherDef:
			if _, dup := p.matchers[v.Name]; dup {
				return nil, &CompileError{Pos: v.Pos, Msg: "duplicate matcher @" + v.Name}
			}
			if v.Type == "classify" {
				// Defer: needs the classifier map (built below in this pass).
				deferredClassifyMatchers = append(deferredClassifyMatchers, v)
				continue
			}
			if v.Type == "all" {
				// Defer: references other named matchers (resolved in Pass 1c).
				deferredAllMatchers = append(deferredAllMatchers, v)
				continue
			}
			m, err := compileMatcher(v.Name, v.Type, rawArgs(v.Args), v.Pos)
			if err != nil {
				return nil, err
			}
			p.matchers[v.Name] = m
		case *cadishfile.Directive:
			switch v.Name {
			case "upstream", "cluster":
				if len(v.Args) >= 1 {
					upstreamNames[v.Args[0].Raw] = true
				}
				if v.Name == "upstream" {
					if c := stickyCookieOf(v); c != "" && p.stickyCookie == "" {
						p.stickyCookie = c
					}
				}
			case "normalize":
				nm, err := compileNormalize(v)
				if err != nil {
					return nil, err
				}
				if _, dup := p.normalizers[nm.name]; dup {
					return nil, &CompileError{Pos: v.Pos, Msg: "duplicate normalize " + quote(nm.name)}
				}
				p.normalizers[nm.name] = nm
			case "classify":
				// Deferred: compiled after every plain matcher is collected so a
				// `when @x` may reference a matcher defined later in the file.
				deferredClassifyDirs = append(deferredClassifyDirs, v)
			case "tenant":
				if v.HasBlock {
					// Request-derived form: `tenant { from … ; map … ; default … }`.
					if p.tenantResolver != nil {
						return nil, &CompileError{Pos: v.Pos, Msg: "only one tenant block allowed per site"}
					}
					tr, err := compileTenantBlock(v)
					if err != nil {
						return nil, err
					}
					p.tenantResolver = tr
				} else {
					// Constant form: `tenant NAME` (used by site-group expansion).
					if len(v.Args) != 1 {
						return nil, &CompileError{Pos: v.Pos, Msg: "tenant needs exactly one name: `tenant NAME` (or a `tenant { … }` block)"}
					}
					p.tenant = v.Args[0].Raw
				}
			}
		}
	}

	// Pass 1b: resolve the deferred classifiers and classify-equality matchers in
	// DEPENDENCY ORDER. A classify-matcher (`@x classify {tok}==v`) needs its
	// classifier {tok}; a classifier's `when @y` rows may reference a classify-matcher
	// @y — so a classify-matcher can feed another classifier (the natural layered
	// age-verify form). A fixed two-pass order cannot express that chain, so we
	// iterate to a fixpoint instead (see resolveClassifyDeps).
	if err := p.resolveClassifyDeps(deferredClassifyDirs, deferredClassifyMatchers); err != nil {
		return nil, err
	}

	// Pass 1c: resolve `all` (AND-composite) matchers. Each `@name all @a !@b …` ANDs the
	// referenced (optionally `!`-negated) sub-matchers into ONE named matcher, so a single
	// `route @name -> u` (and a single `respond !@name 404`) expresses a multi-criteria
	// Gateway HTTPRoute match cleanly. The Gateway translator emits these so the terminal
	// no-match 404 (a conjunction of negated route matchers) stays correct.
	if err := p.resolveAllMatchers(deferredAllMatchers); err != nil {
		return nil, err
	}

	// Pass 2: compile the phase directives in source order.
	pastKey := false
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok {
			continue // matcher defs handled in pass 1
		}
		switch d.Name {
		case "import":
			return nil, &CompileError{Pos: d.Pos, Msg: "unresolved import; call SpliceImports before Compile"}
		case "tls", "cache", "upstream", "cluster", "origin", "lb", "sticky", "device_detect", "geo", "normalize", "tenant", "classify":
			// Setup-shaped directives: not directly part of request evaluation
			// (handled in Pass 1 / by the server / config). Accepted, ignored here.
			// device_detect is parsed by the config layer into the site's UA
			// classifier; the {device} key token reads the class the server resolves
			// from it. `classify` is compiled in Pass 1b into p.classifiers; its
			// derived token is consumed by cache_key / classify matchers.
		case "respond":
			// `respond on_error …` is the origin-error-phase synthetic (D57); the bare
			// `respond PATH STATUS BODY` is the RECV short-circuit. Disambiguate on the
			// first token.
			if len(d.Args) >= 1 && d.Args[0].Raw == "on_error" {
				r, err := compileOnError(d, p.matchers)
				if err != nil {
					return nil, err
				}
				p.onErrorRules = append(p.onErrorRules, r)
				break
			}
			r, err := compileRespond(d, p.matchers)
			if err != nil {
				return nil, err
			}
			p.respondRules = append(p.respondRules, r)
		case "redirect":
			rs, err := compileRedirect(d, p.matchers)
			if err != nil {
				return nil, err
			}
			p.redirectRules = append(p.redirectRules, rs...)
		case "purge":
			r, err := compilePurge(d, p.matchers)
			if err != nil {
				return nil, err
			}
			if err := ensureNotResponsePhase(r.guard, "purge", d.Pos); err != nil {
				return nil, err
			}
			p.purgeRules = append(p.purgeRules, r)
		case "route":
			r, err := compileRoute(d, p.matchers, upstreamNames)
			if err != nil {
				return nil, err
			}
			if err := ensureNotResponsePhase(r.scope, "route", d.Pos); err != nil {
				return nil, err
			}
			p.routeRules = append(p.routeRules, r)
		case "pass":
			sc, err := parseScopeAll(d.Args, p.matchers, d.Pos)
			if err != nil {
				return nil, err
			}
			if sc == nil {
				return nil, &CompileError{Pos: d.Pos, Msg: "pass needs a matcher or condition"}
			}
			if err := ensureNotResponsePhase(sc, "pass", d.Pos); err != nil {
				return nil, err
			}
			p.passRules = append(p.passRules, sc)
		case "upgrade":
			// `upgrade @scope` enables a connection-upgrade (WebSocket / `Connection:
			// Upgrade`) passthrough tunnel for the matching scope. It mirrors `pass`
			// exactly at compile time (RECV phase, OR-set scope) and IMPLIES pass: the
			// tunnel is entirely off the caching path. The actual tunnelling is a server
			// path gated additionally on a genuine upgrade request; pair this with a
			// `route @scope -> upstream` to choose the upstream to tunnel to.
			sc, err := parseScopeAll(d.Args, p.matchers, d.Pos)
			if err != nil {
				return nil, err
			}
			if sc == nil {
				return nil, &CompileError{Pos: d.Pos, Msg: "upgrade needs a matcher or condition"}
			}
			if err := ensureNotResponsePhase(sc, "upgrade", d.Pos); err != nil {
				return nil, err
			}
			p.upgradeRules = append(p.upgradeRules, sc)
		case "cache_credentialed":
			// `cache_credentialed @scope`: ORIGIN-AUTHORITATIVE caching of the matching
			// credentialed requests (D101). Compiled exactly like `pass` (request-phase
			// OR-set scope) — the AST stays semantics-free; meaning lives here + in
			// EvalResponse / the server / the edge. A response-phase matcher is rejected:
			// the directive gates a REQUEST-time decision (the credential bypass), so it
			// must be evaluable in RECV, before any origin response exists.
			sc, err := parseScopeAll(d.Args, p.matchers, d.Pos)
			if err != nil {
				return nil, err
			}
			if sc == nil {
				return nil, &CompileError{Pos: d.Pos, Msg: "cache_credentialed needs a matcher or condition (it is a SCOPED opt-out of the credential bypass; an unscoped form would make ALL credentialed traffic origin-authoritative, which is never what you want)"}
			}
			if err := ensureNotResponsePhase(sc, "cache_credentialed", d.Pos); err != nil {
				return nil, err
			}
			p.credentialedRules = append(p.credentialedRules, sc)
		case "rewrite":
			r, err := compileRewrite(d, p.matchers)
			if err != nil {
				return nil, err
			}
			p.rewriteRules = append(p.rewriteRules, r)
		case "allow":
			r, err := compileSecurityRule(d, secAllow, p.matchers)
			if err != nil {
				return nil, err
			}
			p.allowRules = append(p.allowRules, r)
		case "deny", "block":
			r, err := compileSecurityRule(d, secDeny, p.matchers)
			if err != nil {
				return nil, err
			}
			p.denyRules = append(p.denyRules, r)
		case "rate_limit":
			r, err := compileRateLimit(d, len(p.rateLimitRules), p.matchers)
			if err != nil {
				return nil, err
			}
			p.rateLimitRules = append(p.rateLimitRules, r)
		case "monitor":
			on, err := compileMonitorToggle(d)
			if err != nil {
				return nil, err
			}
			p.securityMonitor = on
		case "cache_key":
			pastKey = true
			r, err := compileCacheKeyRule(d, p.normalizers, p.classifiers, p.tenant, p.tenantResolver, p.matchers)
			if err != nil {
				return nil, err
			}
			p.keyRules = append(p.keyRules, r)
		case "cache_ttl":
			pastKey = true
			r, err := compileTTL(d, p.matchers)
			if err != nil {
				return nil, err
			}
			// cache_ttl runs at EvalResponse, where the origin response headers are
			// known, so a response-phase matcher (set_cookie/content_type) is allowed.
			p.ttlRules = append(p.ttlRules, r)
		case "cache_unsafe":
			if len(d.Args) != 0 {
				return nil, &CompileError{Pos: d.Pos, Msg: "cache_unsafe takes no arguments"}
			}
			p.cacheUnsafe = true
		case "client_cache_control":
			// Per-site flag controlling whether the server honors a request's
			// client-forced-revalidation directive (Cache-Control: no-cache/max-age=0,
			// Pragma: no-cache). The only accepted value is `ignore` (do NOT honor it);
			// the absent default honors it (RFC 9111 §5.2.1.4). A SETUP-phase parse-once
			// toggle — no per-request cost; semantics live here, not in the AST.
			if len(d.Args) != 1 || d.Args[0].Raw != "ignore" {
				return nil, &CompileError{Pos: d.Pos, Msg: "client_cache_control takes exactly one value: `ignore` (do not honor a request no-cache/max-age=0/Pragma; the absent default honors it)"}
			}
			p.ignoreClientRevalidation = true
		case "storage":
			pastKey = true
			r, err := compileStorage(d, p.matchers)
			if err != nil {
				return nil, err
			}
			// storage likewise runs at EvalResponse; response-phase matchers are fine.
			p.storageRules = append(p.storageRules, r)
		case "cookie_allow":
			// Request-cookie allowlist: keep only the named cookies (globs ok), strip the
			// rest from the request before the cache key + the origin fetch. `cookie_allow`
			// with no names strips ALL cookies. The kept cookies are operator-controlled,
			// so they no longer force the credential bypass (see BypassForCredentials).
			if d.HasBlock {
				return nil, &CompileError{Pos: d.Pos, Msg: "cookie_allow takes a cookie-name list, not a block"}
			}
			names := make([]string, 0, len(d.Args))
			for _, a := range d.Args {
				names = append(names, a.Raw)
			}
			p.cookieAllow = newNameGlobSet(names)
		case "strip_cookies":
			pastKey = true
			sc, err := parseScopeAll(d.Args, p.matchers, d.Pos)
			if err != nil {
				return nil, err
			}
			p.stripRules = append(p.stripRules, sc)
		case "cors":
			pastKey = true
			r, err := compileCORS(d, p.matchers)
			if err != nil {
				return nil, err
			}
			// Only one cors per site (docs: "Only one cors and one encode per site").
			// corsRule is a SINGLE pointer, so a second cors would SILENTLY overwrite the
			// first — a scoped `cors @api …` quietly lost behind a later `cors @web …`,
			// with no error and no check warning. Reject the duplicate exactly as encode
			// does below, so the shadow is a clear compile error in both check and run.
			if p.corsRule != nil {
				return nil, &CompileError{Pos: d.Pos, Msg: "only one cors directive allowed per site"}
			}
			p.corsRule = r
		case "replace":
			pastKey = true
			r, err := compileReplace(d, p.matchers)
			if err != nil {
				return nil, err
			}
			p.transformRules = append(p.transformRules, r)
		case "encode":
			pastKey = true
			r, err := compileEncode(d)
			if err != nil {
				return nil, err
			}
			if p.encodeRule != nil {
				return nil, &CompileError{Pos: d.Pos, Msg: "only one encode directive allowed per site"}
			}
			p.encodeRule = r
		case "edge":
			ec, err := compileEdgeBlock(d, p.matchers)
			if err != nil {
				return nil, err
			}
			p.edge = ec
		case "header":
			rule, err := compileHeader(d, p.matchers)
			if err != nil {
				return nil, err
			}
			if pastKey {
				p.respHeaderRules = append(p.respHeaderRules, rule)
			} else {
				// A request-phase header (before cache_key) runs before the response
				// exists, so it cannot be scoped by a content_type matcher.
				if err := ensureNotResponsePhase(rule.scope, "a request-phase header", d.Pos); err != nil {
					return nil, err
				}
				p.reqHeaderRules = append(p.reqHeaderRules, rule)
			}
		default:
			if globalOnlyDirectives[d.Name] {
				// Finding 2: a global-only block written inside a SITE body is parsed ONLY
				// from the leading global-options block by the config layer's *FromFile
				// constructors — never from the site — so it would be SILENTLY ignored at
				// runtime (its knobs never apply) while check sees a registered directive and
				// reports 0 errors. Reject it with a positioned placement error so `cadish
				// check` and `cadish run` fail identically (both reach Compile) and the
				// operator moves the block to the top-level { … } options block.
				return nil, &CompileError{Pos: d.Pos, Msg: quote(d.Name) + " is a global-only block; move it to the top-level { … } options block (it is silently ignored inside a site body)"}
			}
			if !knownDirectives[d.Name] {
				return nil, &CompileError{Pos: d.Pos, Msg: "unknown directive " + quote(d.Name)}
			}
			// Known but unhandled here (future phase): ignore.
		}
	}
	if err := validateKeyRules(p.keyRules); err != nil {
		return nil, err
	}
	// Cross-check every `upstream_healthy NAME…` argument against the DECLARED pool
	// names, exactly as `route -> UPSTREAM` and `origin chain` do (Finding I1). A typo'd
	// name fails closed at runtime (PoolHealthy is false for an unknown pool) → a probe
	// answers 503 forever and an L4/DNS LB pulls the node. Both `cadish check` and
	// `cadish run` reach Compile, so both reject it identically.
	if err := p.validateUpstreamHealthy(upstreamNames); err != nil {
		return nil, err
	}
	// Compile the {device} User-Agent classifier from the site's `device_detect { … }`
	// block (or the built-in default). Single source of truth shared with the config
	// layer + projected into the Edge IR so the worker self-classifies (D70).
	dc, err := classify.FromSite(site)
	if err != nil {
		return nil, err
	}
	p.deviceClassifier = dc
	p.indexMatchers()
	p.usesGeo = p.computeUsesGeo()
	p.needsPoolHealth = p.computeNeedsPoolHealth()
	p.keyCanCoverCred = p.computeKeyCanCoverCred()
	p.derivedSurviveCookies = p.computeDerivedSurviveCookies()
	if err := p.checkDerivedCookieModeConflict(); err != nil {
		return nil, err
	}
	if err := p.checkCredentialedStripCookiesConflict(); err != nil {
		return nil, err
	}
	return p, nil
}

// checkCredentialedStripCookiesConflict (Guard A, D101) rejects a `strip_cookies` scope that
// overlaps a `cache_credentialed` scope. In a cache_credentialed scope the positive in-scope
// cache_ttl signal already STRIPS Set-Cookie before store (the directive subsumes the old
// `strip_cookies @v3_readmodel`), so this guard is redundant FOR SAFETY — but the owner keeps
// it a hard error so an operator cannot believe `strip_cookies` is doing the safety work, or use
// it to disarm/alter the in-scope behavior. Overlap is detected by SHARED matcher identity: a
// named `@scope` (or an inline matcher) referenced by BOTH a `strip_cookies` and a
// `cache_credentialed` directive is the same compiled *matcher pointer. This catches the
// `strip_cookies @s` + `cache_credentialed @s` case the spec forbids (and the testing-stack
// `strip_cookies @v3_readmodel` that must be removed when cache_credentialed lands). Mirrors
// the positioned-error style of checkDerivedCookieModeConflict (Finding 4).
func (p *Pipeline) checkCredentialedStripCookiesConflict() error {
	if len(p.credentialedRules) == 0 || len(p.stripRules) == 0 {
		return nil
	}
	credMatchers := map[*matcher]bool{}
	for _, sc := range p.credentialedRules {
		if sc == nil {
			continue
		}
		for _, m := range sc.matchers {
			credMatchers[m] = true
		}
	}
	for _, sc := range p.stripRules {
		if sc == nil {
			continue
		}
		for _, m := range sc.matchers {
			if credMatchers[m] {
				name := m.name
				ref := "@" + name
				if name == "" {
					ref = "an inline matcher"
				}
				return &CompileError{Pos: m.pos, Msg: "strip_cookies and cache_credentialed both cover " + ref + " — forbidden: in a cache_credentialed (origin-authoritative, shared-key) scope the positive in-scope cache_ttl signal already strips Set-Cookie before store (the directive subsumes strip_cookies for this scope), so a redundant strip_cookies here only obscures where the safety comes from. Drop the strip_cookies rule for this scope (cache_credentialed decides cacheability + cookie stripping there)"}
			}
		}
	}
	return nil
}

// checkDerivedCookieModeConflict (Finding 4) rejects a cookie declared BOTH
// forward-mode (`derives_from cookie X forward`) and strip-mode (bare `derives_from
// cookie X`) across two classify tokens that CO-OCCUR in the SAME cache_key recipe.
// When such tokens are both active for a request, Go keeps+forwards the cookie
// (StripDerivedCookies lets forward win) while the edge strips it (its derivedStripSet
// does not subtract the forward list) — a Go≠JS parity break and an operator footgun.
// Making the config invalid in both check and run renders that divergence unreachable.
// Scoped to a single recipe: tokens in mutually-exclusive recipes are never both active,
// so they cannot diverge within one request and must NOT false-error.
func (p *Pipeline) checkDerivedCookieModeConflict() error {
	for i := range p.keyRules {
		forward := map[string]bool{}
		strip := map[string]cadishfile.Pos{}
		for _, t := range p.keyRules[i].toks {
			if t.kind != tokClassify || t.clsf == nil {
				continue
			}
			for _, c := range t.clsf.derivesFrom {
				if t.clsf.isForwardCookie(c) {
					forward[c] = true
				} else if _, seen := strip[c]; !seen {
					strip[c] = t.clsf.pos
				}
			}
		}
		for c, pos := range strip {
			if forward[c] {
				return &CompileError{Pos: pos, Msg: "cookie " + quote(c) + " is declared both `derives_from cookie " + c + " forward` and `derives_from cookie " + c + "` (strip) within one cache_key recipe — a cookie cannot be both; pick one (`forward` to expose it to origin, or bare for the safe-default strip)"}
			}
		}
	}
	return nil
}

// computeDerivedSurviveCookies builds the static set of `derives_from` cookie names
// that must survive `cookie_allow` because their classify token appears in at least
// one cache_key recipe (so it CAN be active for some request). A classifier whose
// token is never keyed contributes nothing — its cookies are read but never stripped
// (a check warning), and the fast path is untouched. Returns nil when empty so
// HasDerivesFrom is a cheap nil check.
func (p *Pipeline) computeDerivedSurviveCookies() map[string]bool {
	var out map[string]bool
	for i := range p.keyRules {
		for _, t := range p.keyRules[i].toks {
			if t.kind != tokClassify || t.clsf == nil || len(t.clsf.derivesFrom) == 0 {
				continue
			}
			if out == nil {
				out = map[string]bool{}
			}
			for _, c := range t.clsf.derivesFrom {
				out[c] = true
			}
		}
	}
	return out
}

// classifyItem is one deferred classify unit awaiting resolution: either a
// `classify {}` directive (dir != nil) or a `@x classify {tok}==v` matcher def
// (mdef != nil). produces is the name it adds when compiled (the classifier token,
// or the matcher name); needsMatchers/needsToken are the references it must have
// resolved first. Exactly one of dir/mdef is set.
type classifyItem struct {
	dir           *cadishfile.Directive
	mdef          *cadishfile.MatcherDef
	produces      string   // classifier token name (dir) or matcher name (mdef)
	needsMatchers []string // @matcher refs (dir's `when` rows) that must exist first
	needsToken    string   // classifier token a classify-matcher depends on (mdef)
	pos           cadishfile.Pos
}

// resolveClassifyDeps compiles the deferred `classify {}` directives and the
// `@x classify {tok}==v` matchers in DEPENDENCY ORDER by iterating to a FIXPOINT:
// each round compiles every item whose referenced matchers/tokens are already built,
// deferring the rest, until a round makes no progress. This lets a classify-matcher
// feed another classifier (regulated → @regulated → ageverify) at any depth, with no
// reliance on source order.
//
// Chose the fixpoint (option a) over a topological sort (option b): the readiness
// test reuses the existing maps (p.matchers / p.classifiers) and the real compile
// functions, so genuine-undefined references surface with their exact existing error
// messages and no second dependency-graph representation can drift from the compilers.
//
// When a round stalls with items still unresolved, each survivor either (a) waits on
// a reference that NO remaining item can ever produce — a genuine undefined, surfaced
// by invoking the real compiler so the precise `undefined matcher @x` /
// `unknown token {t}` message is returned — or (b) waits only on references other
// stuck items produce, which is a true dependency CYCLE reported with both positions.
func (p *Pipeline) resolveClassifyDeps(dirs []*cadishfile.Directive, mdefs []*cadishfile.MatcherDef) error {
	items := make([]*classifyItem, 0, len(dirs)+len(mdefs))
	// pendMatcher/pendToken record the names still UNbuilt that some deferred item
	// will eventually produce. A reference into these sets is "not ready yet"; a
	// reference outside them (and absent from p.matchers/p.classifiers) is a genuine
	// undefined. They shrink as items resolve.
	pendMatcher := map[string]bool{}
	pendToken := map[string]bool{}
	for _, d := range dirs {
		// token is "" for a malformed directive (wrong arg count / bad placeholder);
		// such an item has no producible token and compileClassify reports the error
		// when it runs (it is always "ready" since "" is never in a pending set).
		token := ""
		if len(d.Args) == 1 {
			token, _ = classifyTokenName(d.Args[0].Raw)
		}
		it := &classifyItem{dir: d, produces: token, needsMatchers: classifyDirMatcherRefs(d), pos: d.Pos}
		items = append(items, it)
		if token != "" {
			pendToken[token] = true
		}
	}
	for _, v := range mdefs {
		it := &classifyItem{mdef: v, produces: v.Name, needsToken: classifyMatcherToken(v.Args), pos: v.Pos}
		items = append(items, it)
		pendMatcher[v.Name] = true
	}

	// ready reports whether every dependency of it is already built. A dependency
	// that is genuinely undefined (not built, not pending) counts as "ready" so the
	// item is compiled and the real compiler emits the precise undefined error.
	ready := func(it *classifyItem) bool {
		for _, name := range it.needsMatchers {
			if _, built := p.matchers[name]; !built && pendMatcher[name] {
				return false // a pending classify-matcher must be built first
			}
		}
		if it.needsToken != "" {
			if _, built := p.classifiers[it.needsToken]; !built && pendToken[it.needsToken] {
				return false
			}
		}
		return true
	}

	compileItem := func(it *classifyItem) error {
		if it.dir != nil {
			cl, err := compileClassify(it.dir, p.matchers)
			if err != nil {
				return err
			}
			if _, dup := p.classifiers[cl.name]; dup {
				return &CompileError{Pos: it.dir.Pos, Msg: "duplicate classify {" + cl.name + "}"}
			}
			if _, dup := p.normalizers[cl.name]; dup {
				return &CompileError{Pos: it.dir.Pos, Msg: "classify token {" + cl.name + "} collides with a normalize of the same name"}
			}
			p.classifiers[cl.name] = cl
			delete(pendToken, cl.name)
			return nil
		}
		m, err := compileClassifyMatcher(it.mdef.Name, rawArgs(it.mdef.Args), it.mdef.Pos, p.classifiers)
		if err != nil {
			return err
		}
		p.matchers[it.mdef.Name] = m
		delete(pendMatcher, it.mdef.Name)
		return nil
	}

	remaining := items
	for len(remaining) > 0 {
		next := remaining[:0:0]
		progressed := false
		for _, it := range remaining {
			if !ready(it) {
				next = append(next, it)
				continue
			}
			if err := compileItem(it); err != nil {
				return err
			}
			progressed = true
		}
		if !progressed {
			// Stalled: every survivor waits only on names other survivors produce —
			// a dependency cycle (a genuine undefined would have been "ready" above and
			// surfaced its real error). Report the cycle naming both endpoints.
			return classifyCycleError(next)
		}
		remaining = next
	}
	return nil
}

// classifyCycleError builds a CompileError describing a classify dependency cycle
// among the still-unresolved items, naming two participants and both source
// positions so the operator can locate the loop. The items are guaranteed to form at
// least one cycle (the fixpoint stalled with all of them waiting on each other).
func classifyCycleError(stuck []*classifyItem) error {
	// Pick the first item and one of the items it (transitively) waits on. Walking
	// one dependency edge is enough to name two distinct cycle members for the
	// message; the operator follows the loop from there.
	a := stuck[0]
	b := dependencyOf(a, stuck)
	if b == nil {
		b = a
	}
	return &CompileError{
		Pos: a.pos,
		Msg: "classify dependency cycle: " + describeClassify(a) + " (" + a.pos.String() + ") and " + describeClassify(b) + " (" + b.pos.String() + ") depend on each other; break the loop by inlining one side's matchers",
	}
}

// dependencyOf returns a stuck item that it directly waits on, or nil if none is
// among the stuck set (should not happen for a true stall).
func dependencyOf(it *classifyItem, stuck []*classifyItem) *classifyItem {
	produces := func(name string) *classifyItem {
		for _, s := range stuck {
			if s != it && s.produces == name {
				return s
			}
		}
		return nil
	}
	for _, name := range it.needsMatchers {
		if s := produces(name); s != nil {
			return s
		}
	}
	if it.needsToken != "" {
		if s := produces(it.needsToken); s != nil {
			return s
		}
	}
	return nil
}

// describeClassify names a deferred item for an error message: `classify {tok}` for a
// directive, `@name (classify {tok}==v)` for a classify-matcher.
func describeClassify(it *classifyItem) string {
	if it.dir != nil {
		return "classify {" + it.produces + "}"
	}
	return "@" + it.produces + " (classify {" + it.needsToken + "}==…)"
}

// keyHeaderNamesForTokens returns the lower-cased set of request header names a
// specific cache-key recipe varies on (its `header:NAME` tokens). A `Vary: NAME`
// response is safe to cache only when the recipe SELECTED for the request keys NAME —
// scoping it per-request (not to the global union of every recipe's header tokens)
// stops one scope's keyed header from covering a Vary on a request whose recipe omits
// it. Returns nil when the recipe names no header (the common case), so a plain
// `cache_key path` allocates nothing.
func keyHeaderNamesForTokens(toks []keyToken) map[string]bool {
	var names map[string]bool
	for _, t := range toks {
		if t.kind == tokHeader && t.arg != "" {
			if names == nil {
				names = map[string]bool{}
			}
			names[strings.ToLower(t.arg)] = true
		}
	}
	return names
}

// tokenCoversCookie / tokenCoversAuth report whether a single key token captures a
// request Cookie / Authorization (so a credentialed request keyed by it gets its own
// per-user cache entry). A `header:Cookie` covers the WHOLE cookie header; a
// `cookie:NAME` covers a specific cookie (the operator's chosen session key).
func tokenCoversCookie(t keyToken) bool {
	return t.kind == tokCookie || (t.kind == tokHeader && strings.EqualFold(t.arg, "Cookie"))
}

func tokenCoversAuth(t keyToken) bool {
	return t.kind == tokHeader && strings.EqualFold(t.arg, "Authorization")
}

// tokenCoversForwardCookie reports whether a key token is a classify {TOKEN} that declares
// a `derives_from … forward` cookie. Such a token COVERS that cookie (which the request
// forwards to origin under the collapsed key), so a recipe containing it CAN isolate a
// credentialed (forward-cookie-bearing) request — the same role tokenCoversCookie plays for
// a raw `cookie:NAME` token. Without this, a forward-only config (keyed by {TOKEN}, never a
// raw cookie token) would make keyCanCoverCred false and BypassForCredentials short-circuit
// to "always bypass", so forward traffic could never cache.
func tokenCoversForwardCookie(t keyToken) bool {
	return t.kind == tokClassify && t.clsf != nil && len(t.clsf.derivesForward) > 0
}

// computeKeyCanCoverCred reports whether ANY cache_key recipe captures a per-user
// credential. When false, no recipe can isolate a credentialed request, so the
// credential safe-default bypasses without selecting a per-request key recipe.
func (p *Pipeline) computeKeyCanCoverCred() bool {
	for i := range p.keyRules {
		for _, t := range p.keyRules[i].toks {
			if tokenCoversCookie(t) || tokenCoversAuth(t) || tokenCoversForwardCookie(t) {
				return true
			}
		}
	}
	return false
}

// computeUsesGeo reports whether any geo granularity is referenced: a geo key token
// in the cache key, or a `geo` matcher anywhere in the matcher set (named or inline,
// whether or not it carries a memo slot). Either means the server must run the geo
// pre-pass to populate Request.Geo/GeoContinent/GeoRegion before evaluation.
func (p *Pipeline) computeUsesGeo() bool {
	for i := range p.keyRules {
		for _, t := range p.keyRules[i].toks {
			if isGeoKeyToken(t.kind) {
				return true
			}
		}
	}
	for _, m := range p.matchers {
		if m.kind == kindGeo {
			return true
		}
	}
	// Inline geo matchers (written directly in a directive scope) are not in the
	// named map; scan every compiled scope's matchers.
	geoInScope := false
	p.forEachScope(func(s *scope) {
		for _, m := range s.matchers {
			if m.kind == kindGeo {
				geoInScope = true
			}
		}
	})
	// A geo matcher used inside a classify `when` row (the geo→business mapping
	// case) also needs the pre-pass.
	for _, cl := range p.classifiers {
		for _, row := range cl.rows {
			for _, m := range row.conj {
				if m.kind == kindGeo {
					geoInScope = true
				}
			}
		}
	}
	// A geo matcher used in a security rule (`deny @ru_cn` where @ru_cn is a geo
	// matcher) likewise needs the geo pre-pass.
	p.forEachSecRule(func(r *secRule) {
		for _, t := range r.terms {
			if t.m.kind == kindGeo {
				geoInScope = true
			}
		}
	})
	return geoInScope
}

// computeNeedsPoolHealth reports whether any `upstream_healthy` matcher is referenced
// anywhere — a named matcher, an inline scope matcher, a scoped-respond / security
// term, or a classify `when` row. Either means the server must inject the per-request
// pool-health view before EvalRequest. Mirrors computeUsesGeo's full walk so an inline
// or terminal-respond use is not missed.
func (p *Pipeline) computeNeedsPoolHealth() bool {
	for _, m := range p.matchers {
		if m.kind == kindUpstreamHealthy {
			return true
		}
	}
	found := false
	p.forEachScope(func(s *scope) {
		for _, m := range s.matchers {
			if m.kind == kindUpstreamHealthy {
				found = true
			}
		}
	})
	p.forEachSecRule(func(r *secRule) {
		for _, t := range r.terms {
			if t.m.kind == kindUpstreamHealthy {
				found = true
			}
		}
	})
	// Scoped `respond @scope` rules carry their matchers as conjunction terms (not
	// scopes), so a matcher used ONLY to scope the AWS probe's `respond @probe @live`
	// is reachable only here — the canonical use of this matcher.
	for i := range p.respondRules {
		for _, t := range p.respondRules[i].terms {
			if t.m.kind == kindUpstreamHealthy {
				found = true
			}
		}
	}
	for _, cl := range p.classifiers {
		for _, row := range cl.rows {
			for _, m := range row.conj {
				if m.kind == kindUpstreamHealthy {
					found = true
				}
			}
		}
	}
	return found
}

// validateUpstreamHealthy cross-checks every `upstream_healthy NAME…` pool argument
// against the set of DECLARED upstream/cluster names (Finding I1). Mirrors the FULL
// matcher walk of computeNeedsPoolHealth so an undeclared name is caught wherever the
// matcher is used — a named matcher, an inline directive scope, a security term, a
// terminal `respond @probe @live` term, or a classify `when` row. Each name is checked
// (ANY semantics: a typo must not hide behind a valid sibling). Like `route -> UPSTREAM`,
// validation is skipped when NO pools are declared (an upstream-less context), so it
// never over-rejects; a real probe config always declares the pools it probes.
func (p *Pipeline) validateUpstreamHealthy(upstreams map[string]bool) error {
	if len(upstreams) == 0 {
		return nil
	}
	var firstErr error
	check := func(m *matcher) {
		if firstErr != nil || m == nil || m.kind != kindUpstreamHealthy {
			return
		}
		for _, name := range m.healthyPools {
			if !upstreams[name] {
				firstErr = &CompileError{Pos: m.pos, Msg: "upstream_healthy references " + quote(name) + " which is not a declared upstream/cluster" + declaredPoolHint(upstreams)}
				return
			}
		}
	}
	for _, m := range p.matchers {
		check(m)
	}
	p.forEachScope(func(s *scope) {
		for _, m := range s.matchers {
			check(m)
		}
	})
	p.forEachSecRule(func(r *secRule) {
		for _, t := range r.terms {
			check(t.m)
		}
	})
	for i := range p.respondRules {
		for _, t := range p.respondRules[i].terms {
			check(t.m)
		}
	}
	for _, cl := range p.classifiers {
		for _, row := range cl.rows {
			for _, m := range row.conj {
				check(m)
			}
		}
	}
	return firstErr
}

// declaredPoolHint lists the declared upstream/cluster pool names (sorted) so an
// undeclared-pool error can suggest the valid choices.
func declaredPoolHint(upstreams map[string]bool) string {
	if len(upstreams) == 0 {
		return ""
	}
	names := make([]string, 0, len(upstreams))
	for n := range upstreams {
		names = append(names, n)
	}
	sort.Strings(names)
	return " (declared: " + strings.Join(names, ", ") + ")"
}

// indexMatchers assigns each distinct matcher referenced by any scope a stable
// index (matcher.idx) and records the total in p.numMatchers. The index is the
// matcher's slot in the per-request memo slice (see matchContext.memo), letting
// evaluation memoize into a stack-backed slice rather than a per-call map.
//
// Named matchers may be shared across scopes (one *matcher, one slot); inline
// matchers each have their own pointer and slot. A matcher defined but never
// referenced by a scope keeps idx -1 and never indexes the memo. Indexing is
// idempotent across the walk because each pointer is assigned at most once.
func (p *Pipeline) indexMatchers() {
	next := 0
	var assign func(m *matcher)
	assignClassifier := func(cl *classifier) {
		if cl == nil {
			return
		}
		for _, r := range cl.rows {
			for _, m := range r.conj {
				assign(m)
			}
		}
	}
	assign = func(m *matcher) {
		if m == nil || m.idx >= 0 {
			return
		}
		m.idx = next
		next++
		// A classify-equality matcher resolves its classifier, which evaluates the
		// row matchers; give those a memo slot too so the resolution memoizes.
		if m.kind == kindClassify {
			assignClassifier(m.classifier)
		}
		// An `all` composite evaluates its sub-matchers; give each a memo slot so the
		// conjunction memoizes and a sub-matcher used only inside an `all` is not flagged
		// unused.
		if m.kind == kindAll {
			for _, t := range m.subTerms {
				assign(t.m)
			}
		}
	}
	p.forEachScope(func(s *scope) {
		for _, m := range s.matchers {
			assign(m)
		}
	})
	// A {classify} cache_key token resolves a classifier directly (not via a
	// scope), so give its row matchers memo slots as well — across every recipe.
	for i := range p.keyRules {
		for _, t := range p.keyRules[i].toks {
			if t.kind == tokClassify {
				assignClassifier(t.clsf)
			}
		}
	}
	// Security gate rules carry their matchers as conjunction terms (not scopes), so
	// assign those memo slots here. A `geo`/`ip` matcher used only by a deny rule is
	// thus indexed and never flagged as unused.
	p.forEachSecRule(func(r *secRule) {
		for _, t := range r.terms {
			assign(t.m)
		}
	})
	// Scoped `respond @scope` rules carry their matchers as conjunction terms (like
	// the security gate), so assign those memo slots too — otherwise a matcher used
	// ONLY to scope a terminal respond would be flagged unused (and uncached).
	for i := range p.respondRules {
		for _, t := range p.respondRules[i].terms {
			assign(t.m)
		}
	}
	p.numMatchers = next
}

// resolveAllMatchers compiles each deferred `@name all @a !@b …` into a kindAll matcher
// whose subTerms AND the referenced (optionally negated) sub-matchers. Sub-matchers must
// be defined (forward refs allowed — every plain matcher was collected in Pass 1). A
// response-phase sub-matcher is rejected (an `all` is used in request-phase routing).
// Nesting (`all` referencing another `all`) is not supported — sub-refs must be plain
// matchers — so resolution needs no fixpoint.
func (p *Pipeline) resolveAllMatchers(defs []*cadishfile.MatcherDef) error {
	for _, v := range defs {
		if len(v.Args) == 0 {
			return &CompileError{Pos: v.Pos, Msg: "all matcher needs at least one @matcher reference"}
		}
		m := &matcher{name: v.Name, kind: kindAll, pos: v.Pos, idx: -1}
		for _, a := range v.Args {
			name, negate, ok := parseSecRef(a)
			if !ok {
				return &CompileError{Pos: a.Pos, Msg: "all matcher: expected a @matcher reference (optionally !-negated), got " + quote(a.Raw)}
			}
			sub, ok := p.matchers[name]
			if !ok {
				return &CompileError{Pos: a.Pos, Msg: "undefined matcher @" + name}
			}
			if sub.kind == kindAll {
				return &CompileError{Pos: a.Pos, Msg: "all matcher cannot reference another all matcher @" + name}
			}
			if isResponsePhaseKind(sub.kind) {
				return &CompileError{Pos: a.Pos, Msg: "all matcher cannot reference a response-phase matcher @" + name}
			}
			m.subTerms = append(m.subTerms, secTerm{m: sub, negate: negate})
		}
		p.matchers[v.Name] = m
	}
	return nil
}

// forEachSecRule invokes fn for every compiled security-gate rule (allow then
// deny). It is the single enumeration of security rules, shared by indexMatchers
// (memo slots) and computeUsesGeo (detect a geo matcher in a deny rule).
func (p *Pipeline) forEachSecRule(fn func(*secRule)) {
	for i := range p.allowRules {
		fn(&p.allowRules[i])
	}
	for i := range p.denyRules {
		fn(&p.denyRules[i])
	}
}

// forEachScope invokes fn for every non-nil directive matcher scope in the
// pipeline (purge/route/pass/header/ttl/storage/strip/cors/replace). It is the
// single canonical enumeration of compiled scopes, shared by indexMatchers (assign
// memo slots) and computeUsesGeo (detect a geo matcher), so the two cannot drift as
// new scoped directives are added.
func (p *Pipeline) forEachScope(fn func(*scope)) {
	visit := func(s *scope) {
		if s != nil {
			fn(s)
		}
	}
	for _, r := range p.purgeRules {
		visit(r.guard)
	}
	// respond on_error `@scope` matchers (D57): a matcher used only to scope an
	// on_error synthetic must get a memo slot (so it is not flagged unused) and be
	// scanned for a geo matcher (so the geo pre-pass runs when it needs one).
	for i := range p.onErrorRules {
		visit(p.onErrorRules[i].scope)
	}
	for _, r := range p.routeRules {
		visit(r.scope)
	}
	for _, sc := range p.passRules {
		visit(sc)
	}
	// upgrade `@scope` matchers: an INLINE geo/upstream_healthy matcher written directly
	// in `upgrade @scope` must get a memo slot AND be scanned by the pre-pass (Finding 5),
	// or computeUsesGeo / computeNeedsPoolHealth would miss it and the matcher fails closed
	// (the tunnel silently never engages). Same shape as passRules.
	for _, sc := range p.upgradeRules {
		visit(sc)
	}
	for _, r := range p.reqHeaderRules {
		visit(r.scope)
	}
	for i := range p.rewriteRules {
		visit(p.rewriteRules[i].scope)
	}
	for _, r := range p.ttlRules {
		visit(r.sel.scope)
	}
	for _, r := range p.storageRules {
		visit(r.sel.scope)
	}
	// cache_key recipe selectors (scoped cache_key): a matcher used only to pick a
	// cache-key recipe must get a memo slot and be scanned for geo, exactly like a
	// cache_ttl selector.
	for i := range p.keyRules {
		visit(p.keyRules[i].sel.scope)
	}
	for _, r := range p.respHeaderRules {
		visit(r.scope)
	}
	for _, sc := range p.stripRules {
		visit(sc)
	}
	if p.corsRule != nil {
		visit(p.corsRule.scope)
	}
	for _, r := range p.transformRules {
		visit(r.scope)
	}
	// rate_limit `@scope` matchers (WAF v1b): a matcher used only to scope a
	// rate_limit rule must get a memo slot (so it is not flagged unused) and be
	// scanned for a geo matcher (so the geo pre-pass runs when it needs one).
	for i := range p.rateLimitRules {
		visit(p.rateLimitRules[i].scope)
	}
}

// rawArgs extracts the raw text of each arg.
func rawArgs(args []cadishfile.Arg) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a.Raw
	}
	return out
}

// stickyCookieOf extracts the sticky cookie name from an `upstream` block's
// `sticky by cookie NAME ...` directive, or "" if none.
func stickyCookieOf(up *cadishfile.Directive) string {
	for _, n := range up.Block {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "sticky" {
			continue
		}
		for i, a := range d.Args {
			if a.Raw == "cookie" && i+1 < len(d.Args) {
				return d.Args[i+1].Raw
			}
		}
	}
	return ""
}

// ensureNotResponsePhase rejects scoping a request-phase directive with a
// response-phase matcher (content_type/set_cookie): the response isn't known in
// RECV/KEY, so such a matcher may only scope the origin-response and DELIVER
// directives (cache_ttl/storage/header/strip_cookies/cors). A nil scope
// (unconditional) is always fine.
func ensureNotResponsePhase(sc *scope, directive string, pos cadishfile.Pos) error {
	if sc == nil {
		return nil
	}
	for _, m := range sc.matchers {
		if isResponsePhaseKind(m.kind) {
			return &CompileError{Pos: pos, Msg: directive + " cannot be scoped by a response-phase matcher (" + matcherKindName(m.kind) + " needs the origin response; use it on cache_ttl/storage/header/strip_cookies/cors)"}
		}
	}
	return nil
}

// matcherKindName returns the Cadishfile keyword for a response-phase matcher kind,
// for use in error messages.
func matcherKindName(k matcherKind) string {
	switch k {
	case kindSetCookie:
		return "set_cookie"
	case kindContentType:
		return "content_type"
	case kindRespHeader:
		return "resp_header"
	default:
		return "a response-phase"
	}
}

// resolveRefs turns matcher-ref args into compiled matchers, erroring on undefined
// references and on the unsupported `and` combinator.
func resolveRefs(refs []cadishfile.Arg, matchers map[string]*matcher) ([]*matcher, error) {
	out := make([]*matcher, 0, len(refs))
	for _, a := range refs {
		if a.Raw == "and" || a.Raw == "AND" {
			return nil, &CompileError{Pos: a.Pos, Msg: "AND across matchers is not supported in v1 (use OR / separate rules)"}
		}
		if a.Kind != cadishfile.ArgMatcherRef {
			return nil, &CompileError{Pos: a.Pos, Msg: "expected a @matcher reference, got " + quote(a.Raw)}
		}
		name := strings.TrimPrefix(a.Raw, "@")
		m, ok := matchers[name]
		if !ok {
			return nil, &CompileError{Pos: a.Pos, Msg: "undefined matcher @" + name}
		}
		out = append(out, m)
	}
	return out, nil
}

// leadingRefScope consumes the leading run of @matcher refs from args into an OR
// scope and returns it with the remaining (non-ref) args. When args does not start
// with a @matcher ref it returns a nil scope and args unchanged. It is the shared
// front half of every directive whose grammar is `@matcher… <rest>` (header,
// replace, cors, the scoped redirect form).
func leadingRefScope(args []cadishfile.Arg, matchers map[string]*matcher) (*scope, []cadishfile.Arg, error) {
	if len(args) == 0 || args[0].Kind != cadishfile.ArgMatcherRef {
		return nil, args, nil
	}
	i := 0
	for i < len(args) && args[i].Kind == cadishfile.ArgMatcherRef {
		i++
	}
	ms, err := resolveRefs(args[:i], matchers)
	if err != nil {
		return nil, nil, err
	}
	return &scope{matchers: ms}, args[i:], nil
}

// parseScopeAll consumes the entire arg list as a single OR scope: either a list
// of @matcher refs, or one inline `TYPE arg...` matcher. Returns nil for an empty
// arg list (meaning "unconditional").
func parseScopeAll(args []cadishfile.Arg, matchers map[string]*matcher, pos cadishfile.Pos) (*scope, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if args[0].Kind == cadishfile.ArgMatcherRef {
		ms, err := resolveRefs(args, matchers)
		if err != nil {
			return nil, err
		}
		return &scope{matchers: ms}, nil
	}
	if isMatcherType(args[0].Raw) {
		m, err := compileMatcher("", args[0].Raw, rawArgs(args[1:]), pos)
		if err != nil {
			return nil, err
		}
		return &scope{matchers: []*matcher{m}}, nil
	}
	return nil, &CompileError{Pos: pos, Msg: "expected @matcher or inline matcher, got " + quote(args[0].Raw)}
}

func compileRespond(d *cadishfile.Directive, matchers map[string]*matcher) (respondRule, error) {
	if len(d.Args) < 2 {
		return respondRule{}, &CompileError{Pos: d.Pos, Msg: "respond needs PATH and CODE"}
	}
	// Scoped form: `respond @scope… STATUS [BODY]`, where @scope is a conjunction of
	// (optionally `!`-negated) matcher refs — the same grammar the security gate uses.
	// The ingress translator emits this as a terminal no-match handler. The exact-path
	// form (`respond PATH STATUS BODY`) keeps its first-arg-is-a-literal-path shape.
	if isSecRefArg(d.Args[0]) {
		return compileScopedRespond(d, matchers)
	}
	code, err := strconv.Atoi(d.Args[1].Raw)
	if err != nil {
		return respondRule{}, &CompileError{Pos: d.Args[1].Pos, Msg: "respond status must be a number, got " + quote(d.Args[1].Raw)}
	}
	r := respondRule{path: d.Args[0].Raw, status: code}
	if len(d.Args) >= 3 {
		r.body = d.Args[2].Raw
	}
	return r, nil
}

// compileScopedRespond compiles the scoped `respond @scope… STATUS [BODY]` form: a
// leading conjunction of (optionally `!`-negated) matcher refs, then a numeric STATUS
// and optional BODY. It reuses parseSecRef so the negation grammar is identical to the
// security gate's. A response-phase matcher is rejected — respond fires in RECV, before
// any origin response exists.
func compileScopedRespond(d *cadishfile.Directive, matchers map[string]*matcher) (respondRule, error) {
	var terms []secTerm
	i := 0
	for ; i < len(d.Args) && isSecRefArg(d.Args[i]); i++ {
		name, negate, ok := parseSecRef(d.Args[i])
		if !ok {
			return respondRule{}, &CompileError{Pos: d.Args[i].Pos, Msg: "respond: expected a @matcher reference (optionally !-negated), got " + quote(d.Args[i].Raw)}
		}
		m, ok := matchers[name]
		if !ok {
			return respondRule{}, &CompileError{Pos: d.Args[i].Pos, Msg: "undefined matcher @" + name}
		}
		if isResponsePhaseKind(m.kind) {
			return respondRule{}, &CompileError{Pos: d.Args[i].Pos, Msg: "respond cannot use a response-phase matcher (" + matcherKindName(m.kind) + "); respond runs in RECV before the origin response exists"}
		}
		terms = append(terms, secTerm{m: m, negate: negate})
	}
	if i >= len(d.Args) {
		return respondRule{}, &CompileError{Pos: d.Pos, Msg: "respond @scope needs a STATUS code"}
	}
	code, err := strconv.Atoi(d.Args[i].Raw)
	if err != nil {
		return respondRule{}, &CompileError{Pos: d.Args[i].Pos, Msg: "respond status must be a number, got " + quote(d.Args[i].Raw)}
	}
	r := respondRule{terms: terms, status: code}
	if i+1 < len(d.Args) {
		r.body = d.Args[i+1].Raw
	}
	return r, nil
}

// defaultOnErrorContentType is the Content-Type sent with an on_error synthetic
// when no `content_type T` is given — the maintenance-page case.
const defaultOnErrorContentType = "text/html; charset=utf-8"

// compileOnError compiles `respond on_error [@scope] STATUS BODY [content_type T]`
// (D57). The leading `on_error` keyword is already confirmed by the caller and is
// stripped here. The @scope (if any) is a request-phase matcher OR-set; a
// response-phase matcher (content_type/set_cookie) is a compile error because the
// origin-error path has only a status, no upstream response headers, to match on.
func compileOnError(d *cadishfile.Directive, matchers map[string]*matcher) (onErrorRule, error) {
	// Strip the leading `on_error` keyword.
	args := d.Args[1:]
	// Optional trailing `content_type T`.
	contentType := defaultOnErrorContentType
	for i := 0; i+1 < len(args); i++ {
		if args[i].Raw == "content_type" {
			contentType = args[i+1].Raw
			args = append(args[:i:i], args[i+2:]...)
			break
		}
	}
	scope, rest, err := leadingRefScope(args, matchers)
	if err != nil {
		return onErrorRule{}, err
	}
	if err := ensureNotResponsePhase(scope, "respond on_error", d.Pos); err != nil {
		return onErrorRule{}, err
	}
	if len(rest) < 2 {
		return onErrorRule{}, &CompileError{Pos: d.Pos, Msg: "respond on_error needs STATUS and BODY"}
	}
	code, err := strconv.Atoi(rest[0].Raw)
	if err != nil {
		return onErrorRule{}, &CompileError{Pos: rest[0].Pos, Msg: "respond on_error status must be a number, got " + quote(rest[0].Raw)}
	}
	return onErrorRule{scope: scope, status: code, body: []byte(rest[1].Raw), contentType: contentType}, nil
}

func compilePurge(d *cadishfile.Directive, matchers map[string]*matcher) (purgeRule, error) {
	if len(d.Args) == 0 || d.Args[0].Raw != "when" {
		return purgeRule{}, &CompileError{Pos: d.Pos, Msg: "purge requires `when <condition>`"}
	}
	// Split condition args from an optional trailing `regex EXPR` (matches the
	// whole cache key `host path …`) or `regex-path EXPR` (anchors against the
	// PATH component only — Varnish-compatible `^/foo`).
	condArgs := d.Args[1:]
	regexToken := ""
	regexPath := false
	for i, a := range condArgs {
		if a.Raw == "regex" || a.Raw == "regex-path" {
			if i+1 >= len(condArgs) {
				return purgeRule{}, &CompileError{Pos: a.Pos, Msg: "purge " + a.Raw + " needs an expression"}
			}
			regexToken = condArgs[i+1].Raw
			regexPath = a.Raw == "regex-path"
			condArgs = condArgs[:i]
			break
		}
	}
	guard, err := parseScopeAll(condArgs, matchers, d.Pos)
	if err != nil {
		return purgeRule{}, err
	}
	if guard == nil {
		return purgeRule{}, &CompileError{Pos: d.Pos, Msg: "purge `when` needs a condition"}
	}
	return purgeRule{guard: guard, regexToken: regexToken, regexPath: regexPath}, nil
}

func compileRoute(d *cadishfile.Directive, matchers map[string]*matcher, upstreams map[string]bool) (routeRule, error) {
	arrow := -1
	for i, a := range d.Args {
		if a.Raw == "->" {
			arrow = i
			break
		}
	}
	if arrow < 0 || arrow+1 >= len(d.Args) {
		return routeRule{}, &CompileError{Pos: d.Pos, Msg: "route requires `@matcher -> UPSTREAM`"}
	}
	up := d.Args[arrow+1].Raw
	if len(upstreams) > 0 && !upstreams[up] {
		return routeRule{}, &CompileError{Pos: d.Args[arrow+1].Pos, Msg: "route target " + quote(up) + " is not a declared upstream/cluster"}
	}
	cond := d.Args[:arrow]
	// The pre-arrow scope is an OR-set (`route @a @b -> u` matches if ANY ref matches),
	// consistent with `pass @a @b` and the rest of the language. The inline form
	// (`route path /x -> u`) and the bare catch-all (`route -> u`) also use scope. A
	// multi-criteria (AND) route references a single `all` composite matcher
	// (`route @gw -> u`), which the Gateway translator emits — keeping the route ref
	// single so the terminal no-match `respond !@gw … 404` stays correct.
	sc, err := parseScopeAll(cond, matchers, d.Pos)
	if err != nil {
		return routeRule{}, err
	}
	return routeRule{scope: sc, upstream: up}, nil
}

// parseSelector parses a cache_ttl / storage selector starting at args[0] and
// returns the selector plus the index of the first arg AFTER it.
func parseSelector(args []cadishfile.Arg, matchers map[string]*matcher, pos cadishfile.Pos) (selector, int, error) {
	if len(args) == 0 {
		return selector{}, 0, &CompileError{Pos: pos, Msg: "missing selector"}
	}
	first := args[0]
	switch {
	case first.Raw == "default":
		return selector{kind: selDefault}, 1, nil
	case first.Raw == "resp_header":
		// `resp_header NAME VALUE [<status|@scope>]` — a RESPONSE-phase header term,
		// optionally ANDed with a trailing `status …` or `@scope` selector (the natural
		// `resp_header X-Powered-By Express status 404 …` combination). NAME + a single
		// VALUE are consumed (exactly two args) so the boundary with the trailing
		// selector / TTL action is unambiguous.
		//
		// A missing VALUE — either no third token, or a VALUE position occupied by a
		// cache_ttl/storage action keyword (the user wrote `resp_header X-Foo ttl 1m`,
		// silently consuming `ttl` as the value) — is a HARD error. We do NOT accept a
		// bare NAME (that would mis-scope), but we guide the user to the explicit presence
		// form `resp_header NAME *` (match the header's mere presence).
		if len(args) < 3 || args[1].Raw == "" || isSelectorTailKeyword(args[2].Raw) {
			return selector{}, 0, &CompileError{Pos: first.Pos, Msg: "resp_header needs NAME VALUE — use `resp_header NAME *` to match the header's mere presence"}
		}
		m, err := compileMatcher("", "resp_header", []string{args[1].Raw, args[2].Raw}, first.Pos)
		if err != nil {
			return selector{}, 0, err
		}
		i := 3
		sel := selector{kind: selDefault, respHeader: m}
		// An optional trailing `status …` or `@scope` is ANDed with the resp_header term.
		if i < len(args) && (args[i].Raw == "status" || args[i].Kind == cadishfile.ArgMatcherRef) {
			sub, j, serr := parseSelector(args[i:], matchers, pos)
			if serr != nil {
				return selector{}, 0, serr
			}
			sub.respHeader = m
			sel = sub
			i += j
		}
		return sel, i, nil
	case first.Raw == "status":
		kind := selStatusIn
		i := 1
		if i < len(args) && args[i].Raw == "not" {
			kind = selStatusNotIn
			i++
		}
		codes := map[int]struct{}{}
		for i < len(args) && isAllDigits(args[i].Raw) {
			c, _ := strconv.Atoi(args[i].Raw)
			codes[c] = struct{}{}
			i++
		}
		if len(codes) == 0 {
			return selector{}, 0, &CompileError{Pos: first.Pos, Msg: "status selector needs at least one code"}
		}
		return selector{kind: kind, codes: codes}, i, nil
	case first.Kind == cadishfile.ArgMatcherRef:
		i := 0
		for i < len(args) && args[i].Kind == cadishfile.ArgMatcherRef {
			i++
		}
		ms, err := resolveRefs(args[:i], matchers)
		if err != nil {
			return selector{}, 0, err
		}
		return selector{kind: selScope, scope: &scope{matchers: ms}}, i, nil
	default:
		return selector{}, 0, &CompileError{Pos: first.Pos, Msg: "unknown selector " + quote(first.Raw) + " (want `status ...`, `@matcher`, or `default`)"}
	}
}

// isSelectorTailKeyword reports whether tok is a cache_ttl / storage action or
// trailing-selector keyword. When such a keyword appears in the resp_header VALUE
// position (`resp_header X-Foo ttl 1m`), the operator omitted the value — the keyword
// would otherwise be silently consumed AS the value. Used only to produce the guiding
// "use `resp_header NAME *`" error, never to accept the input.
func isSelectorTailKeyword(tok string) bool {
	switch tok {
	case "ttl", "from_header", "hit_for_miss", "grace", "grace_from_header",
		"max_stale", "max_stale_from_header", "status", "->":
		return true
	}
	return false
}

func compileTTL(d *cadishfile.Directive, matchers map[string]*matcher) (ttlRule, error) {
	sel, i, err := parseSelector(d.Args, matchers, d.Pos)
	if err != nil {
		return ttlRule{}, err
	}
	rest := d.Args[i:]
	if len(rest) == 0 {
		return ttlRule{}, &CompileError{Pos: d.Pos, Msg: "cache_ttl needs `ttl DUR [grace DUR]`, `from_header HEADER [grace DUR]`, or `hit_for_miss DUR`"}
	}
	r := ttlRule{sel: sel}
	switch rest[0].Raw {
	case "from_header":
		if len(rest) < 2 || rest[1].Raw == "" {
			return ttlRule{}, &CompileError{Pos: rest[0].Pos, Msg: "from_header needs a response-header name (e.g. `from_header X-Cache-Ttl`)"}
		}
		r.fromHeader = rest[1].Raw
		if err := parseTTLTail(&r, rest[2:], "after `from_header HEADER`"); err != nil {
			return ttlRule{}, err
		}
	case "ttl":
		if len(rest) < 2 {
			return ttlRule{}, &CompileError{Pos: rest[0].Pos, Msg: "ttl needs a duration"}
		}
		r.ttl, err = parseDuration(rest[1].Raw)
		if err != nil {
			return ttlRule{}, &CompileError{Pos: rest[1].Pos, Msg: err.Error()}
		}
		if err := parseTTLTail(&r, rest[2:], "after `ttl DUR`"); err != nil {
			return ttlRule{}, err
		}
	case "hit_for_miss":
		if len(rest) < 2 {
			return ttlRule{}, &CompileError{Pos: rest[0].Pos, Msg: "hit_for_miss needs a duration"}
		}
		r.isHFM = true
		r.hfm, err = parseDuration(rest[1].Raw)
		if err != nil {
			return ttlRule{}, &CompileError{Pos: rest[1].Pos, Msg: err.Error()}
		}
		// max_stale (and its header-sourced sibling) are meaningless without a stored
		// object — reject them on hit_for_miss. grace_from_header is likewise rejected:
		// hit_for_miss carries no grace window to source.
		for _, a := range rest[2:] {
			switch a.Raw {
			case "max_stale", "max_stale_from_header":
				return ttlRule{}, &CompileError{Pos: a.Pos, Msg: "max_stale is not valid on hit_for_miss (it needs a stored object to serve)"}
			case "grace_from_header":
				return ttlRule{}, &CompileError{Pos: a.Pos, Msg: "grace_from_header is not valid on hit_for_miss (it has no grace window)"}
			}
		}
	default:
		return ttlRule{}, &CompileError{Pos: rest[0].Pos, Msg: "expected `ttl` or `hit_for_miss`, got " + quote(rest[0].Raw)}
	}
	return r, nil
}

// parseTTLTail parses the optional grace / max_stale tail shared by the `ttl` and
// `from_header` cache_ttl actions, writing into r. Each window may be either a literal
// duration (`grace DUR` / `max_stale DUR`) or sourced from an origin response header
// (`grace_from_header NAME` / `max_stale_from_header NAME`); the literal stays as the
// in-rule fallback when the header is absent/unparseable. Each keyword may appear at
// most once. max_stale (D60) is the serve-stale-on-origin-failure window; a LITERAL
// max_stale smaller than the LITERAL grace is a compile error (it would be dead — grace
// already covers that span). When either window is header-sourced the bound is enforced
// against the RESOLVED values at runtime (EvalResponse) instead. where names the action
// for errors.
func parseTTLTail(r *ttlRule, tail []cadishfile.Arg, where string) error {
	seen := map[string]bool{}
	i := 0
	for i < len(tail) {
		kw := tail[i].Raw
		switch kw {
		case "grace", "max_stale":
			if i+1 >= len(tail) {
				return &CompileError{Pos: tail[i].Pos, Msg: kw + " needs a duration"}
			}
			d, err := parseDuration(tail[i+1].Raw)
			if err != nil {
				return &CompileError{Pos: tail[i+1].Pos, Msg: err.Error()}
			}
			if kw == "grace" {
				r.grace = d
			} else {
				r.maxStale = d
			}
		case "grace_from_header", "max_stale_from_header":
			if i+1 >= len(tail) || tail[i+1].Raw == "" {
				return &CompileError{Pos: tail[i].Pos, Msg: kw + " needs a response-header name"}
			}
			if kw == "grace_from_header" {
				r.graceFromHeader = tail[i+1].Raw
			} else {
				r.maxStaleFromHeader = tail[i+1].Raw
			}
		default:
			return &CompileError{Pos: tail[i].Pos, Msg: "expected `grace DUR`, `grace_from_header NAME`, `max_stale DUR`, and/or `max_stale_from_header NAME` " + where + ", got " + quote(kw)}
		}
		if seen[kw] {
			return &CompileError{Pos: tail[i].Pos, Msg: "duplicate " + kw + " " + where}
		}
		seen[kw] = true
		i += 2
	}
	// The dead-config bound is only knowable at compile when BOTH windows are literals;
	// a header-sourced grace/max_stale is checked against the resolved values at runtime.
	if r.graceFromHeader == "" && r.maxStaleFromHeader == "" && r.maxStale > 0 && r.maxStale < r.grace {
		return &CompileError{Pos: tail[0].Pos, Msg: "max_stale must be >= grace (a max_stale smaller than grace is dead — grace already serves that span)"}
	}
	return nil
}

func compileStorage(d *cadishfile.Directive, matchers map[string]*matcher) (storageRule, error) {
	sel, i, err := parseSelector(d.Args, matchers, d.Pos)
	if err != nil {
		return storageRule{}, err
	}
	rest := d.Args[i:]
	if len(rest) != 2 || rest[0].Raw != "->" {
		return storageRule{}, &CompileError{Pos: d.Pos, Msg: "storage needs `<selector> -> ram|disk`"}
	}
	tier := rest[1].Raw
	if tier != "ram" && tier != "disk" {
		return storageRule{}, &CompileError{Pos: rest[1].Pos, Msg: "storage tier must be ram or disk, got " + quote(tier)}
	}
	return storageRule{sel: sel, tier: tier}, nil
}

func compileHeader(d *cadishfile.Directive, matchers map[string]*matcher) (headerRule, error) {
	args := d.Args
	if len(args) == 0 {
		return headerRule{}, &CompileError{Pos: d.Pos, Msg: "header directive needs an operation"}
	}
	sc, rest, err := leadingRefScope(args, matchers)
	if err != nil {
		return headerRule{}, err
	}
	if sc == nil && isMatcherType(args[0].Raw) && len(args) >= 3 {
		// Inline single-arg matcher scope: `header TYPE ARG NAME VALUE...`. Only a
		// single matcher arg is supported inline; richer scopes need a named
		// matcher. Requires at least one op token to remain.
		m, merr := compileMatcher("", args[0].Raw, []string{args[1].Raw}, d.Pos)
		if merr != nil {
			return headerRule{}, merr
		}
		sc = &scope{matchers: []*matcher{m}}
		rest = args[2:]
	}
	ops, err := parseHeaderOps(rest, d.Pos)
	if err != nil {
		return headerRule{}, err
	}
	return headerRule{scope: sc, ops: ops}, nil
}

// compileReplace parses `replace [@matcher…] OLD NEW`: an optional leading
// matcher scope (commonly a `content_type` matcher) followed by the literal OLD
// and NEW strings.
func compileReplace(d *cadishfile.Directive, matchers map[string]*matcher) (transformRule, error) {
	sc, args, err := leadingRefScope(d.Args, matchers)
	if err != nil {
		return transformRule{}, err
	}
	if len(args) != 2 {
		return transformRule{}, &CompileError{Pos: d.Pos, Msg: "replace needs `[@matcher…] OLD NEW`"}
	}
	if args[0].Raw == "" {
		return transformRule{}, &CompileError{Pos: args[0].Pos, Msg: "replace: OLD must be non-empty"}
	}
	return transformRule{scope: sc, repl: Replacement{Old: args[0].Raw, New: args[1].Raw}}, nil
}

// compileEncode parses `encode [CODEC…]`: an optional codec preference subset of
// {gzip, br/brotli, zstd}. Bare `encode` uses the default order. Unknown codec
// tokens and duplicates are a compile error. The Content-Type include list and
// the min_length floor use the v1 defaults (the optional block form is reserved
// for a later refinement; keep the v1 grammar minimal).
func compileEncode(d *cadishfile.Directive) (*encodeRule, error) {
	if d.HasBlock {
		return nil, &CompileError{Pos: d.Pos, Msg: "encode block form is not supported in v1; use `encode [zstd br gzip]`"}
	}
	r := &encodeRule{
		types:     append([]string(nil), defaultEncodeTypes...),
		minLength: defaultEncodeMinLength,
	}
	if len(d.Args) == 0 {
		r.codecs = append([]string(nil), defaultEncodeCodecs...)
		return r, nil
	}
	seen := map[string]bool{}
	for _, a := range d.Args {
		wire, ok := encodeCodecAliases[a.Raw]
		if !ok {
			return nil, &CompileError{Pos: a.Pos, Msg: "encode: unknown codec " + quote(a.Raw) + " (want gzip, br, or zstd)"}
		}
		if seen[wire] {
			return nil, &CompileError{Pos: a.Pos, Msg: "encode: duplicate codec " + quote(wire)}
		}
		seen[wire] = true
		r.codecs = append(r.codecs, wire)
	}
	return r, nil
}

func compileCORS(d *cadishfile.Directive, matchers map[string]*matcher) (*corsRule, error) {
	// Optional leading @matcher scope, then the origin spec + methods/headers.
	sc, args, err := leadingRefScope(d.Args, matchers)
	if err != nil {
		return nil, err
	}
	r := &corsRule{scope: sc}
	i := 0
	if i >= len(args) {
		return nil, &CompileError{Pos: d.Pos, Msg: "cors needs `*` or an origin list"}
	}
	if args[i].Raw == "*" {
		r.cors.AllowAllOrigins = true
		i++
	} else {
		for i < len(args) && args[i].Raw != "methods" && args[i].Raw != "headers" {
			r.cors.Origins = append(r.cors.Origins, args[i].Raw)
			i++
		}
	}
	for i < len(args) {
		switch args[i].Raw {
		case "methods":
			i++
			for i < len(args) && args[i].Raw != "headers" {
				r.cors.Methods = append(r.cors.Methods, args[i].Raw)
				i++
			}
		case "headers":
			i++
			for i < len(args) && args[i].Raw != "methods" {
				r.cors.Headers = append(r.cors.Headers, args[i].Raw)
				i++
			}
		default:
			return nil, &CompileError{Pos: args[i].Pos, Msg: "unexpected cors token " + quote(args[i].Raw)}
		}
	}
	return r, nil
}
