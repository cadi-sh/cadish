package cadishfile

// DirectiveRegistry is a set of known directive names. It is a hook for later
// milestones (the pipeline compiler and `cadish check`) to warn about unknown
// directives. The parser itself stays semantics-free and never consults a
// registry — this type exists purely so downstream code has a single, shared,
// well-documented place to record which directive keywords are recognized.
//
// The zero value is not usable; construct one with NewDirectiveRegistry.
type DirectiveRegistry struct {
	known map[string]bool
}

// NewDirectiveRegistry returns a registry seeded with the given directive names.
func NewDirectiveRegistry(names ...string) *DirectiveRegistry {
	r := &DirectiveRegistry{known: make(map[string]bool, len(names))}
	r.Add(names...)
	return r
}

// Add records one or more directive names as known. It is idempotent.
func (r *DirectiveRegistry) Add(names ...string) {
	for _, n := range names {
		r.known[n] = true
	}
}

// Has reports whether name is a known directive.
func (r *DirectiveRegistry) Has(name string) bool {
	return r.known[name]
}

// Names returns the known directive names (order is unspecified).
func (r *DirectiveRegistry) Names() []string {
	out := make([]string, 0, len(r.known))
	for n := range r.known {
		out = append(out, n)
	}
	return out
}

// DefaultDirectives is the catalog of directive keywords implemented for the v1
// (form A) Cadishfile, taken from the cadish design document §4 and the canonical
// example configs. It is provided as a convenience seed for DirectiveRegistry;
// the parser does not use it. Keeping it here (rather than hard-coded in the
// pipeline) gives tooling one authoritative list.
var DefaultDirectives = []string{
	"tls",
	"cache",
	"upstream",
	"cluster",
	"origin",
	"pass",
	// `upgrade @scope` enables a WebSocket / `Connection: Upgrade` passthrough tunnel
	// (mirrors `pass`; implies it). Server-only — never projected to the edge.
	"upgrade",
	"cache_key",
	"cache_ttl",
	// site-level opt-out of PART of the safe-by-default refusal: when present, cadish caches
	// a cache_ttl-matched response that carries a private/no-store/no-cache Cache-Control or
	// an uncovered Vary. It does NOT lift the Set-Cookie refusal or Vary:* — a Set-Cookie
	// response is NEVER cached, even under cache_unsafe (use `strip_cookies` to cache a
	// cookie-setting origin), and the request credential bypass (Cookie/Authorization) is
	// independent of it. OFF by default — caching is safe by default.
	"cache_unsafe",
	// `cache_credentialed @scope` makes caching ORIGIN-AUTHORITATIVE for the matching
	// requests: it skips the request-time credential bypass (Cookie/Authorization),
	// forwards the original cookies to origin for auth, and stores under the SHARED key
	// only on a POSITIVE in-scope cache_ttl signal (the SOLE storage gate, fail-closed) — the
	// scoped opt-out that expresses a custom-VCL `return(hash)` on cookie traffic. The signal
	// FORCE-OVERRIDES + STRIPS the per-user Set-Cookie + weak Cache-Control/Pragma/Expires (the
	// VCL `unset set-cookie; unset Cache-Control; set ttl`); no signal ⇒ not stored.
	// `strip_cookies` in the same scope is a compile error. Server+edge serving-tier policy —
	// the AST learns nothing about it.
	"cache_credentialed",
	// site-level opt-out of honoring a request's client-forced revalidation
	// (`Cache-Control: no-cache`/`max-age=0`, `Pragma: no-cache`; RFC 9111 §5.2.1.4).
	// `client_cache_control ignore` makes the server serve the fresh/stale entry as
	// normal instead of forcing a MISS — the equivalent of Varnish's `unset
	// req.http.Cache-Control`, closing the cache-bust / DoS vector of a browser
	// hard-refresh. The absent default honors it (unchanged).
	"client_cache_control",
	"storage",
	"lb",
	"sticky",
	"host_header",
	// per-upstream transport knobs (gap H6): TLS ClientHello server name + connection-reuse
	"sni",
	"http_reuse",
	// per-upstream origin TLS verification (TLSVERIFY): skip-verify / private-CA / pinned ALPN
	"tls_insecure",
	"ca_file",
	"alpn",
	// per-upstream DNS resolver knob (RESOLVER): re-resolution interval + nameserver(s)
	"resolve",
	"header",
	"strip_cookies",
	// request-cookie allowlist: keep only the named cookies, strip the rest before the
	// cache key + the origin fetch (the explicit opt-in to caching cookie-bearing traffic).
	"cookie_allow",
	"route",
	"rewrite",
	"respond",
	"redirect",
	"purge",
	"cors",
	"import",
	"device_detect",
	"geo",
	// standalone site-level trusted-proxy declaration (decouples trust_proxy from the
	// geo block; populates Site.TrustedProxies for {geo} and the security `ip` ACL).
	"trust_proxy",
	"normalize",
	"tenant",
	"replace",
	"encode",
	"classify",
	"edge",
	// global `access_log off` option: disable the in-memory access-log hub. Global-only
	// (parsed from the leading options block); a misplaced occurrence in a site body is
	// rejected by pipeline.Compile with a positioned global-only placement error
	// (globalOnlyDirectives), not silently ignored.
	"access_log",
	// global `strict_host` option: reject an undeclared Host with 421 instead of the
	// lenient single-site fallback (Host-confusion / cache-poisoning hardening).
	// Registered so it parses cleanly as a known directive; a misplaced occurrence in a
	// site body is rejected by pipeline.Compile with a positioned global-only placement
	// error (globalOnlyDirectives) — NOT silently ignored, and not flagged as unknown.
	"strict_host",
	// global `admin { … }` block: the dashboard/metrics listener (D16). Global-only;
	// registered so it parses cleanly as a known directive. A misplaced occurrence in a
	// site body is rejected by pipeline.Compile with a positioned global-only placement
	// error (globalOnlyDirectives), not silently ignored.
	"admin",
	// global `proxy_protocol { trust … }` block: opt-in PROXY-protocol listener
	// (recover the real client IP behind an L4/TCP-passthrough LB). Global-only; a
	// misplaced occurrence in a site body is rejected by pipeline.Compile with a
	// positioned global-only placement error (globalOnlyDirectives).
	"proxy_protocol",
	// global `security { audit_log … }` block: security observability (WAF v1c, D52).
	// Global-only; a misplaced occurrence in a site body is rejected by pipeline.Compile
	// with a positioned global-only placement error (globalOnlyDirectives).
	"security",
	// global `server { maxconn N; read_timeout D; idle_timeout D }` block: the inbound
	// data-plane connection knobs. A global data-plane block, registered so it parses
	// cleanly as a known directive; a misplaced occurrence in a site body is rejected by
	// pipeline.Compile with a positioned global-only placement error (globalOnlyDirectives)
	// — NOT silently ignored, and not flagged as an unknown directive.
	"server",
	// security gate (native primitives, server-only; see internal/pipeline/secgate.go)
	"allow",
	"deny",
	"block",
	"monitor",
	// rate_limit (stateful native primitive, server-only; see internal/pipeline/ratelimit.go)
	"rate_limit",
}

// DefaultMatcherTypes is the catalog of matcher type keywords implemented for v1
// (form A). Like DefaultDirectives it is informational; the parser accepts any
// matcher type. Provided so `cadish check` can warn on unknown matcher types.
var DefaultMatcherTypes = []string{
	"path",
	"path_regex",
	"host",
	"host_regex",
	"header",
	// presence-only request-header guard (any value): the most general "only when
	// header X is present" matcher — e.g. `@has_origin header_present Origin` to make
	// a reflected-Origin CORS header fire only on a CORS request.
	"header_present",
	// regex on a request header VALUE (RE2, like path_regex/host_regex): the
	// canonical `req.http.Accept-Language ~ "^es"` language gate — e.g.
	// `@lang_es header_regex Accept-Language (?i)^es`. Complementary to header_present
	// (presence) and header (exact value).
	"header_regex",
	"method",
	"upstream",
	"content_type",
	// RESPONSE-phase matcher over a named origin response header value (exact or
	// `*`-glob): `cache_ttl resp_header X-Powered-By Express ttl 1m grace 2w` branches
	// freshness on what the origin returned. Response-phase only (cache_ttl/storage and
	// the DELIVER directives); a request-phase use is a compile error.
	"resp_header",
	"cookie",
	// structured-value matchers: a bounded dotted field test inside a JSON cookie/
	// header value (D54). Request-phase; see internal/pipeline/cookie_json.go.
	"cookie_json",
	"header_json",
	"set_cookie",
	"classify",
	"geo",
	"query_present",
	// exact-value test of ONE named query param against an OR set of values (the
	// Gateway HTTPRoute `queryParams` Exact match) — e.g. `@prod query env prod staging`.
	// Complementary to query_present (presence-OR over several param names).
	"query",
	"ip",
	// AND-composite: `@name all @a !@b …` matches when EVERY referenced (optionally
	// `!`-negated) sub-matcher matches. The Gateway controller emits it so a multi-criteria
	// HTTPRoute match (path AND headers AND method AND query) is ONE named matcher — a
	// single `route @name -> u` plus a correct terminal no-match 404.
	"all",
	// liveness probe: `@live upstream_healthy NAME[ NAME…]` matches when ANY named
	// upstream POOL has a live backend (lb nbsrv()>0). Composes with scoped `respond`
	// for the AWS /aws-health-check probe (`respond @probe @live 200` / `respond @probe
	// 503`). SERVER-ONLY — live pool health does not exist at the edge (delegated).
	"upstream_healthy",
}

// NewDefaultDirectiveRegistry returns a DirectiveRegistry seeded with
// DefaultDirectives.
func NewDefaultDirectiveRegistry() *DirectiveRegistry {
	return NewDirectiveRegistry(DefaultDirectives...)
}
