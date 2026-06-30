// Package edgeir projects a compiled *pipeline.Pipeline into a versioned,
// serializable EdgeIR — the single, explicit JSON contract a small generic
// JavaScript worker (Cadish Edge) interprets at the edge. It is the FIRST slice of
// Cadish Edge (the management-plane foundation; no runtime, no Cloudflare API).
//
// The projector is the ONE decision point for "edge-capable vs delegate" (design
// policy C, §2.6): anything the edge v1 cannot faithfully execute (body transforms
// via `replace`; regex BAN purge) is recorded in EdgeIR.Delegate with a reason —
// never silently dropped — so the worker `pass`es it to the Cadish server behind,
// and `cadish edge build` can surface a coverage report (and fail under --strict).
//
// The IR is an EXPLICIT projection (not raw pipeline structs with json tags): the
// field names here are a STABLE contract the JS interpreter mirrors. Keep IRVersion
// in lockstep with the runtime that understands it.
package edgeir

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// kvHardCapBytes is Cloudflare Workers KV's hard per-value ceiling (25 MB). A
// `kv_max_bytes` above this is meaningless (KV would reject the put) and is
// surfaced as a build warning.
const kvHardCapBytes int64 = 25 * 1000 * 1000

// IRVersion is the EdgeIR schema version. The embedded JS runtime declares the
// version it understands; `cadish edge build` refuses a mismatch. Bump it on any
// breaking change to the field shape below.
//
// v2 (D70, edge completion roadmap v1.1) batches three additive shape changes:
//   - Key.Recipes: the FULL ordered scoped cache_key recipe list + selectors, so a
//     scoped site (D65) keys byte-identically at the edge (was delegated in v1).
//   - Device: the {device} User-Agent classifier ruleset, so the worker classifies
//     from the User-Agent natively (was an X-Cadish-Device crutch / constant "").
//   - TTL.MaxStale: the max_stale (D60) window, so the edge bounds its
//     stale-on-error serving instead of serving unboundedly-old content.
//
// v3 (D74) closes the edge open-redirect: Site.RedirectHosts (the normalized
// trusted-host allowlist) + Site.CanonicalHost let the worker resolve a redirect
// TARGET's {host} the SAME safe way the server does (reflect the inbound Host only
// when trusted, else the canonical host) instead of reflecting it verbatim. The
// version is bumped (not just batched into v2) deliberately: a stale runtime that
// ignored these fields would re-open the open redirect, so it must refuse the IR.
//
// v4 (D75/D76, edge completion roadmap v1.2) makes two delegated directives edge-native:
//   - Response.Transforms + Response.TransformMaxBytes: a SIZE-BOUNDED `replace` body
//     transform (D75). The worker applies the literal substitution within the cap and
//     passes an over-cap body through untransformed (unbounded `replace` stays
//     server-only).
//   - Response.OnError: the `respond on_error` outage synthetic (D76). The worker
//     serves it on an origin hard-failure with no servable cached object, instead of a
//     bare 502. A stale runtime ignoring these would silently NOT transform / NOT serve
//     the friendly outage page, so the version is bumped and the runtime refuses a
//     mismatch.
//
// v5 (Finding 6) adds Response.ttl[].StripHeaders: the from_header-family control headers
// (X-Cache-Ttl/X-Cache-Grace/X-Cache-Max-Stale) a cache_ttl rule CONSUMES, so the worker
// strips them before store + deliver exactly as the server does. A stale runtime ignoring
// them would LEAK the internal origin↔cache contract headers to the client (the server
// never does), so the version is bumped and the runtime refuses a mismatch.
//
// v6 (D101) adds CacheCredentialed: the `cache_credentialed @scope` set that makes caching
// ORIGIN-AUTHORITATIVE for the matching credentialed requests. The worker skips the
// credential bypass for them (caches under the SHARED key, forwards the original cookies to
// origin) and applies the in-scope EvalResponse precedence: a positive in-scope cache_ttl
// signal is the SOLE storage gate — it force-stores and FORCE-OVERRIDES + STRIPS the per-user
// Set-Cookie + weak no-store/private/no-cache/Pragma/Expires (matching the VCL); no signal ⇒
// not stored (fail-closed). A stale runtime ignoring the field would credential-BYPASS those
// requests (caching LESS, never wrong) — but to keep Go==JS exact it is a versioned contract,
// so the runtime refuses a mismatch.
//
// v7 (edge `all`+`query` matchers + `query_present` non-empty modifier) makes the last two
// pure-request-data Gateway matchers edge-native (they were serverOnly => forced-pass before)
// and adds the `+` non-empty-value modifier to `query_present`:
//   - `query` reuses the already-projected Name/Values (one named param vs an OR set of exact
//     values; empty set => presence) — only the serverOnly suppression is lifted and a JS
//     `query` matchOne case added.
//   - `all` adds Matcher.Subs: the AND-conjunction of (Ref, Negate) sub-terms. Each term
//     references a named matcher XOR'd with Negate; request-phase, depth-1 (the compiler
//     forbids all-of-all and response-phase subs). The worker recurses through matchOne over
//     ir.matchers[ref], mirroring the Go `got == negate` short-circuit.
//   - `query_present` adds Matcher.QueryNamesNonEmpty: the subset of QueryNames whose `+`
//     modifier requires the matched param to have ≥1 non-empty value (`?t=` empty does NOT
//     match `t+`, `?t=abc` does — Varnish `=[^&]+` parity for the "publi" marketing-param
//     flag). Additive: a stale runtime ignoring it falls back to pure presence (strictly
//     more permissive — may pass one fewer request than intended, never caches one that should
//     be passed), so the version is NOT bumped solely for this field.
//   - Redirect.NoStore is an additive v7 field (json:"noStore,omitempty"): when the
//     `redirect … no_store` modifier is present the worker attaches Cache-Control:
//     no-store, no-cache, must-revalidate, private to the short-circuit Response so no
//     shared cache or browser caches a personalized (cookie/Accept-Language-driven) redirect.
//     A stale runtime that misses it simply omits the header (the pre-modifier behavior —
//     strictly less safe but not wrong), so the version is NOT bumped for this field.
//   - Deliver.CacheAgeHeader is an additive v7 field (json:"cacheAgeHeader,omitempty"):
//     the target header name for `header +cache_age NAME`; the worker emits the object's
//     age in whole seconds on a cache HIT (Math.floor((now − storedAt) / 1000)), omitted
//     on MISS/bypass. A stale runtime ignoring it simply omits the header (observability
//     gap, not a correctness regression), so the version is NOT bumped for this field.
//
// A stale runtime would mis-evaluate `all`/`query` (silent wrong cache/route decision), so
// the version was bumped to 7 and the runtime refuses a mismatch.
//
// v8 (D105, edge pass-route exclusion) adds RouteExclusions: the host+prefix CF route
// globs the worker would ONLY ever `pass` (a path-only unconditional pass with NO other
// edge directive touching the path), populated ONLY when the site opts in with
// `edge { bypass_passes }`. The deploy plane turns each into a Cloudflare route that
// matches but runs no worker (script omitted) so CF proxies it straight to origin,
// skipping a wasted worker invocation. This is purely a DEPLOY-PLANE concern — the
// worker RUNTIME never reads RouteExclusions (a request that reaches the worker is
// still passed correctly), so a stale runtime ignoring the field is unaffected. The
// version is bumped (not silently batched) so the management plane treats the field as
// a versioned contract; the runtime mismatch check is unchanged in behaviour for it.
//
// v9 (F-A1/F-B) adds UsesGeo and SECURITY-relevant request-phase neutralization: the
// worker must blank an UNKEYED {device}/{geo*} (raw OR class-derived {classify.NAME})
// reflected in a REQUEST-phase header (forwarded to origin) so it never forwards a class
// the SELECTED cache-key recipe does not segment on (cross-class cache leak) — the worker
// derives the keyed set from the recipe it selects per request — and it injects the CF geo
// headers ONLY when UsesGeo. The version bump ensures a stale runtime (which would not
// neutralize) is refused.
const IRVersion = 9

// EdgeIR is the versioned, serializable projection of one compiled site. The JSON
// field names are the contract; the JS interpreter is a faithful port of the
// matcher switch + the EvalRequest/EvalResponse/EvalDeliver phase walk over this
// structure.
type EdgeIR struct {
	IRVersion   int                   `json:"irVersion"`
	Site        Site                  `json:"site"`
	Upstream    Upstream              `json:"upstream"`
	Matchers    map[string]Matcher    `json:"matchers"`
	Classifiers map[string]Classifier `json:"classifiers,omitempty"`
	Normalizers map[string]Normalizer `json:"normalizers,omitempty"`
	Tenant      *Tenant               `json:"tenant,omitempty"`

	// Device is the {device} User-Agent classifier ruleset (D70). Present only when the
	// cache key uses the {device} token (zero-cost-when-unused). The worker classifies
	// the User-Agent natively from this ruleset — no X-Cadish-Device header crutch.
	Device *DeviceClassifier `json:"device,omitempty"`

	Recv     Recv     `json:"recv"`
	Key      Key      `json:"key"`
	Response Response `json:"response"`
	Deliver  Deliver  `json:"deliver"`

	// UsesGeo mirrors pipeline.UsesGeoToken (v9): the site varies on or reflects geo. The
	// worker injects the CF geo headers to origin (applyGeoHeaders) ONLY when true, so a
	// site that does not use geo never forwards an unkeyed geo signal an origin could
	// vary on under a geo-independent edge key (F-B compounding path). NOT omitempty:
	// the worker reads usesGeo===false to SUPPRESS injection, so false must be emitted.
	UsesGeo bool `json:"usesGeo"`

	// CacheUnsafe mirrors the site-level `cache_unsafe` opt-out flag. When true the
	// edge interpreter skips the safe-by-default downgrade (Set-Cookie / private
	// Cache-Control / uncovered Vary) that mirrors Go's EvalResponse behaviour.
	// Omitted (false) when the site does not set `cache_unsafe`.
	CacheUnsafe bool `json:"cacheUnsafe,omitempty"`

	// CacheCredentialed is the projected `cache_credentialed @scope` set (D101): the
	// request scopes for which caching is ORIGIN-AUTHORITATIVE. The worker (a) does NOT
	// credential-bypass a matching request (it caches under the SHARED key and forwards the
	// original cookies to origin for auth) and (b) applies the in-scope EvalResponse
	// precedence — a positive in-scope cache_ttl signal is the SOLE storage gate: it force-
	// stores and FORCE-OVERRIDES + STRIPS the per-user Set-Cookie + weak no-store/private/
	// no-cache/Pragma/Expires (matching the VCL); absence of the signal does NOT store
	// (fail-closed). A scope referencing a
	// ServerOnly/untranslatable matcher is NEVER projected here: it fails CLOSED (the whole
	// site fail-open passes + ForcedPass++ so `cadish edge build` fails loud). Omitted when
	// the site declares no `cache_credentialed`.
	CacheCredentialed []Scope `json:"cacheCredentialed,omitempty"`

	// CookieAllow is the `cookie_allow` request-cookie allowlist (name patterns, globs
	// ok). When CookieAllowSet is true the edge worker strips every request cookie not
	// matching a pattern before the cache decision (an EMPTY list strips all cookies),
	// mirroring the server's FilterRequestCookies, so the controlled cookies are exempt
	// from the edge credential bypass and cookie-bearing traffic can cache at the edge.
	CookieAllow    []string `json:"cookieAllow,omitempty"`
	CookieAllowSet bool     `json:"cookieAllowSet,omitempty"`

	// KeyHeaderNames is the lower-cased set of request header names included in the
	// cache key (from every `header:NAME` cache_key token). The edge interpreter uses
	// this to decide whether a `Vary` field is covered by the cache key, mirroring
	// Go's varyCovered helper. Omitted when the key contains no header tokens.
	KeyHeaderNames []string `json:"keyHeaderNames,omitempty"`

	// Edge is the `edge {}` cache-tier policy block (L1 Cache API / L2 KV): a default
	// tier plus per-scope overrides (local | distribute | skip). The worker resolves
	// each response's tier from these. Deploy identity (account/zone/worker/routes/kv)
	// is NOT here — it is management-plane metadata that must not ship to the public
	// worker (the CLI reads it from pipeline.EdgeDeployConfig()).
	Edge Edge `json:"edge"`

	// Delegate lists every non-edge-capable directive, with a reason, that the
	// worker must `pass` to the Cadish server behind. Materializes policy C.
	Delegate []Delegated `json:"delegate,omitempty"`

	// RouteExclusions is the set of host+prefix CF route globs the edge worker would
	// ONLY ever `pass` (D105): a path covered by an unconditional path-only `pass` with
	// NO other edge-emitted directive touching it, reducible to a `<host>/<prefix>*`
	// glob. Populated ONLY when the site sets `edge { bypass_passes }`; the deploy plane
	// (edgedeploy.Enable) creates a no-script Cloudflare route per pattern so CF proxies
	// those paths straight to origin, skipping a wasted worker invocation. A DEPLOY-PLANE
	// concern only — the worker runtime never reads it (a request that still reaches the
	// worker is passed correctly), so a stale runtime ignoring it is unaffected. Omitted
	// when empty / when the toggle is off. The coverage report ALWAYS lists the excludable
	// set (CoverageReport.RouteExcludable) even when the toggle is off, so the operator can
	// review it before opting in.
	RouteExclusions []string `json:"routeExclusions,omitempty"`
}

// Site is the host set the worker routes for.
type Site struct {
	Hosts []string `json:"hosts"`

	// RedirectHosts is the trusted-host allowlist a `redirect` TARGET's {host}
	// placeholder is checked against — the normalized projection of the server's
	// trustedHosts (pipeline.normalizeRedirectHost over the site addresses: scheme/
	// port/path stripped, lower-cased, `*.suffix` wildcards preserved). The worker
	// echoes the inbound request Host into a redirect Location ONLY when it matches one
	// of these (exact, or HasSuffix for a `*.suffix` wildcard — the apex is NOT trusted
	// by a wildcard, mirroring hostSet.Match); otherwise it substitutes CanonicalHost.
	// This closes the edge open-redirect (parity with the server F12 fix). When Hosts
	// is empty the site declared no address (server trustedHosts == nil) and the worker
	// reflects the request Host verbatim, exactly as the server does. Declared hostnames
	// are already public config — no secret is added to the IR. Omitted when empty.
	RedirectHosts []string `json:"redirectHosts,omitempty"`

	// CanonicalHost is the site's primary host (first non-wildcard configured address,
	// scheme/port stripped, lower-cased) — the safe {host} value the worker substitutes
	// into a redirect Location when the inbound Host is NOT in RedirectHosts. Mirrors
	// pipeline.Pipeline.canonicalHost. Omitted when the site declares no address.
	CanonicalHost string `json:"canonicalHost,omitempty"`
}

// Upstream is the origin the worker fetches. To is the default upstream `to` name
// (best-effort projection of the site default; the worker resolves the concrete
// URL from its binding). Empty when the site declares no default upstream.
type Upstream struct {
	To string `json:"to,omitempty"`
}

// Matcher is the `{kind, fields}` projection of one named matcher. Only the fields
// relevant to Kind are populated; the JS matcher switch mirrors this 1:1.
type Matcher struct {
	Kind string `json:"kind"`

	Patterns []string `json:"patterns,omitempty"` // path/host
	Regex    string   `json:"regex,omitempty"`    // path_regex/host_regex/header_regex
	// Flags is the JS-equivalent RegExp flag string ("i"/"is"/…) lifted from a RE2
	// inline flag group (e.g. `(?i)^/cams`) on Regex so the worker compiles
	// `new RegExp(regex, flags)` instead of crashing on the inline `(?i)`. Empty when
	// the source carried no inline flags (BUG-1).
	RegexFlags string `json:"regexFlags,omitempty"`

	Name   string   `json:"name,omitempty"`   // header/cookie name
	Values []string `json:"values,omitempty"` // header/cookie accepted values
	Glob   bool     `json:"glob,omitempty"`   // cookie name-prefix glob

	Methods      []string `json:"methods,omitempty"`
	Upstreams    []string `json:"upstreams,omitempty"`
	ContentTypes []string `json:"contentTypes,omitempty"`
	CookieNames  []string `json:"cookieNames,omitempty"` // set_cookie

	ClassifyToken  string `json:"classifyToken,omitempty"`
	ClassifyValue  string `json:"classifyValue,omitempty"`
	ClassifyNegate bool   `json:"classifyNegate,omitempty"`

	GeoGranularity string   `json:"geoGranularity,omitempty"`
	GeoValues      []string `json:"geoValues,omitempty"`

	QueryNames []string `json:"queryNames,omitempty"`

	// QueryNamesNonEmpty is the subset of QueryNames that carry the `+` modifier
	// (`query_present adult_content+ ff-*+`): a matched param must have ≥1 non-empty
	// value. Absent/empty => all names are presence-only (the previous behavior).
	// Additive under v7: a v7 runtime that does not read it falls back to pure
	// presence, which is strictly more permissive than the intended behavior but never
	// caches something a correct runtime would pass — fail-safe rather than fail-closed.
	QueryNamesNonEmpty []string `json:"queryNamesNonEmpty,omitempty"`

	// Subs is the AND-conjunction of an `all` matcher: each entry references a named
	// matcher (Ref) XOR'd with Negate. Edge-evaluated request-phase; depth-1 (the compiler
	// forbids all-of-all and response-phase subs), so the worker walks ir.matchers[ref] with
	// no cycle guard. Empty slice ⇒ matches (mirrors the Go empty-conjunction). v7.
	Subs []SubMatcher `json:"subs,omitempty"`

	// JSONPath is the dotted PATH of a cookie_json/header_json matcher (D54), e.g.
	// "user.verified" / "flags.0.kind". Name carries the cookie/header name and
	// Values the OR set of accepted scalar string forms (empty => presence). The JS
	// runtime splits JSONPath the same way and applies the same 8 KiB/depth-32 caps.
	JSONPath string `json:"jsonPath,omitempty"`

	// ResponsePhase marks content_type/set_cookie matchers (need the origin
	// response): the JS interpreter only evaluates them in the response/deliver walk.
	ResponsePhase bool `json:"responsePhase,omitempty"`

	// RegexUntranslatable marks a path_regex/host_regex/header_regex whose RE2 source
	// uses a construct with no faithful JS RegExp equivalent (e.g. ungreedy `(?U)`, a scoped
	// `(?i:…)` group, or a mid-pattern inline flag). The source is stripped (never
	// ship a pattern that would crash or silently mismatch); the runtime treats the
	// matcher as a non-match (fail-closed) and the projector delegates every directive
	// that references it. See BUG-1 / regexflags.go.
	RegexUntranslatable bool `json:"regexUntranslatable,omitempty"`

	// Redacted is set when this matcher's literal value(s) were a purge-guard secret
	// (a token compared by `purge when …`) and were stripped from the IR so they never
	// ship to the public edge worker. The name/kind survive (for the coverage report);
	// the values do not. See DECISIONS.md D34.
	Redacted bool `json:"redacted,omitempty"`

	// ServerOnly marks a matcher kind that has no JavaScript runtime case — currently
	// `ip` (trusted-proxy real-IP ACL, no edge analogue, D.R02) and `upstream_healthy`
	// (live lb-pool liveness, no edge analogue, D49). The projector delegates every
	// directive that references such a matcher to the Cadish server behind (Fix #4);
	// the runtime treats it as a non-match (fail-closed) so a site that slipped one
	// through never silently mis-projects. Distinct from RegexUntranslatable (which is
	// regex-specific). `all` and `query` were server-only before IR v7; they became
	// edge-native in v7 (pure functions of request data the worker already parses).
	ServerOnly bool `json:"serverOnly,omitempty"`

	// failsClosed is a DERIVED, projection-only flag (deliberately unexported so it never
	// ships in the IR JSON to the worker): set by Project on a `classify` matcher whose
	// classifier the edge cannot faithfully resolve — any classifier ROW references a
	// matcher that itself fails closed (ServerOnly/RegexUntranslatable) or, transitively,
	// another fail-closed classifier (classifiersFailClosed fixpoint, Finding 1). The
	// classify matcher carries no ServerOnly/RegexUntranslatable flag of its own, so
	// without this scopeFailsClosed would judge a pass/cache_ttl/storage/redirect scope
	// gated on `{C}==v` SAFE and ship it native — over-caching a request the Go server
	// passes (the edge's classifyResolve skips the fail-closed row → returns the default →
	// the gate never fires). The runtime needs no equivalent: its classifyResolve naturally
	// fails the row closed; only the projector's fail-open/delegate decision must account
	// for it, which this flag drives through matcherFailsClosed.
	failsClosed bool `json:"-"`
}

// SubMatcher is one term of an `all` AND-conjunction: a reference to a named matcher
// (Ref, always resolvable — EdgeMatchers projects every named matcher) XOR'd with Negate
// (`!@x`). The worker evaluates matchOne(ir.matchers[Ref]) and compares it to Negate
// (`got == negate ⇒ fail`), the same per-term semantics the server's secTerm uses.
type SubMatcher struct {
	Ref    string `json:"ref"`
	Negate bool   `json:"negate,omitempty"`
}

// serverOnlyEdgeKinds is the set of matcher kinds with no edge JavaScript runtime case:
// `upstream_healthy` (live lb-pool liveness has no edge analogue, D49) and `ip` (resolves
// the trusted-proxy real client IP, no edge analogue, R02). A site using one is delegated
// to the Cadish server behind (Fix #4) rather than silently mis-projected. The slice-2
// Gateway matchers `all` (AND-composite) and `query` (named query-param value test) are NO
// LONGER here — they became edge-native in v7 (both are pure functions of request data the
// worker already parses), so they project + evaluate at the edge.
var serverOnlyEdgeKinds = map[string]bool{
	"upstream_healthy": true, // live upstream-pool liveness probe — lb state has no edge analogue (D49)
	"ip":               true, // IP/CIDR ACL — resolves the trusted-proxy real client IP, no edge analogue (R02)
}

// NOTE — withdrawn "drop unsatisfiable-at-edge classify row" optimization (P2).
// A previous (pre-release) version treated an `ip` matcher in a classify `when` row as
// constant-false-at-the-edge and DROPPED the row from the projected classifier, keeping the
// rest of the classifier edge-native. That was UNSOUND: the `ip` matcher resolves the REAL
// client IP (CF-Connecting-IP via trust_proxy) — a public visitor presents the SAME IP to the
// Cadish server AND to the edge worker. Dropping a row keyed on a public `ip` CIDR makes the
// edge classify that visitor DIFFERENTLY than the server, computing a different cache key and
// serving a variant the server would never produce (the cardinal "edge serves what the server
// wouldn't" over-cache). So no row is dropped: an `ip` (and `upstream_healthy`) matcher in a
// `when` row fails CLOSED the whole classifier (it is in serverOnlyEdgeKinds → ServerOnly, seen
// by classifierRowsFailClosed/classifiersFailClosed), and a recipe reading a fail-closed
// classifier fail-opens → delegates to the Cadish server behind, which CAN evaluate `ip` and
// computes the correct variant. Safe, no silent drop, no over-cache.
//
// A FUTURE sound version could drop ONLY a row whose `ip` matcher is provably NON-routable /
// private (RFC1918/loopback/link-local) CIDRs that no public visitor can present AND that do
// not feed the cache key — but none of that is implemented here.

// ServerOnlyEdgeKinds returns a COPY of the set of matcher kinds that have no edge
// JavaScript runtime case (the projector marks them serverOnly + delegates; the worker
// fails closed). Exported so the conformance coverage gate can assert its own mirror set
// EQUALS this one, making any future drift fail loudly (Finding 7).
func ServerOnlyEdgeKinds() map[string]bool {
	out := make(map[string]bool, len(serverOnlyEdgeKinds))
	for k, v := range serverOnlyEdgeKinds {
		out[k] = v
	}
	return out
}

// Classifier is `{rows:[{conj:[matcherId], value}], default}` — first-match over
// the rows' AND-conjunctions, else default (identical to classifier.resolve).
type Classifier struct {
	Rows    []ClassifyRow `json:"rows"`
	Default string        `json:"default"`
	// DerivesFrom names the request cookies this axis consumes (`derives_from cookie
	// NAME…`). The worker keeps them through cookie_allow so the classifier reads the
	// original value and the key is built from it, then strips them post-key before the
	// credential bypass + origin fetch (the same derive→strip the server does, so the two
	// runtimes collapse cardinality identically). Omitted when none are declared.
	DerivesFrom []string `json:"derivesFrom,omitempty"`
	// DerivesForward is the SUBSET of DerivesFrom declared `forward` (alias `keep`): the
	// worker FORWARDS these to origin (does NOT strip) and treats them as covered by
	// {TOKEN} in the credential bypass — the loud opt-in for cookie-reading backends, the
	// same behavior the server applies. Omitted when no row uses the modifier.
	DerivesForward []string `json:"derivesForward,omitempty"`
}

// ClassifyRow is one row: an AND-conjunction of matcher ids yielding a value.
type ClassifyRow struct {
	Conj  []string `json:"conj"`
	Value string   `json:"value"`
}

// Normalizer projects a `normalize` bucket map: read a request value, map it to a
// bounded bucket, else the default.
type Normalizer struct {
	Source     string            `json:"source"` // header|cookie|query
	SourceName string            `json:"sourceName"`
	Map        map[string]string `json:"map"`
	Default    string            `json:"default,omitempty"`
}

// Tenant projects a request-derived `tenant { … }` resolver.
type Tenant struct {
	FromHeader string      `json:"fromHeader,omitempty"` // "" => derive from Host
	Rules      []TenantMap `json:"rules"`
	Default    string      `json:"default,omitempty"`
}

// TenantMap is one tenant pattern->name rule.
type TenantMap struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name"`
}

// Scope is an OR set of matcher ids (+ inline anonymous matchers). Always=true is
// an unconditional directive (a nil pipeline scope).
type Scope struct {
	Always bool      `json:"always,omitempty"`
	Names  []string  `json:"names,omitempty"`
	Inline []Matcher `json:"inline,omitempty"`
}

// Recv is the RECV-phase projection: the terminal + header directives evaluated
// before the cache key.
type Recv struct {
	Pass      []Scope    `json:"pass,omitempty"`
	Respond   []Respond  `json:"respond,omitempty"`
	Redirect  []Redirect `json:"redirect,omitempty"`
	Purge     []Purge    `json:"purge,omitempty"`
	Route     []Route    `json:"route,omitempty"`
	HeaderReq []Header   `json:"headerReq,omitempty"`
}

// Respond is a synthetic-response rule (`respond PATH STATUS BODY`).
type Respond struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// Redirect is a computed 3xx. Regex and/or Scope select: the combined scope+regex
// form carries BOTH (the worker requires the scope AND the regex to match).
type Redirect struct {
	Regex string `json:"regex,omitempty"`
	// RegexFlags is the JS RegExp flag string lifted from a RE2 inline flag group on
	// Regex (e.g. `redirect (?i)^/cams/?$`). The worker compiles
	// `new RegExp(regex, flags)`. Empty when the source carried no inline flags (BUG-1).
	RegexFlags string `json:"regexFlags,omitempty"`
	Scope      *Scope `json:"scope,omitempty"`
	Status     int    `json:"status"`
	Target     string `json:"target"`
	// NoStore, when true, means the directive carried a trailing `no_store` modifier.
	// The worker attaches Cache-Control: no-store, no-cache, must-revalidate, private
	// to the redirect Response so no shared cache or browser caches the redirect.
	// Additive v7 field (omitted when false — a stale runtime that misses it simply
	// sends no Cache-Control header, which is the pre-modifier behavior).
	NoStore bool `json:"noStore,omitempty"`
}

// Purge is a purge guard scope. NOTE: as of D34 every `purge` directive is
// delegated to the Cadish server behind (the guard compares a SECRET token that
// must never live on a public edge worker), so this type is retained for the IR
// contract but the projector emits no edge-native purge — see Delegated.
type Purge struct {
	Guard Scope `json:"guard"`
}

// Route is a `route @scope -> upstream` rule.
type Route struct {
	Scope    Scope  `json:"scope"`
	Upstream string `json:"upstream"`
}

// Header is a scoped group of header ops.
type Header struct {
	Scope Scope      `json:"scope"`
	Ops   []HeaderOp `json:"ops"`
}

// HeaderOp is one header edit. Op is set|append|remove|cache_status. ValueIsTmpl
// flags a value carrying a template placeholder the worker must expand.
type HeaderOp struct {
	Op          string `json:"op"`
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	ValueIsTmpl bool   `json:"valueIsTmpl,omitempty"`
}

// Key is the cache-key recipe set. Tokens is the catch-all (default/unscoped) recipe,
// kept for backward compatibility and as the worker's fallback. Recipes is the FULL
// ordered scoped recipe list (D70): the worker evaluates it first-match-wins (mirroring
// pipeline.selectKeyTokens) and builds the matching recipe, so a scoped cache_key site
// keys byte-identically at the edge. When Recipes is empty the worker uses Tokens (a
// single-recipe site behaves exactly as v1).
type Key struct {
	Tokens  []KeyToken  `json:"tokens"`
	Recipes []KeyRecipe `json:"recipes,omitempty"`
}

// KeyRecipe is one scoped cache_key recipe: a request-phase selector + its tokens.
// The catch-all recipe has Selector.Always=true. Evaluated first-match-wins by the
// worker, exactly like the Go pipeline.
type KeyRecipe struct {
	Selector Scope      `json:"selector"`
	Tokens   []KeyToken `json:"tokens"`
}

// DeviceClassifier is the projected {device} User-Agent ruleset (D70): an ordered
// first-match-wins rule list + default class + optional folds. The worker ports the
// identical scan so the same User-Agent yields the same {device} bucket as the Go
// server's classify pre-pass.
type DeviceClassifier struct {
	Rules   []DeviceRule `json:"rules"`
	Default string       `json:"default"`
	Folds   []DeviceFold `json:"folds,omitempty"`
}

// DeviceRule is one UA→class rule: ANY of Substrings present (OR) AND NONE of Exclude
// present selects Class. Substrings/Exclude are already lower-cased; matching is
// case-insensitive (the worker lower-cases the UA once).
type DeviceRule struct {
	Class      string   `json:"class"`
	Substrings []string `json:"substrings"`
	Exclude    []string `json:"exclude,omitempty"`
}

// DeviceFold remaps a classified class onto another after rule matching (FROM->INTO).
type DeviceFold struct {
	From string `json:"from"`
	Into string `json:"into"`
}

// KeyToken is one cache-key component. Kind is the stable token name the JS
// interpreter switches on; Arg/Ref/Allow/Deny carry its parameters (Allow for the
// query_allow allowlist, Deny for the query_strip denylist). For "sticky", Arg is
// the site-level sticky cookie name the worker must read; for "header" it is the
// header name; for "tenant"/"literal" it is the constant text.
type KeyToken struct {
	Kind  string   `json:"kind"`
	Arg   string   `json:"arg,omitempty"`
	Ref   string   `json:"ref,omitempty"`
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// Response is the ORIGIN/store-phase projection.
type Response struct {
	TTL          []TTL     `json:"ttl,omitempty"`
	Storage      []Storage `json:"storage,omitempty"`
	StripCookies []Scope   `json:"stripCookies,omitempty"`
	HeaderResp   []Header  `json:"headerResp,omitempty"`
	CORS         *CORS     `json:"cors,omitempty"`

	// HasStripHeaders is true iff at least one cache_ttl rule declares StripHeaders
	// (the from_header-family control headers X-Cache-Ttl/Grace/Max-Stale it consumes).
	// It is a build-time hint so the worker can SKIP the deliver/store-phase evalResponse
	// walk + delete loop entirely on the common config that has no from_header rule —
	// the walk runs only when it can actually strip something. Derivable from
	// TTL[].StripHeaders; surfaced here so the runtime need not scan to learn it.
	HasStripHeaders bool `json:"hasStripHeaders,omitempty"`

	// Transforms is the ordered `replace OLD NEW` deliver-phase body-substitution
	// rule list (D75). Each is edge-native within TransformMaxBytes: the worker
	// applies the literal substitution post-cache, on delivery, to a within-cap body,
	// skipping Range/HEAD/already-encoded responses — mirroring the server's V2e
	// gating (internal/server/transform.go). A body LARGER than the cap passes through
	// UNTRANSFORMED (same as the server's large-object behavior, and a separate
	// permanent server-only non-goal for unbounded/streaming `replace`). Omitted when
	// the site declares no `replace`.
	Transforms []Transform `json:"transforms,omitempty"`

	// TransformMaxBytes is the body-size ceiling (bytes) for edge-native `replace`:
	// a response body at or below it is buffered and transformed; a larger one streams
	// through untransformed. Mirrors the server's maxTransformBody (1 MiB). Present
	// only when Transforms is non-empty (zero-cost-when-unused).
	TransformMaxBytes int64 `json:"transformMaxBytes,omitempty"`

	// OnError is the ordered `respond on_error [@scope] STATUS BODY` rule list (D57,
	// edge-native in D76). On an origin HARD-failure with NO servable cached object
	// (no fresh/grace copy and no stale copy within the max_stale window), the worker
	// serves the first matching synthetic (status + body + content_type) instead of a
	// bare 502 — mirroring the server precedence: serve-stale-within-grace/max_stale >
	// cacheable negative cache > respond on_error > bare 502. Omitted when the site
	// declares no `respond on_error`.
	OnError []OnError `json:"onError,omitempty"`
}

// Transform is one `replace OLD NEW` deliver-phase literal body substitution (D75).
// The worker applies these in order with String.replaceAll semantics (every
// occurrence of Old becomes New), identical to the server's applyReplacements.
type Transform struct {
	Scope Scope  `json:"scope"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// OnError is one `respond on_error [@scope] STATUS BODY` origin-error synthetic
// (D57/D76). Scope is the request-phase selector (Always for an unscoped rule);
// Status/Body/ContentType are fixed at compile. The worker serves the FIRST rule
// whose scope matches, on the outage path only.
type OnError struct {
	Scope       Scope  `json:"scope"`
	Status      int    `json:"status"`
	Body        string `json:"body"`
	ContentType string `json:"contentType"`
}

// TTL is a cache_ttl rule. SelKind is status_in|status_not_in|scope|default. TTL,
// Grace, HitForMiss are Go duration strings (e.g. "1m0s") so the JS side parses
// them with the same semantics.
type TTL struct {
	SelKind    string `json:"selKind"`
	Codes      []int  `json:"codes,omitempty"`
	Scope      *Scope `json:"scope,omitempty"`
	TTL        string `json:"ttl,omitempty"`
	Grace      string `json:"grace,omitempty"`
	HitForMiss string `json:"hitForMiss,omitempty"`
	IsHFM      bool   `json:"isHFM,omitempty"`
	// MaxStale is the max_stale (D60) window as a Go duration string: the additional
	// span beyond ttl+grace during which the edge may serve a stored copy ONLY as a
	// stale-on-error fallback (origin failed). "" => no error-fallback window; the edge
	// must NOT serve a copy older than ttl+grace. Bounds the worker's salvage path so
	// the edge stops serving unboundedly-old content (D70).
	MaxStale string `json:"maxStale,omitempty"`
	// FromHeader names an origin response header the edge reads the TTL from
	// (`cache_ttl from_header HEADER`); "" => the static TTL above. A bare integer
	// value is seconds (Cache-Control max-age style); a unit spelling is a cadish
	// duration. Absent/unparseable => the rule does not apply (fall through).
	FromHeader string `json:"fromHeader,omitempty"`
	// GraceFromHeader / MaxStaleFromHeader name origin response headers the edge reads
	// the grace / max_stale window from (`grace_from_header NAME` /
	// `max_stale_from_header NAME`); "" => the static Grace / MaxStale above. Same
	// parse convention as FromHeader; an absent/unparseable value falls back to the
	// literal (it does NOT make the rule fall through). The worker mirrors the server's
	// resolveGraceMaxStale, including the resolved max_stale >= grace clamp.
	GraceFromHeader    string `json:"graceFromHeader,omitempty"`
	MaxStaleFromHeader string `json:"maxStaleFromHeader,omitempty"`
	// RespHeader is an optional RESPONSE-phase `resp_header NAME VALUE` matcher ANDed in
	// front of the selector: the rule applies only when the origin response carries the
	// named header value AND the selector matches. nil for every non-resp_header rule. The
	// worker evaluates it first (selectorMatches), so Go and JS branch freshness on the
	// origin response identically (a conformance fixture asserts it).
	RespHeader *Matcher `json:"respHeader,omitempty"`
	// StripHeaders names the from_header-family control headers this rule CONSUMES from
	// the origin response (X-Cache-Ttl/X-Cache-Grace/X-Cache-Max-Stale). The worker
	// removes them before store + deliver, mirroring the server (handler.go), so the
	// internal origin↔cache contract never leaks to the client. Omitted for a plain rule.
	StripHeaders []string `json:"stripHeaders,omitempty"`
}

// Storage is a storage tier rule (ram|disk). The edge maps tiers to its own L1/L2
// policy later (the `edge {}` block); this preserves the server intent.
type Storage struct {
	SelKind    string   `json:"selKind"`
	Codes      []int    `json:"codes,omitempty"`
	Scope      *Scope   `json:"scope,omitempty"`
	Tier       string   `json:"tier"`
	RespHeader *Matcher `json:"respHeader,omitempty"` // optional response-phase resp_header AND-term (see TTL.RespHeader)
}

// CORS projects a `cors` directive.
type CORS struct {
	Scope           Scope    `json:"scope"`
	AllowAllOrigins bool     `json:"allowAllOrigins,omitempty"`
	Origins         []string `json:"origins,omitempty"`
	Methods         []string `json:"methods,omitempty"`
	Headers         []string `json:"headers,omitempty"`
}

// Deliver is the DELIVER-phase projection. Body transforms (`replace`) are NOT
// here — they are delegated; CacheStatusHeader is the `header +cache_status` target.
type Deliver struct {
	CacheStatusHeader string `json:"cacheStatusHeader,omitempty"`
	// CacheKeyHeader is the `header +cache_key NAME` target header name (""=none).
	// The worker computes the SAME 12-hex sha256 prefix over the cache key it builds
	// per request (or the raw key when CacheKeyRaw) and sets this header — Go↔JS
	// identical (a conformance fixture asserts it).
	CacheKeyHeader string `json:"cacheKeyHeader,omitempty"`
	// CacheKeyRaw selects the raw projected key string (the `raw` modifier) instead
	// of its hash for CacheKeyHeader.
	CacheKeyRaw bool `json:"cacheKeyRaw,omitempty"`
	// CacheAgeHeader is the `header +cache_age NAME` target header name (""=none).
	// The worker emits the object's age in whole seconds on a cache HIT (fresh or
	// stale), computed as Math.floor((now − storedAt) / 1000). OMITTED on MISS/bypass.
	// Additive v7 field (omitempty): a stale runtime ignoring it simply omits the
	// header (the pre-directive behavior — observability gap, not a correctness
	// regression), so IRVersion stays 7.
	CacheAgeHeader string `json:"cacheAgeHeader,omitempty"`
}

// Edge is the edge cache policy block: per-scope tier policies + a default tier
// (local | distribute | skip), plus the KV (L2) guardrails. Projected from the
// `edge {}` Cadishfile block.
type Edge struct {
	Policies []EdgePolicy `json:"policies,omitempty"`
	Default  string       `json:"default"` // local|distribute|skip

	// KVTTLSeconds caps KV retention (the KV `expirationTtl`) independently of the
	// object's ttl+grace. Zero => unset: KV retention defaults to ceil((ttl+grace)).
	// The runtime computes expirationTtl = clamp(ttl+grace, 60s, kv_ttl).
	KVTTLSeconds int `json:"kvTtlSeconds,omitempty"`
	// KVMaxBytes is the hard size bound for the KV tier: a response body larger than
	// this is written to L1 only, never KV (regardless of its distribute tier).
	// Defaults to 1 MiB; the runtime reads this value.
	KVMaxBytes int64 `json:"kvMaxBytes,omitempty"`
}

// EdgePolicy is one per-scope edge cache-tier policy.
type EdgePolicy struct {
	Scope Scope  `json:"scope"`
	Tier  string `json:"tier"` // local|distribute|skip
}

// Delegated records one non-edge-capable directive the worker must pass to the
// Cadish server behind, with a human reason and (when known) the scope it applies to.
type Delegated struct {
	Directive string `json:"directive"`
	Reason    string `json:"reason"`
	Scope     *Scope `json:"scope,omitempty"`
}

// CoverageReport summarizes what the projection covers edge-natively vs delegates.
// It is the edge equivalent of the `cadish check` report: `cadish edge build`
// prints it, and --strict fails when anything is delegated.
type CoverageReport struct {
	// EdgeNative is the count of edge-expressible directives projected into the IR.
	EdgeNative int `json:"edgeNative"`
	// Delegated is the count of directives recorded in EdgeIR.Delegate.
	Delegated int `json:"delegated"`
	// Items is the per-directive delegate detail (mirrors EdgeIR.Delegate).
	DelegatedItems []DelegatedItem `json:"delegatedItems,omitempty"`
	// Warnings are non-fatal advisories surfaced by `cadish edge build` (e.g. the KV
	// 25 MB hard-cap notice). They are visibility, not a gate, and never fail the
	// build — UNLESS they are also counted in SecurityGate/ValueExposed below, which
	// are gating signals that fail `--strict`.
	Warnings []string `json:"warnings,omitempty"`
	// SecurityGate is non-zero when the site configured a security gate
	// (allow/deny/block/rate_limit). Those rules are SERVER-ONLY and are NOT
	// projected into / enforced by the edge worker (Cloudflare's own layer must
	// enforce them). The projector also records a `security` entry in Delegate so the
	// gate is visible; this dedicated counter lets `--strict` fail loudly even if the
	// Delegate accounting ever changes. Fix A.
	SecurityGate int `json:"securityGate,omitempty"`
	// ValueExposed counts header/cookie matcher literal values that ship verbatim in
	// the IR to the PUBLIC worker bundle (a potential baked-in secret). It mirrors the
	// value-exposure warnings; `--strict` fails when it is non-zero so a CI pipeline
	// catches a secret in the bundle. Fix B.
	ValueExposed int `json:"valueExposed,omitempty"`
	// ForcedPass counts SELECTING directives (pass / route / redirect / cache_key selector or
	// token / cache_ttl / storage / edge-tier / upgrade) that could NOT be faithfully projected
	// because they reference a matcher the edge fails closed on (a ServerOnly Gateway/lb/`ip`
	// matcher, or an untranslatable RE2 regex), so the projector forced the SAFE fallback —
	// a site-wide fail-open `pass` (the edge caches nothing) or a delegated redirect chain.
	// The runtime direction is safe, but the operator's PRECISE intent is silently coarsened, so
	// `cadish edge build` fails NON-ZERO on a non-zero ForcedPass EVEN WITHOUT -strict (R02/R16) —
	// the operator must consciously keep that directive on the Cadish server behind, not discover
	// at runtime that their whole site is being passed. Distinct from Delegated (server-only
	// directives like rewrite/encode/purge/security that have no SELECTING/cache effect).
	ForcedPass int `json:"forcedPass,omitempty"`
	// RouteExcludable is the host+prefix CF route globs the edge worker would ONLY ever
	// `pass` and that no other edge directive touches (D105) — the set the deploy plane
	// would carve out of the worker route as origin-direct (no-worker) routes. It is
	// ALWAYS computed and reported (even when `edge { bypass_passes }` is off) so the
	// operator can review the opportunity; it is only PROJECTED into the IR (and turned
	// into real CF routes) when the toggle is on. Never a gate — exclusions are an
	// optimization, not a coverage gap, so they do not affect `-strict`.
	RouteExcludable []string `json:"routeExcludable,omitempty"`
	// RouteExcludableExplicit is the operator-DECLARED `edge { bypass PATTERN… }` set
	// (D105 explicit companion), host-crossed into CF route globs. Distinct from
	// RouteExcludable (the auto-derived set): these are taken at the operator's word (no
	// excludability gate) and are ALWAYS projected into the IR (declaring `bypass …` is
	// itself the opt-in). The coverage report prints them under the route-excludable
	// section marked `bypass` (vs `~` for auto-derived). Omitted when none are declared.
	RouteExcludableExplicit []string `json:"routeExcludableExplicit,omitempty"`
	// BypassOverlapWarnings are the loud advisories for an explicit `bypass` pattern that
	// OVERLAPS a path the edge would CACHE (a scoped cache_ttl/cache_key/storage rule): the
	// bypass forgoes POP caching for that path. Operator-declared ⇒ a WARNING, never a gate;
	// the pattern is still projected. Printed in the route-excludable section. Omitted when
	// no explicit bypass shadows a cached path.
	BypassOverlapWarnings []string `json:"bypassOverlapWarnings,omitempty"`
}

// AllRouteExcludable returns the EXACT-deduped union of EVERY no-script route the deploy
// plane could have created for this site under any `bypass_passes` toggle state — the
// auto-derived excludable set (RouteExcludable) AND the operator-declared
// `edge { bypass … }` set (RouteExcludableExplicit). `cadish edge disable` tears down
// this union so the kill switch fully reverts (F-D4).
//
// It deliberately does NOT cross-collapse the two sources (no coversGlob merge): `enable`
// projects ir.RouteExclusions = mergeRouteExclusions(auto, explicit), and with
// `bypass_passes` OFF the auto input is nil — so enable can create the NARROW explicit
// `/api/v2*` while disable's always-computed auto set contains the BROADER `/api/*`.
// A cross-collapse would drop `/api/v2*` under `/api/*` and leave the created route
// orphaned (F-D1-r2). Every pattern enable could emit is one of these exact strings
// (merge only ever substitutes a broader INPUT pattern), so the exact union is a
// superset of what was created; deploy.Disable matches by exact pattern, so any pattern
// here that was never created is a harmless no-op.
func (r CoverageReport) AllRouteExcludable() []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(r.RouteExcludable)+len(r.RouteExcludableExplicit))
	for _, s := range r.RouteExcludable {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range r.RouteExcludableExplicit {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// DelegatedItem is one entry in the coverage report's delegate list.
type DelegatedItem struct {
	Directive string `json:"directive"`
	Reason    string `json:"reason"`
}

// Project builds the EdgeIR + CoverageReport for a compiled pipeline. It never
// errors today (the pipeline is already valid), but returns an error to keep the
// contract stable for future validation (e.g. an IR size/cardinality ceiling).
func Project(p *pipeline.Pipeline) (EdgeIR, CoverageReport, error) {
	ir := EdgeIR{
		IRVersion:      IRVersion,
		Site:           Site{Hosts: p.EdgeHosts(), RedirectHosts: p.EdgeRedirectHosts(), CanonicalHost: p.EdgeCanonicalHost()},
		Upstream:       Upstream{To: p.EdgeDefaultUpstream()},
		Matchers:       projectMatchers(p.EdgeMatchers()),
		Edge:           projectEdge(p),
		CacheUnsafe:    p.EdgeCacheUnsafe(),
		KeyHeaderNames: p.EdgeKeyHeaderNames(),
		UsesGeo:        p.UsesGeoToken(),
	}
	if patterns, ok := p.EdgeCookieAllow(); ok {
		ir.CookieAllow, ir.CookieAllowSet = patterns, true
	}
	var rep CoverageReport

	// classifiers / normalizers / tenant.
	if cls := p.EdgeClassifiers(); len(cls) > 0 {
		ir.Classifiers = make(map[string]Classifier, len(cls))
		// BUG-2: merge the matchers synthesized for inline (unnamed) matchers in `when` rows
		// into the matcher map FIRST, under the synthetic names already placed in the rows'
		// Conj. Without this an inline classify matcher projects to an empty conj entry the
		// runtime can never satisfy (a silent no-op).
		for _, c := range cls {
			for sn, sm := range c.Synthetic {
				ir.Matchers[sn] = projectMatcher(sm)
			}
		}
		// Project each classifier's rows FAITHFULLY — EVERY row is kept (no row is ever
		// dropped). A row that requires a matcher the edge cannot evaluate (a ServerOnly
		// `ip`/`upstream_healthy` matcher, or an untranslatable RE2 regex) makes the WHOLE
		// classifier fail-closed via classifierRowsFailClosed/classifiersFailClosed (below), so
		// any recipe reading it fail-opens → delegates to the Cadish server behind. See the
		// withdrawn-P2 note above constantFalseAtEdgeKinds's removal: dropping an `ip` row was
		// unsound (the worker DOES see the real client IP, so a dropped public-CIDR row diverges
		// the edge from the server). Surviving rows' order + the default are preserved.
		for name, c := range cls {
			rows := make([]ClassifyRow, 0, len(c.Rows))
			for _, r := range c.Rows {
				rows = append(rows, ClassifyRow{Conj: r.Conj, Value: r.Value})
			}
			ir.Classifiers[name] = Classifier{Rows: rows, Default: c.Default, DerivesFrom: c.DerivesFrom, DerivesForward: c.DerivesForward}
		}
	}
	if norms := p.EdgeNormalizers(); len(norms) > 0 {
		ir.Normalizers = make(map[string]Normalizer, len(norms))
		for name, n := range norms {
			ir.Normalizers[name] = Normalizer{Source: n.Source, SourceName: n.SourceName, Map: n.Map, Default: n.Default}
		}
	}
	if tr, ok := p.EdgeTenantResolver(); ok {
		rules := make([]TenantMap, 0, len(tr.Rules))
		for _, r := range tr.Rules {
			rules = append(rules, TenantMap{Pattern: r.Pattern, Name: r.Name})
		}
		ir.Tenant = &Tenant{FromHeader: tr.FromHeader, Rules: rules, Default: tr.Default}
	}

	// {device} UA classifier (D70): projected only when the cache key uses the {device}
	// token, so a site that never keys on device ships no ruleset (zero-cost-when-unused).
	// The worker classifies the User-Agent natively from this ruleset — no header crutch.
	if dc, ok := p.EdgeDeviceClassifier(); ok {
		d := &DeviceClassifier{Default: dc.Default}
		for _, r := range dc.Rules {
			d.Rules = append(d.Rules, DeviceRule{Class: r.Class, Substrings: r.Substrings, Exclude: r.Exclude})
		}
		for _, f := range dc.Folds {
			d.Folds = append(d.Folds, DeviceFold{From: f.From, Into: f.Into})
		}
		ir.Device = d
	}

	// Finding 1: a `classify`-token matcher (`@gated classify {C}==v`) carries NO
	// ServerOnly/RegexUntranslatable flag of its own, but the classifier C it reads may
	// have a ROW whose AND-conjunction references a fail-closed matcher (an untranslatable
	// `(?U)`/`(?i:…)` regex, or a server-only Gateway/lb matcher). At the edge that row is
	// skipped by classifyResolve → the classifier silently returns its default where the Go
	// server (full RE2 / live lb state) would have matched the row → a scope gated on
	// `{C}==v` mis-decides. Compute a per-classifier fail-closed flag to a FIXPOINT (a
	// classifier is fail-closed if any row references a fail-closed matcher OR a fail-closed
	// classifier — covering nested classify indirection), then propagate it onto every
	// `classify` matcher that reads such a classifier so scopeFailsClosed (matcherFailsClosed)
	// treats it as fail-closed and the existing pass/cache_ttl/storage fail-open + redirect
	// delegation fire. A classifier whose rows are ALL edge-translatable is never marked, so
	// legit configs still ship native (no over-reaction). Done after the classifier merge so
	// synthesized inline matchers in `when` rows are covered.
	// clsFC is hoisted to function scope so the KEY projection (cache_key recipes +
	// tokens, Findings 1 & 2) can consult the SAME classifier fail-closed fixpoint the
	// matcher pass uses — a `classify` cache-key TOKEN reading a fail-closed classifier
	// must fail-open exactly like a directive SCOPE gated on such a classifier. nil when
	// the site has no classifiers (a nil-map lookup is false, so the guards no-op).
	var clsFC map[string]bool
	if len(ir.Classifiers) > 0 {
		clsFC = classifiersFailClosed(ir.Classifiers, ir.Matchers)
		for name, m := range ir.Matchers {
			if m.Kind == "classify" && clsFC[m.ClassifyToken] {
				m.failsClosed = true
				ir.Matchers[name] = m
			}
		}
	}

	// BUG-1: a path_regex/host_regex matcher (named OR synthesized for an inline
	// classify row) whose RE2 source has no faithful JS equivalent was stripped +
	// marked RegexUntranslatable in projectMatcher. The runtime fails it closed (never
	// crashes), but a directive that relies on it would silently change meaning — so
	// delegate it loudly. Done AFTER the classifier merge so synthesized inline regex
	// matchers are covered too. Sorted for deterministic output.
	{
		var untName []string
		for name, m := range ir.Matchers {
			if m.RegexUntranslatable {
				untName = append(untName, name)
			}
		}
		sort.Strings(untName)
		for _, name := range untName {
			d := Delegated{Directive: ir.Matchers[name].Kind, Reason: "matcher @" + name + " uses a RE2 regex construct with no faithful JavaScript RegExp equivalent (e.g. ungreedy `(?U)`, a scoped `(?i:…)` group, or a mid-pattern inline flag); it is failed-closed at the edge, so any directive matching on it must run on the Cadish server behind"}
			ir.Delegate = append(ir.Delegate, d)
			addDelegate(&rep, d)
			rep.Warnings = append(rep.Warnings, "REGEX: matcher @"+name+" cannot be faithfully compiled by the edge worker's RegExp; it is delegated (fails closed at the edge). Keep its directive(s) on the Cadish server behind.")
		}
	}

	// Fix #4: a slice-2 Gateway matcher (`all` AND-composite, `query` value test) has no
	// JavaScript runtime case. A directive matching on one would silently change meaning
	// at the edge, so delegate it loudly (fail-closed) to the Cadish server behind —
	// mirroring the RegexUntranslatable handling above. This keeps `cadish edge build
	// -strict` tripping (a coverage regression) rather than shipping a broken matcher.
	{
		var soName []string
		for name, m := range ir.Matchers {
			if m.ServerOnly {
				soName = append(soName, name)
			}
		}
		sort.Strings(soName)
		for _, name := range soName {
			kind := ir.Matchers[name].Kind
			d := Delegated{Directive: kind, Reason: "matcher @" + name + " uses the `" + kind + "` matcher (a server-side Gateway matcher with no edge JavaScript runtime case); it is failed-closed at the edge, so any directive matching on it must run on the Cadish server behind"}
			ir.Delegate = append(ir.Delegate, d)
			addDelegate(&rep, d)
			rep.Warnings = append(rep.Warnings, "SERVER-ONLY: matcher @"+name+" (`"+kind+"`) has no edge runtime; it is delegated (fails closed at the edge). Keep its directive(s) on the Cadish server behind.")
		}
	}

	// RECV.
	// failOpenPass trips when a scoped pass / cache_ttl / storage / upgrade rule
	// references a matcher the edge fails CLOSED on (scopeFailsClosed). The edge then
	// CANNOT identify which requests the scope selects, so it cannot reproduce the
	// server's per-path pass/no-cache decision. The only SAFE representable choice — the
	// edge is an additive tier and must NEVER cache a request the server passes/treats
	// specially — is to fail OPEN: pass the WHOLE site unconditionally (one Always pass,
	// appended once below). The edge then over-passes (caches less) but never caches
	// wrong. Findings 2 & 3.
	failOpenPass := false
	for _, sc := range p.EdgePassRules() {
		s := projectScope(sc)
		if fc, _ := directiveScopeOrTokensFailClosed(s, nil, ir.Matchers, clsFC); fc {
			// The pass scope fails closed at the edge: without protection the edge would NOT
			// bypass the cache for the operator-marked never-cache path and could store +
			// serve it cross-user. Fail open (site-wide pass) instead. Finding 2.
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "PASS-FAIL-OPEN: a `pass` scope references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); the edge passes ALL traffic for this site rather than risk caching a passed path. `cadish edge build` fails (non-zero) — keep this `pass` on the Cadish server behind.")
			continue
		}
		ir.Recv.Pass = append(ir.Recv.Pass, s)
		rep.EdgeNative++
	}
	// cache_credentialed (D101): origin-authoritative scopes. Route each through the SAME
	// fail-closed chokepoint as pass/cache_ttl/storage: a scope referencing a ServerOnly or
	// untranslatable matcher CANNOT be evaluated at the edge, so the worker could neither
	// reproduce the credential-bypass opt-out nor apply the in-scope store precedence — it
	// would silently diverge from the server (e.g. credential-bypass a request the server
	// origin-authoritatively caches, or vice-versa). The only SAFE choice is to fail OPEN:
	// pass the WHOLE site (one Always pass, appended once below) so EVERY request reaches the
	// Cadish server behind, which has the full matcher set — and bump ForcedPass so `cadish
	// edge build` fails loud (non-zero). A translatable scope is projected so the worker
	// applies the identical origin-authoritative precedence.
	for _, sc := range p.EdgeCredentialedRules() {
		s := projectScope(sc)
		if fc, _ := directiveScopeOrTokensFailClosed(s, nil, ir.Matchers, clsFC); fc {
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "CACHE-CREDENTIALED-FAIL-OPEN: a `cache_credentialed` scope references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); the edge passes ALL traffic for this site rather than risk diverging from the server's origin-authoritative cache decision. `cadish edge build` fails (non-zero) — keep this `cache_credentialed` on the Cadish server behind.")
			continue
		}
		ir.CacheCredentialed = append(ir.CacheCredentialed, s)
		rep.EdgeNative++
	}
	for _, r := range p.EdgeRespondRules() {
		ir.Recv.Respond = append(ir.Recv.Respond, Respond{Path: r.Path, Status: r.Status, Body: r.Body})
		rep.EdgeNative++
	}
	// E2: the scoped `respond @scope STATUS BODY` form (e.g. an ingress terminal
	// no-match 404, or `respond @down 200 "OK"`) is NOT an exact-path edge respond, so
	// EdgeRespondRules skips it. Record one Delegate per skipped rule so it stays in the
	// coverage report and trips `-strict` — never silently dropped from the IR.
	for i := 0; i < p.EdgeScopedRespondCount(); i++ {
		d := Delegated{Directive: "respond", Reason: "a scoped `respond @scope STATUS BODY` matches on a request-matcher conjunction, not an exact path; the edge IR models only exact-path responds, so it runs on the Cadish server behind (the edge defers to origin for the uncovered path)"}
		ir.Delegate = append(ir.Delegate, d)
		addDelegate(&rep, d)
	}
	// redirectDelegated trips the first time any redirect rule is delegated. After
	// that, EVERY later redirect rule (in source order) is also delegated rather than
	// appended natively (Finding 5): `redirect` is first-match-wins, so if an earlier
	// rule runs on the server behind, the edge must NOT terminally answer a request
	// whose true first match is that delegated rule — it would silently wrong-redirect.
	redirectDelegated := false
	for _, r := range p.EdgeRedirectRules() {
		if redirectDelegated {
			d := Delegated{Directive: "redirect", Reason: "a preceding redirect rule is delegated to the Cadish server behind; to preserve `redirect` first-match-wins semantics this later rule is also delegated, so the edge never terminally answers a request whose true first match runs on the server (additive-tier limitation)"}
			ir.Delegate = append(ir.Delegate, d)
			addDelegate(&rep, d)
			continue
		}
		er := Redirect{Status: r.Status, Target: r.Target, NoStore: r.NoStore}
		// Scope selector (scope-only or the combined scope+regex form).
		if r.HasScope {
			s := projectScope(r.Scope)
			// Finding 1: if the redirect's SCOPE references a matcher the edge fails closed on
			// (a server-only matcher or an untranslatable regex), the scope never matches at
			// the edge — so this redirect silently never fires and a LATER redirect wrongly
			// becomes the edge's first match, while the Go server (full matcher set,
			// first-match-wins) picks THIS one. Treat it exactly like an untranslatable OWN
			// regex: delegate this redirect AND, via redirectDelegated, every later one — so
			// the edge defers the whole chain from here to the Cadish server behind, which
			// produces the correct first-match redirect.
			if fc, _ := directiveScopeOrTokensFailClosed(s, nil, ir.Matchers, clsFC); fc {
				d := Delegated{Directive: "redirect", Reason: "redirect scope references a matcher the edge cannot evaluate (a server-only Gateway/lb matcher or an untranslatable RE2 regex such as `(?U)`/`(?i:…)`); it fails CLOSED at the edge, so a later redirect would wrongly become the first match — the redirect chain from here is delegated to the Cadish server behind to preserve first-match-wins"}
				ir.Delegate = append(ir.Delegate, d)
				addDelegate(&rep, d)
				rep.ForcedPass++ // a redirect SCOPE referencing a fail-closed matcher → delegated chain (R16)
				redirectDelegated = true
				continue
			}
			er.Scope = &s
		}
		// Path-regex selector (regex-only or the combined form). BUG-1: a regex
		// redirect (e.g. `redirect (?i)^/cams/?$ …`) carries the raw RE2 source — lift
		// inline flags so the worker compiles `new RegExp(regex, flags)`.
		if r.Regex != "" {
			pat, flags, ok := splitRE2Flags(r.Regex)
			if !ok {
				// Untranslatable RE2 construct: never ship a pattern that crashes/mismatches.
				// Delegate the whole redirect (loud) — including the combined form — to the
				// Cadish server behind, which has full RE2.
				d := Delegated{Directive: "redirect", Reason: "redirect regex uses a RE2 construct with no faithful JavaScript RegExp equivalent (e.g. ungreedy `(?U)`, a scoped `(?i:…)` group, or a mid-pattern inline flag); delegated to the Cadish server behind so the edge never ships a crashing or divergent pattern"}
				ir.Delegate = append(ir.Delegate, d)
				addDelegate(&rep, d)
				rep.ForcedPass++ // a redirect's OWN untranslatable RE2 regex → delegated chain (R16), same as the scope-fail-closed branch above
				redirectDelegated = true
				continue
			}
			er.Regex = pat
			er.RegexFlags = flags
		}
		ir.Recv.Redirect = append(ir.Recv.Redirect, er)
		rep.EdgeNative++
	}
	// SECURITY (D34): every `purge` is delegated to the Cadish server behind, and the
	// names of matchers reachable from a purge guard are collected so their secret
	// values are redacted from the IR below. The purge guard compares a SECRET token
	// (the documented form is `purge when header X-Purge-Token {$PURGE_TOKEN}`, D12);
	// after `{$ENV}` substitution that literal lives in the compiled matcher. A public
	// edge worker must never hold or ship that token — and it could not perform the
	// constant-time compare safely anyway — so the whole directive (single-key AND
	// regex BAN) is passed to the server behind, which holds the secret and does the
	// `crypto/subtle` compare. This closes the purge-token-leaks-to-the-edge finding.
	// The SECURITY GATE (allow/deny/block/rate_limit) is SERVER-ONLY: it is never
	// projected into the worker IR, so enabling the edge for a site with a gate would
	// SILENTLY turn that ACL into a no-op for all edge-served traffic. Refuse to do so
	// quietly: record the gate as a delegated `security` directive (so `--strict`
	// trips, like a coverage regression) and emit a LOUD warning naming the rules as
	// unenforced at the edge — Cloudflare's own security layer must enforce them. Fix A.
	if p.UsesSecurityGate() {
		d := Delegated{
			Directive: "security",
			Reason:    "allow/deny/block/rate_limit are SERVER-ONLY and are NOT enforced at the edge; the worker cannot run the security gate, so these rules must be enforced by Cloudflare's own security layer (WAF/rules) in front of the worker",
		}
		ir.Delegate = append(ir.Delegate, d)
		addDelegate(&rep, d)
		rep.SecurityGate++
		rep.Warnings = append(rep.Warnings,
			"SECURITY: this site's allow/deny/block/rate_limit rules are NOT enforced at the edge — the worker has no security gate. Enforce them with Cloudflare's own security layer (WAF/firewall rules) in front of the worker, or the ACL is a no-op for all edge-served traffic. `cadish edge build -strict` fails while a security gate is present.")
	}
	guardMatcherNames := map[string]bool{}
	for _, r := range p.EdgePurgeRules() {
		reason := "purge auth guards compare a SECRET token (the purge token, D12) that must never ship to a public edge worker; delegated to the Cadish server behind, which holds the secret and does the constant-time compare"
		if isRegexBan(r.RegexToken) {
			reason = "regex BAN purge (cache-wide eviction) is not edge-expressible, and its auth guard compares a SECRET token that must never ship to a public edge worker; delegated to the Cadish server behind"
		}
		d := Delegated{Directive: "purge", Reason: reason}
		// Redact the guard scope: inline (anonymous) matcher values are stripped so a
		// `purge when header X-Purge-Token <token>` never carries the token into the IR.
		g := redactScope(projectScope(r.Guard))
		d.Scope = &g
		ir.Delegate = append(ir.Delegate, d)
		addDelegate(&rep, d)
		for _, n := range r.Guard.Names {
			guardMatcherNames[n] = true
		}
	}
	// Redact named matchers reachable from a purge guard (`purge when @tok`): their
	// value lives in ir.Matchers and would otherwise leak even though the guard scope
	// itself only references them by name.
	for name := range guardMatcherNames {
		if m, ok := ir.Matchers[name]; ok {
			ir.Matchers[name] = redactMatcher(m)
		}
	}
	for _, r := range p.EdgeRouteRules() {
		s := projectScope(r.Scope)
		// AUDIT (same fail-closed class as the findings): `route @scope upstream` is
		// first-match-wins (resolveUpstream). A route whose SCOPE fails closed at the edge
		// never matches there → the edge skips it and resolves a LATER route or the default
		// upstream → it fetches from the WRONG origin and CACHES that body under the key,
		// while the Go server (full matcher set) routes to the scoped upstream → cross-origin
		// cache poisoning. Route the scope through the SAME guard and fail OPEN (site-wide
		// pass) so the edge never CACHES a wrong-origin body it cannot route. (The implied
		// pass still fetches via resolveUpstream, so a passed request may proxy the default
		// origin — an additive-tier limitation shared with the pass/upgrade fail-open — but it
		// is never stored/served cross-variant, preserving the edge's "never cache wrong" invariant.)
		if fc, _ := directiveScopeOrTokensFailClosed(s, nil, ir.Matchers, clsFC); fc {
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "ROUTE-FAIL-OPEN: a `route` scope references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); the edge cannot reproduce the upstream selection, so it passes ALL traffic for this site rather than cache a wrong-origin body. `cadish edge build` fails (non-zero) — keep this `route` on the Cadish server behind.")
			continue
		}
		ir.Recv.Route = append(ir.Recv.Route, Route{Scope: s, Upstream: r.Upstream})
		rep.EdgeNative++
	}
	for _, h := range p.EdgeReqHeaderRules() {
		ir.Recv.HeaderReq = append(ir.Recv.HeaderReq, projectHeader(h))
		rep.EdgeNative++
	}

	// KEY. The `{sticky}` token resolves against the SITE-level sticky cookie name
	// (not carried on the token), so surface it in Arg — otherwise the JS interpreter
	// has no cookie name to read and the edge cache key silently diverges from the
	// server's. Other tokens carry their own Arg/Ref/Allow.
	stickyCookie := p.EdgeStickyCookie()
	projectToken := func(tk pipeline.EdgeKeyToken) KeyToken {
		kt := KeyToken{Kind: tk.Kind, Arg: tk.Arg, Ref: tk.Ref, Allow: tk.Allow, Deny: tk.Deny}
		if tk.Kind == "sticky" {
			kt.Arg = stickyCookie
		}
		return kt
	}
	// Catch-all (default/unscoped) recipe: kept as Key.Tokens for backward compatibility
	// and as the worker's fallback when there are no scoped recipes.
	var defaultKeyTokens []KeyToken // nil-preserving (an empty cache_key marshals to null, as before)
	for _, tk := range p.EdgeKeyTokens() {
		defaultKeyTokens = append(defaultKeyTokens, projectToken(tk))
	}
	// Finding 2: if the default recipe reads a `classify {C}` TOKEN whose classifier the
	// edge fails closed on (clsFC), the edge resolves that token to the classifier DEFAULT
	// while the Go server returns the matched row → a divergent key COMPONENT → the edge
	// would store one variant and serve it cross-variant. Fail OPEN (the trailing site-wide
	// pass) rather than ship a divergently-keyed default — mirroring cache_ttl/storage.
	if fc, cls := directiveScopeOrTokensFailClosed(Scope{Always: true}, defaultKeyTokens, ir.Matchers, clsFC); fc {
		failOpenPass = true
		rep.ForcedPass++
		rep.Warnings = append(rep.Warnings, "CACHE_KEY-FAIL-OPEN: the default `cache_key` reads a `classify {"+cls+"}` token whose classifier references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); rather than key on the classifier's edge DEFAULT (a divergent key → cross-variant serving), the edge passes ALL traffic for this site. `cadish edge build` fails (non-zero) — keep the precise key on the Cadish server behind.")
	} else {
		ir.Key.Tokens = defaultKeyTokens
	}
	// Scoped cache_key v2 (D70): project the FULL ordered recipe list + selectors so the
	// worker evaluates the SAME first-match-wins selection the Go pipeline does
	// (selectKeyTokens). This makes a scoped cache_key site edge-native — no longer
	// delegated. Each selector here is request-phase (compile rejects response-phase),
	// so every matcher it references is already projected for the worker. A
	// single-unscoped-recipe site projects one Always recipe identical to Key.Tokens.
	for _, rc := range p.EdgeKeyRecipes() {
		kr := KeyRecipe{Selector: projectScope(rc.Selector)}
		for _, tk := range rc.Tokens {
			kr.Tokens = append(kr.Tokens, projectToken(tk))
		}
		// Findings 1 & 2: a non-catch-all recipe whose SELECTOR fails closed at the edge never
		// matches there → selectKeyTokens falls through to a later/catch-all recipe → a
		// DIFFERENT key than Go (full matcher set, first-match-wins); and a recipe whose TOKENS
		// read a fail-closed classifier resolves to the classifier DEFAULT at the edge → again a
		// divergent key component. Either way the edge would store one variant and serve it
		// cross-variant, so do NOT ship the recipe; fail OPEN (the trailing site-wide pass) — the
		// precise scoped key still runs on the Cadish server behind. Same guard as cache_ttl/storage.
		if fc, cls := directiveScopeOrTokensFailClosed(kr.Selector, kr.Tokens, ir.Matchers, clsFC); fc {
			failOpenPass = true
			rep.ForcedPass++
			reason := "references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex such as `(?U)`/`(?i:…)`)"
			if cls != "" {
				reason = "reads a `classify {" + cls + "}` token whose classifier the edge cannot faithfully resolve (a row references a server-only or untranslatable matcher)"
			}
			rep.Warnings = append(rep.Warnings, "CACHE_KEY-FAIL-OPEN: a scoped `cache_key` recipe "+reason+"; rather than key on a divergent fallback recipe (→ cross-variant serving), the edge passes ALL traffic for this site. The precise scoped key still runs on the Cadish server behind.")
			continue
		}
		ir.Key.Recipes = append(ir.Key.Recipes, kr)
	}
	rep.EdgeNative++ // the cache_key (incl. all scoped recipes) as one edge-native directive

	// RESPONSE/store.
	for _, r := range p.EdgeTTLRules() {
		// Finding 2: a SCOPED cache_ttl rule whose scope references a matcher the edge fails
		// closed on never matches at the edge, so the edge silently falls through to the
		// `default` rule — caching the path with a DIFFERENT (typically longer) TTL than the
		// server's scoped rule intended. Do not emit such a rule (it cannot be honored), and
		// fail OPEN to non-caching (site-wide pass) so the edge never caches a fail-closed
		// path differently than the server.
		if fc, _ := directiveScopeOrTokensFailClosed(projectScope(r.Scope), nil, ir.Matchers, clsFC); r.SelKind == "scope" && fc {
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "CACHE_TTL-FAIL-OPEN: a scoped `cache_ttl` references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); rather than silently apply the `default` TTL, the edge passes ALL traffic for this site (caches nothing) so it never caches a path longer/differently than the server intended. `cadish edge build` fails (non-zero) — keep the scoped TTL on the Cadish server behind.")
			continue
		}
		t := projectTTL(r)
		if len(t.StripHeaders) > 0 {
			// At least one cache_ttl rule consumes from_header control headers; arm the
			// build-time hint so the worker runs the strip walk (Finding 5).
			ir.Response.HasStripHeaders = true
		}
		ir.Response.TTL = append(ir.Response.TTL, t)
		rep.EdgeNative++
	}
	for _, r := range p.EdgeStorageRules() {
		// Finding 2: like cache_ttl, a SCOPED storage rule whose scope fails closed at the
		// edge silently falls through to the `default` tier — storing the path in a
		// different tier than the server's scoped rule intended. Do not emit it; fail OPEN
		// to non-caching (site-wide pass) so the edge never caches it under the wrong tier.
		if fc, _ := directiveScopeOrTokensFailClosed(projectScope(r.Scope), nil, ir.Matchers, clsFC); r.SelKind == "scope" && fc {
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "STORAGE-FAIL-OPEN: a scoped `storage` references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); rather than silently apply the `default` tier, the edge passes ALL traffic for this site (caches nothing). `cadish edge build` fails (non-zero) — keep the scoped storage tier on the Cadish server behind.")
			continue
		}
		ir.Response.Storage = append(ir.Response.Storage, projectStorage(r))
		rep.EdgeNative++
	}

	// EDGE TIER POLICY — the LAST store-decision surface. The `edge {}` block's per-scope
	// `local | distribute | skip @scope` policies tell the worker which tier (or none, for
	// `skip`) to store an object in. A policy whose scope references a matcher the edge fails
	// CLOSED on cannot be evaluated by resolveEdgeTier, which then falls the request to the
	// `default` tier — caching a `skip @x` path the operator marked never-cache-at-edge, or
	// mis-tiering a `local`/`distribute` object into the default tier. Route EVERY policy
	// scope through the SAME fail-closed chokepoint as `storage` (just above): on a trip, drop
	// the policy and fail OPEN to non-caching (site-wide pass) so the `skip` is honored and the
	// edge never stores an object it cannot correctly tier. A fully edge-translatable scope
	// still projects native (no over-reaction). The scoped tier policy still runs on the
	// Cadish server behind. All three tiers fail open identically — mirroring `storage`, which
	// already fails open on ANY scoped tier it cannot evaluate (an unevaluatable scope is just
	// as unsafe for `local`/`distribute` mis-tiering as it is for `skip`).
	for _, pol := range p.EdgeTierPolicies() {
		s := projectScope(pol.Scope)
		if fc, _ := directiveScopeOrTokensFailClosed(s, nil, ir.Matchers, clsFC); fc {
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "EDGE-TIER-FAIL-OPEN: an `edge {"+pol.Tier+" @…}` tier policy references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); rather than fall the path to the `default` tier (caching a `skip` path or mis-tiering a local/distribute object), the edge passes ALL traffic for this site (caches nothing). `cadish edge build` fails (non-zero) — keep the scoped edge tier policy on the Cadish server behind.")
			continue
		}
		ir.Edge.Policies = append(ir.Edge.Policies, EdgePolicy{Scope: s, Tier: pol.Tier})
	}

	for _, sc := range p.EdgeStripRules() {
		ir.Response.StripCookies = append(ir.Response.StripCookies, projectScope(sc))
		rep.EdgeNative++
	}
	if c, ok := p.EdgeCORSRule(); ok {
		ir.Response.CORS = &CORS{
			Scope:           projectScope(c.Scope),
			AllowAllOrigins: c.AllowAllOrigins,
			Origins:         c.Origins,
			Methods:         c.Methods,
			Headers:         c.Headers,
		}
		rep.EdgeNative++
	}

	// DELIVER. Response-phase header ops live in headerResp; the cache-status target
	// is surfaced separately for the worker's X-Cache write.
	for _, h := range p.EdgeRespHeaderRules() {
		ir.Response.HeaderResp = append(ir.Response.HeaderResp, projectHeader(h))
		rep.EdgeNative++
		for _, op := range h.Ops {
			if op.Op == "cache_status" {
				ir.Deliver.CacheStatusHeader = op.Name
			}
			if op.Op == "cache_key" {
				ir.Deliver.CacheKeyHeader = op.Name
				ir.Deliver.CacheKeyRaw = op.Value == "raw"
			}
			if op.Op == "cache_age" {
				ir.Deliver.CacheAgeHeader = op.Name
			}
		}
	}

	// `replace` body transforms are EDGE-NATIVE within the worker's body-size cap (D75):
	// project the ordered rule list + the size cap so the worker applies the SAME literal
	// substitution the server does, post-cache, on delivery, to a within-cap body
	// (skipping Range/HEAD/encoded — the worker mirrors the server's V2e gating). A body
	// LARGER than the cap passes through untransformed at the edge, exactly as the server
	// streams a large body untransformed — that over-cap/streaming case remains a
	// permanent server-only non-goal (docs/edge.md). So there is no `replace` delegation
	// anymore; the over-cap path is a runtime pass-through, not a coverage gap.
	if trs := p.EdgeTransformRules(); len(trs) > 0 {
		for _, tr := range trs {
			ir.Response.Transforms = append(ir.Response.Transforms, Transform{Scope: projectScope(tr.Scope), Old: tr.Old, New: tr.New})
			rep.EdgeNative++
		}
		ir.Response.TransformMaxBytes = pipeline.EdgeTransformMaxBytes
	}

	// `respond on_error` is EDGE-NATIVE for the outage path (D76): project the ordered
	// synthetic list (scope + status + body + content_type) so the worker serves the
	// configured synthetic on an origin HARD-failure with no servable cached object —
	// instead of a bare 502 — mirroring the server precedence (serve-stale-within-grace/
	// max_stale > cacheable negative cache > respond on_error > 502). No delegation.
	for _, r := range p.EdgeOnErrorRules() {
		ir.Response.OnError = append(ir.Response.OnError, OnError{
			Scope:       projectScope(r.Scope),
			Status:      r.Status,
			Body:        r.Body,
			ContentType: r.ContentType,
		})
		rep.EdgeNative++
	}

	// `rewrite` and `encode` are server-only in edge v1: they are compiled but not
	// projected to a native edge behavior. Record them as delegated so the coverage
	// report and `--strict` surface them — the projector's "never silently dropped"
	// contract (edgeir.go top). They run on the Cadish server the worker fronts.
	for _, sc := range p.EdgeRewriteScopes() {
		d := Delegated{Directive: "rewrite", Reason: "origin-request URL rewrite (rewrite) is not edge-native in v1; the Cadish server behind applies it before the origin fetch"}
		s := projectScope(sc)
		d.Scope = &s
		ir.Delegate = append(ir.Delegate, d)
		addDelegate(&rep, d)
	}
	if p.EdgeHasEncode() {
		d := Delegated{Directive: "encode", Reason: "on-the-fly response compression (encode) is not edge-native in v1; Cloudflare compresses at its own edge and the Cadish server applies encode for origin fetches"}
		ir.Delegate = append(ir.Delegate, d)
		addDelegate(&rep, d)
	}
	// `upgrade @scope` is inherently server-only: it hosts a live, hijacked
	// connection-upgrade (WebSocket) tunnel to the origin, which a stateless edge
	// worker cannot hold open. Record one Delegate per rule so it surfaces in the
	// coverage report and trips `--strict` — never silently dropped.
	for _, sc := range p.EdgeUpgradeScopes() {
		d := Delegated{Directive: "upgrade", Reason: "a connection-upgrade (WebSocket / Connection: Upgrade) passthrough tunnel is a live, hijacked bidirectional connection the Cadish server holds open; an edge worker cannot host it, so an upgrade route runs on the Cadish server behind"}
		s := projectScope(sc)
		d.Scope = &s
		ir.Delegate = append(ir.Delegate, d)
		addDelegate(&rep, d)
		// Finding 3: `upgrade @scope` IMPLIES pass on the server for EVERY matching request
		// (the whole upgrade scope is uncacheable; only a genuine upgrade tunnels). The
		// connection hijack is delegated above, but the implied PASS must also reach the
		// edge — otherwise a cookieless cacheable GET to an upgrade-scope path is STORED +
		// served cross-user at the edge while the server passes it. Project the scope into
		// recv.pass so the edge reproduces the server's "whole upgrade scope is uncacheable".
		// If the upgrade scope itself fails closed at the edge, fall back to the Finding-2
		// site-wide fail-open pass (the edge cannot evaluate the scope, so it cannot pass
		// only that path).
		if fc, _ := directiveScopeOrTokensFailClosed(s, nil, ir.Matchers, clsFC); fc {
			failOpenPass = true
			rep.ForcedPass++
			rep.Warnings = append(rep.Warnings, "UPGRADE-FAIL-OPEN: an `upgrade` scope references a matcher the edge cannot evaluate (a server-only Gateway/lb/`ip` matcher or an untranslatable RE2 regex); the edge passes ALL traffic for this site so it never caches an upgrade-scope path the server passes. `cadish edge build` fails (non-zero) — keep the `upgrade` route on the Cadish server behind.")
		} else {
			ir.Recv.Pass = append(ir.Recv.Pass, s)
		}
	}

	// Finding 2/3 fail-open: if any scoped pass / cache_ttl / storage / upgrade rule
	// referenced a matcher the edge fails closed on, append ONE unconditional pass so the
	// edge bypasses the cache for the whole site rather than cache a request the server
	// would pass / treat under a rule the edge cannot evaluate. Appended once (idempotent)
	// regardless of how many rules tripped it.
	if failOpenPass {
		ir.Recv.Pass = append(ir.Recv.Pass, Scope{Always: true})
		rep.EdgeNative++
	}

	// Visibility (D34): warn about every header/cookie matcher whose literal VALUE
	// still ships in the IR to the public edge worker — a potential secret the
	// operator should review (the purge token is auto-redacted above; other guards a
	// human wrote with a literal token are NOT auto-detectable, so they are surfaced).
	exposeWarns := valueExposureWarnings(ir)
	rep.Warnings = append(rep.Warnings, exposeWarns...)
	rep.ValueExposed += len(exposeWarns)

	// Env-secret leak guard (security completeness): an UNQUOTED `{$VAR}` placeholder is
	// env-expanded to its literal value BEFORE projection (cli/edge.go SubstituteEnv), so
	// a secret baked into a header value, a `replace` transform, a `respond on_error`
	// body, a `redirect` target, or a cache_key `literal:` token would otherwise ship to
	// the public worker with no advisory — and `cadish edge build -strict` would PASS. The
	// matcher pass above flags ANY literal value; for these non-matcher string fields we
	// scan ONLY for an env-expanded value (a value equal to a non-empty process-env value)
	// so a quoted `"{$VAR}"` (which stays the literal text `{$VAR}` and ships no secret)
	// and an ordinary non-secret literal (e.g. `X-Frame-Options DENY`) do NOT falsely warn.
	envWarns := envValueExposureWarnings(ir)
	rep.Warnings = append(rep.Warnings, envWarns...)
	rep.ValueExposed += len(envWarns)

	// KV size-bound sanity: a `kv_max_bytes` above Workers KV's 25 MB hard cap can
	// never take effect (the put would be rejected). Surface it — advisory only.
	if ir.Edge.KVMaxBytes > kvHardCapBytes {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"edge kv_max_bytes (%d bytes) exceeds the Workers KV 25 MB hard cap — objects that large can never enter KV; lower it",
			ir.Edge.KVMaxBytes))
	}

	// ROUTE EXCLUSIONS (D105): derive the host+prefix CF route globs the worker would
	// ONLY ever `pass` (a path-only unconditional pass with NO other edge directive
	// touching the path). Always report the excludable set so the operator can review it;
	// only project it into the IR (→ real no-worker CF routes on Enable) when the site
	// opted in with `edge { bypass_passes }`. Strict + fail-safe (computeRouteExclusions):
	// when in doubt it excludes nothing — a wrong exclusion would silently strip edge
	// behaviour from a path that needed it.
	routes := edgeDeployRoutes(p)
	excludable := computeRouteExclusions(ir, routes)
	rep.RouteExcludable = excludable

	// EXPLICIT route exclusions (D105 companion): the operator-declared `edge { bypass
	// PATTERN… }` set. Taken at the operator's word (no excludability gate), host-crossed,
	// and ALWAYS projected into the IR — declaring `bypass …` is itself the opt-in (it does
	// NOT require `bypass_passes`). The overlap WARNING (a bypass shadowing a cached path)
	// is advisory only; the pattern is still included.
	explicit, overlapWarn := computeExplicitExclusions(p, ir, routes)
	rep.RouteExcludableExplicit = explicit
	rep.BypassOverlapWarnings = overlapWarn

	// IR projection: the auto-derived set only under the `bypass_passes` toggle, the
	// explicit set always; dedup/collapse the union (an explicit `/v3*` subsumes an auto
	// `/v3/x*` and vice-versa) so the deploy plane gets one clean carve-out set.
	var auto []string
	if p.EdgeBypassPasses() {
		auto = excludable
	}
	ir.RouteExclusions = mergeRouteExclusions(auto, explicit)

	return ir, rep, nil
}

// redactMatcher strips the literal VALUES from a header/cookie/set_cookie matcher
// (a purge-guard secret) while keeping its kind/name for the coverage report. Other
// matcher kinds are returned unchanged.
func redactMatcher(m Matcher) Matcher {
	switch m.Kind {
	case "header", "cookie":
		m.Values = nil
	case "set_cookie":
		m.CookieNames = nil
	}
	m.Redacted = true
	return m
}

// redactScope redacts every inline (anonymous) matcher value in a scope. Named refs
// are redacted at the ir.Matchers level (they have no value inline here).
func redactScope(s Scope) Scope {
	for i := range s.Inline {
		s.Inline[i] = redactMatcher(s.Inline[i])
	}
	return s
}

// valueExposureWarnings lists every named header/cookie matcher whose literal value
// still ships in the IR (post-redaction), so an operator can confirm none is a
// secret. Each warning is also counted into rep.ValueExposed by the caller, which
// makes `cadish edge build -strict` FAIL (Fix B) — a CI gate then catches a secret
// baked into the public worker bundle. In non-strict mode they remain printed
// advisories. The set of flagged matchers is unchanged (header/cookie/cookie_json/
// header_json with literal values) — strict does not broaden what is flagged.
func valueExposureWarnings(ir EdgeIR) []string {
	names := make([]string, 0)
	for name := range ir.Matchers {
		names = append(names, name)
	}
	sort.Strings(names)
	var warns []string
	for _, name := range names {
		m := ir.Matchers[name]
		if m.Redacted {
			continue
		}
		switch m.Kind {
		case "header":
			if len(m.Values) > 0 {
				warns = append(warns, "header matcher @"+name+" ("+m.Name+") ships its literal value(s) in the IR to the public edge — confirm it is not a secret")
			}
		case "cookie":
			if len(m.Values) > 0 {
				warns = append(warns, "cookie matcher @"+name+" ("+m.Name+") ships its literal value(s) in the IR to the public edge — confirm it is not a secret")
			}
		case "cookie_json":
			// cookie_json projects its literal match value(s) into the IR exactly like
			// `cookie` does (edgeview.go) — a `cookie_json sessionCookie auth.token
			// <SECRET>` would otherwise ship the secret without the heads-up its `cookie`
			// equivalent gets. Give it the same advisory (Finding D).
			if len(m.Values) > 0 {
				warns = append(warns, "cookie_json matcher @"+name+" ("+m.Name+") ships its literal value(s) in the IR to the public edge — confirm it is not a secret")
			}
		case "header_json":
			if len(m.Values) > 0 {
				warns = append(warns, "header_json matcher @"+name+" ("+m.Name+") ships its literal value(s) in the IR to the public edge — confirm it is not a secret")
			}
		}
	}
	return warns
}

// minEnvSecretLen is the shortest process-env VALUE the exposure scan treats as a
// plausible baked-in secret. The scan does a SUBSTRING match (an unquoted `{$VAR}` can
// be expanded mid-string), so a trivially short value false-positives constantly: a dev/
// CI box routinely carries 1–2 char env vars (`CLAUDECODE=1`, `MallocNanoZone=0`, shell
// `?`/`$` status), and a legitimate numeric header value like
// `Cache-Control: public, max-age=31536000, immutable` then "contains" `"0"`/`"1"` and
// trips `cadish edge build -strict` (E1). 8 is a defensible floor: no real credential/
// token/key is shorter than 8 characters (the shortest common secrets — short-lived
// codes, PINs — are ~6, but those are never wired into a Cadishfile via `{$VAR}` header/
// redirect/key positions), while it removes the entire class of short-numeric false
// positives. A genuine secret below 8 chars is not a meaningful secret to leak.
const minEnvSecretLen = 8

// envValues returns the set of process-environment VALUES long enough to be a plausible
// secret (>= minEnvSecretLen). It is a package var so tests can inject a hermetic
// environment. The exposure scan compares IR string fields against this set: an unquoted
// `{$VAR}` placeholder was expanded to exactly one of these values before projection, so
// a field whose value appears here carries an env-sourced secret into the public worker
// bundle. Short values are skipped (see minEnvSecretLen) to avoid substring-match false
// positives on ordinary numeric IR strings.
var envValues = func() map[string]struct{} {
	set := map[string]struct{}{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			if v := kv[i+1:]; len(v) >= minEnvSecretLen {
				set[v] = struct{}{}
			}
		}
	}
	return set
}

// envValueExposureWarnings scans every IR string field whose source could be a
// `{$VAR}` env placeholder (quoted OR unquoted — both expand since R07/D94) —
// request/response header op values, `replace`
// transform OLD/NEW, `respond on_error` bodies, `redirect` targets, and cache_key
// `literal:` tokens — and flags any value that EQUALS or CONTAINS a non-empty
// process-env value (the env-expanded secret). Mirrors the matcher value-exposure
// advisory + `-strict` count for these positions so a secret in any of them trips the
// build instead of silently shipping. Returns nothing when the process holds no env
// values with content (no env => no false positives).
func envValueExposureWarnings(ir EdgeIR) []string {
	vals := envValues()
	if len(vals) == 0 {
		return nil
	}
	// exposed reports whether s embeds any non-empty env value (substring match so a
	// `redirect` target like `https://host/{$SECRET}` or an `on_error` body `down {$X}`
	// is caught after expansion, not only a whole-value `{$SECRET}`).
	exposed := func(s string) bool {
		if s == "" {
			return false
		}
		for v := range vals {
			// Skip trivially short env values (see minEnvSecretLen): a 1–2 char value
			// false-positives on ordinary numeric IR strings under the substring match
			// (E1). Guarded here too so the floor holds regardless of how `vals` was
			// populated.
			if len(v) < minEnvSecretLen {
				continue
			}
			if strings.Contains(s, v) {
				return true
			}
		}
		return false
	}
	var warns []string
	headerWarns := func(hs []Header, phase string) {
		for _, h := range hs {
			for _, op := range h.Ops {
				if exposed(op.Value) {
					warns = append(warns, phase+" header op `"+op.Op+" "+op.Name+"` ships an environment-expanded value in the IR to the public edge — confirm it is not a secret (a `{$VAR}` expands whether quoted or not; keep secrets out of edge-projected directives)")
				}
			}
		}
	}
	headerWarns(ir.Recv.HeaderReq, "request")
	headerWarns(ir.Response.HeaderResp, "response")
	for _, tr := range ir.Response.Transforms {
		if exposed(tr.Old) || exposed(tr.New) {
			warns = append(warns, "replace transform ships an environment-expanded value in the IR to the public edge — confirm it is not a secret")
		}
	}
	for _, oe := range ir.Response.OnError {
		if exposed(oe.Body) {
			warns = append(warns, "respond on_error body ships an environment-expanded value in the IR to the public edge — confirm it is not a secret")
		}
		if exposed(oe.ContentType) {
			warns = append(warns, "respond on_error content_type ships an environment-expanded value in the IR to the public edge — confirm it is not a secret")
		}
	}
	for _, rs := range ir.Recv.Respond {
		if exposed(rs.Body) {
			warns = append(warns, "respond body ships an environment-expanded value in the IR to the public edge — confirm it is not a secret")
		}
	}
	for _, r := range ir.Recv.Redirect {
		if exposed(r.Target) {
			warns = append(warns, "redirect target ships an environment-expanded value in the IR to the public edge — confirm it is not a secret")
		}
	}
	keyTokenWarns := func(tks []KeyToken) {
		for _, tk := range tks {
			if tk.Kind == "literal" && exposed(tk.Arg) {
				warns = append(warns, "cache_key literal token ships an environment-expanded value in the IR to the public edge — confirm it is not a secret")
			}
		}
	}
	keyTokenWarns(ir.Key.Tokens)
	for _, rc := range ir.Key.Recipes {
		keyTokenWarns(rc.Tokens)
	}
	return warns
}

func addDelegate(rep *CoverageReport, d Delegated) {
	rep.Delegated++
	rep.DelegatedItems = append(rep.DelegatedItems, DelegatedItem{Directive: d.Directive, Reason: d.Reason})
}

// isRegexBan reports whether a purge regex token denotes a cache-wide BAN (any
// non-empty token — a literal regex or a {http.NAME} request-sourced pattern). An
// empty token is a single-key purge.
func isRegexBan(token string) bool { return token != "" }

func projectMatchers(in map[string]pipeline.EdgeMatcher) map[string]Matcher {
	out := make(map[string]Matcher, len(in))
	for name, m := range in {
		out[name] = projectMatcher(m)
	}
	return out
}

func projectMatcher(m pipeline.EdgeMatcher) Matcher {
	out := Matcher{
		Kind:               m.Kind,
		Patterns:           m.Patterns,
		Regex:              m.Regex,
		Name:               m.Name,
		Values:             m.Values,
		Glob:               m.Glob,
		Methods:            m.Methods,
		Upstreams:          m.Upstreams,
		ContentTypes:       m.ContentTypes,
		CookieNames:        m.CookieNames,
		ClassifyToken:      m.ClassifyToken,
		ClassifyValue:      m.ClassifyValue,
		ClassifyNegate:     m.ClassifyNegate,
		GeoGranularity:     m.GeoGranularity,
		GeoValues:          m.GeoValues,
		QueryNames:         m.QueryNames,
		QueryNamesNonEmpty: m.QueryNamesNonEmpty,
		JSONPath:           m.JSONPath,
		ResponsePhase:      m.ResponsePhase,
	}
	// `all` AND-conjunction: copy the (Ref, Negate) sub-terms through to the wire IR so the
	// worker can recurse over ir.matchers[ref]. v7.
	if len(m.Subs) > 0 {
		out.Subs = make([]SubMatcher, 0, len(m.Subs))
		for _, s := range m.Subs {
			out.Subs = append(out.Subs, SubMatcher{Ref: s.Ref, Negate: s.Negate})
		}
	}
	// BUG-1: lift RE2 inline flags off a path_regex/host_regex/header_regex source so
	// the worker compiles a JS-valid `new RegExp(regex, flags)`. An untranslatable
	// construct is stripped + flagged so the runtime fails the matcher closed and the
	// projector delegates the directives that reference it (see Project).
	if m.Kind == "path_regex" || m.Kind == "host_regex" || m.Kind == "header_regex" {
		if pat, flags, ok := splitRE2Flags(m.Regex); ok {
			out.Regex = pat
			out.RegexFlags = flags
		} else {
			out.Regex = ""
			out.RegexFlags = ""
			out.RegexUntranslatable = true
		}
	}
	// `ip` and `upstream_healthy` have no JS runtime case: mark them server-only so
	// the runtime fails them closed and Project delegates the referencing site (Fix #4).
	// (`all` and `query` were server-only before IR v7; they are edge-native since v7.)
	if serverOnlyEdgeKinds[m.Kind] {
		out.ServerOnly = true
	}
	return out
}

func projectScope(s pipeline.EdgeScope) Scope {
	out := Scope{Always: s.Always, Names: s.Names}
	for _, m := range s.Inline {
		out.Inline = append(out.Inline, projectMatcher(m))
	}
	return out
}

// scopeFailsClosed reports whether a (projected) scope references ANY matcher the edge
// runtime evaluates as fail-closed: a ServerOnly Gateway/lb matcher (`all`/`query`/
// `upstream_healthy`) or a RegexUntranslatable path/host/header_regex (e.g. ungreedy
// `(?U)`, a scoped `(?i:…)` group, a mid-pattern inline flag). At the edge such a matcher
// returns false (matchOne), so the WHOLE scope can silently fail to match — a directive
// gated on it then behaves DIFFERENTLY than on the Go server (which evaluates the matcher
// fully). The projector calls this to delegate (redirect, where the origin server still
// produces the correct answer) or fail-open (pass / cache_ttl / storage / upgrade, where a
// missing rule would let the edge cache a request the server passes / treats specially)
// rather than ship a rule whose scope the edge cannot honor. matchers is the
// already-projected ir.Matchers (for named lookups); inline matchers carry their own
// ServerOnly/RegexUntranslatable flags from projectMatcher. An Always scope never fails
// closed (it has no matcher to evaluate). Shared by the redirect/pass/cache_ttl/storage/
// upgrade projection loops (Findings 1–3).
func scopeFailsClosed(s Scope, matchers map[string]Matcher) bool {
	if s.Always {
		return false
	}
	for _, name := range s.Names {
		if m, ok := matchers[name]; ok && matcherFailsClosed(m, matchers) {
			return true
		}
	}
	for _, m := range s.Inline {
		if matcherFailsClosed(m, matchers) {
			return true
		}
	}
	return false
}

// matcherFailsClosed reports whether the edge runtime evaluates a projected matcher as
// fail-closed (matchOne returns false / non-match): a ServerOnly Gateway/lb matcher, a
// RegexUntranslatable path/host/header_regex, OR a `classify` matcher reading a classifier
// the edge cannot faithfully resolve (failsClosed, set by Project after the
// classifiersFailClosed fixpoint — Finding 1). The single predicate shared by
// scopeFailsClosed so the redirect/pass/cache_ttl/storage/upgrade fail-open + delegation
// all account for classify indirection identically.
//
// For an `all` AND-composite (v7) it RECURSES: an `all` fails closed iff ANY sub's
// referenced matcher fails closed — NEGATE-AGNOSTIC. At runtime a fail-closed sub returns
// false, so a negated term `!@b` flips to TRUE and the whole `all` could MATCH where the
// server (with @b truly matching) would not — a silent wrong route/pass/cache decision. The
// closure flag is binary (it cannot express "evaluate the good subs, delegate the bad one"),
// so any fail-closed sub poisons the whole `all`. No cycle guard / visited-set: depth is ≤1
// by construction (compile forbids all-of-all; a classify row can never reference an `all`,
// so the recursion never re-enters an `all`).
//
// ORDERING INVARIANT (load-bearing): recursing into a `classify` sub reads that sub's
// (unexported) failsClosed, which Project sets AFTER the classifiersFailClosed fixpoint but
// BEFORE every RECV/cache_key projection that calls scopeFailsClosed. Every scopeFailsClosed
// caller therefore sits later in Project, so the classify sub's flag is already final here. A
// future reorder that moves a scopeFailsClosed call ahead of the fixpoint would silently ship
// an `all->classify(fail-closed)` scope native — keep this ordering.
func matcherFailsClosed(m Matcher, matchers map[string]Matcher) bool {
	if m.ServerOnly || m.RegexUntranslatable || m.failsClosed {
		return true
	}
	if m.Kind == "all" {
		for _, sub := range m.Subs {
			if sm, ok := matchers[sub.Ref]; ok && matcherFailsClosed(sm, matchers) {
				return true
			}
		}
	}
	return false
}

// directiveScopeOrTokensFailClosed is the SINGLE fail-closed guard EVERY scoped or
// token-bearing edge rule routes through, so a future scoped/token surface cannot
// silently skip the check — the recurring "a scope/token that fails closed at the edge
// → divergent edge behavior" class (pass/cache_ttl/storage/redirect/upgrade and, as of
// Findings 1 & 2, the cache_key recipe SELECTORS and classify TOKENS). It folds the two
// fail-closed vectors a directive can carry:
//
//   - the directive SCOPE (selector) references a matcher the edge fails closed on
//     (scopeFailsClosed → a ServerOnly Gateway/lb matcher, a RegexUntranslatable
//     path/host/header_regex, or a `classify` matcher reading a fail-closed classifier); and
//   - a cache_key TOKEN reads a fail-closed classifier (a `classify` key token whose
//     classifier resolves to its DEFAULT at the edge while Go returns the matched row —
//     a divergent key component, Finding 2).
//
// Scope-only directives (pass/cache_ttl/storage/redirect/upgrade) pass a nil token slice;
// token-only ones (the default cache_key) pass an Always scope. Returns whether the rule
// fails closed and, when a classify TOKEN is the cause, that classifier's name (so the
// caller can name it in the warning; "" for a scope-driven failure). matchers is the
// projected ir.Matchers; clsFC the classifiersFailClosed fixpoint (nil when the site has
// no classifiers — a nil-map lookup is false, so the token vector no-ops).
func directiveScopeOrTokensFailClosed(s Scope, tokens []KeyToken, matchers map[string]Matcher, clsFC map[string]bool) (bool, string) {
	if scopeFailsClosed(s, matchers) {
		return true, ""
	}
	for _, tk := range tokens {
		if tk.Kind == "classify" && clsFC[tk.Ref] {
			return true, tk.Ref
		}
	}
	return false, ""
}

// classifiersFailClosed computes, for every classifier, whether the edge cannot faithfully
// resolve it. A classifier is fail-closed when ANY of its rows' AND-conjunctions references
// a matcher that itself fails closed at the edge — a ServerOnly or RegexUntranslatable
// matcher — OR (transitively) a `classify` matcher reading a fail-closed classifier. Such a
// row is SKIPPED by classifyResolve at the edge (matchOne returns false for the fail-closed
// matcher), so the classifier silently returns its default where the Go server (full RE2 /
// live lb state) would have matched the row — and a pass/cache_ttl/storage/redirect scope
// gated on `{C}==v` then mis-decides. The transitive case is iterated to a FIXPOINT so
// nested classify indirection (a classifier whose row reads another classifier) is covered.
// A classifier whose rows are ALL edge-translatable is never marked, so legit configs still
// project native (Finding 1 — no over-reaction).
//
// This runs over ir.Classifiers with EVERY row intact (no row is dropped — the unsound P2
// "drop unsatisfiable `ip` row" optimization was withdrawn). So a row requiring a ServerOnly
// `ip`/`upstream_healthy` matcher, or an UNKNOWABLE untranslatable regex / fail-closed classify
// sub, fail-closes its classifier — exactly the safe pre-P2 behavior. The transitive `fc`
// fixpoint is unchanged.
func classifiersFailClosed(classifiers map[string]Classifier, matchers map[string]Matcher) map[string]bool {
	fc := make(map[string]bool, len(classifiers))
	for {
		changed := false
		for name, c := range classifiers {
			if fc[name] {
				continue
			}
			if classifierRowsFailClosed(c, matchers, fc) {
				fc[name] = true
				changed = true
			}
		}
		if !changed {
			return fc
		}
	}
}

// classifierRowsFailClosed reports whether any row of c references a directly fail-closed
// matcher (ServerOnly/RegexUntranslatable) or a `classify` matcher whose classifier is
// ALREADY known fail-closed (fc) — the step relation classifiersFailClosed iterates to a
// fixpoint, so a classifier that reads another classifier resolves transitively.
func classifierRowsFailClosed(c Classifier, matchers map[string]Matcher, fc map[string]bool) bool {
	for _, row := range c.Rows {
		for _, id := range row.Conj {
			m, ok := matchers[id]
			if !ok {
				continue
			}
			if m.ServerOnly || m.RegexUntranslatable {
				return true
			}
			if m.Kind == "classify" && fc[m.ClassifyToken] {
				return true
			}
		}
	}
	return false
}

func projectHeader(h pipeline.EdgeHeaderRule) Header {
	ops := make([]HeaderOp, 0, len(h.Ops))
	for _, op := range h.Ops {
		ops = append(ops, HeaderOp{Op: op.Op, Name: op.Name, Value: op.Value, ValueIsTmpl: op.ValueIsTmpl})
	}
	return Header{Scope: projectScope(h.Scope), Ops: ops}
}

func projectTTL(r pipeline.EdgeTTL) TTL {
	t := TTL{SelKind: r.SelKind, Codes: r.Codes, IsHFM: r.IsHFM, FromHeader: r.FromHeader,
		GraceFromHeader: r.GraceFromHeader, MaxStaleFromHeader: r.MaxStaleFromHeader,
		StripHeaders: r.StripHeaders}
	if r.SelKind == "scope" {
		s := projectScope(r.Scope)
		t.Scope = &s
	}
	if r.RespHeader != nil {
		m := projectMatcher(*r.RespHeader)
		t.RespHeader = &m
	}
	if r.IsHFM {
		t.HitForMiss = r.HitForMiss.String()
	} else {
		if r.TTL > 0 {
			t.TTL = r.TTL.String()
		}
		if r.Grace > 0 {
			t.Grace = r.Grace.String()
		}
		// max_stale (D60): the stale-on-error window beyond ttl+grace. Projected so the
		// worker bounds its salvage path (D70). Only meaningful on a positive TTL rule
		// (rejected on hit_for_miss at compile), so it lives in the non-HFM branch.
		if r.MaxStale > 0 {
			t.MaxStale = r.MaxStale.String()
		}
	}
	return t
}

// projectEdge projects the `edge {}` block's default tier + KV guardrails into the
// worker IR. Deploy identity (account/zone/worker/routes/kv) is intentionally NOT
// projected here — it is management-plane metadata that must not ship to the public
// worker; the CLI reads it from pipeline.EdgeDeployConfig() directly. With no `edge {}`
// block, Default is "local" and there are no policies (the prior stub behavior).
//
// The per-scope `local | distribute | skip @scope` tier POLICIES are intentionally NOT
// projected here: they are a store-decision surface and must route through the single
// fail-closed chokepoint (directiveScopeOrTokensFailClosed), which needs ir.Matchers +
// the classifier fail-closed fixpoint (clsFC) — both computed later in Project. The
// gated policy projection therefore lives inline in Project (mirroring `storage`).
func projectEdge(p *pipeline.Pipeline) Edge {
	e := Edge{Default: p.EdgeDefaultTier()}
	if d, ok := p.EdgeKVTTL(); ok {
		// KV's expirationTtl is whole seconds; round up so a sub-second cap still
		// keeps the entry for at least the requested window (the 60s KV floor is
		// applied in the runtime, not here, so the cap stays honest in the IR).
		secs := int((d + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		e.KVTTLSeconds = secs
	}
	e.KVMaxBytes = p.EdgeKVMaxBytes()
	return e
}

func projectStorage(r pipeline.EdgeStorage) Storage {
	s := Storage{SelKind: r.SelKind, Codes: r.Codes, Tier: r.Tier}
	if r.SelKind == "scope" {
		sc := projectScope(r.Scope)
		s.Scope = &sc
	}
	if r.RespHeader != nil {
		m := projectMatcher(*r.RespHeader)
		s.RespHeader = &m
	}
	return s
}
