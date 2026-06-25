package pipeline

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// maxRequestPurgeRegexLen bounds the length of a purge ban regex sourced from a
// request header (security review #6), so an authorized purge caller cannot supply
// a pathological/oversized pattern.
const maxRequestPurgeRegexLen = 256

// memoStack sizes the stack-backed matcher-memo arrays used by the per-request
// Eval* methods. It covers realistic sites (≤32 distinct matchers) without a heap
// allocation; a larger site spills the memo slice to the heap once (still one
// allocation, paid only by very large configs). See newMemo.
const memoStack = 32

// newMemo returns a zeroed memo slice of length n. n is the Pipeline's matcher
// count; the caller passes a stack array (stack[:]) so the common case is
// allocation-free, and only n > len(stack) escapes to the heap.
func newMemo(stack []int8, n int) []int8 {
	if n <= len(stack) {
		m := stack[:n]
		for i := range m {
			m[i] = memoUnknown
		}
		return m
	}
	return make([]int8, n)
}

// resolveUpstream runs the route rules (first-match-wins) to determine the
// upstream a request is routed to, or the site default ("" if none). Route
// conditions are evaluated with an empty upstream, so a route condition may not
// itself depend on an `upstream` matcher.
//
// It memoizes into its OWN context (separate memo from the caller's main phase):
// an `upstream` matcher evaluates against upstream "" here, so its result must not
// leak into the later phases where the resolved upstream is known.
func (p *Pipeline) resolveUpstream(req *Request) string {
	if len(p.routeRules) == 0 {
		return p.defaultUpstream
	}
	var stack [memoStack]int8
	rc := matchContext{req: req, upstream: "", memo: newMemo(stack[:], p.numMatchers)}
	for i := range p.routeRules {
		if p.routeRules[i].matches(&rc) {
			return p.routeRules[i].upstream
		}
	}
	return p.defaultUpstream
}

// EvalRequest evaluates the RECV + KEY phases and returns the request decision.
// It is safe for concurrent use.
func (p *Pipeline) EvalRequest(req *Request) RequestDecision {
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers)}
	var dec RequestDecision
	dec.Upstream = ctx.upstream

	// respond: a synthetic response short-circuits everything else. Two forms:
	//   - exact path (`respond PATH STATUS BODY`): fires when req.Path == PATH.
	//   - scoped (`respond @scope STATUS BODY`): fires when the matcher conjunction
	//     matches. The ingress translator emits `respond !@r0 !@r1 … 404` as a terminal
	//     no-match handler, so a path matching none of the route matchers 404s instead
	//     of falling back to the site's default upstream.
	for i := range p.respondRules {
		r := &p.respondRules[i]
		if r.terms != nil {
			if respondTermsMatch(ctx, r.terms) {
				dec.Synthetic = &Synthetic{Status: r.status, Body: r.body}
				return dec
			}
			continue
		}
		if req.Path == r.path {
			dec.Synthetic = &Synthetic{Status: r.status, Body: r.body}
			return dec
		}
	}

	// redirect: a computed 3xx likewise short-circuits cache + origin. First
	// matching rule wins; respond is checked first so an exact-path respond can
	// pre-empt a broader redirect regex on the same path.
	for i := range p.redirectRules {
		if rdr := p.redirectRules[i].eval(ctx, p); rdr != nil {
			dec.Redirect = rdr
			return dec
		}
	}

	// purge: first matching guard wins.
	for _, r := range p.purgeRules {
		if ctx.scopeMatches(r.guard) {
			pat := resolveHTTPPlaceholder(r.regexToken, req)
			if pat != "" && r.regexPath {
				pat = pathToKeyRegex(pat)
			}
			dec.Purge = &PurgeDecision{
				Authorized: true,
				Regex:      pat,
			}
			break
		}
	}

	// pass: first matching rule wins (boolean result).
	for _, sc := range p.passRules {
		if ctx.scopeMatches(sc) {
			dec.Pass = true
			break
		}
	}

	// request-phase header edits.
	dec.ReqHeaderOps = applyHeaderRules(p.reqHeaderRules, ctx, CacheStatusUnknown, false, p.classifiers)

	// origin-request path/query rewrite. This is computed AFTER the cache key below
	// is conceptually fixed — it MUST NOT influence the key (see RewriteDecision):
	// the key is built from the unmodified client request, the rewrite only changes
	// the bytes dialed upstream.
	dec.Rewrite = p.evalRewrite(ctx)

	// cache key. ctx is threaded so a {classify} key token resolves its matchers
	// through the same memoized context as the rest of the request phase. The recipe
	// is chosen first-match-wins from the scoped cache_key rules (one unscoped rule,
	// or none, is the common case and costs nothing extra).
	dec.CacheKey = buildKey(p.selectKeyTokens(ctx), req, p.stickyCookie, ctx)
	return dec
}

// selectKeyTokens picks the cache-key recipe for a request: the first keyRule whose
// selector matches (first-match-wins, source order), mirroring how EvalResponse
// picks a cache_ttl rule. Selectors are request-phase only, so status is irrelevant
// here (a status selector is rejected at compile). Returns nil when no rule matches
// or the site declares none — buildKey then falls back to the built-in default
// (method host path), so a site with no cache_key behaves exactly as before.
func (p *Pipeline) selectKeyTokens(ctx *matchContext) []keyToken {
	for i := range p.keyRules {
		if p.keyRules[i].sel.matches(ctx, 0) {
			return p.keyRules[i].toks
		}
	}
	return nil
}

// HasOnError reports whether the site configures any `respond on_error` rule. The
// server gates the origin-error synthetic path on this so a site without the
// directive pays exactly one nil/len check on the error path (zero cost; D57).
func (p *Pipeline) HasOnError() bool { return len(p.onErrorRules) > 0 }

// EvalOnError resolves the origin-error-phase synthetic for a request whose origin
// HARD-failed with no servable object (D57). It runs the on_error rules in source
// order (first-match-wins) evaluating only their request-phase `@scope` matchers —
// the origin-error path carries a status but no upstream response headers, so a
// response-phase matcher can never appear here (rejected at compile). It returns nil
// when no rule is configured or none matches, so the caller falls through to the
// bare-status fallback. status is the mapped origin failure code; it is accepted for
// future status-aware scoping but request-phase matchers do not consult it today.
func (p *Pipeline) EvalOnError(req *Request, status int) *OnError {
	if len(p.onErrorRules) == 0 {
		return nil
	}
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers)}
	for i := range p.onErrorRules {
		r := &p.onErrorRules[i]
		if r.scope == nil || ctx.scopeMatches(r.scope) {
			return &OnError{Status: r.status, Body: r.body, ContentType: r.contentType}
		}
	}
	return nil
}

// EvalResponse evaluates the ORIGIN/store phase using the response status (needed
// by cache_ttl status selectors) and the origin response headers (needed by
// response-phase matchers like `set_cookie`/`content_type`). respHeader may be nil
// (e.g. a bodyless negative entry), in which case response-phase matchers do not
// fire. First-match-wins for both cache_ttl and storage.
func (p *Pipeline) EvalResponse(req *Request, status int, respHeader http.Header) ResponseDecision {
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers), respHeader: respHeader}
	var dec ResponseDecision
	for _, r := range p.ttlRules {
		if !r.sel.matches(ctx, status) {
			continue
		}
		if r.isHFM {
			dec.HitForMiss = r.hfm
			break
		}
		// SAFE BY DEFAULT (NEG-ALL): a broad selector (`default`, `@scope`, or
		// `status not …`) must NOT make a transient error status STORABLE. Caching a
		// 5xx under a generic `cache_ttl default` pins an outage for the whole TTL even
		// after the origin recovers; caching a 401/403 compounds the credential leak.
		// Only the canonical negative-cacheable 404/410, or a status EXPLICITLY listed
		// by a positive `status <code>` selector, may cache an error. (HFM above is a
		// non-store decision and is the correct, unaffected guard for errors.)
		if isUncacheableError(status) && r.sel.kind != selStatusIn {
			break // this rule matched, but we refuse to STORE the error under it
		}
		if r.fromHeader != "" {
			// Header-sourced TTL: read it from the origin response. A missing or
			// unparseable header makes this rule NOT apply, so evaluation falls
			// through to a later (e.g. `default`) rule rather than caching with a
			// zero TTL.
			ttl, ok := headerTTL(respHeader, r.fromHeader)
			if !ok {
				continue
			}
			dec.TTL = ttl
			dec.Grace = r.grace
			dec.MaxStale = r.maxStale
			dec.Cacheable = true
			break
		}
		dec.TTL = r.ttl
		dec.Grace = r.grace
		dec.MaxStale = r.maxStale
		dec.Cacheable = true
		break
	}
	// SAFE BY DEFAULT (security review): a cache_ttl rule deciding Cacheable=true is
	// necessary but not sufficient — a SHARED cache must also refuse a response that is
	// not safely shareable across users (RFC 9111 §3, and what every CDN does). So
	// after a positive rule, downgrade to non-cacheable when the origin response
	// carries Set-Cookie, a private/no-store/no-cache Cache-Control, or a Vary not
	// covered by the cache key. The `cache_unsafe` site flag opts out (the operator has
	// explicitly accepted the risk). The inspection runs ONLY on an already-cacheable
	// response (the site caches this status) and skips entirely when headers are
	// absent, so the hot path and pass-through traffic pay nothing.
	// `Vary: *` ("varies on something not in the request") is NEVER cacheable in a
	// shared cache and is not subject to the cache_unsafe opt-out; the rest of the
	// shareability refusal is. Both run only on an already-cacheable response.
	if dec.Cacheable && respHeader != nil {
		// Vary coverage is judged against the recipe SELECTED for THIS request, not the
		// global union of every recipe's keyed headers — so a Vary the selected key does
		// not partition is correctly refused (no variant cross-serving).
		keyHeaders := keyHeaderNamesForTokens(p.selectKeyTokens(ctx))
		// A `Set-Cookie` response is NEVER cacheable — unconditionally, NOT even under
		// `cache_unsafe` (like `Vary: *`). A Set-Cookie is a per-user credential the
		// origin is minting RIGHT NOW; caching it would hand one user's brand-new session
		// to everyone who reads the entry. This is the load-bearing confidentiality
		// invariant, so it is not behind any opt-out. The ONE way to cache such a response
		// is to CONTROL the cookie: a `strip_cookies` rule covering it removes Set-Cookie
		// before the response is stored or delivered (Varnish's `unset beresp.http.Set-
		// Cookie`), so the cached representation carries no cookie. That is an explicit,
		// per-class operator opt-in — you can't cache a Set-Cookie response by accident.
		// The rest of the shareability refusal (private/no-store/no-cache/s-maxage=0/
		// uncovered-Vary) IS overridable by cache_unsafe.
		setCookieBlocks := hasSetCookie(respHeader) && !p.stripCookiesMatches(ctx)
		if varyStar(respHeader) || setCookieBlocks || (!p.cacheUnsafe && !p.safelyShareable(respHeader, keyHeaders)) {
			dec.Cacheable = false
			dec.TTL = 0
			dec.Grace = 0
			dec.MaxStale = 0
		}
	}
	for _, r := range p.storageRules {
		if r.sel.matches(ctx, status) {
			dec.StoreTier = r.tier
			break
		}
	}
	return dec
}

// isUncacheableError reports whether a status is an error that a SHARED cache must not
// store under a broad (non-explicit) `cache_ttl`/`storage` selector: any 4xx/5xx
// EXCEPT the canonical negative-cacheable 404 (Not Found) and 410 (Gone), which remain
// storable under `default` as documented negative caching. An operator can still cache
// any other error by naming it in a positive `status <code>` selector.
func isUncacheableError(status int) bool {
	return status >= 400 && status != 404 && status != 410
}

// FilterRequestCookies applies the `cookie_allow` allowlist to a raw Cookie header
// value: it returns the header with ONLY the allowed cookies kept (the rest stripped)
// and active=true. When no `cookie_allow` directive is configured it returns
// (raw, false) unchanged. The server calls this at RECV — after the security gate, so
// `deny`/`allow` cookie rules still see the original cookies, but before the cache key,
// the credential-coverage check, and the origin fetch — so all three see only the
// operator-controlled cookies. An empty allowlist strips every cookie.
func (p *Pipeline) FilterRequestCookies(raw string) (string, bool) {
	if p.cookieAllow == nil {
		return raw, false
	}
	if raw == "" {
		return "", true
	}
	// Parse LENIENTLY (lenientCookies), NOT net/http's strict Cookies(): the strict parser
	// drops a JSON/quoted cookie value, which would silently STRIP an allow-listed JSON session
	// cookie here — so it never reaches the cache key or the origin, collapsing distinct
	// sessions onto one entry (a cross-user leak through the very directive meant to make
	// cookie traffic safe). The lenient reader is the same one the gate and the key use.
	cs := lenientCookies(http.Header{"Cookie": {raw}})
	var b strings.Builder
	for _, c := range cs {
		if !p.cookieAllow.match(c.name) {
			continue // not allow-listed → stripped
		}
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.name)
		b.WriteByte('=')
		b.WriteString(c.value)
	}
	return b.String(), true
}

// BypassForCredentials reports whether a request must bypass the SHARED cache because
// it carries a per-user credential (`Authorization` or `Cookie`) that the cache key
// does NOT capture. It is the LEAK-PROOF safe-default for cross-user confidentiality
// (AUTH-LEAK / COOKIE-LEAK): a private response returned for one user's session cookie
// or bearer token must never be stored under a credential-agnostic key and served to
// another user (including anonymous). This mirrors Varnish's builtin VCL (`vcl_recv`
// passes `Authorization || Cookie`) — the tool cadish replaces — and RFC 9111 §3.5.
//
// The ONLY way to cache a credentialed request is to KEY by that credential, so each
// distinct value gets its own entry (`cache_key … cookie:session` for a Cookie,
// `cache_key … header:Authorization` for a bearer token). There is deliberately no
// flag escape hatch: `cache_unsafe` (which governs response Set-Cookie shareability)
// does NOT lift this — you cannot accidentally cache credentialed traffic under a
// shared key. A request carrying a credential the selected key recipe does not cover
// (the default `method host path`, or a key that omits this credential) bypasses.
//
// Applied by the SERVER (and the edge worker enforces the same rule in JS) rather than
// baked into EvalRequest's `Pass`, so the portable pipeline decision — matchers, cache
// key, the conformance snapshot — is unchanged: the credential bypass is a serving-tier
// cache-safety policy, not part of rule evaluation.
func (p *Pipeline) BypassForCredentials(req *Request) bool {
	if req == nil || req.Header == nil {
		return false
	}
	// hasCookie MUST use the same all-lines parse as the cache key and the origin forward
	// (req.Cookies via cookieNames), NOT req.Header.Get("Cookie") — Get returns only the
	// FIRST Cookie header line. A request that splits its cookies across multiple Cookie
	// header lines with an empty first line (`Cookie:\r\nCookie: session=…`, valid HTTP a
	// raw client can send) would make Get return "" while Cookies() still sees the session —
	// so a Get-based check would conclude "no credential", skip the bypass, and cache the
	// per-user response under the shared key (a cross-user leak). cookieNames closes that.
	hasCookie := len(req.cookieNames()) > 0
	// hasAuth, like hasCookie, MUST consider ALL Authorization field-lines, not
	// req.Header.Get (the FIRST line only). A raw client can send an empty first
	// Authorization line then the real token (`Authorization:\r\nAuthorization: Bearer …`);
	// net/http keeps ["", "Bearer …"], Get returns "" → a Get-based check would conclude
	// "no credential" and skip the bypass, while the origin (combining field-lines per RFC
	// 9110 §5.3, or reading Values) still sees the token and returns a private body — which
	// would then be cached under the shared key (the symmetric twin of the Cookie smuggle).
	authVals := req.Header.Values("Authorization")
	hasAuth := false
	for _, v := range authVals {
		if v != "" {
			hasAuth = true
			break
		}
	}
	if !hasCookie && !hasAuth {
		return false // no credentials: normal caching
	}
	// `cookie_allow` does NOT blanket-exempt the request from the cookie check. The server
	// has already STRIPPED every non-allow-listed cookie before this runs, so the cookies
	// still present ARE the operator-controlled allowlist — but a controlled cookie is only
	// safe to cache if the cache key ISOLATES it. The exemption is therefore name-aware
	// (the keyCoversAllCookies check below), NOT a flag short-circuit: an allow-listed cookie
	// the key does not capture (a second identity cookie like `uid` alongside a keyed
	// `session`, or any kept cookie under an unkeyed config) still forces the bypass, exactly
	// as an un-controlled cookie would. So: cookie_allow controls WHICH cookies survive; the
	// key must still cover the survivors, or the request bypasses (never caches a per-user
	// body under a shared key). Authorization is independent and never cookie-exempt.
	if !p.keyCanCoverCred {
		return true // no recipe can cover ANY credential → a credentialed request never caches
	}
	// Select THIS request's recipe and check it covers every credential it carries (a scoped
	// cache_key may key by a credential only for some requests).
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers)}
	toks := p.selectKeyTokens(ctx)
	if len(toks) == 0 {
		toks = defaultKeyTokens
	}
	// Authorization coverage is also count-aware (mirroring keyCoversAllCookies): a
	// `header:Authorization` key token renders only the FIRST field-line (headerGet), while
	// the origin sees ALL of them — so a request sending Authorization MORE THAN ONCE is not
	// safely covered (two users sharing the first token but differing on a later one would
	// collide on one entry). Multiple Authorization lines therefore always bypass.
	if hasAuth && (!keyCoversAuthorization(toks) || len(authVals) > 1) {
		return true
	}
	// The Cookie check is NAME-AWARE: keying by SOME cookie is not enough — the key must
	// capture EVERY cookie the request sends (or the whole Cookie header), or an un-keyed
	// identity cookie (a session named differently than the keyed one, or any second
	// cookie like `cart_count`/`uid`) would let two users collide on one entry and leak one's
	// private body to the other. Under cookie_allow this runs over the allow-listed remainder.
	if hasCookie && !keyCoversAllCookies(toks, req) {
		return true
	}
	return false
}

// keyCoversAuthorization reports whether the recipe captures the whole Authorization
// header (the only way to isolate a bearer token per user — it is one opaque value).
func keyCoversAuthorization(toks []keyToken) bool {
	for _, t := range toks {
		if tokenCoversAuth(t) {
			return true
		}
	}
	return false
}

// keyCoversAllCookies reports whether the selected key recipe isolates EVERY cookie the
// request carries: either a `header:Cookie` token (the whole Cookie header is in the
// key) or a `cookie:NAME` token for every cookie name the request sends. If ANY cookie
// the request carries is not captured, the response is per-user with respect to that
// cookie and must not be shared — so the caller bypasses the cache. Cookie names are
// matched case-sensitively (RFC 6265).
func keyCoversAllCookies(toks []keyToken, req *Request) bool {
	keyed := map[string]struct{}{}
	for _, t := range toks {
		if t.kind == tokHeader && strings.EqualFold(t.arg, "Cookie") {
			return true // whole Cookie header keyed → every cookie (and every value) covered
		}
		if t.kind == tokCookie {
			keyed[t.arg] = struct{}{}
		}
	}
	names := req.cookieNames()
	if len(names) == 0 {
		return false // a non-empty but unparseable Cookie header is not safely covered
	}
	// Count occurrences: a `cookie:NAME` token keys on req.cookie(NAME) — net/http's
	// FIRST occurrence — while the origin receives ALL of them. So a keyed cookie sent
	// MORE THAN ONCE is NOT safely covered: two users sharing the first value but
	// differing on a later one would collide on one entry and leak. Require every cookie
	// to be keyed AND to appear exactly once (whole-header keying above is exempt).
	counts := make(map[string]int, len(names))
	for _, n := range names {
		counts[n]++
	}
	for n, c := range counts {
		if _, ok := keyed[n]; !ok {
			return false // this cookie is not in the key → cannot safely share
		}
		if c > 1 {
			return false // keyed but sent multiple times → the key captures only the first value
		}
	}
	return true
}

// safelyShareable reports whether a cacheable origin response may be stored in the
// SHARED cache and served cross-user. It returns false (refuse) when the response
// carries a Set-Cookie, a Cache-Control with a no-store/private/no-cache directive,
// or a Vary that is not covered by the cache key (and is not solely Accept-Encoding,
// which cadish handles in its encode layer). This mirrors the edge tier's HARD
// invariant in edge/runtime/cache-tiers.js and RFC 9111 shared-cache behavior.
func (p *Pipeline) safelyShareable(h http.Header, keyHeaders map[string]bool) bool {
	// (Set-Cookie is refused UNCONDITIONALLY by the caller — see hasSetCookie — so it is
	// not re-checked here; this function covers only the cache_unsafe-overridable refusals.)
	// Cache-Control: refuse on a no-store / private / no-cache directive. Token match
	// over the comma/space-separated directive list (so `max-age=60` and a value like
	// `private-data` are NOT mistaken for a directive).
	for _, cc := range h.Values("Cache-Control") {
		if hasUncacheableCC(cc) {
			return false
		}
	}
	// Vary: a `*` is never cacheable; any other field must be covered by the cache key
	// (or be Accept-Encoding, handled by the encode layer) or we refuse — serving one
	// variant to every user is exactly the bug.
	for _, v := range h.Values("Vary") {
		if !p.varyCovered(v, keyHeaders) {
			return false
		}
	}
	return true
}

// hasSetCookie reports whether the response carries any Set-Cookie header. Such a
// response is NEVER cacheable in a shared cache — unconditionally, not even under
// cache_unsafe — UNLESS a `strip_cookies` rule covers it (see stripCookiesMatches),
// in which case the cookie is removed before the response is stored or delivered.
func hasSetCookie(h http.Header) bool {
	return len(h.Values("Set-Cookie")) > 0
}

// stripCookiesMatches reports whether a `strip_cookies` rule fires for THIS response,
// using the same scope evaluation as EvalDeliver. When it does, the server (and the
// edge) physically drop Set-Cookie before storing AND before delivering, so the cached
// and served representation never carries the cookie — the cadish equivalent of
// Varnish's `unset beresp.http.Set-Cookie`. This is the EXPLICIT operator opt-in that
// lets a cookie-stamping origin be cached safely: you cache it only because you declared
// the cookie controlled (stripped), so one user's freshly-minted cookie can never be
// stored under the shared key and handed to another. Without a matching strip rule the
// Set-Cookie response is refused (the ironclad default — you can't cache it by accident).
func (p *Pipeline) stripCookiesMatches(ctx *matchContext) bool {
	for _, sc := range p.stripRules {
		if ctx.scopeMatches(sc) {
			return true
		}
	}
	return false
}

// varyStar reports whether any Vary header value is (or contains) `*`. A `Vary: *`
// response can never be served from a shared cache and is refused unconditionally
// (even under cache_unsafe).
func varyStar(h http.Header) bool {
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			if strings.TrimSpace(part) == "*" {
				return true
			}
		}
	}
	return false
}

// hasUncacheableCC reports whether a Cache-Control header value forbids a SHARED cache
// from storing/serving the response: a `no-store`, `private`, or `no-cache` directive,
// or `s-maxage=0` (the shared-cache freshness lifetime is zero → it must revalidate
// before every serve, which cadish — having no conditional revalidation — treats like
// `no-cache`). It scans the comma-separated directive list and compares each directive
// NAME (the part before any `=`) case-insensitively as a whole token, so `max-age=60`
// is cacheable and a `private-data` value is not a `private` directive. A POSITIVE
// `s-maxage` is a freshness hint the operator's `cache_ttl` overrides (the
// operator-authoritative model), like `max-age`; only the absolute-refusal directives
// are honored here — and all of them are overridable site-wide with `cache_unsafe`.
//
// `must-revalidate`/`proxy-revalidate` are deliberately NOT treated as uncacheable:
// they permit caching while FRESH and only forbid serving STALE without revalidation
// (a grace/stale concern, not a store concern).
func hasUncacheableCC(value string) bool {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		name, val := part, ""
		if i := strings.IndexByte(part, '='); i >= 0 {
			name, val = part[:i], strings.TrimSpace(part[i+1:])
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "no-store", "private", "no-cache":
			return true
		case "s-maxage":
			if strings.Trim(val, "\"") == "0" {
				return true
			}
		}
	}
	return false
}

// varyCovered reports whether a Vary header value is safe for a shared cache: `*` is
// never safe; otherwise every listed field must be Accept-Encoding (handled by the
// encode layer) or already part of the cache key. An empty Vary value is safe.
func (p *Pipeline) varyCovered(value string, keyHeaders map[string]bool) bool {
	for _, part := range strings.Split(value, ",") {
		field := strings.TrimSpace(part)
		if field == "" {
			continue
		}
		if field == "*" {
			return false
		}
		lf := strings.ToLower(field)
		if lf == "accept-encoding" {
			continue
		}
		if keyHeaders[lf] {
			continue
		}
		return false
	}
	return true
}

// EvalDeliver evaluates the DELIVER phase. respHeader is the response header set
// being assembled (so `content_type` matchers resolve against the real response
// Content-Type); it may be nil. cacheStatus feeds the `header +cache_status`
// special.
func (p *Pipeline) EvalDeliver(req *Request, respHeader http.Header, cacheStatus CacheStatus) DeliverDecision {
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers), respHeader: respHeader}
	var dec DeliverDecision
	dec.RespHeaderOps = applyHeaderRules(p.respHeaderRules, ctx, cacheStatus, true, p.classifiers)
	for _, r := range p.respHeaderRules {
		if !ctx.scopeMatches(r.scope) {
			continue
		}
		for _, op := range r.ops {
			if op.Op == OpCacheStatus {
				dec.CacheStatusHeader = op.Name
			}
			if op.Op == OpCacheKey {
				// The cache key is the server-held RECV key, not in this phase's match
				// context, so surface the target + raw flag for the server's deliver path
				// to materialize from the key it owns (last matching directive wins, like
				// CacheStatusHeader).
				dec.CacheKeyHeader = op.Name
				dec.CacheKeyRaw = op.Value == "raw"
			}
		}
	}
	for _, sc := range p.stripRules {
		if ctx.scopeMatches(sc) {
			dec.StripCookies = true
			break
		}
	}
	if p.corsRule != nil && ctx.scopeMatches(p.corsRule.scope) {
		c := p.corsRule.cors
		dec.CORS = &c
	}
	for _, tr := range p.transformRules {
		if ctx.scopeMatches(tr.scope) {
			dec.Transforms = append(dec.Transforms, tr.repl)
		}
	}
	if p.encodeRule != nil {
		// Surface the site-wide compression policy. The server negotiates against
		// the client Accept-Encoding and applies the per-response gating
		// (Range/HEAD/existing Content-Encoding/Content-Type/min_length).
		dec.Encode = &EncodeDecision{
			Codecs:    p.encodeRule.codecs,
			Types:     p.encodeRule.types,
			MinLength: p.encodeRule.minLength,
		}
	}
	return dec
}

// applyHeaderRules collects the ops of every header rule whose scope matches. When
// resolveStatus is true, an OpCacheStatus op is materialized into a concrete set
// op writing the cache-status token; otherwise it is dropped (cache status is a
// delivery-only concept).
//
// A set/append op whose value carries a template placeholder (op.ValueTpl, e.g.
// `header Access-Control-Allow-Origin {http.Origin}` or `header X-Real-IP
// {client_ip}` — dynamic header values, #17) is resolved here against the request:
// the emitted HeaderOp carries a fully-resolved literal Value (and ValueTpl
// cleared), so the server applies every op uniformly and never sees a template.
// The TemplateEnv is built lazily — at most once per call, only when a templated
// op actually fires — so a config of plain static headers does zero extra work.
func applyHeaderRules(rules []headerRule, ctx *matchContext, cacheStatus CacheStatus, resolveStatus bool, classifiers map[string]*classifier) []HeaderOp {
	var ops []HeaderOp
	// env is a STACK local built lazily on the first templated op that fires. It is
	// addressed only to pass &env to expandTemplate (which does not retain it), so a
	// config of plain static headers never builds it and the per-request match
	// context never escapes to the heap (zero-cost-when-unused). built guards the
	// one-time lazy fill. Building it inline here — rather than via a *TemplateEnv-
	// returning helper — is what keeps it (and the captured ctx) off the heap: a
	// helper returning a pointer would force the allocation unconditionally.
	var env TemplateEnv
	built := false
	for _, r := range rules {
		if !ctx.scopeMatches(r.scope) {
			continue
		}
		for _, op := range r.ops {
			if op.Op == OpCacheStatus {
				if resolveStatus {
					ops = append(ops, HeaderOp{Op: OpSet, Name: op.Name, Value: cacheStatus.String()})
				}
				continue
			}
			if op.Op == OpCacheKey {
				// The cache key is not in this phase's match context (it is the server-held
				// RECV key), so this op carries no resolvable value here. It is surfaced on
				// the DeliverDecision (CacheKeyHeader/CacheKeyRaw) and materialized by the
				// server from the key it holds — never emitted as an op from here.
				continue
			}
			if op.ValueTpl {
				if !built {
					fillHeaderTemplateEnv(&env, ctx)
					built = true
				}
				// The classify resolver is built INLINE and passed by value (not stored
				// on env), so ctx is copied through the call and never retained — env
				// stays stack-allocatable and ctx never escapes (zero-cost-when-unused).
				op.Value = expandTemplate(op.Value, &env, classifyResolver{ctx: ctx, classifiers: classifiers})
				op.ValueTpl = false
			}
			ops = append(ops, op)
		}
	}
	return ops
}

// fillHeaderTemplateEnv populates a caller-owned TemplateEnv with the per-request
// sources a dynamic header value is expanded against: the request's host/path/query
// plus the request-scoped {http.NAME} (req.Header), {client_ip} (req.ClientIP), and
// {geo*} sources. There is no regex capture in a header-op scope, so Capture is left
// nil ($N expands to ""). {classify.NAME} is resolved separately via the classifyResolver
// passed to expandTemplate (kept OFF env so the match context never escapes). It fills
// a pointer the CALLER stack-allocates (rather than returning a fresh *TemplateEnv) so
// env stays off the heap.
func fillHeaderTemplateEnv(env *TemplateEnv, ctx *matchContext) {
	env.Host = ctx.req.normHost()
	env.Path = ctx.req.Path
	env.Query = canonicalQuery(ctx.req)
	env.Header = ctx.req.Header
	env.ClientIP = ctx.req.ClientIP
	env.Geo = ctx.req.Geo
	env.GeoContinent = ctx.req.GeoContinent
	env.GeoRegion = ctx.req.GeoRegion
}

// resolveHTTPPlaceholder resolves a "{http.NAME}" placeholder against the request
// header NAME; any other token is returned verbatim (an empty token yields "").
//
// A regex sourced from a request header (the `purge … regex {http.X-…}` form) is
// attacker-influenced, so it is bounded before use (security review #6): an
// operator literal is trusted and returned verbatim, but a request-sourced pattern
// is length-capped, must compile as RE2, and must not be a mass-flush "match
// everything" pattern. A rejected pattern yields "" — the safe default of purging
// only the request's own cache key rather than an attacker-chosen swath.
func resolveHTTPPlaceholder(token string, req *Request) string {
	if token == "" {
		return ""
	}
	if strings.HasPrefix(token, "{http.") && strings.HasSuffix(token, "}") {
		name := token[len("{http.") : len(token)-1]
		return boundRequestPurgeRegex(req.headerGet(name))
	}
	return token
}

// pathToKeyRegex rewrites a PATH-anchored purge pattern (the `regex-path EXPR`
// form, written Varnish-style against req.url, e.g. `^/nocookie`) into a pattern
// that matches the PATH component of a cache key. A cache key is a unit-separator
// (\x1f) joined token list — by default `METHOD\x1fHOST\x1fPATH…`, but the PATH may
// be the FIRST token under a custom `cache_key` (e.g. `cache_key url` or
// `cache_key path host`). The PATH token always begins with `/` and is the only
// token that can contain a `/`.
//
// Three cases:
//
//   - Leading `^` (path-start): rewritten to `(^|\x1f)` so it anchors at the start
//     of the whole key OR a token boundary. The bare `\x1f` form (finding 1) failed
//     when PATH led the key, because then no separator precedes it — `(^|\x1f)`
//     matches both placements.
//   - Unanchored AND contains `/`: passes through. Separators delimit tokens and
//     only the path token contains `/`, so it still only matches within the path.
//   - Unanchored AND slashless (e.g. `list`): WITHOUT a `/` to keep it inside the
//     path token it would also match the HOST/method tokens — an over-purge
//     (finding 2). It is anchored to the path token: `(^|\x1f)/[^\x1f]*` requires
//     the match start at a path-token boundary, after the leading `/` and any
//     non-separator chars, so it only matches text inside a single path token.
//
// RE2 has no look-around, so the boundary prefix is consumed by the match —
// harmless for an invalidation regex.
func pathToKeyRegex(pat string) string {
	if strings.HasPrefix(pat, "^") {
		return "(^|" + keyTokenSep + ")" + pat[1:]
	}
	if !strings.Contains(pat, "/") {
		// Slashless and unanchored: confine to the path token so HOST/method tokens
		// (which never contain `/`) cannot be matched.
		return "(^|" + keyTokenSep + ")/[^" + keyTokenSep + "]*" + pat
	}
	return pat
}

// boundRequestPurgeRegex validates an attacker-influenced purge ban regex. It
// returns the pattern unchanged when it is safe, or "" when it is empty, too long,
// not a valid RE2, or matches everything (a mass cache-flush vector).
func boundRequestPurgeRegex(pattern string) string {
	if pattern == "" || len(pattern) > maxRequestPurgeRegexLen {
		return ""
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	// Reject "match everything": a pattern that matches the empty string (e.g.
	// ".*", "a?") or matches a diverse set of unrelated probes (e.g. ".+", "^.*$")
	// would let an authorized caller flush the whole cache.
	if re.MatchString("") {
		return ""
	}
	probes := []string{"a", "/", "9", "x9Q_z", "GET\x1fexample.com\x1f/some/path"}
	matchedAll := true
	for _, p := range probes {
		if !re.MatchString(p) {
			matchedAll = false
			break
		}
	}
	if matchedAll {
		return ""
	}
	return pattern
}

// SpliceImports returns a shallow copy of site with every `import PATH` directive
// replaced, in source order, by the body nodes of the resolved fragment. resolve
// reads and parses PATH (resolving any NESTED imports transitively) and returns its
// statement nodes. This is the only place import I/O happens; Compile itself stays
// pure (a leftover import is an error). A self/cyclic import surfaces here as a
// positioned "import cycle: …" error, never a leaked internal compile message.
func SpliceImports(site *cadishfile.Site, resolve func(path string) ([]cadishfile.Node, error)) (*cadishfile.Site, error) {
	if site == nil {
		return nil, &CompileError{Msg: "nil site"}
	}
	out := &cadishfile.Site{Addresses: site.Addresses, Pos: site.Pos}
	for _, n := range site.Body {
		if d, ok := n.(*cadishfile.Directive); ok && d.Name == "import" {
			if len(d.Args) != 1 {
				return nil, &CompileError{Pos: d.Pos, Msg: "import needs exactly one path"}
			}
			nodes, err := resolve(d.Args[0].Raw)
			if err != nil {
				return nil, &CompileError{Pos: d.Pos, Msg: "import " + d.Args[0].Raw + ": " + err.Error()}
			}
			out.Body = append(out.Body, nodes...)
			continue
		}
		out.Body = append(out.Body, n)
	}
	return out, nil
}

// FileImportResolver returns an import resolver that reads fragments from baseDir
// (relative imports) or absolute paths, parses them, and returns their body nodes.
// It is a convenience for the server and tests; it performs filesystem I/O and is
// therefore deliberately separate from Compile.
//
// The resolver supports two behaviors beyond a single literal path:
//   - Globs: a path containing filepath.Match metacharacters (`* ? [`) splices
//     every matching file in sorted (lexical) order. A glob that matches NO files
//     is a clear error, never a silent empty splice.
//   - Transitive imports: an imported fragment may itself contain `import`
//     directives; those are resolved recursively. A cycle (a file that imports
//     itself, directly or indirectly) is reported as "import cycle: …" rather than
//     looping forever or leaving a leftover `import` for Compile to choke on.
func FileImportResolver(baseDir string) func(string) ([]cadishfile.Node, error) {
	return func(path string) ([]cadishfile.Node, error) {
		return resolveImportPath(baseDir, path, nil)
	}
}

// hasGlobMeta reports whether path contains a filepath.Match metacharacter, i.e.
// whether it should be treated as a glob rather than a literal filename.
func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// resolveImportPath reads one import path — a literal file or a glob — relative to
// baseDir, parses it, and recursively resolves any nested imports. stack is the set
// of absolute paths currently being imported on this branch (the cycle guard).
func resolveImportPath(baseDir, path string, stack []string) ([]cadishfile.Node, error) {
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(baseDir, path)
	}
	if hasGlobMeta(path) {
		matches, err := filepath.Glob(full)
		if err != nil {
			return nil, fmt.Errorf("invalid glob %q: %w", path, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("glob %q matched no files", path)
		}
		sort.Strings(matches)
		var nodes []cadishfile.Node
		for _, m := range matches {
			frag, err := resolveImportFile(m, stack)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, frag...)
		}
		return nodes, nil
	}
	return resolveImportFile(full, stack)
}

// resolveImportFile reads and parses a single fragment file (already an absolute or
// baseDir-joined path), recursively resolving its nested imports. A path already on
// stack is a cycle.
func resolveImportFile(full string, stack []string) ([]cadishfile.Node, error) {
	abs, err := filepath.Abs(full)
	if err != nil {
		abs = full
	}
	for _, s := range stack {
		if s == abs {
			return nil, fmt.Errorf("import cycle: %s is already being imported", full)
		}
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	f, err := cadishfile.Parse(full, data)
	if err != nil {
		return nil, err
	}
	// An imported fragment is a bare body (matchers + directives); some files may
	// also wrap content in sites — include those bodies too.
	raw := append([]cadishfile.Node(nil), f.Body...)
	for _, s := range f.Sites {
		raw = append(raw, s.Body...)
	}
	// Recursively resolve any nested imports, tracking this file on the stack so a
	// self/back-reference is caught as a cycle.
	dir := filepath.Dir(full)
	nextStack := append(append([]string(nil), stack...), abs)
	var out []cadishfile.Node
	for _, n := range raw {
		if d, ok := n.(*cadishfile.Directive); ok && d.Name == "import" {
			if len(d.Args) != 1 {
				return nil, fmt.Errorf("%s: import needs exactly one path", d.Pos)
			}
			frag, err := resolveImportPath(dir, d.Args[0].Raw, nextStack)
			if err != nil {
				return nil, err
			}
			out = append(out, frag...)
			continue
		}
		out = append(out, n)
	}
	return out, nil
}
