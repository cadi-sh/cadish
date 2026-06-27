package pipeline

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
	up := p.resolveUpstream(req)
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: up, memo: newMemo(stack[:], p.numMatchers)}
	var dec RequestDecision
	// Assign Upstream from the local, NOT via ctx.upstream: reading a field through the
	// ctx pointer into the returned dec makes escape analysis flow the whole matchContext
	// (and its stack-backed memo) to the heap, defeating the stack-array memo optimization.
	dec.Upstream = up

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

	// upgrade: a matching `upgrade @scope` rule marks the request as a
	// connection-upgrade tunnel candidate and IMPLIES pass (a tunnel never touches the
	// cache). The server still requires a genuine upgrade request before it actually
	// hijacks; a non-upgrade request on an upgrade route falls through as a plain pass.
	for _, sc := range p.upgradeRules {
		if ctx.scopeMatches(sc) {
			dec.Upgrade = true
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
	toks := p.selectKeyTokens(ctx)
	// Capture the SELECTED recipe on the request (Finding 1): this is the authoritative,
	// singular selection — computed on the PRE-derives_from-strip request — that every
	// later gate reuses via resolvedKeyTokens, so coverage and Vary are always judged
	// against the recipe that BUILT the key, even after StripDerivedCookies mutates the
	// request. Always overwrite (a value-copied Request re-running EvalRequest re-derives).
	if req != nil {
		req.selKey = toks
		req.selKeySet = true
	}
	dec.CacheKey = buildKey(toks, req, p.stickyCookie, ctx)
	return dec
}

// resolvedKeyTokens returns the cache-key recipe SELECTED for ctx.req: the authoritative
// selection captured by EvalRequest (computed on the pre-strip request) when present,
// otherwise a fresh selectKeyTokens for callers that never ran EvalRequest (direct unit
// tests / the conformance harness). Reusing the captured selection is the Finding 1
// safety fix — the cache key, the credential-coverage check, and the Vary decision all
// reference the same recipe, so a `derives_from` cookie stripped between EvalRequest and
// a later gate can never flip the selection to a different recipe than the one that built
// the stored key. The returned slice may be nil (no recipe matched); callers apply the
// defaultKeyTokens fallback exactly as they do for a fresh selectKeyTokens result.
func (p *Pipeline) resolvedKeyTokens(ctx *matchContext) []keyToken {
	if ctx.req != nil && ctx.req.selKeySet {
		return ctx.req.selKey
	}
	return p.selectKeyTokens(ctx)
}

// recipeTokensForReq returns the cache-key recipe SELECTED for req, with the built-in
// default applied when no rule matched. It is the credential/derives_from gates' way to
// read the recipe WITHOUT rebuilding a matchContext (R29): when EvalRequest already
// captured the selection (the server's hot path — selKeySet) the captured recipe is
// reused directly, so the redundant resolveUpstream (route-matcher re-evaluation, whose
// result resolvedKeyTokens then ignores anyway) is skipped entirely. Only a direct caller
// that never ran EvalRequest (unit tests / the conformance harness) pays the
// resolveUpstream + selectKeyTokens path — byte-for-byte the previous behavior. The
// returned slice is the same one resolvedKeyTokens(ctx)+default-fallback produced before.
func (p *Pipeline) recipeTokensForReq(req *Request) []keyToken {
	var toks []keyToken
	if req != nil && req.selKeySet {
		toks = req.selKey
	} else {
		var stack [memoStack]int8
		ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers)}
		toks = p.selectKeyTokens(ctx)
	}
	if len(toks) == 0 {
		toks = defaultKeyTokens
	}
	return toks
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
	// perResponseSignal records whether the cache_ttl rule that decided Cacheable=true derived
	// its TTL from a PER-RESPONSE ORIGIN SIGNAL — i.e. the origin affirmatively marked THIS
	// response cacheable (a `from_header NAME` whose header the origin actually SENT). A STATIC
	// operator `ttl N` (whether `default` or scoped) is NOT a per-response signal: the operator
	// fixed the TTL, the origin said nothing about THIS response. This is the SOLE gate that may
	// authorize a cache_credentialed share (see the credentialed block below) — a static TTL must
	// never let a per-user body be stored under the shared key.
	var perResponseSignal bool
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
			dec.Grace, dec.MaxStale = resolveGraceMaxStale(&r, respHeader)
			dec.StripHeaders = r.consumedHeaders()
			dec.Cacheable = true
			// The origin SENT the header — this IS a per-response origin signal, so it may
			// authorize a cache_credentialed share.
			perResponseSignal = true
			break
		}
		dec.TTL = r.ttl
		dec.Grace, dec.MaxStale = resolveGraceMaxStale(&r, respHeader)
		dec.StripHeaders = r.consumedHeaders()
		dec.Cacheable = true
		// STATIC operator TTL (`ttl N`): NOT a per-response origin signal. perResponseSignal
		// stays false ⇒ this Cacheable response can never authorize a cache_credentialed share.
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
		// Vary coverage is judged against the recipe that BUILT this request's key (the
		// selection EvalRequest captured — Finding 1), not the global union of every
		// recipe's keyed headers, and not a fresh re-selection on the post-strip request
		// (which could pick a DIFFERENT recipe than the stored key's). So a Vary the
		// stored key does not partition is correctly refused (no variant cross-serving).
		keyHeaders := keyHeaderNamesForTokens(p.resolvedKeyTokens(ctx))
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
		// cache_credentialed (D101): in an ORIGIN-AUTHORITATIVE scope caching matches the
		// custom VCL EXACTLY — a credentialed store requires a PER-RESPONSE ORIGIN CACHE SIGNAL
		// (perResponseSignal), fail-closed, and it does NOT consult cache_unsafe (Guard B):
		//   (1) The in-scope cache_ttl rule that decided dec.Cacheable derived its TTL from a
		//       per-response origin signal — `from_header X-Cache-Ttl` whose header the origin
		//       SENT (or, if such a rule kind is ever added, an origin Cache-Control max-age/
		//       s-maxage). The origin affirmatively marked THIS response cacheable ⇒ STORE under
		//       the SHARED key, and the signal FORCE-OVERRIDES and STRIPS both the per-user
		//       `Set-Cookie` AND the weak refusals the shared readmodel bodies carry (Cache-
		//       Control no-store/private/no-cache, Pragma: no-cache, a past Expires) — the VCL
		//       `if (X-Cache-Ttl) { unset set-cookie; unset Cache-Control; set ttl }`. The server
		//       strips them from BOTH the stored entry AND the delivered response (see
		//       CredentialedStore), so the shared entry carries no per-user credential and cadish
		//       never replays a no-store it just cached. We do NOT refuse on Set-Cookie or on an
		//       uncovered/`*` Vary: the affirmative signal is the operator's explicit "this is
		//       shared, drop the cookie" opt-in (faithful to Varnish, NOT stricter). NOT marked
		//       ForcedPrivate — a deliberate opt-in to SHARE.
		//   (2) else — no per-response signal — we FALL THROUGH to the normal shareability
		//       refusal below. A STATIC operator `ttl N` (default or scoped) makes dec.Cacheable
		//       true but is NOT a per-response signal: it does NOT authorize a credentialed share.
		//       Without this gate, a co-existing `cache_ttl default ttl 60s` would mark a per-user
		//       `favorites` response (Set-Cookie, no X-Cache-Ttl) Cacheable, store it under the
		//       SHARED key with Set-Cookie stripped, and leak one user's private body to another
		//       (a confirmed cross-user leak). The per-response signal — not merely dec.Cacheable
		//       — is the sole storage gate, so a per-user route that merely omits the marking is
		//       never shared-cached. THIS is the fail-closed property (same trust model as the
		//       custom VCL: a per-user route that erroneously emits X-Cache-Ttl is an operator
		//       bug, exactly as in Varnish).
		if req != nil && perResponseSignal && p.cacheCredentialedMatches(ctx) {
			// Positive in-scope signal (dec.Cacheable) is the gate; store and strip Set-Cookie +
			// the weak controls on store+deliver. cache_unsafe is never consulted here (Guard B).
			dec.CredentialedStore = true
		} else {
			setCookieBlocks := hasSetCookie(respHeader) && !p.stripCookiesMatches(ctx)
			shareable := p.safelyShareable(respHeader, keyHeaders)
			if varyStar(respHeader) || setCookieBlocks || (!p.cacheUnsafe && !shareable) {
				dec.Cacheable = false
				dec.TTL = 0
				dec.Grace = 0
				dec.MaxStale = 0
			} else if p.cacheUnsafe && !shareable {
				// The store survives ONLY because cache_unsafe overrode an unshareable origin
				// Cache-Control (private/no-store/no-cache/s-maxage=0). Cache it (the operator's
				// opt-in) but flag it so the server advertises `private, max-age=N` downstream
				// rather than promoting it to `public` (R13/D96) — shared caches must still
				// refuse a response the origin marked confidential.
				dec.ForcedPrivate = true
			}
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

// resolveGraceMaxStale computes the effective grace and max_stale windows for a TTL
// rule. Each is sourced from its configured origin response header when present and
// parseable (reusing headerTTL — same seconds-as-int convention, non-positive
// rejection, and one-year clamp as the header TTL), otherwise falling back to the
// rule's literal `grace` / `max_stale`. The max_stale >= grace invariant is enforced
// against the RESOLVED values: an effective max_stale below the effective grace is
// IGNORED (no error-fallback window) rather than erroring at runtime, since grace
// already serves that span.
func resolveGraceMaxStale(r *ttlRule, respHeader http.Header) (grace, maxStale time.Duration) {
	grace = r.grace
	if r.graceFromHeader != "" {
		if g, ok := headerTTL(respHeader, r.graceFromHeader); ok {
			grace = g
		}
	}
	maxStale = r.maxStale
	if r.maxStaleFromHeader != "" {
		if ms, ok := headerTTL(respHeader, r.maxStaleFromHeader); ok {
			maxStale = ms
		}
	}
	if maxStale > 0 && maxStale < grace {
		maxStale = 0
	}
	return grace, maxStale
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
		// A `derives_from` cookie whose classify token is in some cache_key recipe must
		// SURVIVE the allow-list strip so the classifier reads the ORIGINAL value and the
		// key is built from it; StripDerivedCookies then removes it post-key (and
		// reconciles it to this same allow-list rule when its token is NOT in the selected
		// recipe). So keep it here even when it is not allow-listed.
		if !p.cookieAllow.match(c.name) && !p.derivedSurviveCookies[c.name] {
			continue // not allow-listed and not a surviving axis input → stripped
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

// HasDerivesFrom reports whether ANY classify token that feeds a cache_key recipe
// declares `derives_from cookie …`. The server gates the post-key cookie strip on this
// so a site without the feature pays exactly one nil check and the request path is
// byte-for-byte unchanged (COOKIE-NORM is opt-in, zero-cost when unused).
func (p *Pipeline) HasDerivesFrom() bool { return len(p.derivedSurviveCookies) > 0 }

// SelectedDerivedStripCookies returns the sorted set of request cookies the ACTIVE
// `derives_from` axes consume for THIS request — i.e. the cookies declared by every
// classify {TOKEN} present in the recipe SELECTED for the request (the per-request
// gate). These are the cookies Varnish would `unset` after deriving its VARY-* axes:
// they were read to build the key and must now leave the request before the origin
// fetch. Empty when no derives_from token is in the selected recipe. Pure (no mutation)
// so the edge/conformance can compute the identical set.
func (p *Pipeline) SelectedDerivedStripCookies(req *Request) []string {
	if len(p.derivedSurviveCookies) == 0 {
		return nil
	}
	// Reuse the recipe EvalRequest captured when available (Finding 1) so the strip set is
	// derived from the SAME recipe that built the key, WITHOUT recomputing routing (R29);
	// recipeTokensForReq falls back to a fresh selection for direct callers. The cookie is
	// still present at strip time, so a fresh selection would pick the same recipe anyway —
	// this keeps the single-authoritative-selection invariant.
	toks := p.recipeTokensForReq(req)
	var names []string
	seen := map[string]bool{}
	for _, t := range toks {
		if t.kind != tokClassify || t.clsf == nil {
			continue
		}
		for _, c := range t.clsf.derivesFrom {
			// A `forward` (alias `keep`) cookie is NOT stripped — it is forwarded to origin
			// unchanged and covered by {TOKEN}. Only strip-mode cookies leave here.
			if t.clsf.isForwardCookie(c) {
				continue
			}
			if !seen[c] {
				seen[c] = true
				names = append(names, c)
			}
		}
	}
	sort.Strings(names)
	return names
}

// SelectedDerivedForwardCookies returns the sorted set of request cookies the ACTIVE
// `derives_from … forward` axes FORWARD to origin for THIS request — i.e. the forward-mode
// cookies declared by every classify {TOKEN} present in the recipe SELECTED for the request.
// These are read to derive + key but, unlike strip-mode cookies, are KEPT in the request
// (forwarded to origin) and treated as COVERED by {TOKEN} in the credential bypass — the
// loud opt-in for cookie-reading backends. Empty when no forward axis is in the selected
// recipe. Pure (no mutation) so the edge/conformance compute the identical set. The gate is
// the SAME as strip-mode (token in the selected recipe): a forward cookie whose axis is NOT
// selected is NOT returned here, so it is never covered — it bypasses like any kept cookie.
func (p *Pipeline) SelectedDerivedForwardCookies(req *Request) []string {
	if len(p.derivedSurviveCookies) == 0 {
		return nil
	}
	// Reuse the captured recipe WITHOUT recomputing routing (R29); recipeTokensForReq
	// falls back to a fresh selection for direct callers.
	toks := p.recipeTokensForReq(req)
	var names []string
	seen := map[string]bool{}
	for _, t := range toks {
		if t.kind != tokClassify || t.clsf == nil {
			continue
		}
		for _, c := range t.clsf.derivesForward {
			if !seen[c] {
				seen[c] = true
				names = append(names, c)
			}
		}
	}
	sort.Strings(names)
	return names
}

// StripDerivedCookies removes, from req's Cookie header, the cookies consumed by the
// ACTIVE `derives_from` axes (those whose token is in the SELECTED cache_key recipe) —
// the derive→strip half of the Varnish cardinality collapse. The server calls it AFTER
// the cache key is captured but BEFORE the credential check and the origin fetch, so:
//
//   - the key (incl. {TOKEN}) was already built from the ORIGINAL cookie value, and
//   - the credential bypass (BypassForCredentials) and the origin both see the request
//     with the per-user cookie GONE — so the origin reply is anonymous w.r.t. the axis
//     and is safely stored under the collapsed (shared) key. This is the SINGLE
//     fail-closed mechanism: nothing teaches the coverage check to treat the token as
//     covering the cookie; the cookie is simply absent, so no bypass fires for it.
//
// It also RECONCILES the survive-set: a `derives_from` cookie that was force-kept
// through cookie_allow (so the classifier could read it) but whose token is NOT in the
// selected recipe is stripped iff cookie_allow would have stripped it — restoring
// exactly the behavior a site without the feature would have for that request (the
// gate). It returns whether it modified the Cookie header (for trace/fast-path).
func (p *Pipeline) StripDerivedCookies(req *Request) bool {
	if len(p.derivedSurviveCookies) == 0 || req == nil || req.Header == nil {
		return false
	}
	active := map[string]bool{}
	for _, c := range p.SelectedDerivedStripCookies(req) {
		active[c] = true
	}
	// Active forward-mode cookies (token in the selected recipe) are FORWARDED, never
	// stripped — they were read + keyed but the operator opted them into reaching origin.
	activeForward := map[string]bool{}
	for _, c := range p.SelectedDerivedForwardCookies(req) {
		activeForward[c] = true
	}
	cs := req.lenientCookies()
	if len(cs) == 0 {
		return false
	}
	// Decide per cookie whether it must be removed. Only survive-set cookies (the ones
	// force-kept for derivation) are subject to this; every other cookie is left exactly
	// as cookie_allow / the raw request left it.
	remove := func(name string) bool {
		if !p.derivedSurviveCookies[name] {
			return false // not an axis input we force-kept → untouched
		}
		if activeForward[name] {
			return false // active FORWARD axis input → keep (forwarded to origin, covered)
		}
		if active[name] {
			return true // active strip axis input → derive-then-strip
		}
		// Force-kept but its token is not in the selected recipe: reconcile to
		// cookie_allow's rule (strip iff cookie_allow would have, i.e. not allow-listed).
		// With no cookie_allow it was never force-stripped today, so keep it (and let the
		// credential bypass handle it) — fail-closed, never a silent shared store.
		return p.cookieAllow != nil && !p.cookieAllow.match(name)
	}
	changed := false
	var b strings.Builder
	for _, c := range cs {
		if remove(c.name) {
			changed = true
			continue
		}
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.name)
		b.WriteByte('=')
		b.WriteString(c.value)
	}
	if !changed {
		return false // no axis input present → leave the header (and its formatting) alone
	}
	if b.Len() == 0 {
		req.Header.Del("Cookie")
	} else {
		req.Header.Set("Cookie", b.String())
	}
	return true
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
	// Check the recipe that BUILT this request's key covers every credential it carries.
	// resolvedKeyTokens reuses the selection EvalRequest captured (Finding 1) — NOT a fresh
	// re-selection on the now-derives_from-stripped request, which could pick a different
	// recipe than the stored key's and validate coverage against the wrong key (a leak). A
	// scoped cache_key may key by a credential only for some requests, so the recipe must be
	// the one that owns this request's key. recipeTokensForReq reuses the captured selection
	// WITHOUT recomputing routing on the hot credentialed path (R29).
	toks := p.recipeTokensForReq(req)
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
	//
	// COOKIE-NORM forward mode: a `derives_from … forward` cookie REMAINS in the request
	// (unlike strip-mode, which removed it before this check), so without help it would look
	// like an un-keyed credential and force a bypass. We treat it as COVERED — but ONLY when
	// its axis is in the SELECTED recipe (SelectedDerivedForwardCookies applies the same gate
	// as the key), so the cookie is ALWAYS keyed via {TOKEN}: no shared-key leak along the
	// keyed axis. This is the single re-introduced coverage rule, scoped to a cookie that is
	// both keyed (by its token) AND explicitly opted into forward. Any OTHER cookie (a second
	// identity cookie, a forward cookie whose axis is NOT selected) is NOT in this set, so it
	// still bypasses — fail-closed.
	var forwardCovered map[string]bool
	if fc := p.SelectedDerivedForwardCookies(req); len(fc) > 0 {
		forwardCovered = make(map[string]bool, len(fc))
		for _, c := range fc {
			forwardCovered[c] = true
		}
	}
	if hasCookie && !keyCoversAllCookies(toks, req, forwardCovered) {
		return true
	}
	return false
}

// HasCacheCredentialed reports whether the site declares any `cache_credentialed @scope`
// directive. The server gates the whole origin-authoritative path on this so a site without
// it pays exactly one len check and the credential-bypass hot path is byte-for-byte
// unchanged (the directive is opt-in and zero-cost when unused).
func (p *Pipeline) HasCacheCredentialed() bool { return len(p.credentialedRules) > 0 }

// CacheCredentialedMatches reports whether req matches a `cache_credentialed @scope`
// directive — i.e. caching is ORIGIN-AUTHORITATIVE for it (D101). The SERVER calls this at
// the credential-bypass decision: when true it does NOT call/short-circuit
// BypassForCredentials (so a Cookie/Authorization request is NOT bypassed) and restores the
// original cookies onto the OUTBOUND origin request (origin auth, not the cache key — the
// entry stays under the SHARED key). Mirrors BypassForCredentials' server+edge split: a
// serving-tier policy toggled by a matcher, NOT baked into EvalRequest's snapshot, so
// portable rule eval / cache key / matchers are unchanged. Returns false immediately when no
// directive is declared (zero cost). The matchers are request-phase (response-phase rejected
// at compile), so a path/host scope evaluates identically here and in EvalResponse.
func (p *Pipeline) CacheCredentialedMatches(req *Request) bool {
	if len(p.credentialedRules) == 0 || req == nil {
		return false
	}
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: p.resolveUpstream(req), memo: newMemo(stack[:], p.numMatchers)}
	return p.cacheCredentialedMatches(ctx)
}

// cacheCredentialedMatches is the shared scope evaluation used by CacheCredentialedMatches
// (server) and EvalResponse (the in-scope precedence). It is an OR over the compiled
// `cache_credentialed` scopes, evaluated through the caller's memoized context.
func (p *Pipeline) cacheCredentialedMatches(ctx *matchContext) bool {
	for _, sc := range p.credentialedRules {
		if ctx.scopeMatches(sc) {
			return true
		}
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
//
// forwardCovered names the cookies a `derives_from … forward` axis SELECTED for this
// request keys via {TOKEN} (the caller computes it under the same recipe gate). Such a
// cookie is keyed by its normalized axis, so it is treated as covered HERE even though no
// raw `cookie:NAME` token names it — the loud opt-in for forwarding a cookie to origin
// under a collapsed key. It is nil/empty on every non-forward request (zero cost).
//
// Duplicate occurrences are handled by HOW the cookie is covered (fail-closed except the
// one proven-safe case):
//   - RAW `cookie:NAME`-keyed, sent more than once → NOT covered (bypass). The token keys
//     on net/http's FIRST occurrence while the origin receives ALL, so two users sharing
//     the first value but differing on a later one collide on one entry → genuine leak.
//   - FORWARD-covered ONLY (covered solely via a selected `derives_from … forward` token):
//     the key is a DERIVED `classify` axis, not the raw value, so the keyed axis is
//     occurrence-independent. Sent more than once it is safely covered IFF every
//     occurrence's value is byte-identical (the derived axis is the same for all AND the
//     origin sees N identical values — no divergence). If the occurrences DIFFER, the
//     classifier may have read a specific one → genuinely ambiguous → bypass.
//   - BOTH raw-keyed AND forward-covered, sent more than once → the raw-keyed rule WINS
//     (the raw value enters the key) → bypass. Fail-closed precedence.
func keyCoversAllCookies(toks []keyToken, req *Request, forwardCovered map[string]bool) bool {
	keyed := map[string]struct{}{}
	for _, t := range toks {
		if t.kind == tokHeader && strings.EqualFold(t.arg, "Cookie") {
			return true // whole Cookie header keyed → every cookie (and every value) covered
		}
		if t.kind == tokCookie {
			keyed[t.arg] = struct{}{}
		}
	}
	// Read ALL occurrences (name + value) the SAME lenient way the key and origin see them,
	// so the byte-identical comparison below sees every occurrence's value, not just the
	// first. order preserves first-seen order for a stable, allocation-light walk.
	cookies := req.lenientCookies()
	if len(cookies) == 0 {
		return false // a non-empty but unparseable Cookie header is not safely covered
	}
	values := make(map[string][]string, len(cookies))
	order := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if _, seen := values[c.name]; !seen {
			order = append(order, c.name)
		}
		values[c.name] = append(values[c.name], c.value)
	}
	for _, n := range order {
		_, isKeyed := keyed[n]
		if !isKeyed && !forwardCovered[n] {
			return false // not in the key and not a forward-covered axis → cannot safely share
		}
		vals := values[n]
		if len(vals) <= 1 {
			continue // single occurrence → covered (the common path)
		}
		if isKeyed {
			// Raw-keyed (alone or also forward-covered): the raw value enters the key,
			// which captures only the first occurrence → bypass, fail-closed precedence.
			return false
		}
		// Forward-covered ONLY: safe iff every occurrence is byte-identical (the derived
		// axis is occurrence-independent and the origin sees N identical values → no
		// divergence possible). Any differing occurrence → genuinely ambiguous → bypass.
		if !allEqualStrings(vals) {
			return false
		}
	}
	return true
}

// allEqualStrings reports whether every element of vs equals the first (vs is non-empty at
// the only call site). Used by keyCoversAllCookies to decide whether duplicate
// forward-covered cookie occurrences carry identical (byte-equal) values.
func allEqualStrings(vs []string) bool {
	for _, v := range vs[1:] {
		if v != vs[0] {
			return false
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
// they permit caching while FRESH and only forbid serving STALE without revalidation.
// cadish's serve-stale behavior is OPERATOR-AUTHORITATIVE (ADR D97): by DEFAULT no
// `grace` is configured (`grace 0`), so a stale object is never served — `must-revalidate`
// is honored as a matter of course (the object revalidates on its next request). A stale
// object is served ONLY when the operator EXPLICITLY opts into a `grace`/`max_stale`
// window, and that explicit decision is authoritative over the origin's `must-revalidate`
// (just as `cache_ttl` overrides the origin's `max-age`). cadish therefore does not store
// or act on the directive here — recording it to override an explicit operator grace would
// invert the authority model and let an origin silently defeat the operator's `grace`.
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
	if ctx.req.TLS {
		env.Scheme = "https"
	} else {
		env.Scheme = "http"
	}
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
	// Parse the fragment with the site-body grammar (ParseFragment), NOT the
	// top-level file grammar: a brace-bodied directive (classify {…}, upstream {…},
	// tls {…}, …) must associate its body into a Directive.Block exactly as it would
	// inline at the splice point, never be mis-read as a site header and flattened.
	raw, err := cadishfile.ParseFragment(full, data)
	if err != nil {
		return nil, err
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
