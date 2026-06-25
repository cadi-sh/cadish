package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/geo"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/pipeline"
	"github.com/cadi-sh/cadish/internal/ratelimit"
)

// boundSite is a runtime site. The cache store and pipeline live on the
// config.Site; the routing table (internal/server) owns how it is bound.
type boundSite struct {
	*config.Site
}

// originFor selects the origin for a routed upstream name, falling back to the
// site default when the name is empty or unknown.
func (b *boundSite) originFor(name string) origin.Origin {
	if name != "" {
		if o, ok := b.Origins[name]; ok {
			return o
		}
	}
	return b.Origin
}

// rateLimitKey namespaces a pipeline-computed bucket key under this site, so two
// sites sharing the handler's single limiter never collide on the same key. The
// site's first address is a stable per-site identity (the routing key); a site with
// no address falls back to a constant (single-site configs still bucket correctly
// because the pipeline key already embeds the rule id and the keyed dimension).
func (b *boundSite) rateLimitKey(key string) string {
	site := ""
	if len(b.Addresses) > 0 {
		site = b.Addresses[0]
	}
	return site + "\x00" + key
}

// reqInfo accumulates per-request facts for the access log, populated as the
// request flows through the lifecycle.
type reqInfo struct {
	cacheStatus string // HIT / MISS / HIT-STALE / PASS / "" (error before classify)
	upstream    string
	// tr is the per-request transaction-trace record (nil when tracing is off, in
	// which case every hook on it is a no-op). It rides on reqInfo so the deep
	// serve helpers can record their decisions without a signature change. See
	// tracer.go.
	tr *traceRecord
}

// hopByHop are connection-scoped headers that must not be copied between the client
// and origin (RFC 7230 §6.1).
var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// canonicalizeRequestCookies collapses a multi-line Cookie request header into a single
// line so every downstream reader sees identical cookies regardless of how the client framed
// them. The hot path (zero or one Cookie line — the overwhelming common case) is a no-op.
// It JOINS the raw lines with "; " (RFC 6265's single-header form) rather than re-parsing
// via net/http: net/http's cookie parser rejects values containing JSON octets ('{', '"',
// ':'), which the lenient `cookie_json` matcher must still see, so a rebuild could silently
// drop a cookie and reopen a gate-bypass. Joining preserves every byte. See the call site:
// this MUST run before the security gate, the credential bypass, the cache key, and origin.
func canonicalizeRequestCookies(h http.Header) {
	lines := h["Cookie"]
	if len(lines) <= 1 {
		return // 0 or 1 line: nothing to collapse, and Get already agrees with Cookies()
	}
	h["Cookie"] = []string{strings.Join(lines, "; ")}
}

// ServeHTTP implements the cadish request lifecycle: site selection, EvalRequest
// (respond/purge/pass/key), LOOKUP (fresh/stale/miss), ORIGIN (coalesced fetch +
// serve-and-cache), and DELIVER (header ops, cache-status).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	info := &reqInfo{}
	// Start a transaction trace (nil + every hook a no-op when -trace is off).
	info.tr = h.tracer.begin(methodOf(r), r.Host, r.URL.Path)

	site, strictReject := h.selectSite(r.Host)
	defer func() {
		dur := time.Since(start)
		h.logRequest(r, rec, info, dur)
		info.tr.flush(rec.status, info.cacheStatus, dur)
	}()
	// Panic recovery (DoS / crash-safety): a panic anywhere in the request lifecycle
	// is recovered HERE rather than only by net/http's per-connection guard (which
	// resets the connection and dumps a stack to stderr). We answer the client with a
	// clean 500 (only if nothing has been written yet — a panic mid-body can't be
	// turned into a 500), count it, and log it. Re-panic is deliberately NOT done: we
	// own the recovery. This defer is registered AFTER the logging defer so it runs
	// FIRST (LIFO), letting logRequest/flush observe the final 500 status. The
	// coalesce-winner path (serveMiss) wraps its own finish() in a defer so a winner's
	// panic still wakes waiters before unwinding to this guard.
	defer func() {
		if v := recover(); v != nil {
			h.metrics.IncInternalError()
			if !rec.wroteHeader {
				writeStatus(rec, http.StatusInternalServerError, "internal error")
			}
			if h.log != nil {
				h.log.Error("recovered panic in ServeHTTP", "panic", v, "method", methodOf(r), "host", r.Host, "path", r.URL.Path)
			}
		}
	}()

	if site == nil {
		// strict_host: the Host matched no declared site address and the lenient
		// single-site fallback was suppressed. 421 Misdirected Request (RFC 9110) is
		// the correct answer — the request reached a server that is not configured to
		// produce a response for this authority — and it never opens a cache entry for
		// an undeclared Host (Host-confusion / cache-poisoning hardening).
		if strictReject {
			writeStatus(rec, http.StatusMisdirectedRequest, "no site configured for host")
			return
		}
		// No declared site matched (lenient, non-strict_host case). The core server answers
		// 502 Bad Gateway; the Gateway data plane opts into 404 (GW-P1) via
		// Options.UnmatchedHostStatus so a Gateway API client sees the expected not-found. The
		// override is gateway-scoped — the core server leaves unmatchedHostStatus at 0.
		status := http.StatusBadGateway
		if h.unmatchedHostStatus != 0 {
			status = h.unmatchedHostStatus
		}
		writeStatus(rec, status, "no site configured for host")
		return
	}

	// Optional request-body cap (DoS): when an operator set MaxRequestBodyBytes, wrap
	// a body-carrying request's body in http.MaxBytesReader so an oversized client
	// upload makes the body read fail (the request is aborted upstream, surfacing as a
	// 5xx) rather than being relayed unbounded to upstream.
	// Gated on maxBodyBytes>0 AND a body-carrying method, so the hot GET HIT path (no
	// body, cap usually unset) takes ZERO extra work; default unset = stream unbounded
	// (the media-proxy use case). The underlying ResponseWriter (w, not rec) is passed
	// so net/http can close the connection on overflow.
	if h.maxBodyBytes > 0 && r.Body != nil {
		if m := methodOf(r); m != http.MethodGet && m != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
		}
	}

	preq := buildPipelineRequest(r)
	// {client_ip} (header stamp + cache_key) and the {sticky} client-ip fallback must
	// mean the REAL client behind a trusted proxy, not the immediate peer — the SAME
	// trust_proxy/XFF resolution as {geo} and the `ip` ACL (D4). Without this, a site
	// behind an LB stamps every request with the LB's socket address (and sticky-by-IP
	// pins all clients to one backend). Gated on a configured trust_proxy set: with
	// none, the socket peer IS the client and buildPipelineRequest's value stands
	// (zero cost on directly-exposed sites).
	if len(site.TrustedProxies) > 0 {
		if ip := geo.ClientIP(r.RemoteAddr, r.Header, site.TrustedProxies); ip.IsValid() {
			preq.ClientIP = ip.String()
		}
	}
	// geo pre-pass: resolve the real client IP (trusted-proxy aware) and the geo
	// classes, only when the site varies on geo (a {geo}/{geo.continent}/{geo.region}
	// token or a `geo` matcher — all gated by UsesGeoToken) and a geo source is
	// configured. Continent is derived from the country via an in-tree table (no
	// GeoIP dep); region comes from a configured upstream header (no bundled GeoIP DB).
	// Runs at most once per request (guarded by geoResolved) so a security gate that
	// uses a geo matcher can hoist it before EvalSecurity without paying for it twice.
	geoResolved := false
	resolveGeo := func() {
		if geoResolved || site.Geo == nil || !site.Pipeline.UsesGeoToken() {
			return
		}
		geoResolved = true
		ip := geo.ClientIP(r.RemoteAddr, r.Header, site.TrustedProxies)
		// Header-sourced geo (CF-IPCountry / CF-Region) is client-spoofable, so honor
		// it ONLY when the immediate peer is a trusted proxy — the same trust model as
		// X-Forwarded-For / geo.ClientIP. From an untrusted/direct peer we pass a nil
		// header so a header source returns Unknown (no geo-fence bypass, no
		// attacker-chosen {geo} cache bucket); an IP-DB source still resolves off the
		// trusted-proxy-aware client IP, unaffected. With no trust_proxy the peer is
		// never trusted, so header geo requires trust_proxy by design.
		hdr := r.Header
		if !geo.PeerTrusted(r.RemoteAddr, site.TrustedProxies) {
			hdr = nil
		}
		preq.Geo = site.Geo.Lookup(ip, hdr)
		preq.GeoContinent = geo.Continent(preq.Geo)
		if site.GeoRegion != nil {
			preq.GeoRegion = site.GeoRegion.Lookup(ip, hdr)
		}
	}
	// COOKIE CANONICALIZATION (security, cross-user leak): collapse a multi-line Cookie
	// header into ONE line BEFORE anything reads it — the security gate, the credential
	// bypass, the cache key, and the origin fetch. A raw client can split its cookies across
	// several Cookie header lines (`Cookie:\r\nCookie: session=…`); net/http keeps them as
	// r.Header["Cookie"] = ["", "session=…"], where Header.Get returns only the FIRST line
	// (""), while Cookies() parses ALL lines. That divergence let an empty first line hide a
	// session from any Get-based reader (the bypass, the header:Cookie key token, the
	// cookie_json gate) while the origin still saw it — caching a private body under a
	// shared key. Joining the raw lines (not re-parsing via net/http, which would drop a
	// JSON cookie value the cookie_json matcher must still see) makes every reader agree.
	canonicalizeRequestCookies(r.Header)

	// SECURITY GATE: the FIRST step of RECV (design §1/§3). It runs before the cache
	// key is computed, before the cache is consulted, and before the origin is dialed,
	// so an enforced `deny` touches NEITHER cache NOR origin. The whole gate is skipped
	// (one cheap branch) when the site configures no allow/deny rules (zero cost).
	// Security is SERVER-ONLY — this gate never runs at Cadish Edge (design §2.15).
	if site.Pipeline.UsesSecurityGate() {
		// Resolve the REAL client IP for the `ip` matcher via the SAME trusted-proxy/XFF
		// logic as {geo} (decision #16) — never the immediate peer. Done only when a
		// security gate is configured (gated above), so non-security sites pay nothing.
		preq.RealClientIP = geo.ClientIP(r.RemoteAddr, r.Header, site.TrustedProxies)
		// A geo-based allow/deny matcher reads preq.Geo/GeoContinent/GeoRegion; those
		// must be populated BEFORE EvalSecurity or the matcher sees "" and silently
		// fails open. Resolve the geo classes up front when the site uses a geo token;
		// resolveGeo is idempotent so the pre-pass below is then a no-op.
		resolveGeo()
		sec := site.Pipeline.EvalSecurity(preq)
		info.tr.note("SECURITY", securityTrace(sec))
		switch {
		case sec.Block:
			info.cacheStatus = "DENY"
			h.metrics.RecordSecurity("deny", sec.Rule)
			h.audit(r, "deny", true, sec.Rule, preq.RealClientIP.String(), sec.Status)
			writeStatus(rec, sec.Status, "forbidden")
			return
		case sec.Monitor:
			// monitor mode: a deny WOULD have fired; record the would-block and pass.
			h.metrics.RecordSecurity("monitor", sec.Rule)
			h.audit(r, "deny", false, sec.Rule, preq.RealClientIP.String(), sec.Status)
			if h.log != nil {
				h.log.Warn("security would-block (monitor)", "rule", sec.Rule, "host", r.Host, "path", r.URL.Path, "client", preq.RealClientIP.String())
			}
		case sec.Allow:
			h.metrics.RecordSecurity("allow", sec.Rule)
		case sec.RateLimit != nil:
			// RATE LIMIT (WAF v1b): the pure gate identified the rule + computed the
			// bucket key; the server's in-memory token bucket does the counting. The key
			// is namespaced per site so two sites never share a bucket. On a throttle we
			// return 429 + Retry-After, touching NEITHER cache NOR origin (same guarantee
			// as deny). In monitor mode we record a would-429 and PASS.
			hit := sec.RateLimit
			d := h.limiter.Allow(site.rateLimitKey(hit.Key), ratelimit.Rule{RatePerSec: hit.RatePerSec, Burst: hit.Burst})
			info.tr.note("RATELIMIT", rateLimitTrace(hit, d))
			if !d.OK {
				if hit.Monitor {
					h.metrics.RecordRateLimit("monitor", hit.Rule)
					h.audit(r, "ratelimit", false, hit.Rule, preq.RealClientIP.String(), http.StatusTooManyRequests)
					if h.log != nil {
						h.log.Warn("rate limit would-429 (monitor)", "rule", hit.Rule, "host", r.Host, "path", r.URL.Path, "client", preq.RealClientIP.String())
					}
				} else {
					info.cacheStatus = "RATELIMIT"
					h.metrics.RecordRateLimit("throttle", hit.Rule)
					h.audit(r, "ratelimit", true, hit.Rule, preq.RealClientIP.String(), http.StatusTooManyRequests)
					rec.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(d.RetryAfter)))
					writeStatus(rec, http.StatusTooManyRequests, "too many requests")
					return
				}
			} else {
				h.metrics.RecordRateLimit("pass", hit.Rule)
			}
		}
	}
	// {device} pre-pass: classify the User-Agent into a bounded device class for
	// the cache key, but only when the site's key actually varies on it.
	if site.Device != nil && site.Pipeline.UsesDeviceToken() {
		preq.Device = site.Device.Classify(r.UserAgent())
	}
	// cookie_allow: strip every request cookie not on the operator's allowlist, AFTER the
	// security gate (so `deny`/`allow` cookie rules saw the originals) but BEFORE the cache
	// key, the credential bypass, and the origin fetch — so all three see only the
	// controlled cookies. Stripping the rest (incl. any session) is what makes caching the
	// cookie-bearing request safe. preq.Header is r.Header, so the forwarded origin request
	// inherits the filtered Cookie too.
	if filtered, active := site.Pipeline.FilterRequestCookies(r.Header.Get("Cookie")); active {
		if filtered == "" {
			r.Header.Del("Cookie")
		} else {
			r.Header.Set("Cookie", filtered)
		}
	}

	// geo pre-pass for the cache key / `geo` matchers in EvalRequest. Idempotent:
	// a no-op when the security gate above already resolved geo for its matcher.
	resolveGeo()
	rd := site.Pipeline.EvalRequest(preq)
	info.tr.recv(rd)         // RECV decision: route/pass/respond/purge + req-header ops
	info.tr.key(rd.CacheKey) // KEY: computed cache key

	// respond: synthetic short-circuits cache + origin.
	if rd.Synthetic != nil {
		info.cacheStatus = "SYNTH"
		body := rd.Synthetic.Body
		rec.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rec.Header().Set("Content-Length", strconv.Itoa(len(body)))
		rec.WriteHeader(rd.Synthetic.Status)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(rec, body)
		}
		return
	}

	// redirect: a computed 3xx (from a `redirect` rule) likewise short-circuits
	// cache + origin. The pipeline already built the Location from the request.
	if rd.Redirect != nil {
		info.cacheStatus = "REDIRECT"
		rec.Header().Set("Location", rd.Redirect.Location)
		rec.Header().Set("Content-Length", "0")
		rec.WriteHeader(rd.Redirect.Status)
		return
	}

	// purge: an authorized purge invalidates the freshness marker(s) so the next
	// matching request revalidates. Two forms:
	//   - no regex  → forget this request's OWN cache key (single-key purge).
	//   - regex EXPR → register a cache-wide BAN (backlog #22, Varnish ban-lurker
	//     parity): every cached key matching EXPR that was stored before now is
	//     invalidated lazily on its next lookup (O(1) purge, no store scan). The
	//     pattern is already bounded for a request-sourced regex (pipeline
	//     boundRequestPurgeRegex), so an over-broad pattern arrives empty here and
	//     falls back to the safe single-key purge.
	// NOTE: the cache.Store exposes no key-delete, so a blob may linger until
	// evicted; dropping/superseding the freshness entry forces revalidation, which is
	// the observable purge effect. True eviction is a separate seam.
	if rd.Purge != nil {
		info.cacheStatus = "PURGE"
		banned := false
		matched := -1 // -1 = count unknown (single-key forget); >=0 = ban match count
		if rd.Purge.Regex != "" {
			if re, err := regexp.Compile(rd.Purge.Regex); err == nil {
				matched = h.fresh.ban(re)
				banned = true
				info.tr.note("PURGE", "ban "+rd.Purge.Regex)
			}
		}
		if !banned && rd.CacheKey != "" {
			h.fresh.forget(rd.CacheKey)
		}
		// Surface the matched count so an operator can tell a real invalidation from
		// a no-op (a regex that compiled but matched nothing — gap G1). For a ban,
		// it is the number of live freshness entries invalidated; matched==0 means
		// the pattern matched NOTHING indexed. Omitted for a single-key forget,
		// where there is nothing to count.
		if matched >= 0 {
			rec.Header().Set("X-Purge-Count", strconv.Itoa(matched))
		}
		writeStatus(rec, http.StatusOK, "purged")
		return
	}

	// SAFE BY DEFAULT (security, AUTH-LEAK/COOKIE-LEAK): an explicit `pass` rule OR a
	// request carrying a credential the cache key does not cover (Authorization, or a
	// Cookie not exempted by `cookie_allow` — see BypassForCredentials) bypasses the
	// shared cache, never serving from / storing to it. Without the credential bypass a
	// private response for one user's cookie/token leaks to every other user. `cache_unsafe`
	// does NOT lift this — only keying by the credential, or `cookie_allow`-controlling the
	// cookie, does. Applied here (not in EvalRequest) so the portable pipeline decision stays
	// unchanged; the edge worker enforces the same rule.
	if rd.Pass || site.Pipeline.BypassForCredentials(preq) {
		info.cacheStatus = "PASS"
		info.tr.lookup("PASS (bypass cache)")
		h.serveOrigin(rec, r, site, preq, rd, "", false, pipeline.CacheStatusMiss, info)
		return
	}

	key := rd.CacheKey

	// CLUSTER seam (#8 ownership routing): when this site is clustered and we are not
	// the OWNER of this object, reverse-proxy to the owner so the object is cached
	// once per region. Ownership is keyed on the request path (the same key #7's
	// peer read-through shards on), so #7 and #8 agree on who owns an object.
	// Returns true when it fully handled the request. Gated by site.Cluster != nil —
	// a non-clustered cadish never enters here (zero cost). Read-through (#7) is NOT
	// here: it runs via the origin chain on a local miss.
	if site.Cluster != nil && h.clusterRoute(rec, r, site, preq.Path, info) {
		info.tr.note("CLUSTER", "routed to peer owner")
		return
	}

	// Single combined classification (one shard lock, shared on the hot path) yields
	// both the hit-for-miss bypass flag and the fresh/stale/miss state.
	state, hfm := h.fresh.classify(key)
	// hit-for-miss window: bypass the cache entirely (fetch, never store).
	if hfm {
		info.tr.lookup("HIT-FOR-MISS (bypass cache)")
		h.serveOrigin(rec, r, site, preq, rd, key, false, pipeline.CacheStatusMiss, info)
		return
	}

	// CLIENT-FORCED REVALIDATION (RFC 9111 §5.2.1.4): a request `Cache-Control:
	// no-cache` / `max-age=0` (or the HTTP/1.0 `Pragma: no-cache`) forbids serving a
	// stored response without revalidating with origin. We honor it by NOT serving a
	// fresh/stale entry directly and instead going to origin (serveMiss), which
	// re-fetches and re-stores. (We do NOT honor request `no-store` as a bypass — it
	// only affects what we store, which the safe-method/cacheability gates handle.)
	// The check is a cheap header-presence scan: a request with neither header pays
	// almost nothing on the hot HIT path.
	if clientForcesRevalidate(r.Header) {
		info.tr.lookup("CLIENT no-cache -> REVALIDATE (origin)")
		h.serveMiss(rec, r, site, preq, rd, key, info)
		return
	}

	// UNSAFE-METHOD SERVE GUARD (RFC 9111 §3 / §4): a shared cache serves stored
	// responses only to safe methods. The DEFAULT cache key includes `method`, but a
	// user-written `cache_key path` drops it — without this guard a POST/PUT/… at the
	// same path would be served the cached GET body and NEVER reach origin, silently
	// dropping its side-effect. This is the SERVE-side symmetric of the store guard in
	// serveOrigin (isSafeMethod). For an unsafe method we skip the fresh/stale
	// serveFromCache branches and go to origin; the store guard already prevents the
	// response from being cached. One cheap method check; GET/HEAD hot path is unchanged.
	//
	// RFC 9111 §4.4 INVALIDATION: a SUCCESSFUL (2xx/3xx) response to an unsafe method
	// on a URI invalidates any cached entry for that URI. After the origin serve we
	// forget the freshness marker for the SIBLING GET entry (the key a GET to this same
	// URI would produce), so the next GET re-fetches the post-write representation
	// rather than serving the stale pre-write body — the same observable mechanism as a
	// single-key purge. We compute the GET key up front (before serveMiss, while preq is
	// untouched), then invalidate only on success. Gated on a non-empty key (a pass'd /
	// synthetic request never reaches here) and on the unsafe path alone — GET/HEAD pay
	// nothing.
	if !isSafeMethod(r.Method) {
		info.tr.lookup("UNSAFE METHOD -> ORIGIN (not served from cache)")
		getKey := h.siblingGetKey(site, preq, key)
		h.serveMiss(rec, r, site, preq, rd, key, info)
		// A 4xx/5xx is NOT a success and must not invalidate (the write didn't land);
		// only a 2xx/3xx does. rec.status holds the status actually written to the client.
		if getKey != "" && rec.status >= 200 && rec.status < 400 {
			h.fresh.forget(getKey)
			info.tr.note("INVALIDATE", "§4.4 forgot sibling GET key")
		}
		return
	}

	switch state {
	case stateFresh:
		info.tr.lookup("FRESH")
		if h.serveFromCache(rec, r, site, preq, key, pipeline.CacheStatusHit, info) {
			return
		}
		info.tr.lookup("FRESH marker but object evicted -> ORIGIN")
	case stateStale:
		info.tr.lookup("STALE (serve + background revalidate)")
		if h.serveFromCache(rec, r, site, preq, key, pipeline.CacheStatusHitStale, info) {
			h.triggerBgFetch(site, r, preq, rd, key)
			return
		}
		info.tr.lookup("STALE marker but object evicted -> ORIGIN")
	default:
		info.tr.lookup("MISS")
	}

	// MISS (or a fresh/stale marker whose object was evicted): go to origin.
	h.serveMiss(rec, r, site, preq, rd, key, info)
}

// serveMiss runs the coalesced origin fetch for a cacheable miss. Range requests
// and non-GET/HEAD methods bypass coalescing (a partial body must not populate the
// shared full-object cache, and only idempotent reads are single-flighted).
func (h *Handler) serveMiss(rec *statusRecorder, r *http.Request, site *boundSite, preq *pipeline.Request, rd pipeline.RequestDecision, key string, info *reqInfo) {
	coalescable := r.Header.Get("Range") == "" &&
		(r.Method == "" || r.Method == http.MethodGet)
	if !coalescable {
		h.serveOrigin(rec, r, site, preq, rd, key, true, pipeline.CacheStatusMiss, info)
		return
	}

	call, winner := h.coalesce.enter(key)
	if winner {
		h.metrics.IncCoalesceWinner()
		// finish() MUST run even if serveOrigin panics: otherwise call.done is never
		// closed and waiters block until their own client context cancels, AND the
		// calls[key] entry leaks so no future request for this key can ever coalesce.
		// We default succeeded=false, run the fetch, then mark true only on a clean
		// return — so a panicking winner wakes waiters with a failure result (they fall
		// through to their own clean miss) and re-panics into ServeHTTP's recover guard,
		// which answers THIS client with a 500. The defer runs before the re-panic
		// unwinds past it, so done is closed first.
		ok := false
		defer func() { h.coalesce.finish(key, call, ok) }()
		ok = h.serveOrigin(rec, r, site, preq, rd, key, true, pipeline.CacheStatusMiss, info)
		return
	}

	h.metrics.IncCoalesceWaiter()
	// Waiter: block until the winner finishes (or the client goes away).
	select {
	case <-call.done:
	case <-r.Context().Done():
		return
	}
	if call.succeeded {
		if h.serveFromCache(rec, r, site, preq, key, pipeline.CacheStatusHit, info) {
			return
		}
	}
	// Winner failed or its object isn't cached: run our own (still-cacheable) fetch.
	h.serveOrigin(rec, r, site, preq, rd, key, true, pipeline.CacheStatusMiss, info)
}

// serveFromCache serves a cached object (with Range support) and returns true on a
// successful serve. It returns false when the key is not actually in the store, so
// the caller can fall through to the origin.
func (h *Handler) serveFromCache(rec *statusRecorder, r *http.Request, site *boundSite, preq *pipeline.Request, key string, status pipeline.CacheStatus, info *reqInfo) bool {
	reader, tier, ok := site.Store.GetTier(key)
	if !ok {
		return false
	}
	// The stored representation may be encoded (the origin compressed it and cadish cached
	// the compressed bytes). Serving it to a client that does NOT accept that encoding would
	// hand back an undecodable body, so fall through to a fresh origin fetch instead (the
	// origin will negotiate this client's Accept-Encoding). Common clients all accept gzip, so
	// this rarely fires; when it does it stays correct (the cache key doesn't partition by
	// encoding, so we cannot serve a per-encoding variant from here).
	if ce := reader.Meta.ContentEncoding; ce != "" && !clientAcceptsEncoding(r.Header.Get("Accept-Encoding"), ce) {
		reader.Close()
		return false
	}
	defer reader.Close()

	info.cacheStatus = status.String()
	info.upstream = "cache:" + tier
	info.tr.note("SERVE", "from "+info.upstream)

	hdr := rec.Header()
	setIfNonEmpty(hdr, "Content-Type", reader.Meta.ContentType)
	setIfNonEmpty(hdr, "ETag", reader.Meta.ETag)
	setIfNonEmpty(hdr, "Last-Modified", reader.Meta.LastModified)
	// Replay the stored Content-Encoding: the cache holds the encoded bytes, so a HIT MUST
	// re-emit the encoding header or the client receives an undecodable body. Setting it here
	// also makes the encode layer's encodeApplies() skip re-compression (never double-encode).
	setIfNonEmpty(hdr, "Content-Encoding", reader.Meta.ContentEncoding)
	// Replay the stored Vary so a downstream shared cache / the edge tier keeps the variance
	// signal (cadish partitioned its OWN cache by the key; downstream did not). A later
	// ensureVaryForEncode appends Accept-Encoding when cadish compresses on delivery.
	setIfNonEmpty(hdr, "Vary", reader.Meta.Vary)
	hdr.Set("Accept-Ranges", "bytes")
	// Age + Date (RFC 9111 §5.1): a shared cache reports how long the entry has been
	// held so a downstream cache can compute freshness. Date is set to the serve
	// instant (serveFromCache copies no origin headers, so the origin Date is not
	// otherwise present). storedAt takes a shared RLock and is a no-op miss for an
	// evicted/HFM key.
	now := h.now()
	hdr.Set("Date", now.UTC().Format(http.TimeFormat))
	if st, ok := h.fresh.storedAt(key); ok {
		if age := int64(now.Sub(st).Seconds()); age >= 0 {
			hdr.Set("Age", strconv.FormatInt(age, 10))
		}
	}
	transforms, enc := h.applyDeliver(hdr, site, preq, status, key)
	info.tr.deliver(transforms)

	// CONDITIONAL REQUEST -> 304 (RFC 9111 §4.3.2 / RFC 9110 §13.1): on a HIT for a
	// 200 representation, an If-None-Match matching the cached ETag (or `*`) or an
	// If-Modified-Since at/after the cached Last-Modified short-circuits the body —
	// the client already holds a current copy. Preconditions are evaluated BEFORE range
	// processing (RFC 9110 §13.1), so a matching If-None-Match yields 304 even when the
	// request also carries a Range (RG2) — the range is moot once we know the client's
	// copy is current. (If-Range is a separate, range-specific validator handled below;
	// it never produces a 304.) The cheap header-presence check up front means a request
	// with no conditional header pays nothing (no allocations) on the hot HIT path. The
	// 304 carries the validators + Date/Age/cache-status already set on hdr; per RFC 9110
	// §15.4.5 it must not carry entity headers, so Content-Type/Content-Length are
	// stripped and no body is written.
	// A deliver-phase `replace` rewrites the body, so the cached ETag/Last-Modified
	// no longer describe what we'd serve — skip the 304 short-circuit when a body
	// transform applies (transformsApply also excludes Range/HEAD/encoded). The check
	// is a cheap len()==0 in the common no-transform case.
	if reader.Meta.EffectiveStatus() == http.StatusOK &&
		!transformsApply(transforms, hdr, false, r.Method == http.MethodHead) &&
		conditionalNotModified(r.Header, reader.Meta.ETag, reader.Meta.LastModified, h.now) {
		hdr.Del("Content-Type")
		hdr.Del("Content-Length")
		hdr.Del("Accept-Ranges")
		rec.WriteHeader(http.StatusNotModified)
		return true
	}

	size := reader.Meta.Size
	isRange := r.Header.Get("Range") != ""
	// Negotiate the response codec once (uncompressed when none / no `encode`).
	codec := negotiateEncoding(enc, r.Header.Get("Accept-Encoding"))
	// Range is only meaningful for a positive (200) representation. A full-body
	// NEGATIVE entry (404/410, D15) carries an error-page body with Size > 0, but
	// a 404/410 is not range-serveable — a Range request must still serve the
	// recorded negative status with the full body, never a 206 slice of the error
	// page. So honor Range only when the cached object's effective status is 200.
	// If-Range (RFC 9110 §14.2): when present, the Range applies ONLY if its validator
	// still matches the representation; otherwise the Range is IGNORED and the full 200
	// is served (RG1). A non-matching/weak/garbled If-Range therefore falls through to
	// the full-body path below.
	if rangeHdr := r.Header.Get("Range"); rangeHdr != "" && size > 0 && reader.Meta.EffectiveStatus() == http.StatusOK &&
		ifRangeAllowsRange(r.Header.Get("If-Range"), reader.Meta.ETag, reader.Meta.LastModified) {
		pr, err := parseSingleRange(rangeHdr, size)
		switch {
		case err == nil:
			hdr.Set("Content-Range", pr.contentRange(size))
			hdr.Set("Content-Length", strconv.FormatInt(pr.length, 10))
			rec.WriteHeader(http.StatusPartialContent)
			if r.Method != http.MethodHead {
				_, _ = io.CopyN(io.Discard, reader, pr.start)
				_, _ = io.CopyN(rec, reader, pr.length)
			}
			return true
		case errors.Is(err, errUnsatisfiableRange):
			hdr.Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
			rec.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return true
			// errInvalidRange falls through to a full 200.
		}
	}

	isHead := r.Method == http.MethodHead
	effStatus := reader.Meta.EffectiveStatus()
	// Tell downstream shared caches to vary on Accept-Encoding for a compressible
	// candidate, even when this request negotiated to identity.
	ensureVaryForEncode(enc, hdr, effStatus == http.StatusOK)
	// Deliver-phase body transforms (`replace`): the cache holds the canonical
	// body; we substitute on the copy written to the client, for bodies within the
	// size cap only (larger bodies stream untransformed). Range is handled above.
	if transformsApply(transforms, hdr, false, isHead) && size >= 0 && size <= maxTransformBody {
		if buf, _, err := readCapped(reader, maxTransformBody); err == nil {
			out := applyReplacements(buf, transforms)
			hdr.Del("ETag") // body changed; the stored ETag no longer matches
			// `replace` runs on plaintext first; `encode` compresses the result. The
			// codec writer is created BEFORE the encode headers are committed, so a
			// codec-init failure falls through to the uncompressed write below instead
			// of emitting plaintext under a Content-Encoding header.
			if effStatus == http.StatusOK && encodeApplies(enc, codec, hdr, int64(len(out)), isRange, isHead) {
				if ew := newEncodeWriter(rec, codec); ew != nil {
					h.encodeCompressions.Add(1)
					applyEncodeHeaders(hdr, codec)
					rec.WriteHeader(effStatus)
					_, _ = ew.Write(out)
					_ = ew.Close()
					return true
				}
				// codec init failed: fall through to the uncompressed write.
			}
			hdr.Set("Content-Length", strconv.Itoa(len(out)))
			rec.WriteHeader(effStatus)
			_, _ = rec.Write(out)
			return true
		}
		// On a read error fall through to the plain streaming path.
	}

	// Compression of the (untransformed) cached body. With the cached-variant
	// optimization (D69) a HIT first tries to serve a STORED precompressed
	// representation for the negotiated codec; only on a miss does it compress on the
	// fly (and lazily store the variant for next time). HEAD never has a body to
	// compress and never materializes a variant.
	if effStatus == http.StatusOK && !isHead && encodeApplies(enc, codec, hdr, size, isRange, isHead) {
		srcFP, canCacheVariant := sourceFingerprint(reader.Meta)
		// 1. Serve a stored variant directly (no recompression) when present + current.
		// Only attempted when the identity has a real validator (canCacheVariant) — a
		// validator-less representation is never stored as a variant (see
		// sourceFingerprint), so there is nothing safe to look up.
		if canCacheVariant {
			if vr, ok := lookupVariant(site.Store, key, codec, srcFP); ok {
				defer vr.Close()
				applyEncodeHeaders(hdr, codec)
				hdr.Set("Content-Length", strconv.FormatInt(vr.Meta.Size, 10))
				rec.WriteHeader(effStatus)
				_, _ = io.Copy(rec, vr)
				return true
			}
		}
		// 2. No usable variant: compress the canonical body. For a body within the cap
		// we buffer the identity, compress in memory (so the exact bytes can also be
		// stored as the variant), then serve. Larger bodies stream-compress without
		// caching a variant (the zero-extra-copy discipline: we never buffer a huge
		// body just to cache a variant).
		buf, exceeded, resume := drainReader(reader, maxTransformBody)
		if !exceeded {
			if comp, ok := compressBytes(codec, buf); ok {
				h.encodeCompressions.Add(1)
				if canCacheVariant {
					storeVariant(site.Store, key, codec, srcFP, reader.Meta.ContentType, comp)
				}
				applyEncodeHeaders(hdr, codec)
				hdr.Set("Content-Length", strconv.Itoa(len(comp)))
				rec.WriteHeader(effStatus)
				_, _ = rec.Write(comp)
				return true
			}
			// compression failed: serve the buffered identity below.
			if size >= 0 {
				hdr.Set("Content-Length", strconv.FormatInt(size, 10))
			}
			rec.WriteHeader(effStatus)
			_, _ = rec.Write(buf)
			return true
		}
		// Oversize body: stream-compress on the fly without caching a variant (we
		// never buffer a huge body just to store a precompressed copy).
		if ew := newEncodeWriter(rec, codec); ew != nil {
			h.encodeCompressions.Add(1)
			applyEncodeHeaders(hdr, codec)
			rec.WriteHeader(effStatus)
			_, _ = io.Copy(ew, resume)
			_ = ew.Close()
			return true
		}
		// codec init failed: fall through to the uncompressed path. The reader was
		// partially drained; serve the resumed stream so no bytes are lost.
		if size >= 0 {
			hdr.Set("Content-Length", strconv.FormatInt(size, 10))
		}
		rec.WriteHeader(effStatus)
		_, _ = io.Copy(rec, resume)
		return true
	}

	if size >= 0 {
		hdr.Set("Content-Length", strconv.FormatInt(size, 10))
	}
	// Serve the cached status: 200 for a normal object, or the recorded negative
	// status (404/410/…) for a negatively-cached entry, whose body is empty.
	rec.WriteHeader(effStatus)
	if !isHead {
		_, _ = io.Copy(rec, reader)
	}
	return true
}

// serveOrigin fetches from the (routed) origin and streams to the client, teeing
// into the cache when store is true and the response is positively cacheable. It
// returns true when a cacheable body was fully committed to the cache (the signal
// the coalescer uses to let waiters read from cache).
func (h *Handler) serveOrigin(rec *statusRecorder, r *http.Request, site *boundSite, preq *pipeline.Request, rd pipeline.RequestDecision, key string, store bool, status pipeline.CacheStatus, info *reqInfo) bool {
	if info.cacheStatus == "" {
		info.cacheStatus = status.String()
	}
	info.upstream = rd.Upstream
	info.tr.origin(rd.Upstream)
	o := site.originFor(rd.Upstream)
	if o == nil {
		writeStatus(rec, http.StatusBadGateway, "no upstream origin")
		return false
	}

	h.metrics.IncOriginFetch()

	// Origin path/query: default to the client-facing request, then apply any
	// `rewrite` rule (origin-only; the cache key already stayed on the client URL).
	oPath, oQuery := originTarget(preq.Path, r.URL.RawQuery, rd.Rewrite)
	oreq := &origin.Request{
		Method:     r.Method,
		Key:        oPath,
		RawQuery:   oQuery, // forward the query so query-varying origins get the right response
		Header:     buildOriginHeader(r.Header, rd.ReqHeaderOps),
		ClientHost: pipeline.NormalizeHost(r.Host), // canonical host (matches the cache key) per host_header policy (#11)
	}
	// Forward the CLIENT request body to the origin for a write method (POST/PUT/…).
	// Only write methods carry a body that must reach the upstream; GET/HEAD (the
	// cacheable / coalesced read path) leave Body nil so a cacheable read never tries
	// to forward one. The body is streamed straight through (not buffered). The
	// http.Server owns r.Body's lifecycle (it closes it after this handler returns),
	// and net/http's Client closes it when sending the upstream request — so the
	// origin layer never closes it itself (see origin.Request.Body).
	if m := r.Method; m != http.MethodGet && m != http.MethodHead && r.Body != nil {
		oreq.Body = r.Body
		oreq.ContentLength = r.ContentLength
	}
	// Attach the lb routing key (the {sticky} value) so a sticky/shard-by-key
	// upstream pins this request to a backend; plain origins ignore it.
	fetchCtx := h.routingCtx(r.Context(), site, rd.Upstream, r)
	resp, err := o.Fetch(fetchCtx, oreq)
	if err != nil {
		return h.handleOriginError(rec, r, site, preq, key, store, err, info)
	}

	// Between-bytes deadline (gap G5): an `upstream { timeout … between_bytes D }`
	// sets a per-upstream body-stall budget that the origin stamps onto the Response.
	// The idle-timeout reader already enforces a between-bytes deadline (it resets on
	// each progress-making read); honor the per-upstream budget when set, and when
	// BOTH it and the global -idle-timeout are active take the STRICTER (smaller) of
	// the two, so an explicit between_bytes is never loosened by the global default.
	idle := h.idleTimeout
	if bb := resp.BetweenBytes; bb > 0 {
		if idle <= 0 || bb < idle {
			idle = bb
		}
	}
	ir := newIdleTimeoutReader(h.sweeper, resp.Body, idle, h.log, key)
	defer ir.Close()

	sd := site.Pipeline.EvalResponse(preq, resp.StatusCode, resp.Header)

	// MAX_STALE (D60) on a NEGATIVE response. A 404/410 comes back here as a
	// full-body NEGATIVE *Response (not via handleOriginError, which sees only
	// transport / 5xx / bodyless-not-found errors). For max_stale this is still an
	// "origin failing" shape: if a last-good copy is within its max_stale window,
	// serve it instead — outranking BOTH the cacheable negative cache (D15) and
	// `respond on_error` (D57), exactly as on the transport-error path. The marker
	// is not refreshed (staleWithin is read-only). The negative body is drained by
	// the deferred ir.Close().
	if resp.Negative && key != "" && h.fresh.staleWithin(key) {
		info.tr.note("MAX_STALE", "origin returned negative; serving last-good (HIT-STALE-ERROR)")
		if h.serveFromCache(rec, r, site, preq, key, pipeline.CacheStatusHitStaleError, info) {
			return false
		}
	}

	if sd.HitForMiss > 0 && key != "" {
		h.fresh.setHitForMiss(key, sd.HitForMiss)
		store = false
	}
	// Storable when the pipeline marks the status cacheable AND it is either a
	// positive 200 OR a full-body NEGATIVE response (404/410, backlog #21). A
	// negative response carries its real error-page body+headers, which we store
	// via the SAME streaming tee path as a 200 — recording the negative status in
	// meta.Status so the hit is served with the right code. This supersedes the
	// bodyless negative path (which still covers a bodyless ErrNotFound / a
	// transport status with no response) handled in handleOriginError.
	cacheableStatus := resp.StatusCode == http.StatusOK || resp.Negative
	// RFC 9111 §3: a shared cache stores responses only to SAFE methods (GET/HEAD).
	// The DEFAULT cache key includes `method`, but a user-written `cache_key path`
	// drops it — without this guard a cacheable POST/PUT/… 200 would be stored under
	// a method-less key and later served to a GET at the same key. Gate storage on the
	// request method regardless of the key. (HEAD has no body to store; doStore is
	// further short-circuited on the isHead branches below, so this only admits GET.)
	doStore := store && key != "" && sd.Cacheable && cacheableStatus && isSafeMethod(r.Method)
	info.tr.response(resp.StatusCode, sd, doStore) // RESP: ttl/grace/hfm/store

	hdr := rec.Header()
	copyOriginHeaders(hdr, resp.Header)
	transforms, enc := h.applyDeliver(hdr, site, preq, status, key)
	info.tr.deliver(transforms) // DELIVER: body transforms applied
	if resp.ContentLength >= 0 {
		hdr.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	negStatus := 0
	if resp.Negative {
		negStatus = resp.StatusCode // recorded so a HIT serves the 404/410, not 200
	}
	meta := cache.ObjectMeta{
		Key:             key,
		Size:            resp.ContentLength,
		Status:          negStatus,
		ContentType:     resp.Header.Get("Content-Type"),
		ETag:            resp.Header.Get("ETag"),
		LastModified:    resp.Header.Get("Last-Modified"),
		ContentEncoding: resp.Header.Get("Content-Encoding"), // replayed on HIT (else corrupt body)
		Vary:            resp.Header.Get("Vary"),             // replayed on HIT (downstream variant safety)
		Tier:            sd.StoreTier,                        // `storage <sel> -> ram|disk` placement
	}
	isHead := r.Method == http.MethodHead
	isRange := r.Header.Get("Range") != "" || resp.StatusCode == http.StatusPartialContent
	// Negotiate the response codec once (uncompressed when none / no `encode`).
	// Compression engages only for a 200 (a 206/3xx/error keeps the raw path).
	codec := negotiateEncoding(enc, r.Header.Get("Accept-Encoding"))
	canEncode := resp.StatusCode == http.StatusOK
	// Tell downstream shared caches to vary on Accept-Encoding for a compressible
	// candidate, even when this request negotiated to identity.
	ensureVaryForEncode(enc, hdr, canEncode)

	// Deliver-phase body transforms (`replace`): for a within-cap body, buffer it,
	// store the CANONICAL bytes in the cache, and write the SUBSTITUTED copy to the
	// client. Range/HEAD/encoded/oversize bodies skip this and stream untransformed
	// (the reader is restored after a cap overrun, so no bytes are lost).
	src := io.Reader(ir)
	if transformsApply(transforms, hdr, isRange, isHead) && (resp.ContentLength < 0 || resp.ContentLength <= maxTransformBody) {
		if buf, exceeded, rerr := readCapped(ir, maxTransformBody); rerr == nil && !exceeded {
			committed := false
			if doStore {
				if cw, werr := site.Store.Writer(meta); werr == nil {
					if _, e := cw.Write(buf); e == nil {
						if cw.Commit() == nil {
							committed = true
							h.fresh.store(key, sd.TTL, sd.Grace, sd.MaxStale)
						}
					} else {
						_ = cw.Abort()
					}
				}
			}
			out := applyReplacements(buf, transforms)
			hdr.Del("ETag") // body changed; the upstream ETag no longer matches
			// `replace` runs on plaintext first; `encode` compresses the result. The
			// codec writer is created BEFORE the encode headers are committed, so a
			// codec-init failure falls through to the uncompressed write instead of
			// emitting plaintext under a Content-Encoding header.
			if canEncode && !isHead && encodeApplies(enc, codec, hdr, int64(len(out)), isRange, isHead) {
				if ew := newEncodeWriter(rec, codec); ew != nil {
					h.encodeCompressions.Add(1)
					applyEncodeHeaders(hdr, codec)
					rec.WriteHeader(resp.StatusCode)
					_, _ = ew.Write(out)
					_ = ew.Close()
					return committed
				}
				// codec init failed: fall through to the uncompressed write.
			}
			hdr.Set("Content-Length", strconv.Itoa(len(out)))
			rec.WriteHeader(resp.StatusCode)
			if !isHead {
				_, _ = rec.Write(out)
			}
			return committed
		} else if rerr == nil {
			src = resumeReader(buf, ir) // cap overrun: stream the remainder untransformed
		}
	}

	var body io.Reader = src
	var tee *cacheTee
	if doStore {
		if cw, werr := site.Store.Writer(meta); werr == nil {
			tee = newCacheTee(src, cw, h.log, key)
			body = tee
		} else if h.log != nil {
			h.log.Warn("cache writer unavailable", "key", key, "err", werr)
		}
	}

	// On-the-fly compression of the streamed body: wrap the CLIENT writer in a
	// codec writer. The tee (when present) mirrors the RAW upstream bytes into the
	// cache as they are read through `body`, so the cache still stores the canonical
	// uncompressed representation; only the bytes written to the client are
	// compressed. When encode does not apply (excluded Content-Type, e.g. a large
	// image), this is skipped and the raw fast path streams untouched (zero-copy).
	var clientW io.Writer = rec
	var ew *encodeWriter
	if canEncode && !isHead && encodeApplies(enc, codec, hdr, resp.ContentLength, isRange, isHead) {
		if ew = newEncodeWriter(rec, codec); ew != nil {
			h.encodeCompressions.Add(1)
			applyEncodeHeaders(hdr, codec)
			clientW = ew
		}
	}

	rec.WriteHeader(resp.StatusCode)
	if isHead {
		if tee != nil {
			tee.abort()
		}
		return false
	}

	n, copyErr := io.Copy(clientW, body)
	if ew != nil {
		_ = ew.Close()
	}
	if tee == nil {
		return false
	}
	complete := resp.ContentLength < 0 || n == resp.ContentLength
	committed := tee.finish(copyErr, complete)
	if committed {
		h.fresh.store(key, sd.TTL, sd.Grace, sd.MaxStale)
	}
	return committed
}

// handleOriginError maps an origin fetch error to a client response, adding
// NEGATIVE CACHING: when the response pipeline marks the failing status cacheable
// (e.g. `cache_ttl status 404 410 ttl 60s grace 1h`), a bodyless entry is stored
// under key so subsequent requests are served the negative status from cache
// instead of re-hitting origin. Non-cacheable errors preserve the prior
// behavior: a 404 is surfaced ("not found"), a non-cacheable non-2xx / transport
// error becomes the upstream status or 502 (honoring a hit-for-miss rule), and a
// client cancellation writes nothing. It returns true only when a negative entry
// was committed — the signal the coalescer uses to let waiters read it from
// cache.
func (h *Handler) handleOriginError(rec *statusRecorder, r *http.Request, site *boundSite, preq *pipeline.Request, key string, store bool, err error, info *reqInfo) bool {
	// MAX_STALE (D60), the FIRST fallback on origin error: if a stored copy exists
	// and is still within its max_stale window, serve it stale rather than erroring.
	// This outranks the cacheable negative cache (D15) and `respond on_error` (D57)
	// — a real (if old) representation beats a synthetic error or a cached failure —
	// and fires on EVERY failure shape, including ErrNotFound: serving the last-good
	// copy of a page whose origin now 404s during an outage is the whole point
	// (owner decision). The full ordering is:
	//   fresh > grace-stale > max_stale-on-error > negative cache > on_error > 502/404.
	// fresh and grace-stale are decided earlier in ServeHTTP and never reach here.
	//
	// staleWithin is read-only and does NOT refresh the marker, so the object stays
	// exactly as stale as it was: a persistently-down origin keeps serving the same
	// HIT-STALE-ERROR until maxStaleUntil finally elapses (no silent re-arming of
	// grace). On a marker-without-object (the blob was evicted), serveFromCache
	// returns false and we fall through to the normal error chain below.
	if key != "" && h.fresh.staleWithin(key) {
		info.tr.note("MAX_STALE", "origin failed; serving last-good (HIT-STALE-ERROR)")
		if h.serveFromCache(rec, r, site, preq, key, pipeline.CacheStatusHitStaleError, info) {
			return false
		}
	}

	notFound := errors.Is(err, origin.ErrNotFound)
	st := origin.StatusOf(err) // 404 for ErrNotFound, the code for a *StatusError, 0 for transport
	// Only a definitive HTTP status (incl. 404) can be cached or hit-for-missed;
	// a transport error (st == 0) has no status to consult the pipeline with.
	hasStatus := notFound || (st >= 400 && st < 600)

	code := http.StatusBadGateway
	// No healthy/eligible backend in the pool → 503 Service Unavailable, which is
	// semantically "no upstream available right now" (and retriable) rather than 502
	// "got a bad reply from upstream" (LB-D1). A definitive upstream HTTP status (the
	// st check below) and ErrNotFound still take precedence.
	if errors.Is(err, lb.ErrNoBackend) {
		code = http.StatusServiceUnavailable
	}
	if st >= 400 && st < 600 {
		code = st
	}
	if notFound {
		code = http.StatusNotFound
	}

	var sd pipeline.ResponseDecision
	if hasStatus && key != "" {
		// An origin error path carries only a status, not response headers (the
		// origin contract drains non-2xx bodies), so a set_cookie/content_type
		// matcher has nothing to resolve against here — pass nil.
		sd = site.Pipeline.EvalResponse(preq, code, nil)
	}

	// Negative caching: a cacheable negative status is a valid origin answer we
	// store (bodyless) and serve from cache thereafter. SAFE-METHOD STORE GUARD
	// (RFC 9111 §3, symmetric with serveOrigin's doStore): never STORE a negative
	// entry for an UNSAFE method (POST/PUT/PATCH/DELETE). The default cache key embeds
	// the method, but a user-written `cache_key path` drops it — without this guard a
	// cacheable error response to a POST would be negatively cached under the
	// method-less key and then served to a subsequent GET (poisoning the GET with a
	// cached failure that never reaches origin). For an unsafe method we skip the
	// store and fall through to serve the status to THIS client only.
	if store && key != "" && sd.Cacheable && isSafeMethod(r.Method) {
		return h.storeAndServeNegative(rec, r, site, preq, key, code, sd)
	}

	if notFound {
		writeStatus(rec, http.StatusNotFound, "not found")
		return false
	}

	// Transport error or a non-cacheable non-2xx status: this is the UNCACHEABLE
	// hard-failure path. Precedence (D57): serve-stale-within-grace (handled earlier
	// in ServeHTTP) > cacheable negative cache (the block above) > respond on_error
	// (below) > the bare 502 fallback. So on_error fires only here, and only when it
	// is configured and the request matches its @scope.
	h.metrics.IncOriginError()
	if r.Context().Err() != nil {
		return false // client went away; nothing to write
	}
	// Honor a hit-for-miss rule on a transient upstream status so a herd of misses
	// doesn't stampede a flapping origin (Varnish HFM). Done before the on_error
	// synthetic so the HFM bookkeeping is identical whether or not a maintenance page
	// is served — on_error only changes what THIS client sees, never the bookkeeping.
	if sd.HitForMiss > 0 && key != "" {
		h.fresh.setHitForMiss(key, sd.HitForMiss)
	}
	// respond on_error: a configured synthetic maintenance page for an uncacheable
	// hard failure with no servable object. Gated on HasOnError so a site without the
	// directive pays one len-check (zero cost; D57). The synthetic is written straight
	// to the client and is NOT cached.
	if site.Pipeline.HasOnError() {
		if oe := site.Pipeline.EvalOnError(preq, code); oe != nil {
			h.writeOnError(rec, r, oe)
			return false
		}
	}
	writeStatus(rec, code, "origin error")
	return false
}

// writeOnError writes the configured `respond on_error` synthetic (D57): the
// operator-supplied status + body + Content-Type. HEAD writes the status + headers
// with no body; a Range request gets the FULL synthetic (never a 206 slice of an
// error page), mirroring the negative-entry Range rule in serveFromCache. The body
// is operator config (never reflected request data), so there is no injection
// surface. The synthetic is not cached — it is written straight to the client.
func (h *Handler) writeOnError(rec *statusRecorder, r *http.Request, oe *pipeline.OnError) {
	hdr := rec.Header()
	hdr.Set("Content-Type", oe.ContentType)
	hdr.Set("Content-Length", strconv.Itoa(len(oe.Body)))
	rec.WriteHeader(oe.Status)
	if r.Method != http.MethodHead {
		_, _ = rec.Write(oe.Body)
	}
}

// storeAndServeNegative writes a bodyless negative cache entry (recording the
// failing status) under key, sets its freshness from the response decision, and
// serves the status to this client. The origin already discarded the negative
// body (the origin contract drains non-2xx bodies), so the cached entry — and
// the served response — is bodyless; this matches how a deleted object's 404 is
// represented. Returning true tells the coalescer the entry is in cache so
// waiters read it instead of re-hitting origin.
func (h *Handler) storeAndServeNegative(rec *statusRecorder, r *http.Request, site *boundSite, preq *pipeline.Request, key string, code int, sd pipeline.ResponseDecision) bool {
	committed := false
	meta := cache.ObjectMeta{Key: key, Status: code, Size: 0}
	if cw, werr := site.Store.Writer(meta); werr == nil {
		// No body to write; commit an empty object carrying the negative status.
		// max_stale does not apply to a bodyless negative entry (there is no
		// last-good representation to serve on a later failure — the entry IS the
		// failure), so it is stored with no max_stale window (0).
		if cerr := cw.Commit(); cerr == nil {
			h.fresh.store(key, sd.TTL, sd.Grace, 0)
			committed = true
		} else if h.log != nil {
			h.log.Warn("negative cache commit failed", "key", key, "err", cerr)
		}
	} else if h.log != nil {
		h.log.Warn("negative cache writer unavailable", "key", key, "err", werr)
	}

	hdr := rec.Header()
	h.applyDeliver(hdr, site, preq, pipeline.CacheStatusMiss, key)
	hdr.Set("Content-Length", "0") // bodyless negative entry; nothing to compress
	rec.WriteHeader(code)
	return committed
}

// maxConcurrentBgRevalidations caps the number of in-flight background (SWR) origin
// refreshes process-wide. It bounds the origin amplification + goroutine count when a
// flood of requests lands across a large warm-but-stale catalog (each distinct stale key
// would otherwise fire its own detached refresh). A skipped refresh is harmless: the object
// is still served from its grace window and gets refreshed on a later request.
const maxConcurrentBgRevalidations = 128

// triggerBgFetch launches at most one background revalidation per key (coalesced), subject
// to a GLOBAL concurrency cap (h.bgSem): it re-fetches from origin and re-populates the
// cache so a stale-served object becomes fresh again, without blocking the client that
// received the stale body.
func (h *Handler) triggerBgFetch(site *boundSite, r *http.Request, preq *pipeline.Request, rd pipeline.RequestDecision, key string) {
	if !h.bg.begin(key) {
		return
	}
	// Global cap: acquire a slot WITHOUT blocking. If the background-refresh pool is full,
	// skip this refresh — the object is still within grace and will be refreshed by a later
	// request — rather than launch an unbounded goroutine/origin-dial per distinct stale key.
	select {
	case h.bgSem <- struct{}{}:
	default:
		h.bg.end(key)
		return
	}
	// Detach from the client's request context: the client already got its stale
	// response; the revalidation must outlive that request.
	clone := *preq
	go func() {
		defer func() { <-h.bgSem }()
		defer h.bg.end(key)
		h.revalidate(site, &clone, rd, key)
	}()
}

// revalidate performs the background origin fetch + cache store for a stale key.
func (h *Handler) revalidate(site *boundSite, preq *pipeline.Request, rd pipeline.RequestDecision, key string) {
	o := site.originFor(rd.Upstream)
	if o == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.bgTimeout)
	defer cancel()
	// The client's headers are gone by now; seed origin headers from the request-
	// phase header ops alone. preq.Host survives on the clone, so a preserve
	// host_header policy still forwards the original Host on this revalidation (#11).
	// Mirror the foreground origin path/query rewrite on the background
	// revalidation so the refreshed object is fetched from the same upstream URL.
	oPath, oQuery := originTarget(preq.Path, rawQueryOf(preq), rd.Rewrite)
	oreq := &origin.Request{Method: http.MethodGet, Key: oPath, RawQuery: oQuery, Header: buildOriginHeader(http.Header{}, rd.ReqHeaderOps), ClientHost: pipeline.NormalizeHost(preq.Host)}
	resp, err := o.Fetch(ctx, oreq)
	if err != nil {
		notFound := errors.Is(err, origin.ErrNotFound)
		st := origin.StatusOf(err)
		if notFound || (st >= 400 && st < 600) {
			code := st
			if notFound {
				code = http.StatusNotFound
			}
			// Negative revalidation: if the now-failing status is cacheable, replace
			// the stale entry with a bodyless negative entry (a deleted object's 404
			// supersedes its stale 200) instead of leaving the 200 to be served from
			// grace until it expires.
			// Negative revalidation has only a failing status, no response
			// headers — response-phase matchers don't apply, so pass nil.
			if sd := site.Pipeline.EvalResponse(preq, code, nil); sd.Cacheable {
				meta := cache.ObjectMeta{Key: key, Status: code, Size: 0, Tier: sd.StoreTier}
				if cw, werr := site.Store.Writer(meta); werr == nil {
					if cw.Commit() == nil {
						// Bodyless negative entry: no max_stale window (see
						// storeAndServeNegative).
						h.fresh.store(key, sd.TTL, sd.Grace, 0)
					}
				}
				return
			}
			if notFound {
				return
			}
		}
		return
	}
	defer resp.Body.Close()

	sd := site.Pipeline.EvalResponse(preq, resp.StatusCode, resp.Header)
	if !sd.Cacheable || resp.StatusCode != http.StatusOK {
		if sd.HitForMiss > 0 {
			h.fresh.setHitForMiss(key, sd.HitForMiss)
		}
		return
	}
	meta := cache.ObjectMeta{
		Key:             key,
		Size:            resp.ContentLength,
		ContentType:     resp.Header.Get("Content-Type"),
		ETag:            resp.Header.Get("ETag"),
		LastModified:    resp.Header.Get("Last-Modified"),
		ContentEncoding: resp.Header.Get("Content-Encoding"), // replayed on HIT (else corrupt body)
		Vary:            resp.Header.Get("Vary"),             // replayed on HIT (downstream variant safety)
		Tier:            sd.StoreTier,
	}
	cw, werr := site.Store.Writer(meta)
	if werr != nil {
		return
	}
	tee := newCacheTee(resp.Body, cw, h.log, key)
	n, copyErr := io.Copy(io.Discard, tee)
	complete := resp.ContentLength < 0 || n == resp.ContentLength
	if tee.finish(copyErr, complete) {
		h.fresh.store(key, sd.TTL, sd.Grace, sd.MaxStale)
	}
}

// applyDeliver runs EvalDeliver for the given cache status and applies the result
// (response header ops, strip_cookies, CORS) to hdr. hdr is the response header
// set already populated with the upstream/cache headers (incl. Content-Type), so
// it doubles as the input a `content_type` matcher resolves against.
// applyDeliver returns the deliver decision's body transforms (empty when none)
// and its compression policy (nil when no `encode` is configured), so the caller
// can apply them to the response body it is about to write.
func (h *Handler) applyDeliver(hdr http.Header, site *boundSite, preq *pipeline.Request, status pipeline.CacheStatus, key string) ([]pipeline.Replacement, *pipeline.EncodeDecision) {
	dd := site.Pipeline.EvalDeliver(preq, hdr, status)
	applyHeaderOps(hdr, dd.RespHeaderOps)
	if dd.StripCookies {
		hdr.Del("Set-Cookie")
	}
	if dd.CORS != nil {
		applyCORS(hdr, dd.CORS, preq.Header.Get("Origin"))
	}
	// `header +cache_key NAME [raw]` (debug): emit the computed cache key the server
	// already holds — its 12-hex sha256 prefix by default, the raw key under `raw`.
	// Omitted when the request has no key (a pass/synthetic/redirect: key == "").
	// The key is already computed; the only added work is one sha256 over a short
	// existing string, done only when the directive is configured.
	if dd.CacheKeyHeader != "" {
		if v := pipeline.CacheKeyHeaderValue(key, dd.CacheKeyRaw); v != "" {
			hdr.Set(dd.CacheKeyHeader, v)
		}
	}
	return dd.Transforms, dd.Encode
}

// --- helpers ---

// buildPipelineRequest builds the engine's backend-agnostic Request from an
// *http.Request.
func buildPipelineRequest(r *http.Request) *pipeline.Request {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	// Parse the query splitting ONLY on '&' (parseQueryLossless), NOT via r.URL.Query():
	// Go's url.Query() rejects a ';'-containing segment and silently DROPS it, so the cache
	// key would disagree with the raw query forwarded verbatim to the origin — a parameter-
	// cloaking cache-poisoning vector (`/p?cb=x;y=1` keys as `/p`, colliding with the plain
	// resource while the origin sees the cloaked params). '&'-only parsing keeps ';' a literal
	// value byte, matching both the raw bytes the origin receives and the edge's URLSearchParams
	// parse. Returns nil for an empty query (no alloc on the common query-less HIT path).
	query := parseQueryLossless(r.URL.RawQuery)
	return &pipeline.Request{
		Method:   r.Method,
		Host:     host,
		Path:     normalizePath(r.URL.Path),
		Query:    query,
		Header:   r.Header,
		ClientIP: clientIP(r),
	}
}

// clientAcceptsEncoding reports whether a client's Accept-Encoding header accepts the given
// content-coding. identity is always acceptable. A coding is accepted when it is listed with a
// non-zero q-value, or a `*` is listed with non-zero q. An empty Accept-Encoding means the
// client expressed no preference, which per RFC 9110 §12.5.3 means identity only — so a
// non-identity coding is NOT accepted. Matching is case-insensitive on the token.
func clientAcceptsEncoding(acceptEncoding, coding string) bool {
	if coding == "" || strings.EqualFold(coding, "identity") {
		return true
	}
	star := false
	for _, part := range strings.Split(acceptEncoding, ",") {
		tok := strings.TrimSpace(part)
		q := "1"
		if i := strings.IndexByte(tok, ';'); i >= 0 {
			params := tok[i+1:]
			tok = strings.TrimSpace(tok[:i])
			if j := strings.Index(strings.ToLower(params), "q="); j >= 0 {
				q = strings.TrimSpace(params[j+2:])
			}
		}
		accepted := q != "0" && q != "0.0" && q != "0.00" && q != "0.000"
		if strings.EqualFold(tok, coding) {
			return accepted
		}
		if tok == "*" {
			star = accepted
		}
	}
	return star
}

// parseQueryLossless parses a raw URL query into url.Values, splitting ONLY on '&' — the
// WHATWG/URLSearchParams rule the Cadish Edge uses (edge/runtime/entry.js buildIReq). It is
// identical to net/url.ParseQuery (same '+'→space, same percent-decoding, same skip on an
// unescape error) EXCEPT it does not treat ';' as a separator and does not reject a
// ';'-containing segment: Go's ParseQuery errors on such a segment and url.Query() then
// silently DROPS it, which made the cache key omit query content the origin still receives
// (a parameter-cloaking cache-poisoning vector, and a key divergence from the edge). Keeping
// ';' as a literal value byte makes the key match both the origin's raw view and the edge.
// Returns nil for an empty query so the query-less hot path allocates nothing.
func parseQueryLossless(raw string) url.Values {
	if raw == "" {
		return nil
	}
	m := url.Values{}
	for raw != "" {
		var seg string
		seg, raw, _ = strings.Cut(raw, "&")
		if seg == "" {
			continue
		}
		k, v, _ := strings.Cut(seg, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			continue // mirror ParseQuery: skip a pair whose key fails to unescape
		}
		val, err := url.QueryUnescape(v)
		if err != nil {
			continue // mirror ParseQuery: skip a pair whose value fails to unescape
		}
		m[key] = append(m[key], val)
	}
	return m
}

// normalizePath collapses duplicate slashes and dot-segments in a client path so
// the path the pipeline MATCHES (deny/ACL, path matchers, the `path` cache_key
// token) is the SAME path the origin will actually be dialed with. It mirrors the
// httporigin urlFor cleaning EXACTLY: path.Clean collapses "//"->"/" and resolves
// "../", and a trailing slash is re-appended when the input had one (HTTP trailing
// slashes are semantically meaningful and path.Clean strips them).
//
// Without this, a path-anchored deny on "/.env" matches the raw "/.env" but lets
// "//.env" / "///.env" / "//.git/config" through (matcher sees the raw double
// slash), while urlFor cleans them back to "/.env" before fetching — serving the
// protected file (F9 path-ACL bypass). Matching and dialing must agree.
//
// Percent-encoding is unaffected: r.URL.Path is already decoded by net/http, and
// the query string is untouched, so the by-design "percent-encoded paths key to
// distinct cache entries" behavior is preserved. The empty-path edge (path.Clean
// returns ".") is normalized to "/".
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	// Strip ASCII control bytes (0x00-0x1f, 0x7f) first (Fix #8). Go's HTTP server
	// does not reject them, but the cache key joins tokens with the unit separator
	// 0x1f and the variant fingerprint uses NUL, so a control byte in the path would
	// violate the "no control byte ever appears in a cache key" invariant (and could
	// be fragile/confusing downstream). Stripping (rather than 400ing) keeps matching
	// == cache key == dialed path consistent and is the least surprising for the
	// common accidental-byte case. The fast path below is preserved when the path is
	// already clean and control-free.
	if hasControlByte(p) {
		p = stripControlBytes(p)
		if p == "" {
			return "/"
		}
	}
	cleaned := path.Clean(p)
	if cleaned == p {
		return p // already canonical: zero allocation on the hot path
	}
	// Preserve a meaningful trailing slash (directory vs. file), but never on the
	// root, which path.Clean already leaves as "/".
	if len(p) > 1 && p[len(p)-1] == '/' && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// isControlByte reports whether c is an ASCII control byte (0x00-0x1f or 0x7f DEL).
func isControlByte(c byte) bool { return c < 0x20 || c == 0x7f }

// hasControlByte reports whether s contains any ASCII control byte. It is the cheap
// guard that keeps the normalizePath hot path allocation-free for well-formed paths.
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if isControlByte(s[i]) {
			return true
		}
	}
	return false
}

// stripControlBytes returns s with every ASCII control byte removed. Called only when
// hasControlByte already found one, so the allocation is paid only on a malformed path.
func stripControlBytes(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isControlByte(c) {
			b = append(b, c)
		}
	}
	return string(b)
}

// siblingGetKey computes the cache key that a GET to THIS request's URI would
// produce — the entry RFC 9111 §4.4 invalidation must forget after a successful
// unsafe (POST/PUT/PATCH/DELETE) write. The default cache key embeds the method, so
// the unsafe request's own key (unsafeKey) does NOT name the cached GET; we re-run
// the pure request phase on a shallow copy of preq with Method forced to GET to
// derive the sibling key the GET path would have stored under. preq is a value type
// whose fields are read-only during key building, so the copy shares its maps safely
// and the original is untouched (serveMiss still sees the real POST request).
//
// Best-effort fallback: if the re-evaluation yields an empty key (e.g. a config in
// which a GET to this URI would `pass` / `respond` and so produce no key), we fall
// back to the unsafe request's own key. That is correct when the key is already
// method-less (a `cache_key path` — the GET and the POST share one key, the very case
// that motivates §4.4) and a harmless no-op otherwise (the method-bearing unsafe key
// names no stored object). Returns "" only when there is no key to invalidate.
func (h *Handler) siblingGetKey(site *boundSite, preq *pipeline.Request, unsafeKey string) string {
	getReq := *preq // shallow copy; key building only reads its fields
	getReq.Method = http.MethodGet
	if k := site.Pipeline.EvalRequest(&getReq).CacheKey; k != "" {
		return k
	}
	return unsafeKey
}

// routingCtx attaches the lb routing key (the {sticky} normalizer value) to ctx so
// a sticky / shard-by-key upstream can pin the request to a backend. The effective
// upstream name is the routed one (from `route`) or the site default. When that
// upstream declared a sticky spec, the key is derived from it (cookie, with the
// configured fallback); otherwise the client IP is attached as a best-effort key
// for shard-by-key / sticky-by-ip pools. round-robin / shard-by-url pools and plain
// origins ignore the key. An empty key attaches nothing (lb falls back to
// round-robin for that request).
func (h *Handler) routingCtx(ctx context.Context, site *boundSite, routed string, r *http.Request) context.Context {
	name := routed
	if name == "" {
		name = site.DefaultUpstreamName
	}
	// Resolve the client IP through the SAME trusted-proxy/XFF logic as the security
	// gate and {geo} (decision #16) so sticky-by-ip and shard-by-key pools pin on the
	// REAL client behind a trusted proxy, not the proxy's address.
	cip := routingClientIP(site, r)
	var key string
	if spec := site.StickySpecs[name]; spec != nil {
		key = stickyKey(spec, r, cip)
	} else {
		key = cip
	}
	if key == "" {
		return ctx
	}
	return lb.WithRoutingKey(ctx, key)
}

// routingClientIP resolves the client IP used as a load-balancing routing key,
// applying the SAME trusted-proxy / XFF logic as the security gate and {geo}
// (decision #16). Behind a trusted proxy it returns the real client (from XFF);
// otherwise it returns the peer and never honours a spoofed XFF. Returns "" for an
// unresolvable address. When the site declares no trust_proxy this is effectively
// the peer host — the common, zero-config case.
func routingClientIP(site *boundSite, r *http.Request) string {
	if addr := geo.ClientIP(r.RemoteAddr, r.Header, site.TrustedProxies); addr.IsValid() {
		return addr.String()
	}
	return ""
}

// stickyKey derives the routing key for a sticky upstream from the request, per its
// StickySpec (a cookie value, the resolved client IP, or the configured
// else-fallback). cip is the trusted-proxy-resolved client IP (see routingClientIP).
func stickyKey(spec *lb.StickySpec, r *http.Request, cip string) string {
	switch spec.Source {
	case "cookie":
		if v := cookieValue(r, spec.Cookie); v != "" {
			return v
		}
		return stickyFallback(spec, r, cip)
	case "client_ip":
		return cip
	default:
		return stickyFallback(spec, r, cip)
	}
}

// stickyFallback resolves a StickySpec's else-source. cip is the
// trusted-proxy-resolved client IP (see routingClientIP).
func stickyFallback(spec *lb.StickySpec, r *http.Request, cip string) string {
	switch spec.Fallback {
	case "client_ip":
		return cip
	case "cookie":
		return cookieValue(r, spec.FallbackCookie)
	default:
		return ""
	}
}

// cookieValue returns the named cookie's value, or "". Reads LENIENTLY (the same parser
// the gate/key/origin use) so a JSON/quoted sticky cookie produces backend affinity
// instead of silently dropping to the else-source.
func cookieValue(r *http.Request, name string) string {
	if name == "" {
		return ""
	}
	return pipeline.LenientCookieValue(r.Header, name)
}

// clientIP extracts the client IP (no port) from RemoteAddr.
func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// originTarget resolves the path + raw query to dial upstream. With no `rewrite`
// rule it returns the client-facing path/query unchanged (the common case, zero
// work). When rw is non-nil it returns the rewritten origin-only path/query — the
// cache key was already computed from the client request, so the rewrite never
// poisons it.
func originTarget(clientPath, clientRawQuery string, rw *pipeline.RewriteDecision) (path, rawQuery string) {
	if rw == nil {
		return clientPath, clientRawQuery
	}
	return rw.Path, rw.RawQuery
}

// rawQueryOf renders a pipeline.Request's query as a raw query string for the
// background revalidation path (whose original *http.Request is gone). It is "" for
// a query-less request.
func rawQueryOf(preq *pipeline.Request) string {
	return preq.Query.Encode()
}

// connectionTokens returns the canonicalized set of header names listed in src's
// `Connection` header token list (RFC 7230 §6.1). A proxy must drop those
// connection-scoped headers in BOTH directions, else a client could smuggle one to
// the origin (or an origin leak one to the client) that a compliant proxy would
// remove. Mirrors net/http/httputil's removeConnectionHeaders. Returns nil (no
// allocation) when no Connection header is present, the common case.
func connectionTokens(src http.Header) map[string]bool {
	vs := src["Connection"]
	if len(vs) == 0 {
		return nil
	}
	conn := map[string]bool{}
	for _, v := range vs {
		for _, tok := range strings.Split(v, ",") {
			if tok = textproto.TrimString(tok); tok != "" {
				conn[http.CanonicalHeaderKey(tok)] = true
			}
		}
	}
	return conn
}

// buildOriginHeader clones the client headers that should be forwarded to the
// origin (dropping hop-by-hop + Host), then applies the request-phase header ops.
func buildOriginHeader(client http.Header, ops []pipeline.HeaderOp) http.Header {
	// Connection-named hop-by-hop headers come from the CLIENT's Connection list,
	// read before the copy below drops the Connection header itself (it is in
	// hopByHop). A client must not smuggle a Connection-listed header to the origin.
	conn := connectionTokens(client)
	out := http.Header{}
	for k, vs := range client {
		ck := http.CanonicalHeaderKey(k)
		if hopByHop[ck] || conn[ck] || ck == "Host" {
			continue
		}
		for _, v := range vs {
			out.Add(k, v)
		}
	}
	applyHeaderOps(out, ops)
	return out
}

// copyOriginHeaders copies upstream response headers (minus hop-by-hop) into hdr.
func copyOriginHeaders(hdr, src http.Header) {
	// Connection-named hop-by-hop headers come from the ORIGIN's Connection list, so
	// an origin cannot leak a connection-scoped header to the client.
	conn := connectionTokens(src)
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if hopByHop[ck] || conn[ck] {
			continue
		}
		for _, v := range vs {
			hdr.Add(k, v)
		}
	}
}

// applyHeaderOps applies a list of header edits to hdr in order.
func applyHeaderOps(hdr http.Header, ops []pipeline.HeaderOp) {
	for _, op := range ops {
		switch op.Op {
		case pipeline.OpSet:
			hdr.Set(op.Name, op.Value)
		case pipeline.OpAppend:
			hdr.Add(op.Name, op.Value)
		case pipeline.OpRemove:
			hdr.Del(op.Name)
		}
	}
}

// applyCORS writes CORS response headers from a CORSDecision. With an explicit
// origin allow-list it ECHOES the request's Origin (a single value) when allowed
// and emits no Access-Control-Allow-Origin otherwise — matching the edge
// (edge/entry.js) and the Fetch spec, which forbids a comma-joined origin list.
func applyCORS(hdr http.Header, c *pipeline.CORSDecision, reqOrigin string) {
	if c.AllowAllOrigins {
		hdr.Set("Access-Control-Allow-Origin", "*")
	} else if len(c.Origins) > 0 {
		if reqOrigin != "" && slices.Contains(c.Origins, reqOrigin) {
			hdr.Set("Access-Control-Allow-Origin", reqOrigin)
			hdr.Add("Vary", "Origin")
		}
	}
	if len(c.Methods) > 0 {
		hdr.Set("Access-Control-Allow-Methods", strings.Join(c.Methods, ", "))
	}
	if len(c.Headers) > 0 {
		hdr.Set("Access-Control-Allow-Headers", strings.Join(c.Headers, ", "))
	}
}

// conditionalNotModified reports whether a cached 200 representation with the given
// validators satisfies the request's conditional headers such that a 304 Not
// Modified is the correct response (RFC 9110 §13). It is called only on a cache HIT.
//
// Precedence (RFC 9110 §13.2.2): If-None-Match takes priority over
// If-Modified-Since; If-Modified-Since is evaluated only when If-None-Match is
// absent. If-None-Match matches on `*` (any current representation) or when any
// member of the comma-separated list matches the cached ETag under a WEAK
// comparison (the weak/strong `W/` prefix is ignored on both sides, the correct
// comparison for If-None-Match per §8.8.3.2). If-Modified-Since yields 304 when the
// cached Last-Modified is not after the client's date (the client already holds a
// copy at least as new). A malformed/absent validator on the cache side simply does
// not match (falls through to a full 200). The leading presence check keeps a
// request with no conditional header allocation-free.
func conditionalNotModified(reqHdr http.Header, etag, lastModified string, now func() time.Time) bool {
	if inm := reqHdr.Get("If-None-Match"); inm != "" {
		return ifNoneMatch(inm, etag)
	}
	if ims := reqHdr.Get("If-Modified-Since"); ims != "" && lastModified != "" {
		imsTime, err1 := http.ParseTime(ims)
		lmTime, err2 := http.ParseTime(lastModified)
		if err1 == nil && err2 == nil {
			// 304 when the resource was NOT modified after the client's date and the
			// client's date is not in the future relative to our clock.
			return !lmTime.After(imsTime) && !imsTime.After(now())
		}
	}
	return false
}

// ifNoneMatch evaluates an If-None-Match header value against a cached ETag,
// returning true when the precondition fails (so a 304 is served). `*` matches any
// existing representation. Otherwise the value is a comma-separated list of entity
// tags; a match (weak comparison, ignoring any W/ prefix on either side) means the
// client's copy is current.
func ifNoneMatch(inm, etag string) bool {
	inm = strings.TrimSpace(inm)
	if inm == "*" {
		return true
	}
	if etag == "" {
		return false
	}
	want := trimETagWeak(etag)
	for _, tok := range strings.Split(inm, ",") {
		if trimETagWeak(strings.TrimSpace(tok)) == want {
			return true
		}
	}
	return false
}

// trimETagWeak strips an optional leading weak indicator (W/) from an entity tag so
// two tags can be compared with the weak comparison function (RFC 9110 §8.8.3.2).
func trimETagWeak(tag string) string {
	return strings.TrimPrefix(tag, "W/")
}

// ifRangeAllowsRange evaluates an `If-Range` header (RFC 9110 §14.2): the Range request
// is honored (206) only when the validator still matches the cached representation;
// otherwise the Range is IGNORED and the full 200 is served (RG1). The comparison is
// the STRONG one — an entity-tag must match exactly and neither side may be weak (a
// `W/` tag never satisfies If-Range), and an HTTP-date must equal the Last-Modified
// exactly. An empty If-Range (the common case) always allows the Range.
func ifRangeAllowsRange(ifRange, etag, lastModified string) bool {
	ifRange = strings.TrimSpace(ifRange)
	if ifRange == "" {
		return true
	}
	// Entity-tag form (a quoted tag). Strong comparison: exact, and neither weak.
	if strings.HasPrefix(ifRange, "\"") {
		return etag != "" && !strings.HasPrefix(etag, "W/") && ifRange == etag
	}
	// A weak validator in If-Range can never satisfy the required strong comparison.
	if strings.HasPrefix(ifRange, "W/") {
		return false
	}
	// HTTP-date form: it must equal the representation's Last-Modified exactly.
	if lastModified == "" {
		return false
	}
	irTime, err1 := http.ParseTime(ifRange)
	lmTime, err2 := http.ParseTime(lastModified)
	return err1 == nil && err2 == nil && irTime.Equal(lmTime)
}

// clientForcesRevalidate reports whether the request demands the cache revalidate
// with origin before serving a stored response: `Cache-Control: no-cache` or
// `max-age=0`, or the HTTP/1.0 `Pragma: no-cache` (RFC 9111 §5.2.1.4). The
// presence checks short-circuit so a request carrying neither header does a single
// map lookup that returns "" — no parsing, no allocation. Only a non-empty
// Cache-Control is tokenized.
func clientForcesRevalidate(reqHdr http.Header) bool {
	if cc := reqHdr.Get("Cache-Control"); cc != "" {
		for _, tok := range strings.Split(cc, ",") {
			switch strings.ToLower(strings.TrimSpace(tok)) {
			case "no-cache", "max-age=0":
				return true
			}
		}
	}
	// Pragma: no-cache is the HTTP/1.0 equivalent; honored only as a no-cache signal.
	if p := reqHdr.Get("Pragma"); p != "" {
		for _, tok := range strings.Split(p, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "no-cache") {
				return true
			}
		}
	}
	return false
}

// isSafeMethod reports whether the request method is one whose response a shared
// cache may store (RFC 9111 §3 / RFC 9110 §9.2.1 safe methods). An empty method
// means GET (net/http default). Only GET and HEAD qualify; HEAD has no body to
// store, so in practice only GET responses are cached.
func isSafeMethod(m string) bool {
	return m == "" || m == http.MethodGet || m == http.MethodHead
}

func setIfNonEmpty(hdr http.Header, name, value string) {
	if value != "" {
		hdr.Set(name, value)
	}
}

// audit emits one security-audit record for an ENFORCED or MONITORED gate action,
// off the request hot path (the AuditLog's writer goroutine serializes it). The
// h.auditLog.Enabled() gate keeps a non-configured server at exactly one nil-check:
// nothing is built or sent when the audit log is off (the default). The record MAY
// carry the real client IP — recording who was blocked is the whole point — but
// never the query string / signed-URL signature (D18 / D52).
func (h *Handler) audit(r *http.Request, action string, enforced bool, rule, clientIP string, status int) {
	if !h.auditLog.Enabled() {
		return
	}
	h.auditLog.Record(AuditRecord{
		Time:     h.now(),
		Action:   action,
		Enforced: enforced,
		Rule:     rule,
		Method:   methodOf(r),
		Host:     r.Host,
		Path:     r.URL.Path,
		ClientIP: clientIP,
		Status:   status,
	})
}

// securityTrace renders a one-line trace note for a security-gate decision.
func securityTrace(sec pipeline.SecurityDecision) string {
	switch {
	case sec.Block:
		return "DENY " + sec.Rule + " (403)"
	case sec.Monitor:
		return "WOULD-DENY " + sec.Rule + " (monitor, passed)"
	case sec.Allow:
		return "ALLOW " + sec.Rule + " (short-circuit)"
	case sec.RateLimit != nil:
		return "RATE_LIMIT " + sec.RateLimit.Rule + " (key " + sec.RateLimit.Key + ")"
	default:
		return "pass (no rule matched)"
	}
}

// rateLimitTrace renders a one-line trace note for a rate-limit enforcement.
func rateLimitTrace(hit *pipeline.RateLimitHit, d ratelimit.Decision) string {
	if d.OK {
		return "PASS " + hit.Rule
	}
	if hit.Monitor {
		return "WOULD-429 " + hit.Rule + " (monitor, passed)"
	}
	return "429 " + hit.Rule + " (retry-after " + strconv.Itoa(ratelimit.RetryAfterSeconds(d.RetryAfter)) + "s)"
}

// writeStatus writes a plain-text status response.
func writeStatus(rec *statusRecorder, code int, msg string) {
	rec.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rec.WriteHeader(code)
	_, _ = io.WriteString(rec, msg)
}
