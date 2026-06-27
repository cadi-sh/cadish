package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/cadi-sh/cadish/internal/metrics"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// minTunnelIdle is the WS-tunnel idle FLOOR (Finding 2 + R32). It is applied to EVERY
// tunnel, not just the unconfigured default: the server's -idle-timeout (h.idleTimeout)
// is the ORIGIN body-stall watchdog (a between-bytes deadline for a streaming fetch),
// NOT a WebSocket-tunnel knob. A short origin idle (the common media-edge 60s) reused
// verbatim on the tunnel would reap a legitimately quiet WS that has no app-level
// heartbeat. So the tunnel idle is floored to this WS-safe minimum — decoupled from the
// origin watchdog (whose own behaviour, in idlereader.go / serveOrigin, is unchanged) —
// while still arming the AfterFunc watchdog so a wedged peer (no bytes, no close) can
// never pin the upstream conn + the active gauge forever. It does not affect a live
// tunnel: any byte in either direction resets the timer, so traffic (incl. WebSocket
// keepalive pings) keeps it open; only a tunnel with NO activity for this long is reaped.
const minTunnelIdle = 15 * time.Minute

// upgradeType returns the protocol-upgrade token of a header set, mirroring the stdlib
// httputil.ReverseProxy's unexported upgradeType: the `Upgrade` header value, but only
// when `Connection` carries an `upgrade` token (case-insensitive, RFC 7230 §6.1);
// otherwise "". Used to validate the upstream's 101 against the request before tunnelling.
func upgradeType(h http.Header) string {
	connHasUpgrade := false
	for _, v := range h["Connection"] {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				connHasUpgrade = true
			}
		}
	}
	if !connHasUpgrade {
		return ""
	}
	return h.Get("Upgrade")
}

// isPrintableASCII reports whether s is entirely printable ASCII (0x20..0x7e). It mirrors
// the stdlib ReverseProxy's ascii.IsPrint guard on the response Upgrade token: a non-
// printable token is rejected rather than tunnelled.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// isUpgradeRequest reports whether r is a GENUINE protocol-upgrade request: its
// `Connection` header lists an `upgrade` token (case-insensitive, RFC 7230 §6.1)
// AND an `Upgrade` header is present. Only such a request is tunnelled; a plain
// request on an `upgrade @scope` route is served as a normal pass. This is the gate
// that keeps the tunnel opt-in AND behaviour-bound — no request without the upgrade
// handshake is ever hijacked.
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header["Connection"] {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// serveUpgrade tunnels a genuine connection-upgrade (WebSocket / `Connection:
// Upgrade`) request to the routed upstream's backend pick, entirely off the caching
// path. It REUSES httputil.ReverseProxy — whose `101` hijack, bidirectional copy and
// half-close teardown are already correct and hardened — rather than hand-rolling an
// http.Hijacker. The ReverseProxy is aimed at the upstream resolved by the SAME
// route the rest of the pipeline used (origin.Upgrader.ResolveUpgrade), so the lb
// health/sticky pick and the per-upstream transport (connect/TLS timeouts, `sni`,
// `http_reuse`, `tls_insecure`/`ca_file`/`alpn`) are honored — no second dialer.
func (h *Handler) serveUpgrade(rec *statusRecorder, r *http.Request, site *boundSite, preq *pipeline.Request, rd pipeline.RequestDecision, origCookie string, info *reqInfo) {
	info.cacheStatus = "UPGRADE"
	info.upstream = rd.Upstream
	info.upgraded = true
	info.tr.lookup("UPGRADE (tunnel; bypass cache)")

	o := site.originFor(rd.Upstream)
	up, ok := o.(origin.Upgrader)
	if !ok {
		// The routed origin cannot host a tunnel (e.g. an S3 / chain origin). Fail
		// closed with a clean 502 — never silently fall through to a cache fetch that
		// would strip the upgrade headers and hang the client's handshake.
		h.log.Warn("upgrade: routed upstream does not support connection-upgrade tunnels",
			"upstream", rd.Upstream, "host", r.Host, "path", r.URL.Path)
		writeStatus(rec, http.StatusBadGateway, "upgrade not supported by upstream")
		return
	}

	// Restore the ORIGINAL client Cookie onto r.Header BEFORE routing (R11) — exactly what
	// the plain pass path does (handler.go restores it before serveOrigin's routingCtx).
	// cookie_allow / derives_from stripped r.Header's Cookie purely to normalize the CACHE
	// KEY, but a Sticky / Shard-BY-COOKIE pool derives its routing key from that very Cookie
	// (routingCtx → stickyKey → cookieValue). Routing on the stripped header makes the tunnel
	// pick a DIFFERENT backend than a normal cookie-routed request would, breaking session
	// affinity ("Session ID unknown"). This tunnel never consults rd.CacheKey and is NEVER
	// cached/stored, so restoring the per-user cookie here cannot contaminate a shared cache
	// entry — the same reason the pass path does it (SPEC-PASS-FORWARDS-COOKIES). The outbound
	// clone `out` inherits this restored Cookie, so the upstream also receives the original
	// handshake cookie; no separate Director restore is needed.
	restoreClientCookie(r.Header, origCookie)

	// SPEC-WS-UPGRADE-PATH-STRIP: apply the request-phase `rewrite path` transform to the
	// URL the tunnel dials upstream — the SAME originTarget the HTTP origin fetch uses
	// (handler.go's serveOrigin). An upgrade route that also rewrites the path (e.g.
	// `rewrite path ^/chatserver(/.*)$ $1`) must reach the origin at the STRIPPED path on
	// the handshake too, exactly as a cached/passed HTTP request would; today the tunnel
	// dialed `r.URL` verbatim and the rewrite was a silent no-op on `upgrade`, 404'ing the
	// socket.io handshake. The cache key / route matching already ran on the ORIGINAL
	// client path (the matcher needs the `/chatserver` prefix), so the rewrite is
	// origin-only here just as for HTTP. With NO matching `rewrite`, rd.Rewrite is nil and
	// originTarget returns the client path/query unchanged → dialReq stays r and the dial
	// is byte-identical to before (no behavior change). Host/SNI rewrite on upgrade is
	// explicitly out of scope (use host_header/sni); only the request PATH/query is rewritten.
	dialReq := r
	if rd.Rewrite != nil {
		dialPath, dialRawQuery := originTarget(preq.Path, r.URL.RawQuery, rd.Rewrite)
		dialReq = r.Clone(r.Context())
		dialReq.URL.Path = dialPath
		dialReq.URL.RawPath = "" // re-derive the escaped form from the rewritten Path (as urlFor does)
		dialReq.URL.RawQuery = dialRawQuery
	}

	oreq := &origin.Request{
		Method:     methodOf(r),
		Key:        dialReq.URL.RequestURI(),
		ClientHost: pipeline.NormalizeHost(preq.Host),
		Header:     r.Header,
	}
	// Thread the SAME lb routing key the Fetch path uses (cookie-or-client-IP, per the
	// routed upstream's sticky spec) so a Sticky / Shard-by-key pool pins this tunnel to
	// the SAME backend a normal request would hit — preserving socket.io / WebSocket
	// affinity instead of silently falling back to round-robin (Finding 3). routingCtx now
	// reads the RESTORED Cookie (above), so a sticky-by-cookie pick matches the one a normal
	// cookie-routed request makes. An empty key (no sticky spec / no cookie) attaches nothing
	// and pick falls back to round-robin, exactly as before.
	rctx := h.routingCtx(r.Context(), site, rd.Upstream, r)
	tgt, err := up.ResolveUpgrade(rctx, oreq)
	if err != nil || tgt.URL == nil {
		// An EMPTY pool (no backend currently eligible — all down/ejected) is a transient,
		// retriable condition, NOT a broken gateway. Mirror the Fetch path's
		// lb.ErrNoBackend→503 mapping (handler.go) so a client/LB sees "no upstream
		// available right now, retry" instead of a 502 implying a faulty upstream. Any
		// OTHER ResolveUpgrade failure, or a nil target URL, stays a 502.
		status, msg := http.StatusBadGateway, "no upstream available for upgrade"
		if errors.Is(err, origin.ErrNoUpgradeBackend) {
			status, msg = http.StatusServiceUnavailable, "no upstream available for upgrade"
		}
		h.log.Warn("upgrade: no eligible backend for tunnel",
			"upstream", rd.Upstream, "host", r.Host, "path", r.URL.Path, "err", err)
		writeStatus(rec, status, msg)
		return
	}

	clientHost := r.Host
	// R05 on the tunnel: the verified inputs for the forwarded-header sanitization the
	// Director applies below (same trust-boundary policy as the non-upgrade origin path).
	fwd := &forwardCtx{remoteAddr: r.RemoteAddr, tls: r.TLS != nil, host: clientHost, trusted: site.TrustedProxies}

	// Build the tunnel proxy. NewSingleHostReverseProxy's director sets scheme/host,
	// joins the base path, and merges the query; we extend it to apply the upstream's
	// host_header policy and the X-Forwarded-* trailer. ReverseProxy itself preserves
	// the inbound Upgrade/Connection tokens (it recomputes the upgrade type from the
	// outbound request after stripping hop-by-hop), and Sec-WebSocket-* are not
	// hop-by-hop, so the handshake headers reach the upstream verbatim.
	proxy := httputil.NewSingleHostReverseProxy(tgt.URL)
	base := proxy.Director
	proxy.Director = func(out *http.Request) {
		base(out)
		if tgt.Host != "" {
			out.Host = tgt.Host // host_header policy (HostFixed / HostOrigin); "" preserves client Host
		}
		// R05 trust-boundary forwarded-header sanitization on the tunnel (was MISSING — only
		// X-Forwarded-Proto/Host were set, so a forged X-Forwarded-For from an untrusted peer
		// reached origin as `1.2.3.4, <peer>`: httputil.ReverseProxy APPENDS the socket peer
		// to the inbound chain rather than overwriting it). Reuse the SAME helper the origin
		// path uses; appendPeer=false because ReverseProxy appends the verified peer itself
		// AFTER this Director (it reads the inbound req.RemoteAddr). So for an untrusted peer
		// the spoofable inbound XFF is DROPPED (the proxy then stamps the peer alone) and for
		// a trusted proxy the vetted chain is kept (the proxy appends the peer to it). This
		// also sets X-Real-IP / X-Forwarded-Proto / X-Forwarded-Host and drops Forwarded.
		applyForwardedHeaders(out.Header, out.Header, fwd, false)
		// The ORIGINAL client Cookie was already restored on r.Header before routing (R11),
		// so the outbound clone `out` carries it (SPEC-PASS-FORWARDS-COOKIES) — no separate
		// restore here. This tunnel never touches the cache (it does not use rd.CacheKey), so
		// forwarding the per-user cookie is safe; a stripped handshake would otherwise arrive
		// anonymous and the upstream would reject a logged-in user's socket.
		// Apply the request-phase header ops (Finding 3): the plain pass path runs these
		// via buildOriginHeader → applyHeaderOps, but the tunnel Director previously did
		// not, so a request-phase `header` op (operator strips like `header -X-Internal-Auth`
		// AND dynamic trust stamps like `header X-Real-IP {client_ip}` /
		// `header X-Forwarded-For {client_ip}`) was SKIPPED on a genuine upgrade — a
		// trust-boundary control bypass. Applied AFTER the forwarded-header sanitization and
		// the cookie restore so the ordering matches the pass path (an operator `header` op
		// can still intentionally override either).
		applyHeaderOps(out.Header, rd.ReqHeaderOps)
	}
	// FlushInterval = -1 makes ReverseProxy stream immediately (no write buffering),
	// which is mandatory for an interactive bidirectional tunnel.
	proxy.FlushInterval = -1
	// The tunnel transport REUSES the per-upstream RoundTripper (knobs honored) and
	// wraps the established 101 connection for the active-tunnel gauge + idle teardown.
	proxy.Transport = &upgradeTransport{
		base:    tgt.Transport,
		idle:    h.idleTimeout,
		metrics: h.metrics,
	}
	if h.log != nil {
		proxy.ErrorLog = slog.NewLogLogger(h.log.Handler(), slog.LevelWarn)
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
		// Reached when the upstream dial / 101 handshake fails BEFORE the client conn
		// is hijacked. After the hijack ReverseProxy owns teardown and this is not
		// called. statusRecorder latches the first status, so a 502 here is safe.
		h.log.Warn("upgrade: tunnel dial failed", "upstream", rd.Upstream, "host", clientHost, "path", r.URL.Path, "err", e)
		w.WriteHeader(http.StatusBadGateway)
	}

	// Dial with the rewritten request (dialReq == r when no `rewrite` matched, so the
	// outbound path/query are byte-identical to before). ReverseProxy clones dialReq
	// internally; its SingleHost director joins tgt.URL's base path with dialReq.URL.Path
	// and merges dialReq.URL.RawQuery — so the rewritten path/query reach the upstream.
	proxy.ServeHTTP(rec, dialReq)
}

// upgradeTransport is the RoundTripper the upgrade tunnel hands to httputil.Reverse-
// Proxy. It delegates to the per-upstream base transport (so the dial honors every
// configured knob — never a second independent dialer) and, when the upstream answers
// `101 Switching Protocols`, wraps the hijacked connection so the server can (a)
// count the live tunnel on the active-tunnel gauge and (b) tear it down on idle.
type upgradeTransport struct {
	base    http.RoundTripper
	idle    time.Duration
	metrics *metrics.Metrics
	// onTeardown, when non-nil, is invoked once when the tunnel conn is closed (tests
	// observe teardown without racing on the metrics gauge).
	onTeardown func()
}

func (t *upgradeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := t.base
	if rt == nil {
		// Defensive: a configured origin always supplies its own transport. Fall back
		// to a fresh default rather than nil-panic, never to a shared global with
		// caps that would kill an idle tunnel.
		rt = &http.Transport{}
	}
	res, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// On a 101 the body is the raw upgraded connection (an io.ReadWriteCloser that
	// ReverseProxy copies bidirectionally). Wrap it so both copy directions (client→
	// upstream Write, upstream→client Read) reset one idle timer; either side closing,
	// or the idle deadline, tears down the pair. Only a real 101 increments the gauge.
	if res.StatusCode == http.StatusSwitchingProtocols {
		// Validate the upgrade BEFORE counting/wrapping (Finding 2). ReverseProxy's
		// handleUpgradeResponse early-returns — WITHOUT closing res.Body — when the
		// response Upgrade token is non-printable or does not equal-fold the request's.
		// If we had already IncUpgrade()'d and wrapped, idleTunnelConn.Close (and its
		// DecUpgrade) would then NEVER run: the gauge would inflate permanently and the
		// upstream conn would leak. So mirror the stdlib check here and, on a mismatch,
		// close the body and return an error — ReverseProxy's ErrorHandler emits a clean
		// 502 with no leak, and Inc/Dec stay exactly-once.
		reqUpType := upgradeType(req.Header)
		resUpType := upgradeType(res.Header)
		if !isPrintableASCII(resUpType) || !strings.EqualFold(reqUpType, resUpType) {
			res.Body.Close()
			return nil, fmt.Errorf("upstream switched to unexpected protocol %q", resUpType)
		}
		if rwc, ok := res.Body.(io.ReadWriteCloser); ok {
			t.metrics.IncUpgrade()
			// Floor the tunnel idle to the WS-safe minimum (R32), decoupling it from the
			// origin body-stall watchdog (t.idle == h.idleTimeout).
			res.Body = newIdleTunnelConn(rwc, t.idle, minTunnelIdle, t.metrics, t.onTeardown)
		}
	}
	return res, nil
}

// idleTunnelConn wraps the hijacked upgrade connection. It implements io.ReadWrite-
// Closer (the type ReverseProxy.handleUpgradeResponse copies through). Read and Write
// each reset a single idle timer; when it fires — or either copy direction errors and
// closes — the underlying conn is closed exactly once, the active-tunnel gauge is
// decremented, and any test hook fires. idle == 0 disables the watchdog (the tunnel
// lives until either side closes), matching the server's default unbounded behaviour.
type idleTunnelConn struct {
	rwc        io.ReadWriteCloser
	metrics    *metrics.Metrics
	onTeardown func()
	idle       time.Duration

	closeOnce sync.Once

	mu     sync.Mutex
	timer  *time.Timer
	closed bool
}

func newIdleTunnelConn(rwc io.ReadWriteCloser, idle, floor time.Duration, m *metrics.Metrics, onTeardown func()) *idleTunnelConn {
	// Floor the effective tunnel idle (Finding 2 + R32). `floor` is the WS-safe minimum
	// (production passes minTunnelIdle; tests pass a tiny value to exercise the timer fast).
	// This serves two ends at once: (a) a non-positive configured idle would otherwise leave
	// an established tunnel with NO watchdog, letting a wedged peer pin the upstream conn +
	// the active gauge forever; and (b) a SHORT configured idle (the origin body-stall
	// watchdog, default 60s) reused verbatim would reap a legitimately quiet WS with no
	// app-level heartbeat. Flooring covers both — the tunnel is never reaped sooner than the
	// floor, and a live tunnel resets the timer on every byte so active traffic is undisturbed.
	if floor <= 0 {
		floor = minTunnelIdle
	}
	if idle < floor {
		idle = floor
	}
	c := &idleTunnelConn{rwc: rwc, metrics: m, onTeardown: onTeardown, idle: idle}
	if idle > 0 {
		// AfterFunc fires Close from its own goroutine; Close is idempotent (closeOnce).
		// Assign c.timer UNDER mu: the timer goroutine reads c.timer under mu in Close,
		// and AfterFunc may have already armed the timer by the time we assign, so the
		// lock provides the happens-before that makes the assignment visible (and not a
		// data race) to that goroutine.
		c.mu.Lock()
		c.timer = time.AfterFunc(idle, func() { _ = c.Close() })
		c.mu.Unlock()
	}
	return c
}

// reset extends the idle deadline on any byte of activity in EITHER direction. The
// two copy goroutines call Read and Write concurrently; the timer is guarded by mu.
func (c *idleTunnelConn) reset() {
	if c.idle <= 0 {
		return
	}
	c.mu.Lock()
	if !c.closed && c.timer != nil {
		c.timer.Reset(c.idle)
	}
	c.mu.Unlock()
}

func (c *idleTunnelConn) Read(p []byte) (int, error) {
	n, err := c.rwc.Read(p)
	if n > 0 {
		c.reset()
	}
	return n, err
}

func (c *idleTunnelConn) Write(p []byte) (int, error) {
	n, err := c.rwc.Write(p)
	if n > 0 {
		c.reset()
	}
	return n, err
}

func (c *idleTunnelConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
		err = c.rwc.Close()
		c.metrics.DecUpgrade()
		if c.onTeardown != nil {
			c.onTeardown()
		}
	})
	return err
}
