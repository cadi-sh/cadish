package server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/metrics"
)

// wsEcho is a minimal RAW connection-upgrade echo upstream built on net/http's
// Hijacker (no third-party WebSocket dep): on a genuine upgrade it writes a `101`
// handshake and echoes every subsequent byte; on a NON-upgrade request it records
// the `Upgrade` header it received (so the security regression test can prove the
// global hop-by-hop strip still removes Upgrade on the normal pass path) and answers
// 200.
type wsEcho struct {
	srv *httptest.Server

	// respHandshake is the raw status+headers the upstream writes on a genuine upgrade.
	// Default is a well-formed `101` with `Upgrade: websocket`; a test can override it to
	// model a mismatched/empty Upgrade token (Finding 2).
	respHandshake string
	// connClosed is closed once the hijacked upstream goroutine returns (its deferred
	// conn.Close ran) — the observable that proves the backend conn did NOT leak.
	connClosed chan struct{}

	mu                 sync.Mutex
	sawNonUpgrade      bool
	nonUpgradeUpgrade  string
	nonUpgradeConnRecv string
	// upgradeCookie records the Cookie header the upstream received on the GENUINE
	// upgrade (tunnel) path — the Finding 1 probe that the original client cookies reach
	// the upstream intact, not stripped by cookie_allow / derives_from.
	upgradeCookie    string
	sawUpgradeCookie bool
	// upgradePath is the request-target (path + raw query) the upstream received on the
	// GENUINE upgrade path — the SPEC-WS-UPGRADE-PATH-STRIP probe that a `rewrite path`
	// on the route IS applied to the tunnel dial (stripped prefix), not the verbatim
	// client path.
	upgradePath string
	// upgradeReqHdr is a snapshot of ALL headers the upstream received on the genuine
	// upgrade path — the Finding 3 probe that request-phase header ops (strips + dynamic
	// trust stamps) ARE applied to the tunnel handshake, not bypassed.
	upgradeReqHdr http.Header
	// httpPath is the request-target (path + raw query) the upstream received on the
	// NON-upgrade (ordinary HTTP) path — the HTTP↔upgrade parity probe: a plain GET and a
	// genuine upgrade through the SAME rewrite+route must dial the origin at the SAME
	// request-target (escaping + query canonicalization identical), since the whole point
	// of SPEC-WS-UPGRADE-PATH-STRIP is HTTP↔upgrade dial parity.
	httpPath    string
	sawHTTPPath bool
}

func newWSEcho(t *testing.T) *wsEcho {
	t.Helper()
	e := &wsEcho{
		respHandshake: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
		connClosed:    make(chan struct{}),
	}
	var closeOnce sync.Once
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgradeRequest(r) {
			e.mu.Lock()
			e.sawNonUpgrade = true
			e.nonUpgradeUpgrade = r.Header.Get("Upgrade")
			e.nonUpgradeConnRecv = r.Header.Get("Connection")
			e.httpPath = r.URL.RequestURI()
			e.sawHTTPPath = true
			e.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "plain")
			return
		}
		e.mu.Lock()
		e.upgradeCookie = r.Header.Get("Cookie")
		e.upgradeReqHdr = r.Header.Clone()
		e.upgradePath = r.URL.RequestURI()
		e.sawUpgradeCookie = true
		e.mu.Unlock()
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer closeOnce.Do(func() { close(e.connClosed) })
		defer conn.Close()
		_, _ = io.WriteString(conn, e.respHandshake)
		// Echo raw bytes both buffered and subsequent until either side closes.
		_, _ = io.Copy(conn, buf)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

const wsCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	cache_ttl default ttl 60s
}
`

// dialUpgrade opens a raw TCP connection to serverURL and sends a WebSocket upgrade
// handshake for path. It returns the live conn plus a buffered reader positioned just
// after the response headers, and the response status line.
func dialUpgrade(t *testing.T, serverURL, path, host string, genuine bool) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial cadish: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	connHdr := "Upgrade"
	if !genuine {
		// A non-genuine upgrade: an Upgrade header WITHOUT a Connection:upgrade token,
		// so isUpgradeRequest is false and the request must NOT be tunnelled.
		connHdr = "keep-alive"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: " + connHdr + "\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	// Drain headers up to the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br, strings.TrimSpace(status)
}

// TestGlobalHopByHopStripUntouched is a pure unit guard: the global hop-by-hop strip
// set MUST still contain Upgrade and Connection. The tunnel adds a NEW path; it must
// never relax the global strip that protects every normal request.
func TestGlobalHopByHopStripUntouched(t *testing.T) {
	for _, h := range []string{"Upgrade", "Connection"} {
		if !hopByHop[h] {
			t.Fatalf("hopByHop[%q] = false, want true (global strip must stay closed)", h)
		}
	}
}

// TestUpgradeTunnelWebSocketEcho stands up a raw WS echo upstream and asserts a full
// tunnel through cadish: 101 Switching Protocols, bidirectional frames, clean close.
func TestUpgradeTunnelWebSocketEcho(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, br, status := dialUpgrade(t, front.URL, "/ws/chat", "test.local", true)
	defer conn.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101 Switching Protocols", status)
	}

	// Bidirectional: client -> upstream -> client echo, both ways, multiple frames.
	for _, msg := range []string{"hello", "world", "third frame"} {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("read echo of %q: %v", msg, err)
		}
		if string(got) != msg {
			t.Fatalf("echo = %q, want %q", got, msg)
		}
	}

	// Clean close: closing the client tears the pair down; the upstream's io.Copy
	// returns and the goroutine exits (no leak — race detector would flag a misuse).
	conn.Close()
}

// wsRewriteCfg routes the /chatserver prefix to the WS upstream, upgrades it, AND strips
// the prefix with `rewrite path` — the live socket.io chat shape (prefix routing + handshake
// strip). The matcher needs the ORIGINAL /chatserver prefix, so the rewrite is origin-only
// and must be honored on the tunnel dial (SPEC-WS-UPGRADE-PATH-STRIP).
const wsRewriteCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @chat -> ws
	upgrade @chat
	rewrite path ^/chatserver(/.*)$ $1
	@chat path /chatserver/*
	cache_ttl default ttl 60s
}
`

// wsChatNoRewriteCfg is wsRewriteCfg WITHOUT the `rewrite path` line — the no-rewrite control
// that proves the dial is byte-identical (verbatim /chatserver path) when no rewrite matches.
const wsChatNoRewriteCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @chat -> ws
	upgrade @chat
	@chat path /chatserver/*
	cache_ttl default ttl 60s
}
`

// TestUpgradeAppliesRewritePathToDial is the SPEC-WS-UPGRADE-PATH-STRIP outcome-equivalence
// proof: a route that BOTH upgrades (`upgrade @chat`) and strips its routing prefix
// (`rewrite path ^/chatserver(/.*)$ $1`) must dial the upstream at the STRIPPED path on the
// WebSocket handshake — exactly as the cached/passed HTTP path does — so a socket.io client
// reaching cadish at /chatserver/socket.io/?EIO=4 hits the chat origin at /socket.io/?EIO=4.
// Before the fix the tunnel dialed r.URL verbatim and the origin 404'd the handshake.
func TestUpgradeAppliesRewritePathToDial(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsRewriteCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, _, status := dialUpgrade(t, front.URL, "/chatserver/socket.io/?EIO=4", "test.local", true)
	defer conn.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101 Switching Protocols (origin must accept the stripped path)", status)
	}
	echo.mu.Lock()
	got := echo.upgradePath
	echo.mu.Unlock()
	// The origin must see the STRIPPED path AND the query preserved/rewritten consistently
	// (a path-only rewrite forwards the original query verbatim).
	if want := "/socket.io/?EIO=4"; got != want {
		t.Fatalf("upstream upgrade target = %q, want %q (rewrite path must strip the /chatserver prefix on the tunnel dial)", got, want)
	}
}

// TestUpgradeNoRewriteDialsVerbatim is the no-rewrite control: the SAME route shape WITHOUT a
// `rewrite path` rule (rd.Rewrite == nil) dials the upstream at the VERBATIM client path —
// byte-identical to before the SPEC-WS-UPGRADE-PATH-STRIP change, so the fix is a pure no-op
// when no rewrite matches.
func TestUpgradeNoRewriteDialsVerbatim(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsChatNoRewriteCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, _, status := dialUpgrade(t, front.URL, "/chatserver/socket.io/?EIO=4", "test.local", true)
	defer conn.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101 Switching Protocols", status)
	}
	echo.mu.Lock()
	got := echo.upgradePath
	echo.mu.Unlock()
	if want := "/chatserver/socket.io/?EIO=4"; got != want {
		t.Fatalf("upstream upgrade target = %q, want %q (no rewrite must dial the verbatim client path — byte-identical)", got, want)
	}
}

// TestUpgradeNonGenuineRequestStillStripsUpgrade is the SECURITY REGRESSION: a request
// on an upgrade route that is NOT a genuine upgrade (no Connection:upgrade token) must
// NOT be tunnelled — it falls through to the normal pass path, where buildOriginHeader
// STILL strips the Upgrade (and Connection) hop-by-hop headers. The echo upstream must
// therefore never see an Upgrade header on that path.
func TestUpgradeNonGenuineRequestStillStripsUpgrade(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, _, status := dialUpgrade(t, front.URL, "/ws/poll", "test.local", false)
	defer conn.Close()
	if !strings.Contains(status, "200") {
		t.Fatalf("non-genuine upgrade status = %q, want 200 (plain pass)", status)
	}

	echo.mu.Lock()
	defer echo.mu.Unlock()
	if !echo.sawNonUpgrade {
		t.Fatalf("upstream never saw the non-upgrade request")
	}
	if echo.nonUpgradeUpgrade != "" {
		t.Fatalf("upstream received Upgrade header %q on the normal path — global strip regressed", echo.nonUpgradeUpgrade)
	}
	if strings.Contains(strings.ToLower(echo.nonUpgradeConnRecv), "upgrade") {
		t.Fatalf("upstream received Connection:%q with an upgrade token on the normal path — global strip regressed", echo.nonUpgradeConnRecv)
	}
}

// TestUpgradeIdleNotReapedByOriginWatchdog is the R32 regression: the WS tunnel idle is
// FLOORED to the WS-safe minimum (minTunnelIdle), DECOUPLED from -idle-timeout (the ORIGIN
// body-stall watchdog). A short -idle-timeout (the common media-edge 60s) must NOT reap a
// legitimately quiet WS that has no app-level heartbeat. With a tiny IdleTimeout the tunnel
// must stay established well past it: the gauge stays 1 and a quiet read TIMES OUT (still
// connected) rather than returning EOF (torn down). Before the fix the tunnel reused
// h.idleTimeout verbatim and would be reaped at the short value.
func TestUpgradeIdleNotReapedByOriginWatchdog(t *testing.T) {
	echo := newWSEcho(t)
	m := metrics.New()
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{IdleTimeout: 100 * time.Millisecond, Metrics: m})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, br, status := dialUpgrade(t, front.URL, "/ws/quiet", "test.local", true)
	defer conn.Close()
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101", status)
	}
	waitGauge(t, m, 1, time.Second)

	// Stay silent for many multiples of the origin idle (100ms). Under the OLD behaviour
	// the watchdog would have reaped the tunnel at 100ms; with the R32 floor it survives.
	conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	buf := make([]byte, 16)
	_, err := br.Read(buf)
	if err == nil {
		t.Fatalf("unexpected data on a quiet tunnel")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("quiet read err = %v; want a client read TIMEOUT (tunnel still established), got a teardown — the origin idle watchdog reaped the WS (R32 regressed)", err)
	}
	// The tunnel must still be live: the gauge stays at 1 (not reaped).
	if got := m.Snapshot().UpgradesActive; got != 1 {
		t.Fatalf("UpgradesActive = %d after a quiet period, want 1 (the WS must not be reaped by the short origin idle watchdog)", got)
	}
}

// recordRWC is a minimal io.ReadWriteCloser for the idle-floor unit tests: Read blocks
// nothing (returns EOF), Write swallows, Close records that the conn was closed.
type recordRWC struct {
	mu     sync.Mutex
	closed bool
}

func (r *recordRWC) Read(p []byte) (int, error)  { return 0, io.EOF }
func (r *recordRWC) Write(p []byte) (int, error) { return len(p), nil }
func (r *recordRWC) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}
func (r *recordRWC) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// TestTunnelIdleFloor unit-tests the R32 floor math in newIdleTunnelConn: the effective
// tunnel idle is never below the floor (so a short origin idle, or none, never reaps a WS
// sooner than the WS-safe minimum), while an idle ABOVE the floor is preserved verbatim.
func TestTunnelIdleFloor(t *testing.T) {
	cases := []struct {
		name        string
		idle, floor time.Duration
		want        time.Duration
	}{
		{"unconfigured-floored-to-default", 0, 0, minTunnelIdle},
		{"short-origin-idle-floored-to-default", 100 * time.Millisecond, 0, minTunnelIdle},
		{"above-floor-preserved", 30 * time.Minute, 0, 30 * time.Minute},
		{"explicit-floor-applied", 0, 20 * time.Millisecond, 20 * time.Millisecond},
		{"idle-above-explicit-floor-preserved", 50 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := metrics.New()
			m.IncUpgrade() // mirror RoundTrip's Inc so Close's Dec balances the gauge
			c := newIdleTunnelConn(&recordRWC{}, tc.idle, tc.floor, m, nil)
			if c.idle != tc.want {
				t.Fatalf("effective idle = %v, want %v", c.idle, tc.want)
			}
			_ = c.Close() // stop the armed watchdog timer + balance the gauge
		})
	}
}

// TestTunnelIdleReaperFires proves the floored watchdog still tears a truly-stuck tunnel
// down: with a tiny explicit floor the AfterFunc fires, closing the conn, decrementing the
// active gauge, and invoking the teardown hook — the defense-in-depth that keeps a wedged
// peer from pinning the upstream conn + the gauge forever.
func TestTunnelIdleReaperFires(t *testing.T) {
	m := metrics.New()
	m.IncUpgrade()
	done := make(chan struct{})
	rwc := &recordRWC{}
	// idle 0 floored to the tiny test floor (20ms) → the watchdog fires fast.
	c := newIdleTunnelConn(rwc, 0, 20*time.Millisecond, m, func() { close(done) })
	_ = c
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle reaper did not fire within 2s")
	}
	if got := m.Snapshot().UpgradesActive; got != 0 {
		t.Fatalf("UpgradesActive = %d after reap, want 0", got)
	}
	if !rwc.isClosed() {
		t.Fatal("underlying conn was not closed on reap")
	}
}

// TestUpgradeActiveGaugeIncDec proves the active-upgraded-connections gauge increments
// on the 101 hijack and decrements on teardown.
func TestUpgradeActiveGaugeIncDec(t *testing.T) {
	echo := newWSEcho(t)
	m := metrics.New()
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{Metrics: m})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, _, status := dialUpgrade(t, front.URL, "/ws/g", "test.local", true)
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101", status)
	}
	waitGauge(t, m, 1, time.Second)
	conn.Close()
	waitGauge(t, m, 0, time.Second)
}

// TestUpgradeConcurrentTunnels opens many tunnels at once (run under -race): each does
// a bidirectional echo and a clean close. It exercises concurrent hijack + teardown +
// gauge accounting for the race detector.
func TestUpgradeConcurrentTunnels(t *testing.T) {
	echo := newWSEcho(t)
	m := metrics.New()
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{Metrics: m})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, br, status := dialUpgrade(t, front.URL, "/ws/c", "test.local", true)
			defer conn.Close()
			if !strings.Contains(status, "101") {
				errs <- fmt.Errorf("conn %d: status %q", i, status)
				return
			}
			msg := fmt.Sprintf("frame-%d", i)
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte(msg)); err != nil {
				errs <- fmt.Errorf("conn %d write: %w", i, err)
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(br, got); err != nil {
				errs <- fmt.Errorf("conn %d read: %w", i, err)
				return
			}
			if string(got) != msg {
				errs <- fmt.Errorf("conn %d echo %q != %q", i, got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	waitGauge(t, m, 0, 2*time.Second)
}

// TestUpgradeMismatchedProtocolNoLeak is the Finding 2 regression: when the upstream
// answers 101 with an Upgrade token that does NOT match the request's (here "h2c" vs
// "websocket"), httputil.ReverseProxy's handleUpgradeResponse early-returns. The tunnel
// transport must therefore NOT increment the active gauge or wrap the body — otherwise
// the gauge inflates permanently and the upstream conn leaks. We assert: the client gets
// a clean 502 (no hijacked tunnel), the active gauge stays/returns to 0, and the backend
// conn is closed (no leak).
func TestUpgradeMismatchedProtocolNoLeak(t *testing.T) {
	echo := newWSEcho(t)
	echo.respHandshake = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"
	m := metrics.New()
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{Metrics: m})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, _, status := dialUpgrade(t, front.URL, "/ws/bad", "test.local", true)
	defer conn.Close()
	if !strings.Contains(status, "502") {
		t.Fatalf("mismatched-101 status = %q, want 502 (clean error, no tunnel)", status)
	}
	// The gauge must never have stuck high: it returns to (stays at) 0.
	waitGauge(t, m, 0, time.Second)
	// The backend conn must be closed — no leak.
	select {
	case <-echo.connClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("backend upstream conn was not closed after a mismatched 101 (leak)")
	}
}

// wsCookieCfg is an upgrade route that ALSO strips cookies for cache-key normalization:
// `cookie_allow darkMode` keeps only darkMode (it strips session), and the `classify`
// recipe's `derives_from cookie session` consumes session post-key (COOKIE-NORM
// auto-strip). Both run BEFORE the tunnel dispatch, so without the Finding 1 fix the
// genuine WS handshake would reach the upstream with `session` stripped.
const wsCookieCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	@verified cookie session loggedin
	classify {auth} {
		derives_from cookie session
		when @verified -> 1
		default        -> 0
	}
	cookie_allow darkMode
	cache_key default host url {auth}
	cache_ttl default ttl 60s
}
`

// TestUpgradeTunnelForwardsOriginalCookie is the Finding 1 regression: on an `upgrade
// @scope` route that ALSO has cookie_allow + derives_from active, a genuine WebSocket
// handshake carrying an identity cookie must reach the upstream with the ORIGINAL Cookie
// intact — NOT the cache-key-normalized (stripped) one. The tunnel runs off the cache, so
// a logged-in user's socket must stay authenticated. Before the fix the upstream received
// only `darkMode=1` (session stripped) and would reject the handshake as anonymous.
func TestUpgradeTunnelForwardsOriginalCookie(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsCookieCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial cadish: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	const cookie = "session=abc123; darkMode=1"
	req := "GET /ws/chat HTTP/1.1\r\n" +
		"Host: test.local\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Cookie: " + cookie + "\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101 Switching Protocols", strings.TrimSpace(status))
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		echo.mu.Lock()
		seen, got := echo.sawUpgradeCookie, echo.upgradeCookie
		echo.mu.Unlock()
		if seen {
			if !strings.Contains(got, "session=abc123") {
				t.Fatalf("upstream received Cookie %q, want the ORIGINAL incl. session=abc123 (cookie_allow/derives_from must NOT strip the tunnel handshake)", got)
			}
			if got != cookie {
				t.Fatalf("upstream Cookie = %q, want the original %q forwarded verbatim", got, cookie)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream never recorded the upgrade request")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wsHeaderOpsCfg is an upgrade route carrying REQUEST-PHASE header ops (before cache_key):
// a `header -X-Secret` operator strip and a `header X-Real-IP {client_ip}` dynamic trust
// stamp. Both compile into rd.ReqHeaderOps and MUST be applied to the tunnel handshake.
const wsHeaderOpsCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	header -X-Secret
	header X-Real-IP {client_ip}
	cache_key default host url
	cache_ttl default ttl 60s
}
`

// TestUpgradeTunnelAppliesRequestHeaderOps is the Finding 3 regression: a genuine
// connection-upgrade on an `upgrade @scope` route must run the route's request-phase
// header ops (rd.ReqHeaderOps) on the outbound tunnel request, exactly as the plain pass
// path does via buildOriginHeader. Before the fix serveUpgrade's Director set only the
// X-Forwarded-* trailers and restored the Cookie but NEVER applied ReqHeaderOps, so an
// operator strip (`header -X-Secret`) and a re-stamp (`header X-Real-IP {client_ip}`) were
// bypassed on the tunnel — a trust-boundary control bypass that let a client smuggle the
// stripped header and SPOOF X-Real-IP through to the upstream. We send the handshake with a
// X-Secret and a spoofed X-Real-IP and assert the upstream sees the secret GONE and
// X-Real-IP re-stamped to the real client IP (loopback), not the spoofed value.
func TestUpgradeTunnelAppliesRequestHeaderOps(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsHeaderOpsCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial cadish: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET /ws/chat HTTP/1.1\r\n" +
		"Host: test.local\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"X-Secret: leak-me\r\n" +
		"X-Real-IP: 6.6.6.6\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101 Switching Protocols", strings.TrimSpace(status))
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		echo.mu.Lock()
		seen := echo.sawUpgradeCookie
		hdr := echo.upgradeReqHdr.Clone()
		echo.mu.Unlock()
		if seen {
			if got := hdr.Get("X-Secret"); got != "" {
				t.Fatalf("upstream received X-Secret %q on the tunnel — request-phase strip bypassed", got)
			}
			if got := hdr.Get("X-Real-IP"); got != "127.0.0.1" {
				t.Fatalf("upstream X-Real-IP = %q, want the re-stamped client IP 127.0.0.1 (not the spoofed 6.6.6.6)", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream never recorded the upgrade request")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestUpgradeEmptyPoolReturns503 is the Finding 4 regression: an upgrade request routed to
// a pool with NO eligible backend (here a health-spec'd single backend pointed at a closed
// origin, so it starts DOWN) must return 503 Service Unavailable — the retriable "no
// upstream available right now" — mirroring the Fetch path's lb.ErrNoBackend→503, NOT a
// 502 Bad Gateway implying a broken upstream. The failure occurs in ResolveUpgrade, before
// any hijack, so a plain ResponseRecorder suffices.
func TestUpgradeEmptyPoolReturns503(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	deadURL := origin.srv.URL
	origin.srv.Close() // unreachable: the health-spec backend starts DOWN and never probes UP

	cfg := `test.local {
	cache { ram 8MiB }
	upstream ws {
		to %s
		health GET /healthz expect 200 interval 1s window 1 threshold 1
	}
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, deadURL)
	req := httptest.NewRequest("GET", "http://test.local/ws/chat", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("upgrade to empty/all-down pool: code = %d, want 503 Service Unavailable (ErrNoUpgradeBackend → retriable), not 502", rec.Code)
	}
}

// countingWS is a minimal upgrade backend that records how many genuine upgrades it
// served (used to observe which backend of a sticky pool a tunnel was pinned to). On a
// genuine upgrade it counts, writes a 101 handshake and echoes; otherwise answers 200.
type countingWS struct {
	srv *httptest.Server
	mu  sync.Mutex
	n   int
}

func newCountingWS(t *testing.T) *countingWS {
	t.Helper()
	c := &countingWS{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgradeRequest(r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(conn, buf)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *countingWS) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// buildHandlerTwoBackends loads a config template carrying TWO %s upstream backends.
func buildHandlerTwoBackends(t *testing.T, tmpl, url1, url2 string) *Handler {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	cfgText := fmt.Sprintf(tmpl, url1, url2)
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, cfgText)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	h := NewHandler(cfg, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)
	return h
}

// wsStickyCookieCfg is a TWO-backend sticky-BY-COOKIE pool that ALSO strips the sticky
// cookie for cache-key normalization: `cookie_allow darkMode` keeps only darkMode and
// strips `session` (the very cookie the pool pins on). The strip runs BEFORE the tunnel
// dispatch, so without the R11 fix the upgrade routing key would be computed from the
// stripped header (no session → the `else client_ip` fallback, constant for one client →
// every tunnel pinned to ONE backend), diverging from how a normal cookie-routed request
// picks.
const wsStickyCookieCfg = `test.local {
	cache { ram 8MiB }
	upstream pool {
		to %s
		to %s
		sticky by cookie session else client_ip
	}
	route @sock -> pool
	upgrade @sock
	@sock path /ws*
	cookie_allow darkMode
	cache_ttl default ttl 60s
}
`

// dialUpgradeCookie sends a genuine WS upgrade carrying a Cookie header and returns the
// status line. It closes the conn before returning (the test only needs the routing pick,
// recorded by the backend before the 101).
func dialUpgradeCookie(t *testing.T, serverURL, path, host, cookie string) string {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial cadish: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Cookie: " + cookie + "\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return strings.TrimSpace(status)
}

// TestUpgradeStickyByCookieRoutesOnRestoredCookie is the R11 regression: a sticky-BY-COOKIE
// pool must route the tunnel on the ORIGINAL (pre-strip) cookie, exactly as a normal
// cookie-routed request does — not on the cookie-stripped header. We send many upgrades
// each carrying a DISTINCT `session` value (all from the same loopback client) on a route
// whose `cookie_allow darkMode` strips `session`. Under the bug the routing key collapses
// to the constant `else client_ip` fallback → every tunnel is pinned to ONE backend (the
// other sees zero). With the fix the cookie is restored before routing, so the per-session
// consistent-hash spreads the tunnels across BOTH backends. We assert both backends served
// at least one tunnel (impossible under the constant-fallback bug).
func TestUpgradeStickyByCookieRoutesOnRestoredCookie(t *testing.T) {
	b1 := newCountingWS(t)
	b2 := newCountingWS(t)
	h := buildHandlerTwoBackends(t, wsStickyCookieCfg, b1.srv.URL, b2.srv.URL)
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	const n = 24
	for i := 0; i < n; i++ {
		cookie := fmt.Sprintf("session=user-%d; darkMode=1", i)
		status := dialUpgradeCookie(t, front.URL, "/ws/chat", "test.local", cookie)
		if !strings.Contains(status, "101") {
			t.Fatalf("upgrade %d status = %q, want 101", i, status)
		}
	}

	got1, got2 := b1.count(), b2.count()
	if got1+got2 != n {
		t.Fatalf("backends served %d+%d tunnels, want %d total", got1, got2, n)
	}
	if got1 == 0 || got2 == 0 {
		t.Fatalf("sticky-by-cookie tunnels landed on a single backend (%d / %d) — routing used the COOKIE-STRIPPED header (R11): with the original cookie restored before routing, distinct session values must spread across both backends", got1, got2)
	}
}

// dialUpgradeXFF sends a genuine WS upgrade carrying a forged X-Forwarded-For header and
// returns the status line. It closes the conn before returning (the test only needs the
// upstream's recorded handshake headers).
func dialUpgradeXFF(t *testing.T, serverURL, path, host, xff string) string {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial cadish: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"X-Forwarded-For: " + xff + "\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return strings.TrimSpace(status)
}

// waitUpgradeHdr polls until the echo upstream has recorded a genuine-upgrade handshake
// and returns a snapshot of the headers it saw.
func waitUpgradeHdr(t *testing.T, echo *wsEcho) http.Header {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		echo.mu.Lock()
		seen := echo.sawUpgradeCookie
		hdr := echo.upgradeReqHdr.Clone()
		echo.mu.Unlock()
		if seen {
			return hdr
		}
		if time.Now().After(deadline) {
			t.Fatal("upstream never recorded the upgrade request")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wsTrustCfg is an upgrade route that TRUSTS the loopback peer as a proxy, so the inbound
// X-Forwarded-For chain is vetted (kept) and the verified socket peer is appended.
const wsTrustCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	trust_proxy 127.0.0.0/8
	cache_ttl default ttl 60s
}
`

// TestUpgradeTunnelXFFSanitizedUntrusted is the R05 WS-tunnel regression: a genuine
// connection-upgrade from an UNTRUSTED/direct peer carrying a forged X-Forwarded-For must
// reach the upstream with XFF = the verified socket peer, NOT the spoofed value. Before the
// fix the tunnel built its origin request via httputil.NewSingleHostReverseProxy, whose
// Director APPENDS the socket peer to the (spoofed) inbound XFF rather than overwriting it,
// so an XFF-trusting origin taking the leftmost entry saw the attacker's IP.
func TestUpgradeTunnelXFFSanitizedUntrusted(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	status := dialUpgradeXFF(t, front.URL, "/ws/chat", "test.local", "1.2.3.4")
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101", status)
	}
	hdr := waitUpgradeHdr(t, echo)
	got := hdr.Get("X-Forwarded-For")
	if strings.Contains(got, "1.2.3.4") {
		t.Fatalf("upstream X-Forwarded-For = %q — the forged 1.2.3.4 from an untrusted peer reached origin (R05 not applied on the WS-upgrade path)", got)
	}
	if got != "127.0.0.1" {
		t.Fatalf("upstream X-Forwarded-For = %q, want the verified socket peer 127.0.0.1", got)
	}
}

// TestUpgradeTunnelXFFAppendedTrusted is the trusted-proxy half of R05 on the WS tunnel:
// behind a configured trust_proxy the vetted inbound chain is KEPT and the socket peer is
// APPENDED (standard reverse-proxy semantics), not blindly trusted.
func TestUpgradeTunnelXFFAppendedTrusted(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsTrustCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	status := dialUpgradeXFF(t, front.URL, "/ws/chat", "test.local", "1.2.3.4")
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101", status)
	}
	hdr := waitUpgradeHdr(t, echo)
	if got := hdr.Get("X-Forwarded-For"); got != "1.2.3.4, 127.0.0.1" {
		t.Fatalf("upstream X-Forwarded-For = %q, want %q (vetted chain kept, peer appended)", got, "1.2.3.4, 127.0.0.1")
	}
}

// TestUpgradeOriginDisconnectTearsDownClient exercises the ORIGIN-initiated teardown
// (the existing echo tests only cover CLIENT-initiated close): the upstream writes the
// 101 handshake then immediately closes its end. Two things must hold:
//   - the disconnect PROPAGATES to the client: its read returns EOF (not a hang/timeout),
//     because httputil.ReverseProxy half-closes the client's read side (CloseWrite) when
//     the backend copy reaches EOF; and
//   - once the client (as any real WS client does on seeing that EOF) closes its socket,
//     the tunnel is fully reaped: the active gauge returns to 0, no conn/goroutine leak
//     (run under -race).
//
// NOTE on the silent-client window: ReverseProxy's handleUpgradeResponse waits for BOTH
// copy directions before it closes the backend conn (and our idleTunnelConn → DecUpgrade).
// After an origin disconnect the client->backend direction stays blocked reading a client
// that has not yet closed, so the gauge is decremented only when the client closes OR the
// idle watchdog (minTunnelIdle floor) reaps the tunnel. A cooperative client closes
// promptly; the watchdog is the bounded backstop for a non-cooperative one.
func TestUpgradeOriginDisconnectTearsDownClient(t *testing.T) {
	closeAfterHandshake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgradeRequest(r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		// Origin-initiated disconnect: drop the tunnel right after the handshake.
		_ = conn.Close()
	}))
	t.Cleanup(closeAfterHandshake.Close)

	m := metrics.New()
	h := buildHandlerOpts(t, wsCfg, closeAfterHandshake.URL, Options{Metrics: m})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, br, status := dialUpgrade(t, front.URL, "/ws/drop", "test.local", true)
	if !strings.Contains(status, "101") {
		conn.Close()
		t.Fatalf("handshake status = %q, want 101", status)
	}
	waitGauge(t, m, 1, time.Second)

	// The origin closed: the client read must terminate with EOF (the half-close was
	// propagated), not hang/timeout.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := br.Read(make([]byte, 16))
	if err == nil {
		conn.Close()
		t.Fatal("client read returned data after an origin disconnect, want EOF (read-side teardown should propagate)")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		conn.Close()
		t.Fatalf("client read TIMED OUT after an origin disconnect — the upstream->client half-close did not reach the client (hang)")
	}
	// A real WS client closes on seeing the EOF; doing so must fully reap the tunnel —
	// the active gauge returns to 0 (no conn/goroutine leak on the cooperative path).
	conn.Close()
	waitGauge(t, m, 0, 2*time.Second)
}

// TestUpgradeOriginRefusesNon101 covers the error path where the origin DECLINES the
// upgrade with an ordinary HTTP response (here 401) instead of a 101. ReverseProxy must
// relay that response verbatim to the client (no hijack, no half-upgrade), the active
// gauge must never increment, and the body must reach the client. This proves a refused
// handshake surfaces as a clean status, not a wedged/hijacked connection.
func TestUpgradeOriginRefusesNon101(t *testing.T) {
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Even on a genuine upgrade request, answer a normal 401 (origin auth refusal).
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "nope")
	}))
	t.Cleanup(refuse.Close)

	m := metrics.New()
	h := buildHandlerOpts(t, wsCfg, refuse.URL, Options{Metrics: m})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn, br, status := dialUpgrade(t, front.URL, "/ws/auth", "test.local", true)
	defer conn.Close()
	if !strings.Contains(status, "401") {
		t.Fatalf("refused-upgrade status = %q, want 401 (origin's non-101 relayed verbatim)", status)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	body := make([]byte, len("nope"))
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("read refused-upgrade body: %v", err)
	}
	if string(body) != "nope" {
		t.Fatalf("refused-upgrade body = %q, want the origin body \"nope\" relayed", body)
	}
	// No tunnel was ever established: the active gauge must stay at 0.
	if got := m.Snapshot().UpgradesActive; got != 0 {
		t.Fatalf("UpgradesActive = %d after a non-101 refusal, want 0 (no hijack on a declined upgrade)", got)
	}
}

// wsDenyCfg is an upgrade route guarded by a path ACL: `deny @blocked` covers
// /ws/admin*, while the rest of /ws* is a tunnel. A GENUINE connection-upgrade to the
// denied sub-path MUST be blocked at the SECURITY GATE (which runs BEFORE the upgrade
// dispatch) — never tunnelled. This is the load-bearing no-bypass invariant: a client
// must not smuggle past a path ACL merely by adding Upgrade/Connection headers.
const wsDenyCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	@blocked path /ws/admin*
	deny @blocked
	cache_ttl default ttl 60s
}
`

// TestUpgradeDeniedByACLNotTunnelled is the CRITICAL no-bypass regression: a genuine WS
// upgrade to an ACL-denied path must return 403 and MUST NOT be tunnelled — the backend
// must never see it (no hijack). The security gate runs before the upgrade dispatch
// (handler.go: EvalSecurity at the top of RECV, the `rd.Upgrade && isUpgradeRequest`
// dispatch far below), so adding Upgrade/Connection headers cannot smuggle a request past
// a path/ip ACL. A positive control (an upgrade to the ALLOWED sub-path) proves the route
// still tunnels, so the 403 is the ACL firing, not the route being broken.
func TestUpgradeDeniedByACLNotTunnelled(t *testing.T) {
	backend := newCountingWS(t)
	h := buildHandlerOpts(t, wsDenyCfg, backend.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	// Genuine upgrade to the DENIED sub-path -> 403, never tunnelled.
	conn, _, status := dialUpgrade(t, front.URL, "/ws/admin/socket", "test.local", true)
	conn.Close()
	if !strings.Contains(status, "403") {
		t.Fatalf("denied upgrade status = %q, want 403 Forbidden (ACL must gate the upgrade path)", status)
	}
	if got := backend.count(); got != 0 {
		t.Fatalf("backend served %d upgrades for an ACL-denied path, want 0 — a genuine upgrade SMUGGLED PAST the path ACL (CRITICAL no-bypass invariant broken)", got)
	}

	// Positive control: an upgrade to the ALLOWED sub-path still tunnels (101).
	conn2, _, status2 := dialUpgrade(t, front.URL, "/ws/chat", "test.local", true)
	defer conn2.Close()
	if !strings.Contains(status2, "101") {
		t.Fatalf("allowed upgrade status = %q, want 101 (the route must still tunnel)", status2)
	}
	deadline := time.Now().Add(2 * time.Second)
	for backend.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := backend.count(); got != 1 {
		t.Fatalf("backend served %d upgrades after one allowed tunnel, want 1", got)
	}
}

// wsRateLimitCfg gates the upgrade route with a 1r/s burst-1 rate limit keyed on client
// IP. The SECOND rapid upgrade from the same client must be throttled (429) BEFORE the
// upgrade dispatch — a genuine upgrade must not bypass the rate limiter.
const wsRateLimitCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @sock -> ws
	upgrade @sock
	@sock path /ws*
	rate_limit @sock 1r/s burst 1 key ip
	cache_ttl default ttl 60s
}
`

// TestUpgradeRateLimitedNotTunnelled is the CRITICAL no-bypass regression for the rate
// limiter: with a 1r/s burst-1 limit, the first genuine upgrade tunnels (101) and the
// second rapid upgrade from the same client is throttled with 429 — NOT tunnelled. The
// limiter is consulted in the security gate, before the upgrade dispatch, so an upgrade
// request cannot bypass it. We assert the second status is 429 and the backend served
// exactly one tunnel (the throttled upgrade never reached it).
func TestUpgradeRateLimitedNotTunnelled(t *testing.T) {
	backend := newCountingWS(t)
	h := buildHandlerOpts(t, wsRateLimitCfg, backend.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	conn1, _, status1 := dialUpgrade(t, front.URL, "/ws/a", "test.local", true)
	defer conn1.Close()
	if !strings.Contains(status1, "101") {
		t.Fatalf("first upgrade status = %q, want 101 (burst token available)", status1)
	}
	// Second rapid upgrade from the same loopback client: burst exhausted -> 429.
	conn2, _, status2 := dialUpgrade(t, front.URL, "/ws/b", "test.local", true)
	conn2.Close()
	if !strings.Contains(status2, "429") {
		t.Fatalf("second rapid upgrade status = %q, want 429 Too Many Requests (rate limit must gate the upgrade path)", status2)
	}
	if got := backend.count(); got != 1 {
		t.Fatalf("backend served %d upgrades, want 1 — the throttled upgrade was TUNNELLED, bypassing the rate limiter (CRITICAL)", got)
	}
}

// httpGetThroughSite drives an ordinary HTTP GET for target through the front server,
// forcing the Host so the host-bound site matches (httptest gives a 127.0.0.1 authority).
// It returns the response status code after draining the body.
func httpGetThroughSite(t *testing.T, frontURL, target, host string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, frontURL+target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http get %q: %v", target, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestUpgradeHTTPDialParity is the core SPEC-WS-UPGRADE-PATH-STRIP guarantee: an ordinary
// HTTP request and a genuine WebSocket upgrade, driven through the SAME `rewrite path`
// route, must dial the origin at the BYTE-IDENTICAL request-target. The whole point of the
// fix is HTTP↔upgrade parity — the upgrade tunnel reuses the same originTarget helper the
// HTTP origin fetch uses and resets URL.RawPath="" so url.URL re-derives the escaped wire
// form exactly as httporigin.urlFor does. We probe several targets that exercise path-prefix
// stripping, query reordering/canonicalization, and characters that need re-escaping, and
// assert the origin saw the SAME target on both the HTTP and the upgrade path. Any escaping
// or query-canonicalization divergence between the two paths fails here.
func TestUpgradeHTTPDialParity(t *testing.T) {
	cases := []struct {
		name   string
		target string // client request-target under /chatserver (rewrite strips the prefix)
		want   string // request-target the origin must see on BOTH paths
	}{
		{"plain", "/chatserver/socket.io/?EIO=4&transport=websocket", "/socket.io/?EIO=4&transport=websocket"},
		{"query-reordered-canonicalized", "/chatserver/x/?z=last&a=1", "/x/?a=1&z=last"},
		{"query-space-reencoded", "/chatserver/y/?room=hello%20world", "/y/?room=hello+world"},
		{"path-needs-escape", "/chatserver/a%20b/c", "/a%20b/c"},
		{"no-query", "/chatserver/socket.io/", "/socket.io/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			echo := newWSEcho(t)
			h := buildHandlerOpts(t, wsRewriteCfg, echo.srv.URL, Options{})
			front := httptest.NewServer(h)
			t.Cleanup(front.Close)

			// HTTP path: a plain GET (MISS) reaches the origin, which records the dialed target.
			if code := httpGetThroughSite(t, front.URL, tc.target, "test.local"); code != http.StatusOK {
				t.Fatalf("http GET %q status = %d, want 200", tc.target, code)
			}
			echo.mu.Lock()
			sawHTTP, httpPath := echo.sawHTTPPath, echo.httpPath
			echo.mu.Unlock()
			if !sawHTTP {
				t.Fatalf("origin never recorded the HTTP request for %q", tc.target)
			}
			if httpPath != tc.want {
				t.Fatalf("HTTP dial target = %q, want %q", httpPath, tc.want)
			}

			// Upgrade path: a genuine WS handshake through the same route.
			conn, _, status := dialUpgrade(t, front.URL, tc.target, "test.local", true)
			defer conn.Close()
			if !strings.Contains(status, "101") {
				t.Fatalf("upgrade %q status = %q, want 101", tc.target, status)
			}
			echo.mu.Lock()
			wsPath := echo.upgradePath
			echo.mu.Unlock()

			// The headline parity assertion: HTTP and upgrade must dial the IDENTICAL target.
			if wsPath != httpPath {
				t.Fatalf("HTTP↔upgrade dial DIVERGED for %q: http=%q ws=%q (the tunnel must dial the SAME request-target the HTTP origin fetch does)", tc.target, httpPath, wsPath)
			}
			if wsPath != tc.want {
				t.Fatalf("upgrade dial target = %q, want %q", wsPath, tc.want)
			}
		})
	}
}

// wsRewriteHeaderOpsCfg combines a `rewrite path` prefix-strip with the request-phase
// header ops (a `-X-Secret` strip + an X-Real-IP re-stamp) and a sticky-by-cookie context,
// so the CLONE branch of serveUpgrade (rd.Rewrite != nil) is exercised TOGETHER with the
// trust-boundary controls. The existing security regressions all run rewrite-less configs
// (dialReq == r, no clone); this guards that cloning r for the rewrite does not fork the
// header/forwarded/cookie handling in a way that drops a control on the tunnel.
const wsRewriteHeaderOpsCfg = `test.local {
	cache { ram 8MiB }
	upstream ws { to %s }
	route @chat -> ws
	upgrade @chat
	rewrite path ^/chatserver(/.*)$ $1
	@chat path /chatserver/*
	header -X-Secret
	header X-Real-IP {client_ip}
	cache_key default host url
	cache_ttl default ttl 60s
}
`

// TestUpgradeRewriteStillAppliesSecurityControls proves the rewrite CLONE path preserves
// every trust-boundary control the rewrite-less path has: with `rewrite path` active the
// genuine upgrade must STILL (a) strip the operator-controlled X-Secret, (b) re-stamp
// X-Real-IP to the real client IP (not the spoofed value), (c) sanitize a forged
// X-Forwarded-For to the verified peer, AND (d) reach the origin at the STRIPPED path. A
// regression in any of these would mean cloning r for the rewrite forked the header/URL
// handling and dropped a control on the tunnel.
func TestUpgradeRewriteStillAppliesSecurityControls(t *testing.T) {
	echo := newWSEcho(t)
	h := buildHandlerOpts(t, wsRewriteHeaderOpsCfg, echo.srv.URL, Options{})
	front := httptest.NewServer(h)
	t.Cleanup(front.Close)

	u, err := url.Parse(front.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial cadish: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET /chatserver/socket.io/?EIO=4 HTTP/1.1\r\n" +
		"Host: test.local\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"X-Secret: leak-me\r\n" +
		"X-Real-IP: 6.6.6.6\r\n" +
		"X-Forwarded-For: 1.2.3.4\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("handshake status = %q, want 101", strings.TrimSpace(status))
	}

	hdr := waitUpgradeHdr(t, echo)
	if got := hdr.Get("X-Secret"); got != "" {
		t.Fatalf("upstream received X-Secret %q on the rewrite tunnel — request-phase strip dropped by the clone", got)
	}
	if got := hdr.Get("X-Real-IP"); got != "127.0.0.1" {
		t.Fatalf("upstream X-Real-IP = %q, want re-stamped 127.0.0.1 (not spoofed 6.6.6.6) on the rewrite tunnel", got)
	}
	if got := hdr.Get("X-Forwarded-For"); strings.Contains(got, "1.2.3.4") || got != "127.0.0.1" {
		t.Fatalf("upstream X-Forwarded-For = %q, want sanitized 127.0.0.1 on the rewrite tunnel (forged 1.2.3.4 must not survive)", got)
	}
	echo.mu.Lock()
	wsPath := echo.upgradePath
	echo.mu.Unlock()
	if want := "/socket.io/?EIO=4"; wsPath != want {
		t.Fatalf("upstream upgrade target = %q, want %q (rewrite must still strip the prefix while applying controls)", wsPath, want)
	}
}

// TestUpgradeRewriteTraversalNeutralized is the path-traversal guard for the rewrite tunnel.
// httporigin.urlFor confines an HTTP origin fetch to the base path (path.Clean + a base-path
// containment check); the upgrade tunnel dials via httputil.ReverseProxy, which does NOT
// path.Clean or confine. That divergence is NEUTRALIZED upstream of the dial because preq.Path
// is normalizePath()'d (decoded + path.Clean) BEFORE both routing/matching and the rewrite, so
// a client-supplied `..` (raw or %2e-encoded) collapses before it can match the `/chatserver/*`
// scope or be captured by the rewrite regex. A traversal attempt therefore never matches the
// upgrade route → it is never tunnelled and the WS origin never sees an escaped target.
func TestUpgradeRewriteTraversalNeutralized(t *testing.T) {
	for _, target := range []string{
		"/chatserver/socket.io/../../../etc/passwd",
		"/chatserver/%2e%2e/%2e%2e/secret",
	} {
		backend := newCountingWS(t)
		h := buildHandlerOpts(t, wsRewriteCfg, backend.srv.URL, Options{})
		front := httptest.NewServer(h)

		conn, _, status := dialUpgrade(t, front.URL, target, "test.local", true)
		conn.Close()
		if strings.Contains(status, "101") {
			front.Close()
			t.Fatalf("traversal target %q produced a 101 tunnel — `..` was not normalized before routing", target)
		}
		if got := backend.count(); got != 0 {
			front.Close()
			t.Fatalf("WS origin served %d upgrades for traversal target %q, want 0 (must never reach the origin)", got, target)
		}
		front.Close()
	}
}

// waitGauge polls the active-upgrade gauge until it equals want or the timeout
// elapses (teardown is asynchronous to the client close).
func waitGauge(t *testing.T, m *metrics.Metrics, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := m.Snapshot().UpgradesActive; got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("UpgradesActive = %d, want %d after %s", m.Snapshot().UpgradesActive, want, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
