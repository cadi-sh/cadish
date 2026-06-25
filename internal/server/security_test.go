package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doFrom performs one request against the handler from a specific RemoteAddr
// (peer) so the `ip` ACL matcher (trusted-proxy-resolved client IP) can be
// exercised. extraHdr is applied verbatim (e.g. an X-Forwarded-For chain).
func doFrom(h *Handler, method, target, remoteAddr string, extraHdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = "test.local"
	req.RemoteAddr = remoteAddr
	for k, vs := range extraHdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const cfgDeny = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@scanners path /.env /.git/*
	deny @scanners
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestDenyBlocksBeforeCacheAndOrigin is the load-bearing guarantee (design §1): an
// enforced deny returns 403 and touches NEITHER the cache NOR the origin.
func TestDenyBlocksBeforeCacheAndOrigin(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret")
	})
	h, _ := buildHandler(t, nil, cfgDeny, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/.env", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied request: got %d, want 403", rec.Code)
	}
	if rec.Body.String() == "secret" {
		t.Fatal("denied request leaked the origin body (origin was reached)")
	}
	if origin.hits.Load() != 0 {
		t.Fatalf("origin was hit %d times for a denied request, want 0", origin.hits.Load())
	}
	// X-Cache is a deliver-phase header; a blocked request never reaches DELIVER, so
	// it must be absent (the request never touched the cache lookup path).
	if got := rec.Header().Get("X-Cache"); got != "" {
		t.Fatalf("denied request set X-Cache=%q, want empty (never reached cache)", got)
	}

	// A second denied request must STILL hit origin 0 times (nothing was cached).
	_ = do(h, "GET", "http://test.local/.env", nil)
	if origin.hits.Load() != 0 {
		t.Fatalf("after two denied requests origin hits = %d, want 0", origin.hits.Load())
	}

	// A non-denied path serves normally and reaches origin.
	rec = do(h, "GET", "http://test.local/index.html", nil)
	if rec.Code != 200 || origin.hits.Load() != 1 {
		t.Fatalf("allowed path: code=%d origin hits=%d, want 200 / 1", rec.Code, origin.hits.Load())
	}
}

// TestDenyPathNormalizationBypass is the regression for F9: a path-anchored deny
// must fire for non-normalized variants of the protected path (//.env, ///.env,
// //.git/config). Without path normalization the security matcher sees the raw
// "//.env" and lets it through (200), while the origin's urlFor cleans it back to
// "/.env" and serves the protected file — an ACL bypass. Matching and the upstream
// dial must agree on the path.
func TestDenyPathNormalizationBypass(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret")
	})
	h, _ := buildHandler(t, nil, cfgDeny, origin.srv.URL)

	// Every variant collapses (path.Clean) to a path the deny rule covers, so each
	// MUST be blocked with 403 and MUST NOT reach the origin.
	variants := []string{
		"http://test.local/.env",         // baseline (already blocked today)
		"http://test.local//.env",        // F9: leading double slash
		"http://test.local///.env",       // F9: triple slash
		"http://test.local//.git/config", // F9: glob /.git/* via double slash
		"http://test.local/x/..//.env",   // dot-segment + double slash -> /.env
	}
	for _, v := range variants {
		rec := do(h, "GET", v, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403 (path-ACL bypass)", v, rec.Code)
		}
		if rec.Body.String() == "secret" {
			t.Errorf("%s: leaked origin body (origin reached, ACL bypassed)", v)
		}
	}
	if got := origin.hits.Load(); got != 0 {
		t.Fatalf("origin hit %d times for denied variants, want 0", got)
	}
}

const cfgAllowDenyIP = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@office ip 198.51.100.7/32
	@admin path /wp-admin/*
	allow @office
	deny @admin !@office
	cache_ttl default ttl 60s
}
`

// TestAllowShortCircuitAndIPACL verifies the office IP bypasses the deny while a
// non-office IP hitting the same admin path is blocked — proving the `ip` matcher
// resolves the peer client IP and `allow` short-circuits.
func TestAllowShortCircuitAndIPACL(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "admin-page")
	})
	h, _ := buildHandler(t, nil, cfgAllowDenyIP, origin.srv.URL)

	// Office IP -> allow short-circuits, admin page served.
	rec := doFrom(h, "GET", "http://test.local/wp-admin/x", "198.51.100.7:5000", nil)
	if rec.Code != 200 || rec.Body.String() != "admin-page" {
		t.Fatalf("office IP to /wp-admin: got %d %q, want 200 admin-page", rec.Code, rec.Body.String())
	}

	// Non-office IP -> deny @admin !@office fires -> 403, origin not re-hit.
	before := origin.hits.Load()
	rec = doFrom(h, "GET", "http://test.local/wp-admin/x", "203.0.113.9:5000", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-office IP to /wp-admin: got %d, want 403", rec.Code)
	}
	if origin.hits.Load() != before {
		t.Fatalf("denied request reached origin (hits %d -> %d)", before, origin.hits.Load())
	}
}

const cfgTrustProxy = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	geo {
		source header CF-IPCountry
		trust_proxy 10.0.0.0/8
	}
	@bad ip 203.0.113.9/32
	deny @bad
	cache_ttl default ttl 60s
}
`

// TestIPMatcherResolvesRealClientBehindProxy verifies decision #16: the `ip`
// matcher must ACL the REAL client (from XFF, when the peer is a trusted proxy),
// not the proxy's own IP.
func TestIPMatcherResolvesRealClientBehindProxy(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgTrustProxy, origin.srv.URL)

	// Peer is the trusted proxy (10.x); the REAL client (XFF) is the banned IP.
	// The gate must deny based on the real client, not the proxy peer.
	xff := http.Header{"X-Forwarded-For": {"203.0.113.9"}}
	rec := doFrom(h, "GET", "http://test.local/", "10.0.0.1:443", xff)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned real client behind trusted proxy: got %d, want 403", rec.Code)
	}

	// A different real client behind the same proxy passes.
	xff = http.Header{"X-Forwarded-For": {"198.51.100.50"}}
	rec = doFrom(h, "GET", "http://test.local/", "10.0.0.1:443", xff)
	if rec.Code != 200 {
		t.Fatalf("benign real client behind trusted proxy: got %d, want 200", rec.Code)
	}

	// The banned IP as the PEER (no trusted proxy in front) is also denied (XFF
	// untrusted from a non-proxy peer => peer IS the client).
	rec = doFrom(h, "GET", "http://test.local/", "203.0.113.9:443", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned IP as direct peer: got %d, want 403", rec.Code)
	}
}

const cfgStandaloneTrustProxy = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 10.0.0.0/8
	@bad ip 203.0.113.9/32
	deny @bad
	cache_ttl default ttl 60s
}
`

// TestStandaloneTrustProxyResolvesRealClient is the security regression for the
// silent-no-op: with a STANDALONE `trust_proxy` and NO `geo { … }` block, the `ip`
// ACL must still resolve the REAL client from XFF (peer is the trusted proxy), not
// the proxy IP — proving TrustedProxies is no longer sourced only from geo.
func TestStandaloneTrustProxyResolvesRealClient(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgStandaloneTrustProxy, origin.srv.URL)

	// Peer is the trusted proxy (10.x); the REAL client (XFF) is the banned IP.
	// Without the standalone trust_proxy, TrustedProxies would be nil and the gate
	// would see the proxy peer (10.x) — NOT banned — and let the attacker through.
	xff := http.Header{"X-Forwarded-For": {"203.0.113.9"}}
	rec := doFrom(h, "GET", "http://test.local/", "10.0.0.1:443", xff)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned real client behind trusted proxy (standalone trust_proxy): got %d, want 403", rec.Code)
	}

	// A benign real client behind the same proxy passes.
	xff = http.Header{"X-Forwarded-For": {"198.51.100.50"}}
	rec = doFrom(h, "GET", "http://test.local/", "10.0.0.1:443", xff)
	if rec.Code != 200 {
		t.Fatalf("benign real client behind trusted proxy: got %d, want 200", rec.Code)
	}
}

const cfgGeoDeny = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 0.0.0.0/0
	geo { source header CF-IPCountry }
	@ru geo country RU
	deny @ru
	cache_ttl default ttl 60s
}
`

// TestGeoDenyEnforcesAtGate is the security regression for the fail-open bug: a
// `deny @geo` rule must enforce. The geo classes (preq.Geo/...) must be resolved
// BEFORE the security gate runs EvalSecurity — otherwise a geo matcher sees Geo=""
// and never fires, so a geo-based deny silently fails open.
func TestGeoDenyEnforcesAtGate(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgGeoDeny, origin.srv.URL)

	// RU client -> geo deny fires -> 403, origin not reached.
	rec := do(h, "GET", "http://test.local/", http.Header{"CF-IPCountry": {"RU"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("geo deny for RU: got %d, want 403", rec.Code)
	}
	if origin.hits.Load() != 0 {
		t.Fatalf("denied geo request reached origin: hits=%d, want 0", origin.hits.Load())
	}

	// US client -> not denied.
	rec = do(h, "GET", "http://test.local/", http.Header{"CF-IPCountry": {"US"}})
	if rec.Code == http.StatusForbidden {
		t.Fatalf("US client wrongly denied: got 403, want not-403")
	}

	// Absent header -> Geo="" -> not denied.
	rec = do(h, "GET", "http://test.local/", nil)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("client with no geo header wrongly denied: got 403, want not-403")
	}
}

const cfgMonitor = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	monitor
	@scanners path /.env
	deny @scanners
	cache_ttl default ttl 60s
}
`

// TestMonitorModePassesAndReachesOrigin verifies monitor mode records a would-block
// but lets the request through to origin (decision #19).
func TestMonitorModePassesAndReachesOrigin(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "env-body")
	})
	h, _ := buildHandler(t, nil, cfgMonitor, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/.env", nil)
	if rec.Code != 200 || rec.Body.String() != "env-body" {
		t.Fatalf("monitor mode: got %d %q, want 200 env-body (passes)", rec.Code, rec.Body.String())
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("monitor mode should reach origin: hits=%d want 1", origin.hits.Load())
	}
}

// TestAuditLogEmitsOnGateActions wires an AuditLog into a handler and verifies an
// enforced deny writes an audit record (action=deny, monitor=false, the matched
// rule + the resolved real client IP + 403), while a passing request writes none.
func TestAuditLogEmitsOnGateActions(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	h, _ := buildHandler(t, nil, cfgDeny, origin.srv.URL)
	buf := &syncBuffer{}
	h.auditLog = newAuditLogWriter(buf, nil, 16)
	t.Cleanup(func() { _ = h.auditLog.Close() })

	// Enforced deny -> one audit record.
	if rec := doFrom(h, "GET", "http://test.local/.env", "203.0.113.9:5000", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("deny: got %d, want 403", rec.Code)
	}
	// A passing request must NOT write an audit record (only enforced/monitored do).
	if rec := do(h, "GET", "http://test.local/index.html", nil); rec.Code != 200 {
		t.Fatalf("allowed path: got %d, want 200", rec.Code)
	}

	if err := h.auditLog.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d audit lines, want 1 (only the enforced deny):\n%s", len(lines), buf.String())
	}
	var w auditWire
	if err := json.Unmarshal([]byte(lines[0]), &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if w.Action != "deny" || w.Monitor || w.Status != 403 || w.Rule != "scanners" || w.Client != "203.0.113.9" || w.Path != "/.env" {
		t.Errorf("audit record wrong: %+v", w)
	}
}

// TestAuditLogOffWritesNothing: with no audit log configured (the default), an
// enforced deny still blocks but produces no audit output (zero cost / OFF default).
func TestAuditLogOffWritesNothing(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {})
	h, _ := buildHandler(t, nil, cfgDeny, origin.srv.URL) // no auditLog injected -> nil
	if h.auditLog != nil {
		t.Fatal("default handler should have a nil auditLog (off by default)")
	}
	// The gate must still work; the nil audit sink is a no-op (no panic).
	if rec := do(h, "GET", "http://test.local/.env", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("deny with audit off: got %d, want 403", rec.Code)
	}
}
