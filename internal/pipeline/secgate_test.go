package pipeline

import (
	"net/netip"
	"testing"
)

// secReq builds a request with a resolved real client IP for the `ip` matcher.
func secReq(path, ip string) *Request {
	r := &Request{Host: "example.com", Path: path}
	if ip != "" {
		r.RealClientIP = netip.MustParseAddr(ip)
	}
	return r
}

// TestSecurityGateZeroCostWhenNoRules verifies a site with no allow/deny rules
// reports no security gate and EvalSecurity is a no-op (the server skips it).
func TestSecurityGateZeroCostWhenNoRules(t *testing.T) {
	p := compileSrc(t, `example.com {
	cache_ttl default ttl 60s
}
`)
	if p.UsesSecurityGate() {
		t.Fatal("a site with no security rules must not use the gate")
	}
	d := p.EvalSecurity(secReq("/", "1.2.3.4"))
	if d.Block || d.Monitor || d.Allow {
		t.Fatalf("zero-rule gate returned a decision: %+v", d)
	}
}

// TestIPMatcherV4V6CIDRBare exercises the new `ip` matcher across IPv4/IPv6,
// CIDR and bare-IP forms.
func TestIPMatcherV4V6CIDRBare(t *testing.T) {
	p := compileSrc(t, `example.com {
	@office ip 203.0.113.43/32 10.0.0.0/8 ::1 2001:db8::/32
	deny @office
	cache_ttl default ttl 60s
}
`)
	cases := []struct {
		ip    string
		block bool
	}{
		{"203.0.113.43", true},   // bare /32
		{"81.47.161.44", false},  // adjacent, outside /32
		{"10.5.6.7", true},       // inside 10.0.0.0/8
		{"11.0.0.1", false},      // outside
		{"::1", true},            // bare v6
		{"2001:db8::dead", true}, // inside v6 CIDR
		{"2001:dead::1", false},  // outside v6 CIDR
	}
	for _, c := range cases {
		d := p.EvalSecurity(secReq("/", c.ip))
		if d.Block != c.block {
			t.Errorf("ip %s: block=%v want %v", c.ip, d.Block, c.block)
		}
	}
	// An unset/invalid real client IP matches nothing.
	if p.EvalSecurity(secReq("/", "")).Block {
		t.Error("invalid client IP must not match an ip ACL")
	}
}

// TestIPMatcher4in6Normalized verifies a 4-in-6 mapped client IP matches a v4 CIDR
// (both sides Unmap'd), so a client arriving as ::ffff:10.0.0.5 still ACLs.
func TestIPMatcher4in6Normalized(t *testing.T) {
	p := compileSrc(t, `example.com {
	@net ip 10.0.0.0/8
	deny @net
	cache_ttl default ttl 60s
}
`)
	r := &Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("::ffff:10.0.0.5")}
	if !p.EvalSecurity(r).Block {
		t.Error("4-in-6 mapped client IP did not match a v4 CIDR")
	}
}

// TestAllowShortCircuitsDeny verifies an `allow` short-circuits the gate before any
// `deny` runs — an office IP is never blocked even though a deny would match.
func TestAllowShortCircuitsDeny(t *testing.T) {
	p := compileSrc(t, `example.com {
	@office ip 203.0.113.43/32
	@admin path /wp-admin/*
	allow @office
	deny @admin
	cache_ttl default ttl 60s
}
`)
	// Office IP hitting /wp-admin: allow wins, no block.
	d := p.EvalSecurity(secReq("/wp-admin/index.php", "203.0.113.43"))
	if d.Block || !d.Allow {
		t.Fatalf("office IP should be allowed (short-circuit), got %+v", d)
	}
	// Non-office IP hitting /wp-admin: deny fires.
	d = p.EvalSecurity(secReq("/wp-admin/index.php", "9.9.9.9"))
	if !d.Block || d.Status != 403 {
		t.Fatalf("non-office /wp-admin should be denied 403, got %+v", d)
	}
	// Non-office IP hitting a normal path: passes.
	d = p.EvalSecurity(secReq("/index.php", "9.9.9.9"))
	if d.Block || d.Allow {
		t.Fatalf("normal path should pass, got %+v", d)
	}
}

// TestDenyANDNegation verifies the classify-style AND + `!` negation:
// `deny @admin !@office` blocks admin paths EXCEPT from the office.
func TestDenyANDNegation(t *testing.T) {
	p := compileSrc(t, `example.com {
	@office ip 203.0.113.43/32
	@admin path /wp-admin/*
	deny @admin !@office
	cache_ttl default ttl 60s
}
`)
	// Admin path from a non-office IP: AND(@admin, NOT @office) => block.
	if !p.EvalSecurity(secReq("/wp-admin/x", "9.9.9.9")).Block {
		t.Error("admin path from outside office should be denied")
	}
	// Admin path from the office IP: NOT @office is false => no block.
	if p.EvalSecurity(secReq("/wp-admin/x", "203.0.113.43")).Block {
		t.Error("admin path from office must NOT be denied (negation term)")
	}
	// Non-admin path from outside: @admin false => no block.
	if p.EvalSecurity(secReq("/", "9.9.9.9")).Block {
		t.Error("non-admin path should not be denied")
	}
}

// TestGeoBlock verifies geo-block reuses the existing `geo` matcher in a deny rule.
func TestGeoBlock(t *testing.T) {
	p := compileSrc(t, `example.com {
	@ru_cn geo country RU CN
	deny @ru_cn
	cache_ttl default ttl 60s
}
`)
	if !p.UsesGeoToken() {
		t.Fatal("a geo matcher used by deny must require the geo pre-pass")
	}
	block := func(country string) bool {
		return p.EvalSecurity(&Request{Host: "example.com", Path: "/", Geo: country}).Block
	}
	if !block("RU") || !block("CN") {
		t.Error("RU/CN should be geo-blocked")
	}
	if block("US") || block("") {
		t.Error("US / unknown should not be geo-blocked")
	}
}

// TestPatternDeny verifies pattern-deny reuses path/method matchers.
func TestPatternDeny(t *testing.T) {
	p := compileSrc(t, `example.com {
	@scanners path /.env /.git/*
	deny @scanners
	cache_ttl default ttl 60s
}
`)
	if !p.EvalSecurity(&Request{Host: "example.com", Path: "/.env"}).Block {
		t.Error("/.env should be denied")
	}
	if !p.EvalSecurity(&Request{Host: "example.com", Path: "/.git/config"}).Block {
		t.Error("/.git/* should be denied")
	}
	if p.EvalSecurity(&Request{Host: "example.com", Path: "/index.html"}).Block {
		t.Error("normal path should pass")
	}
}

// TestMonitorModeGlobal verifies the global `monitor` toggle: a deny logs a
// would-block and PASSES (Block false, Monitor true). allow is unaffected.
func TestMonitorModeGlobal(t *testing.T) {
	p := compileSrc(t, `example.com {
	monitor
	@scanners path /.env
	deny @scanners
	cache_ttl default ttl 60s
}
`)
	d := p.EvalSecurity(&Request{Host: "example.com", Path: "/.env"})
	if d.Block {
		t.Fatal("monitor mode must NOT block")
	}
	if !d.Monitor || d.Status != 403 {
		t.Fatalf("monitor mode should record a would-block (403), got %+v", d)
	}
}

// TestMonitorModePerRule verifies a per-rule `monitor` keyword on a deny.
func TestMonitorModePerRule(t *testing.T) {
	p := compileSrc(t, `example.com {
	@scanners path /.env
	@bad path /.git
	deny @scanners monitor
	deny @bad
	cache_ttl default ttl 60s
}
`)
	// Per-rule monitor: would-block, passes.
	if d := p.EvalSecurity(&Request{Host: "example.com", Path: "/.env"}); d.Block || !d.Monitor {
		t.Fatalf("per-rule monitor deny should pass as would-block, got %+v", d)
	}
	// The other deny (no monitor) still enforces.
	if d := p.EvalSecurity(&Request{Host: "example.com", Path: "/.git"}); !d.Block {
		t.Fatalf("non-monitor deny should block, got %+v", d)
	}
}

// TestBlockAlias verifies `block` is an alias for `deny`.
func TestBlockAlias(t *testing.T) {
	p := compileSrc(t, `example.com {
	@bad path /bad
	block @bad
	cache_ttl default ttl 60s
}
`)
	if !p.EvalSecurity(&Request{Host: "example.com", Path: "/bad"}).Block {
		t.Error("`block` should deny like `deny`")
	}
}

// TestInlineIPMatcher verifies an inline (un-named) ip matcher in a rule.
func TestInlineIPMatcher(t *testing.T) {
	p := compileSrc(t, `example.com {
	deny ip 192.168.0.0/16
	cache_ttl default ttl 60s
}
`)
	if !p.EvalSecurity(secReq("/", "192.168.4.4")).Block {
		t.Error("inline ip matcher should deny")
	}
	if p.EvalSecurity(secReq("/", "8.8.8.8")).Block {
		t.Error("outside the inline range should pass")
	}
}

// TestSecurityCompileErrors covers the rejected grammars.
func TestSecurityCompileErrors(t *testing.T) {
	cases := []string{
		"example.com {\n\tdeny @missing\n}\n",                          // undefined matcher
		"example.com {\n\tdeny\n}\n",                                   // no condition
		"example.com {\n\t@ct content_type text/html\n\tdeny @ct\n}\n", // response-phase matcher
		"example.com {\n\t@x ip not-an-ip\n\tdeny @x\n}\n",             // bad IP
		"example.com {\n\tmonitor maybe\n}\n",                          // bad monitor arg
		"example.com {\n\tdeny path\n}\n",                              // path matcher with no pattern
	}
	for _, src := range cases {
		compileErr(t, src)
	}
}

// TestSecurityNotInEdgeIR verifies security rules + the ip matcher are NOT
// projected into the edge IR (design §2.15: security is server-only).
func TestSecurityNotInEdgeIR(t *testing.T) {
	p := compileSrc(t, `example.com {
	@office ip 203.0.113.43/32
	@ru geo country RU
	allow @office
	deny @ru
	cache_ttl default ttl 60s
}
`)
	// The `ip` matcher (server-only) must not appear in the projected matchers.
	for name, em := range p.EdgeMatchers() {
		if em.Kind == "ip" || em.Kind == "unknown" {
			t.Errorf("ip / unknown matcher %q leaked into the edge IR (kind=%q)", name, em.Kind)
		}
	}
	if _, ok := p.EdgeMatchers()["office"]; ok {
		t.Error("the @office ip matcher must not be projected to the edge IR")
	}
	// There is no edge projection for allow/deny rules at all — they are absent by
	// construction (the projector never reads p.allowRules/p.denyRules).
}
