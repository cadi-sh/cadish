package check

import "testing"

// TestSecurityGateCatalog verifies `cadish check` is taught the WAF v1a security
// gate: allow/deny/block are RECV-phase directives, monitor is Setup, the `ip`
// matcher is known, and none of them raise unknown-directive / unknown-matcher
// warnings.
func TestSecurityGateCatalog(t *testing.T) {
	for _, d := range []string{"allow", "deny", "block"} {
		if got := phaseOf(d); got != PhaseRECV {
			t.Errorf("phaseOf(%s) = %v, want PhaseRECV", d, got)
		}
		if !defaultDirectives[d] {
			t.Errorf("%s missing from the known-directive set", d)
		}
	}
	if got := phaseOf("monitor"); got != PhaseSetup {
		t.Errorf("phaseOf(monitor) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["monitor"] {
		t.Error("monitor missing from the known-directive set")
	}
	if !isMatcherType("ip") {
		t.Error("ip missing from the known-matcher-type set")
	}

	src := []byte("example.com {\n" +
		"  @office ip 203.0.113.43/32 10.0.0.0/8\n" +
		"  @ru geo country RU\n" +
		"  @admin path /wp-admin/*\n" +
		"  monitor off\n" +
		"  allow @office\n" +
		"  deny @ru\n" +
		"  deny @admin !@office\n" +
		"  block ip 192.168.0.0/16\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	for _, code := range []string{"unknown-directive", "unknown-matcher-type", "unused-matcher"} {
		if n := codes(r)[code]; n != 0 {
			t.Errorf("got %d %q diagnostics, want 0:\n%s", n, code, render(t, r))
		}
	}
}

// TestSecurityBlockCatalog verifies the global `security { audit_log … }` block
// (WAF v1c, D52) is taught to the catalog: it is a SETUP directive (read once at
// startup; no per-request matcher cost) and a known directive, so a config using
// it raises no unknown-directive warning.
func TestSecurityBlockCatalog(t *testing.T) {
	if got := phaseOf("security"); got != PhaseSetup {
		t.Errorf("phaseOf(security) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["security"] {
		t.Error("security missing from the known-directive set")
	}

	src := []byte("{\n" +
		"  security {\n" +
		"    audit_log /var/log/cadish\n" +
		"  }\n" +
		"}\n" +
		"example.com {\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("got %d unknown-directive diagnostics, want 0:\n%s", n, render(t, r))
	}
}

// TestIPMatcherUsedByAllowDenyNotUnused is the focused regression guard (mirrors
// the `replace` case): a matcher referenced ONLY by allow/deny — including a
// `!`-negated reference — must not be flagged unused.
func TestIPMatcherUsedByAllowDenyNotUnused(t *testing.T) {
	src := `example.com {
	@office ip 203.0.113.43/32
	@admin  path /wp-admin/*
	allow @office
	deny @admin !@office
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-matcher"]; n != 0 {
		t.Fatalf("unused-matcher warnings = %d, want 0 (@office/@admin used by allow/deny)\n%s", n, render(t, r))
	}
}

// TestIPACLWithoutTrustProxyWarns: an `ip`-based deny/allow with NO trust_proxy
// (and no geo { trust_proxy }) warns ip-acl-without-trust-proxy — the silent-no-op.
func TestIPACLWithoutTrustProxyWarns(t *testing.T) {
	cases := []struct {
		name, src string
	}{
		{"named ip via deny", "example.com {\n @bad ip 203.0.113.9/32\n deny @bad\n cache_ttl default ttl 1m\n}"},
		{"inline ip via deny", "example.com {\n deny ip 203.0.113.0/24\n cache_ttl default ttl 1m\n}"},
		{"named ip via allow", "example.com {\n @office ip 10.0.0.0/8\n allow @office\n deny path /x\n cache_ttl default ttl 1m\n}"},
		{"named ip via block", "example.com {\n @bad ip 203.0.113.9/32\n block @bad\n cache_ttl default ttl 1m\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := CheckSource("t.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource: %v", err)
			}
			if n := codes(r)["ip-acl-without-trust-proxy"]; n != 1 {
				t.Fatalf("got %d ip-acl-without-trust-proxy, want 1\n%s", n, render(t, r))
			}
		})
	}
}

// TestIPACLWithTrustProxyNoWarn: declaring a trusted proxy (standalone OR via the
// geo block) silences the warning.
func TestIPACLWithTrustProxyNoWarn(t *testing.T) {
	cases := []struct {
		name, src string
	}{
		{"standalone trust_proxy", "example.com {\n @bad ip 203.0.113.9/32\n deny @bad\n trust_proxy 10.0.0.0/8\n cache_ttl default ttl 1m\n}"},
		{"geo block trust_proxy", "example.com {\n @bad ip 203.0.113.9/32\n deny @bad\n geo {\n source header CF-IPCountry\n trust_proxy 10.0.0.0/8\n}\n cache_ttl default ttl 1m\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := CheckSource("t.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource: %v", err)
			}
			if n := codes(r)["ip-acl-without-trust-proxy"]; n != 0 {
				t.Fatalf("got %d ip-acl-without-trust-proxy, want 0\n%s", n, render(t, r))
			}
		})
	}
}

// TestNoIPACLNoWarn: a site with NO ip-based security rule never warns (a path/geo
// deny without trust_proxy is fine; trust_proxy only matters for the `ip` matcher).
func TestNoIPACLNoWarn(t *testing.T) {
	cases := []string{
		"example.com {\n @scanners path /.env\n deny @scanners\n cache_ttl default ttl 1m\n}",
		"example.com {\n @ru geo country RU\n geo { source header CF-IPCountry }\n deny @ru\n cache_ttl default ttl 1m\n}",
		"example.com {\n cache_ttl default ttl 1m\n}",
	}
	for _, src := range cases {
		r, err := CheckSource("t.cadish", []byte(src))
		if err != nil {
			t.Fatalf("CheckSource: %v", err)
		}
		if n := codes(r)["ip-acl-without-trust-proxy"]; n != 0 {
			t.Fatalf("no ip ACL: got %d ip-acl-without-trust-proxy, want 0\n%s", n, render(t, r))
		}
	}
}

// TestTrustProxyStandaloneKnown: the standalone `trust_proxy` directive is a known
// SETUP directive (no unknown-directive warning).
func TestTrustProxyStandaloneKnown(t *testing.T) {
	if got := phaseOf("trust_proxy"); got != PhaseSetup {
		t.Errorf("phaseOf(trust_proxy) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["trust_proxy"] {
		t.Error("trust_proxy missing from the known-directive set")
	}
	r, err := CheckSource("t.cadish", []byte("example.com {\n trust_proxy 10.0.0.0/8\n cache_ttl default ttl 1m\n}"))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("trust_proxy raised %d unknown-directive\n%s", n, render(t, r))
	}
}
