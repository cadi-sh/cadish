package check

import "testing"

// TestRateLimitCatalog verifies `cadish check` is taught the WAF v1b `rate_limit`
// directive: it is RECV-phase, in the known-directive set, and a real config using
// it raises no unknown-directive / unknown-matcher / unused-matcher warnings.
func TestRateLimitCatalog(t *testing.T) {
	if got := phaseOf("rate_limit"); got != PhaseRECV {
		t.Errorf("phaseOf(rate_limit) = %v, want PhaseRECV", got)
	}
	if !defaultDirectives["rate_limit"] {
		t.Error("rate_limit missing from the known-directive set")
	}

	src := []byte("example.com {\n" +
		"  @api path /api/*\n" +
		"  trust_proxy 10.0.0.0/8\n" +
		"  rate_limit @api 100r/s burst 50 key ip\n" +
		"  rate_limit 5r/s key header X-Api-Key monitor\n" +
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

// TestRateLimitScopeMatcherNotUnused is the focused regression guard: a matcher
// referenced ONLY to scope a rate_limit rule must not be flagged unused (mirrors the
// allow/deny + replace guards).
func TestRateLimitScopeMatcherNotUnused(t *testing.T) {
	src := `example.com {
	@api path /api/*
	trust_proxy 10.0.0.0/8
	rate_limit @api 100r/s key ip
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-matcher"]; n != 0 {
		t.Fatalf("unused-matcher warnings = %d, want 0 (@api used by rate_limit)\n%s", n, render(t, r))
	}
}

// TestRateLimitKeyIPWithoutTrustProxyWarns: `rate_limit … key ip` (explicit or
// default) with no trust_proxy warns ip-acl-without-trust-proxy — the same
// trusted-proxy footgun as the `ip` ACL.
func TestRateLimitKeyIPWithoutTrustProxyWarns(t *testing.T) {
	cases := []struct{ name, src string }{
		{"explicit key ip", "example.com {\n rate_limit 100r/s key ip\n cache_ttl default ttl 1m\n}"},
		{"default key (ip)", "example.com {\n rate_limit 100r/s\n cache_ttl default ttl 1m\n}"},
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

// TestRateLimitKeyHeaderGlobalNoTrustProxyWarn: keying on a header or global does
// NOT depend on the resolved client IP, so it must NOT warn.
func TestRateLimitKeyHeaderGlobalNoTrustProxyWarn(t *testing.T) {
	cases := []struct{ name, src string }{
		{"key header", "example.com {\n rate_limit 100r/s key header X-Api-Key\n cache_ttl default ttl 1m\n}"},
		{"key global", "example.com {\n rate_limit 100r/s key global\n cache_ttl default ttl 1m\n}"},
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
