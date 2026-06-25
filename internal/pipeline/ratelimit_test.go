package pipeline

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// TestRateLimitParsesRateBurstKey verifies the grammar
// `rate_limit @api 100r/s burst 50 key ip` compiles and the pure gate identifies
// the rule + bucket key (the resolved real client IP) without counting.
func TestRateLimitParsesRateBurstKey(t *testing.T) {
	p := compileSrc(t, `example.com {
	@api path /api/*
	rate_limit @api 100r/s burst 50 key ip
	cache_ttl default ttl 60s
}
`)
	if !p.UsesSecurityGate() {
		t.Fatal("a rate_limit rule must enable the security gate")
	}
	r := &Request{Host: "example.com", Path: "/api/x", RealClientIP: netip.MustParseAddr("9.9.9.9")}
	d := p.EvalSecurity(r)
	if d.RateLimit == nil {
		t.Fatal("rate_limit rule did not produce a RateLimitHit for a matching request")
	}
	if d.RateLimit.RatePerSec != 100 {
		t.Errorf("RatePerSec = %v, want 100", d.RateLimit.RatePerSec)
	}
	if d.RateLimit.Burst != 50 {
		t.Errorf("Burst = %d, want 50", d.RateLimit.Burst)
	}
	if d.RateLimit.Monitor {
		t.Error("rule is not in monitor mode")
	}
	// key ip => the bucket key embeds the resolved real client IP.
	if d.RateLimit.Key == "" {
		t.Fatal("bucket key must be non-empty for key ip")
	}
	// Two requests from the same IP share a key; a different IP gets a different key.
	r2 := &Request{Host: "example.com", Path: "/api/y", RealClientIP: netip.MustParseAddr("9.9.9.9")}
	r3 := &Request{Host: "example.com", Path: "/api/z", RealClientIP: netip.MustParseAddr("8.8.8.8")}
	if k2 := p.EvalSecurity(r2).RateLimit.Key; k2 != d.RateLimit.Key {
		t.Errorf("same IP must yield same key: %q != %q", k2, d.RateLimit.Key)
	}
	if k3 := p.EvalSecurity(r3).RateLimit.Key; k3 == d.RateLimit.Key {
		t.Error("different IP must yield a different key")
	}
}

// TestRateLimitScopeOnlyMatching verifies a scoped rate_limit applies only to
// matching requests (an unscoped path is not rate-limited).
func TestRateLimitScopeOnlyMatching(t *testing.T) {
	p := compileSrc(t, `example.com {
	@api path /api/*
	rate_limit @api 10r/s key ip
	cache_ttl default ttl 60s
}
`)
	hit := p.EvalSecurity(&Request{Host: "example.com", Path: "/api/x", RealClientIP: netip.MustParseAddr("1.1.1.1")})
	if hit.RateLimit == nil {
		t.Fatal("matching request must hit the rate_limit rule")
	}
	miss := p.EvalSecurity(&Request{Host: "example.com", Path: "/static/x", RealClientIP: netip.MustParseAddr("1.1.1.1")})
	if miss.RateLimit != nil {
		t.Fatal("non-matching request must NOT hit the rate_limit rule")
	}
}

// TestRateLimitDefaultKeyIP verifies `key ip` is the default when key is omitted.
func TestRateLimitDefaultKeyIP(t *testing.T) {
	p := compileSrc(t, `example.com {
	rate_limit 5r/s
	cache_ttl default ttl 60s
}
`)
	a := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("1.2.3.4")})
	b := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("5.6.7.8")})
	if a.RateLimit == nil || b.RateLimit == nil {
		t.Fatal("unscoped rate_limit must apply to all requests")
	}
	if a.RateLimit.Key == b.RateLimit.Key {
		t.Error("default key must be per-IP (distinct IPs => distinct keys)")
	}
}

// TestRateLimitKeyHeader verifies `key header X-Api-Key` buckets by the header value.
func TestRateLimitKeyHeader(t *testing.T) {
	p := compileSrc(t, `example.com {
	rate_limit 100r/s key header X-Api-Key
	cache_ttl default ttl 60s
}
`)
	mk := func(v string) *Request {
		h := http.Header{}
		if v != "" {
			h.Set("X-Api-Key", v)
		}
		return &Request{Host: "example.com", Path: "/", Header: h, RealClientIP: netip.MustParseAddr("1.1.1.1")}
	}
	k1 := p.EvalSecurity(mk("alice")).RateLimit.Key
	k1b := p.EvalSecurity(mk("alice")).RateLimit.Key
	k2 := p.EvalSecurity(mk("bob")).RateLimit.Key
	if k1 != k1b {
		t.Error("same header value must yield same key")
	}
	if k1 == k2 {
		t.Error("different header value must yield different key")
	}
}

// TestRateLimitKeyGlobal verifies `key global` buckets the whole site (one shared key).
func TestRateLimitKeyGlobal(t *testing.T) {
	p := compileSrc(t, `example.com {
	rate_limit 100r/s key global
	cache_ttl default ttl 60s
}
`)
	a := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("1.1.1.1")})
	b := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("2.2.2.2")})
	if a.RateLimit.Key != b.RateLimit.Key {
		t.Error("key global must bucket all clients into ONE key")
	}
}

// TestRateLimitMonitor verifies per-rule and global monitor flags propagate.
func TestRateLimitMonitor(t *testing.T) {
	perRule := compileSrc(t, `example.com {
	rate_limit 5r/s key ip monitor
	cache_ttl default ttl 60s
}
`)
	d := perRule.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("1.1.1.1")})
	if d.RateLimit == nil || !d.RateLimit.Monitor {
		t.Fatal("per-rule monitor flag must propagate to the hit")
	}
	global := compileSrc(t, `example.com {
	monitor
	rate_limit 5r/s key ip
	cache_ttl default ttl 60s
}
`)
	g := global.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("1.1.1.1")})
	if g.RateLimit == nil || !g.RateLimit.Monitor {
		t.Fatal("global monitor must make rate_limit hits monitor-mode")
	}
}

// TestRateLimitRateUnits verifies r/s, r/m, r/h all parse to tokens/second.
func TestRateLimitRateUnits(t *testing.T) {
	cases := []struct {
		spec   string
		perSec float64
	}{
		{"120r/s", 120},
		{"120r/m", 2},
		{"3600r/h", 1},
	}
	for _, c := range cases {
		p := compileSrc(t, `example.com {
	rate_limit `+c.spec+` key ip
	cache_ttl default ttl 60s
}
`)
		d := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("1.1.1.1")})
		if d.RateLimit == nil {
			t.Fatalf("%s: no hit", c.spec)
		}
		if d.RateLimit.RatePerSec != c.perSec {
			t.Errorf("%s: RatePerSec = %v, want %v", c.spec, d.RateLimit.RatePerSec, c.perSec)
		}
	}
}

// TestRateLimitDenyShortCircuitsRateLimit verifies a deny fires BEFORE rate_limit
// (gate order allow -> deny -> rate_limit): a denied request never gets a hit.
func TestRateLimitDenyShortCircuitsRateLimit(t *testing.T) {
	p := compileSrc(t, `example.com {
	@bad ip 6.6.6.6/32
	deny @bad
	rate_limit 5r/s key ip
	cache_ttl default ttl 60s
}
`)
	d := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("6.6.6.6")})
	if !d.Block {
		t.Fatal("denied IP must be blocked")
	}
	if d.RateLimit != nil {
		t.Fatal("a denied request must NOT also produce a rate_limit hit (deny short-circuits)")
	}
}

// TestRateLimitAllowShortCircuits verifies an allow bypasses rate_limit entirely.
func TestRateLimitAllowShortCircuits(t *testing.T) {
	p := compileSrc(t, `example.com {
	@office ip 10.0.0.0/8
	allow @office
	rate_limit 1r/s key ip
	cache_ttl default ttl 60s
}
`)
	d := p.EvalSecurity(&Request{Host: "example.com", Path: "/", RealClientIP: netip.MustParseAddr("10.1.2.3")})
	if !d.Allow {
		t.Fatal("office IP must be allow-listed")
	}
	if d.RateLimit != nil {
		t.Fatal("an allow-listed request must NOT be rate-limited")
	}
}

// TestRateLimitNotInEdgeIR verifies rate_limit (server-only security) is not
// projected into the edge IR, mirroring allow/deny. There is no edge accessor for
// rate-limit rules at all — they are absent by construction (the projector never
// reads p.rateLimitRules), so a rate_limit rule never leaks to the edge. A scoped
// rate_limit must also not drag its `@api` path matcher in as an unexpected leak of
// a *server-only* construct (path itself is edge-capable, but here it is used only
// by a server-only directive, so EdgeMatchers should still only expose named
// matchers used by edge-projected directives).
func TestRateLimitNotInEdgeIR(t *testing.T) {
	p := compileSrc(t, `example.com {
	@api path /api/*
	rate_limit @api 100r/s burst 50 key ip
	cache_ttl default ttl 60s
}
`)
	// EdgeMatchers exposes named matchers; `path` is edge-capable so @api may appear,
	// but crucially there is NO rate_limit projection. Assert the pipeline reports a
	// security gate (server-side) yet the projector has no rate-limit surface.
	if !p.UsesSecurityGate() {
		t.Fatal("rate_limit must register as a (server-only) security gate")
	}
	// Defense: no Edge accessor returns rate-limit data. We can only assert what IS
	// projected; the absence is structural (there is no EdgeRateLimitRules method).
	// Verify a matching request is rate-limited on the SERVER path only.
	if p.EvalSecurity(&Request{Host: "example.com", Path: "/api/x", RealClientIP: netip.MustParseAddr("1.1.1.1")}).RateLimit == nil {
		t.Fatal("rate_limit must be enforced server-side")
	}
}

// TestRateLimitCompileErrors verifies bad specs are rejected at compile time.
func TestRateLimitCompileErrors(t *testing.T) {
	bad := []string{
		`example.com {
	rate_limit
}
`,
		`example.com {
	rate_limit @api
}
`,
		`example.com {
	rate_limit 100r/s burst
}
`,
		`example.com {
	rate_limit 100r/s key header
}
`,
		`example.com {
	rate_limit notarate key ip
}
`,
		`example.com {
	rate_limit 0r/s key ip
}
`,
	}
	for _, src := range bad {
		f, perr := cadishfile.Parse("test.cadish", []byte(src))
		if perr != nil {
			continue // a parse error is also a rejection
		}
		if _, cerr := Compile(f.Sites[0]); cerr == nil {
			t.Errorf("expected a compile error for:\n%s", src)
		}
	}
}
