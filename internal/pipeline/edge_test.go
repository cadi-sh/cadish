package pipeline

import (
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func TestEdgeBlockParsesDeployAndTiers(t *testing.T) {
	p := compileSite(t, `example.com {
    @html   content_type text/html
    @assets path /assets/*
    edge {
        account acc-123
        zone    example.com
        worker  cadish-edge-example
        route   example.com/*
        kv      EDGE_CACHE
        default local
        distribute @html
        skip @assets
    }
    cache_ttl default ttl 1m
}`)

	d := p.EdgeDeployConfig()
	if !d.Configured {
		t.Fatal("EdgeDeployConfig.Configured = false, want true")
	}
	if d.Account != "acc-123" || d.Zone != "example.com" || d.Worker != "cadish-edge-example" {
		t.Errorf("deploy identity = %+v", d)
	}
	if len(d.Routes) != 1 || d.Routes[0] != "example.com/*" {
		t.Errorf("routes = %v", d.Routes)
	}
	if d.KVNamespace != "EDGE_CACHE" {
		t.Errorf("kv = %q", d.KVNamespace)
	}
	if !p.EdgeUsesKV() {
		t.Error("EdgeUsesKV = false, want true (explicit kv + distribute)")
	}
	if p.EdgeDefaultTier() != "local" {
		t.Errorf("default tier = %q, want local", p.EdgeDefaultTier())
	}
	pols := p.EdgeTierPolicies()
	if len(pols) != 2 {
		t.Fatalf("want 2 tier policies, got %d", len(pols))
	}
	if pols[0].Tier != "distribute" || len(pols[0].Scope.Names) != 1 || pols[0].Scope.Names[0] != "html" {
		t.Errorf("policy[0] = %+v", pols[0])
	}
	if pols[1].Tier != "skip" || pols[1].Scope.Names[0] != "assets" {
		t.Errorf("policy[1] = %+v", pols[1])
	}
}

func TestEdgeBlockKVGuardrails(t *testing.T) {
	p := compileSite(t, `example.com {
    @html content_type text/html
    edge {
        worker w
        kv     EDGE_CACHE
        distribute @html
        kv_ttl       5m
        kv_max_bytes 256KiB
    }
    cache_ttl default ttl 1m
}`)
	d, ok := p.EdgeKVTTL()
	if !ok {
		t.Fatal("EdgeKVTTL ok = false, want true")
	}
	if d != 5*time.Minute {
		t.Errorf("kv_ttl = %v, want 5m", d)
	}
	if got := p.EdgeKVMaxBytes(); got != 256*1024 {
		t.Errorf("kv_max_bytes = %d, want %d", got, 256*1024)
	}
}

func TestEdgeBlockKVGuardrailDefaults(t *testing.T) {
	p := compileSite(t, `example.com {
    @html content_type text/html
    edge {
        worker w
        distribute @html
    }
    cache_ttl default ttl 1m
}`)
	if _, ok := p.EdgeKVTTL(); ok {
		t.Error("kv_ttl should be unset when not declared")
	}
	if got := p.EdgeKVMaxBytes(); got != defaultKVMaxBytes {
		t.Errorf("default kv_max_bytes = %d, want %d (1 MiB)", got, defaultKVMaxBytes)
	}
}

func TestEdgeBlockKVNoEdgeBlock(t *testing.T) {
	p := compileSite(t, `example.com {
    cache_ttl default ttl 1m
}`)
	if _, ok := p.EdgeKVTTL(); ok {
		t.Error("kv_ttl should be unset with no edge block")
	}
	if got := p.EdgeKVMaxBytes(); got != defaultKVMaxBytes {
		t.Errorf("kv_max_bytes with no edge block = %d, want default %d", got, defaultKVMaxBytes)
	}
}

func TestEdgeBlockKVGuardrailErrors(t *testing.T) {
	cases := []struct{ name, src string }{
		{"kv_ttl not a duration", `example.com { edge { kv_ttl notaduration } }`},
		{"kv_ttl needs one arg", `example.com { edge { kv_ttl 1m 2m } }`},
		{"kv_ttl non-positive", `example.com { edge { kv_ttl 0s } }`},
		{"kv_max_bytes bad size", `example.com { edge { kv_max_bytes huge } }`},
		{"kv_max_bytes needs one arg", `example.com { edge { kv_max_bytes 1MB 2MB } }`},
		{"kv_max_bytes non-positive", `example.com { edge { kv_max_bytes 0 } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := cadishfile.Parse("e.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := Compile(f.Sites[0]); err == nil {
				t.Errorf("expected a compile error for %q", tc.src)
			}
		})
	}
}

func TestEdgeBlockDefaults(t *testing.T) {
	p := compileSite(t, `example.com {
    cache_ttl default ttl 1m
}`)
	if p.EdgeDeployConfig().Configured {
		t.Error("no edge block: Configured should be false")
	}
	if p.EdgeDefaultTier() != "local" {
		t.Errorf("default tier without edge block = %q, want local", p.EdgeDefaultTier())
	}
	if p.EdgeUsesKV() {
		t.Error("EdgeUsesKV should be false without an edge block")
	}
	if len(p.EdgeTierPolicies()) != 0 {
		t.Error("no edge block: expected no tier policies")
	}
}

func TestEdgeBlockUsesKVImpliedByDistribute(t *testing.T) {
	p := compileSite(t, `example.com {
    @html content_type text/html
    edge {
        worker w
        distribute @html
    }
    cache_ttl default ttl 1m
}`)
	if !p.EdgeUsesKV() {
		t.Error("a distribute policy must imply EdgeUsesKV even without an explicit kv name")
	}
}

// TestEdgeBypassPatternsParse: `bypass /a* /b` is accepted, multiple lines accumulate,
// and the patterns are surfaced via EdgeBypassPatterns in declaration order.
func TestEdgeBypassPatternsParse(t *testing.T) {
	p := compileSite(t, `example.com {
    edge {
        worker w
        zone   example.com
        bypass /transmit* /v2/*
        bypass /atvpanel
    }
    cache_ttl default ttl 1m
}`)
	got := p.EdgeBypassPatterns()
	want := []string{"/transmit*", "/v2/*", "/atvpanel"}
	if len(got) != len(want) {
		t.Fatalf("EdgeBypassPatterns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("EdgeBypassPatterns[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// No bypass declared => nil.
	np := compileSite(t, `example.com {
    edge { worker w }
    cache_ttl default ttl 1m
}`).EdgeBypassPatterns()
	if len(np) != 0 {
		t.Fatalf("no bypass: want empty, got %v", np)
	}
}

// TestEdgeBypassPatternErrors: a malformed bypass pattern is a compile error.
func TestEdgeBypassPatternErrors(t *testing.T) {
	cases := []struct{ name, src string }{
		{"no args", `example.com { edge { bypass } }`},
		{"leading wildcard", `example.com { edge { bypass */x } }`},
		{"no leading slash", `example.com { edge { bypass a } }`},
		{"interior wildcard", `example.com { edge { bypass /a*/b } }`},
		{"double wildcard", `example.com { edge { bypass /a** } }`},
		{"second arg bad", `example.com { edge { bypass /ok b } }`},
		{"catch-all root", `example.com { edge { bypass / } }`},       // next#4
		{"catch-all root glob", `example.com { edge { bypass /* } }`}, // next#4
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := cadishfile.Parse("e.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := Compile(f.Sites[0]); err == nil {
				t.Errorf("expected a compile error for %q", tc.src)
			}
		})
	}
}

func TestEdgeBlockErrors(t *testing.T) {
	cases := []struct{ name, src string }{
		{"bad tier", `example.com { edge { default bogus } }`},
		{"unknown setting", `example.com { edge { frobnicate x } }`},
		{"account needs one arg", `example.com { edge { account a b } }`},
		{"tier needs scope", `example.com { @h content_type text/html
            edge { distribute } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := cadishfile.Parse("e.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := Compile(f.Sites[0]); err == nil {
				t.Errorf("expected a compile error for %q", tc.src)
			}
		})
	}
}
