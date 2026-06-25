package cluster

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// parseBlock lexes+parses a single top-level `cluster { … }` directive out of a
// bare config body and returns it.
func parseBlock(t *testing.T, src string) *cadishfile.Directive {
	t.Helper()
	file, err := cadishfile.Parse("test.cadish", []byte("example.com {\n"+src+"\n}\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, n := range file.Sites[0].Body {
		if d, ok := n.(*cadishfile.Directive); ok && d.Name == "cluster" {
			return d
		}
	}
	t.Fatalf("no cluster directive found")
	return nil
}

func TestParse_Minimal(t *testing.T) {
	d := parseBlock(t, `
cluster {
    self    http://10.0.0.1:6081
    peers   http://10.0.0.1:6081 http://10.0.0.2:6081 http://10.0.0.3:6081
    region  gra
}`)
	cfg, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Region != "gra" {
		t.Errorf("region = %q, want gra", cfg.Region)
	}
	if cfg.Self != "http://10.0.0.1:6081" {
		t.Errorf("self = %q", cfg.Self)
	}
	if len(cfg.Peers) != 3 {
		t.Fatalf("peers = %d, want 3", len(cfg.Peers))
	}
	// Default mode is read_through (opportunistic, the safest default).
	if cfg.Mode != ModeReadThrough {
		t.Errorf("mode = %v, want read_through", cfg.Mode)
	}
	// Default fallback for owner mode is degraded.
	if cfg.Fallback != FallbackDegraded {
		t.Errorf("fallback = %v, want degraded", cfg.Fallback)
	}
}

func TestParse_OwnerModeStrict(t *testing.T) {
	d := parseBlock(t, `
cluster {
    self     http://a:6081
    peers    http://a:6081 http://b:6081
    region   gra
    mode     owner
    fallback strict
}`)
	cfg, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Mode != ModeOwner {
		t.Errorf("mode = %v, want owner", cfg.Mode)
	}
	if cfg.Fallback != FallbackStrict {
		t.Errorf("fallback = %v, want strict", cfg.Fallback)
	}
}

func TestParse_DynamicPeers(t *testing.T) {
	d := parseBlock(t, `
cluster {
    self    http://10.0.0.1:6081
    peers   dns://cadish-peers:6081
    region  gra
    health  GET /healthz expect 200 interval 1s window 3 threshold 2
}`)
	cfg, err := Parse(d)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Health == nil {
		t.Fatalf("health spec not parsed")
	}
	if cfg.Health.ExpectCode != 200 {
		t.Errorf("expect = %d", cfg.Health.ExpectCode)
	}
}

func TestParse_Errors(t *testing.T) {
	cases := map[string]string{
		"no peers": `cluster {
    self   http://a:6081
    region gra
}`,
		"no self": `cluster {
    peers  http://a:6081
    region gra
}`,
		"no region": `cluster {
    self  http://a:6081
    peers http://a:6081
}`,
		"self not in peers": `cluster {
    self   http://z:6081
    peers  http://a:6081 http://b:6081
    region gra
}`,
		"bad mode": `cluster {
    self   http://a:6081
    peers  http://a:6081
    region gra
    mode   bogus
}`,
		"named cluster rejected": `cluster pool {
    self   http://a:6081
    peers  http://a:6081
    region gra
}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			d := parseBlock(t, src)
			if _, err := Parse(d); err == nil {
				t.Fatalf("expected error for %q", name)
			}
		})
	}
}

// A `cluster NAME { to … }` LB-pool block (the pre-existing upstream-pool form)
// must NOT be parsed as a membership block — IsMembershipBlock distinguishes them
// by shape (no name + a `peers` directive).
func TestIsMembershipBlock(t *testing.T) {
	pool := parseBlock(t, `cluster peers { to http://a:6081; shard_by url }`)
	if IsMembershipBlock(pool) {
		t.Errorf("named LB-pool cluster wrongly classified as membership")
	}
	mem := parseBlock(t, `cluster { self http://a:6081; peers http://a:6081; region gra }`)
	if !IsMembershipBlock(mem) {
		t.Errorf("membership cluster not recognized")
	}
}

func TestParse_PositionedError(t *testing.T) {
	d := parseBlock(t, `cluster {
    self   http://a:6081
    peers  http://a:6081
    region gra
    mode   bogus
}`)
	_, err := Parse(d)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "test.cadish:") {
		t.Errorf("error not positioned: %v", err)
	}
}
