package lb

import (
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/origin/httporigin"
)

// baseFingerprintCfg builds a representative multi-feature pool config for the
// fingerprint tests.
func baseFingerprintCfg(t *testing.T) Config {
	t.Helper()
	return staticCfg(t, RoundRobin, "http://a:80", "http://b:80")
}

// TestFingerprintStableAndOrderInsensitive: identical configs hash equal, and the
// target set is order-insensitive (reordering `to` lines does not flip it).
func TestFingerprintStableAndOrderInsensitive(t *testing.T) {
	c1 := baseFingerprintCfg(t)
	c2 := baseFingerprintCfg(t)
	if c1.fingerprint() != c2.fingerprint() {
		t.Fatal("identical configs must hash equal")
	}
	// Idempotent.
	if c1.fingerprint() != c1.fingerprint() {
		t.Fatal("fingerprint must be deterministic")
	}
	// Reorder the backends: same set, same fingerprint.
	reordered := staticCfg(t, RoundRobin, "http://b:80", "http://a:80")
	if reordered.fingerprint() != c1.fingerprint() {
		t.Fatal("target set must be order-insensitive")
	}
}

// TestFingerprintFlipsPerField: each identity-defining field change flips the hash.
func TestFingerprintFlipsPerField(t *testing.T) {
	base := baseFingerprintCfg(t)
	baseFP := base.fingerprint()

	flips := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"name", func(c *Config) { c.Name = "other" }},
		{"kind", func(c *Config) { c.Kind = "cluster" }},
		{"add-backend", func(c *Config) {
			tgt, err := parseTarget("http://c:80", cadishfile.Pos{})
			if err != nil {
				t.Fatal(err)
			}
			c.Backends = append(c.Backends, tgt)
		}},
		{"change-backend", func(c *Config) { c.Backends[0].Raw = "http://z:80" }},
		{"policy", func(c *Config) { c.Policy = LeastConn }},
		{"shard", func(c *Config) { c.Shard = ShardURL }},
		{"replicas", func(c *Config) { c.Replicas = 99 }},
		{"maxconns", func(c *Config) { c.MaxConns = 7 }},
		{"hosthdr-policy", func(c *Config) { c.HostHeader = HostHeaderPolicy{Policy: httporigin.HostOrigin} }},
		{"hosthdr-value", func(c *Config) {
			c.HostHeader = HostHeaderPolicy{Policy: httporigin.HostFixed, Value: "h.internal"}
		}},
		{"timeout-connect", func(c *Config) { c.Timeouts.Connect = 3 * time.Second }},
		{"timeout-firstbyte", func(c *Config) { c.Timeouts.FirstByte = 9 * time.Second }},
		{"timeout-betweenbytes", func(c *Config) { c.Timeouts.BetweenBytes = 4 * time.Second }},
		{"sni", func(c *Config) { c.SNI = "vhost.internal" }},
		{"disable-reuse", func(c *Config) { c.DisableReuse = true }},
		{"resolve-interval", func(c *Config) { c.ResolveInterval = 10 * time.Second }},
		{"nameservers", func(c *Config) { c.Nameservers = []string{"10.0.0.1:53"} }},
		{"capem", func(c *Config) { c.CAPEMHash = "deadbeef" }},
		{"health-added", func(c *Config) {
			c.Health = &HealthSpec{Method: "GET", Path: "/", ExpectCode: 200, Interval: time.Second, Window: 2, Threshold: 2}
		}},
	}
	for _, f := range flips {
		c := baseFingerprintCfg(t)
		f.mutate(&c)
		if c.fingerprint() == baseFP {
			t.Errorf("field %q: fingerprint did not change", f.name)
		}
	}
}

// TestFingerprintHealthFieldsFlip: every Health sub-field changes the hash.
func TestFingerprintHealthFieldsFlip(t *testing.T) {
	withHealth := func(h HealthSpec) Config {
		c := baseFingerprintCfg(t)
		c.Health = &h
		return c
	}
	base := HealthSpec{Method: "GET", Path: "/healthz", ExpectCode: 200, Interval: time.Second, Window: 3, Threshold: 2}
	baseFP := withHealth(base).fingerprint()

	mods := []func(h *HealthSpec){
		func(h *HealthSpec) { h.Method = "HEAD" },
		func(h *HealthSpec) { h.Path = "/ping" },
		func(h *HealthSpec) { h.ExpectCode = 204 },
		func(h *HealthSpec) { h.Interval = 5 * time.Second },
		func(h *HealthSpec) { h.Window = 5 },
		func(h *HealthSpec) { h.Threshold = 3 },
	}
	for i, m := range mods {
		h := base
		m(&h)
		if withHealth(h).fingerprint() == baseFP {
			t.Errorf("health mod %d did not change fingerprint", i)
		}
	}
}

// TestFingerprintResolveKnobs pins Finding 2: the `resolve` knobs (interval +
// nameserver set, with ORDER significant) are part of the pool identity, so editing
// them and reloading rebuilds the resolver instead of transplanting the stale one.
func TestFingerprintResolveKnobs(t *testing.T) {
	withNS := func(ns ...string) Config {
		c := baseFingerprintCfg(t)
		c.Nameservers = ns
		return c
	}
	// Identical nameserver lists hash equal.
	if withNS("10.0.0.1:53", "10.0.0.2:53").fingerprint() != withNS("10.0.0.1:53", "10.0.0.2:53").fingerprint() {
		t.Fatal("identical nameserver lists must hash equal")
	}
	// ORDER is meaningful (DNS fall-through) — a reorder must FLIP the fingerprint.
	if withNS("10.0.0.1:53", "10.0.0.2:53").fingerprint() == withNS("10.0.0.2:53", "10.0.0.1:53").fingerprint() {
		t.Fatal("nameserver ORDER must change the fingerprint (fall-through order is significant)")
	}
	// A split-point difference must not alias (length-prefixed hashing): ["ab","c"] vs
	// ["a","bc"] concatenate to the same bytes only without the length prefix.
	if withNS("ab", "c").fingerprint() == withNS("a", "bc").fingerprint() {
		t.Fatal("distinct nameserver lists must not alias (length prefix required)")
	}
	// Interval alone differing flips it; identical intervals match.
	a := baseFingerprintCfg(t)
	a.ResolveInterval = 5 * time.Second
	b := baseFingerprintCfg(t)
	b.ResolveInterval = 5 * time.Second
	if a.fingerprint() != b.fingerprint() {
		t.Fatal("identical resolve intervals must hash equal")
	}
	b.ResolveInterval = 7 * time.Second
	if a.fingerprint() == b.fingerprint() {
		t.Fatal("a different resolve interval must flip the fingerprint")
	}
}

// TestFingerprintCAPEMContent pins Finding 4: the same ca_file PATH with DIFFERENT PEM
// bytes (an in-place CA rotation) must flip the fingerprint, so the pool is rebuilt with
// the rotated RootCAs rather than transplanting the old pool across a reload.
func TestFingerprintCAPEMContent(t *testing.T) {
	c1 := baseFingerprintCfg(t)
	c1.CAFile = "/etc/cadish/ca.pem"
	c1.CAPEMHash = "hash-of-old-pem"
	c2 := baseFingerprintCfg(t)
	c2.CAFile = "/etc/cadish/ca.pem" // SAME path
	c2.CAPEMHash = "hash-of-new-pem" // ROTATED content
	if c1.fingerprint() == c2.fingerprint() {
		t.Fatal("same ca_file path with different PEM content must flip the fingerprint (in-place CA rotation honored on reload)")
	}
	// Same path AND same content still match (transplant preserved for the no-change case).
	c2.CAPEMHash = "hash-of-old-pem"
	if c1.fingerprint() != c2.fingerprint() {
		t.Fatal("same ca_file path and content must still hash equal")
	}
}

// TestUpstreamFingerprintMatchesConfig: the exported pool accessor equals its config
// fingerprint.
func TestUpstreamFingerprintMatchesConfig(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := baseFingerprintCfg(t)
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	if u.Fingerprint() != cfg.fingerprint() {
		t.Fatal("Upstream.Fingerprint must equal Config.fingerprint")
	}
}

// TestFingerprintSNIAndDisableReuse: fingerprint must change when only SNI or
// DisableReuse changes — these are transport fields that survive a reload transplant.
func TestFingerprintSNIAndDisableReuse(t *testing.T) {
	base := baseFingerprintCfg(t)
	baseFP := base.fingerprint()

	withSNI := baseFingerprintCfg(t)
	withSNI.SNI = "backend.internal"
	if withSNI.fingerprint() == baseFP {
		t.Error("SNI change did not flip the fingerprint")
	}

	noReuse := baseFingerprintCfg(t)
	noReuse.DisableReuse = true
	if noReuse.fingerprint() == baseFP {
		t.Error("DisableReuse change did not flip the fingerprint")
	}

	// Same SNI/DisableReuse → same fingerprint.
	a := baseFingerprintCfg(t)
	a.SNI = "x.internal"
	a.DisableReuse = true
	b2 := baseFingerprintCfg(t)
	b2.SNI = "x.internal"
	b2.DisableReuse = true
	if a.fingerprint() != b2.fingerprint() {
		t.Error("identical SNI+DisableReuse configs must hash equal")
	}
}
