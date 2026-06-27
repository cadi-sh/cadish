package lb

import (
	"crypto/x509"
	"net/http"
	"testing"
)

// TestFingerprintTLSVerifyIsolation guards the per-upstream isolation invariant: two
// pools that differ ONLY by a TLSVERIFY knob (tls_insecure / ca_file / alpn) must NOT
// hash equal, so a reload never transplants one pool's transport onto another whose
// origin-TLS verification differs.
func TestFingerprintTLSVerifyIsolation(t *testing.T) {
	base := baseFingerprintCfg(t)
	baseFP := base.fingerprint()

	flips := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"insecure", func(c *Config) { c.Insecure = true }},
		{"cafile", func(c *Config) { c.CAFile = "/etc/cadish/internal-ca.pem" }},
		{"alpn", func(c *Config) { c.ALPN = []string{"http/1.1"} }},
		{"alpn-list", func(c *Config) { c.ALPN = []string{"h2", "http/1.1"} }},
	}
	for _, f := range flips {
		c := baseFingerprintCfg(t)
		f.mutate(&c)
		if c.fingerprint() == baseFP {
			t.Errorf("field %q: fingerprint did not change (pools would wrongly coalesce)", f.name)
		}
	}

	// Two pools differing only by tls_insecure must NOT coalesce (the headline case).
	a := baseFingerprintCfg(t)
	b := baseFingerprintCfg(t)
	b.Insecure = true
	if a.fingerprint() == b.fingerprint() {
		t.Fatal("a pool with tls_insecure coalesced with a verifying pool")
	}
	// Identical TLSVERIFY knobs → identical fingerprint.
	x := baseFingerprintCfg(t)
	x.Insecure = true
	x.ALPN = []string{"http/1.1"}
	y := baseFingerprintCfg(t)
	y.Insecure = true
	y.ALPN = []string{"http/1.1"}
	if x.fingerprint() != y.fingerprint() {
		t.Fatal("identical TLSVERIFY configs must hash equal")
	}
}

// TestOriginTLSConfig_DefaultNil proves the no-knob path leaves probe/origin TLS
// untouched: originTLSConfig returns nil, so the probe transport keeps Go's default
// (system roots, dialed-host SNI).
func TestOriginTLSConfig_DefaultNil(t *testing.T) {
	cfg := baseFingerprintCfg(t)
	if tc := originTLSConfig(cfg); tc != nil {
		t.Fatalf("originTLSConfig(no knob) = %v, want nil (default datapath unchanged)", tc)
	}
	doer := defaultProbeDoer(cfg.Timeouts, originTLSConfig(cfg)).(*http.Client)
	if tr := doer.Transport.(*http.Transport); tr.TLSClientConfig != nil {
		t.Errorf("default probe transport TLSClientConfig = %v, want nil", tr.TLSClientConfig)
	}
}

// TestProbeDoerSharesTLSConfig proves the health probe transport applies the SAME
// per-upstream TLS settings as live fetches (HAProxy `http-check connect ssl`
// parity) — including the previously-missed `sni`. This is the fix for the
// probe-Doer parity gap.
func TestProbeDoerSharesTLSConfig(t *testing.T) {
	cfg := baseFingerprintCfg(t)
	cfg.SNI = "www.placercams.com"
	cfg.Insecure = true
	cfg.RootCAs = nil
	cfg.ALPN = []string{"http/1.1"}

	tc := originTLSConfig(cfg)
	if tc == nil {
		t.Fatal("originTLSConfig returned nil despite knobs set")
	}
	if tc.ServerName != "www.placercams.com" {
		t.Errorf("ServerName = %q, want www.placercams.com (the sni-on-probe fix)", tc.ServerName)
	}
	if !tc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not set")
	}
	if len(tc.NextProtos) != 1 || tc.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [http/1.1]", tc.NextProtos)
	}

	doer := defaultProbeDoer(cfg.Timeouts, tc).(*http.Client)
	tr := doer.Transport.(*http.Transport)
	if tr.TLSClientConfig != tc {
		t.Fatal("probe transport did not receive the per-upstream TLS config")
	}

	// A ca_file pool also reaches the probe transport.
	pool := x509.NewCertPool()
	caCfg := baseFingerprintCfg(t)
	caCfg.RootCAs = pool
	caTC := originTLSConfig(caCfg)
	if caTC == nil || caTC.RootCAs != pool {
		t.Fatal("ca_file RootCAs pool did not reach the origin/probe TLS config")
	}
}

// TestOriginTLSConfigVerificationWinsOverInsecure pins Finding 7 (defense-in-depth):
// the tls_insecure ⊕ ca_file combination is unreachable (rejected at compile time), but
// if both were ever set, verification (RootCAs) must WIN — InsecureSkipVerify stays
// false — so a future plumbing mistake fails CLOSED rather than silently disabling
// verification against a configured private CA.
func TestOriginTLSConfigVerificationWinsOverInsecure(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := baseFingerprintCfg(t)
	cfg.Insecure = true // both knobs forced on (the unreachable mistake)
	cfg.RootCAs = pool  //
	tc := originTLSConfig(cfg)
	if tc == nil {
		t.Fatal("originTLSConfig returned nil despite knobs set")
	}
	if tc.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must be false when a RootCAs pool is configured (verification wins; fail closed)")
	}
	if tc.RootCAs != pool {
		t.Fatal("RootCAs pool must be retained for verification")
	}
}
