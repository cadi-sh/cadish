package config

import (
	"net/netip"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func parseFile(t *testing.T, src string) *cadishfile.File {
	t.Helper()
	f, err := cadishfile.Parse("test", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

// A well-formed proxy_protocol block populates the trust set.
func TestProxyProtocolBlock(t *testing.T) {
	f := parseFile(t, `{
  proxy_protocol {
    trust 10.0.0.0/8 192.0.2.7/32
  }
}
example.com {
  cache_ttl default ttl 60s
}`)
	pp, err := proxyProtocolFromFile(f)
	if err != nil {
		t.Fatalf("proxyProtocolFromFile: %v", err)
	}
	if pp == nil {
		t.Fatal("expected a ProxyProtocolConfig, got nil")
	}
	if len(pp.Trust) != 2 {
		t.Fatalf("trust = %d prefixes, want 2: %v", len(pp.Trust), pp.Trust)
	}
	if !prefixContains(pp.Trust, "10.1.2.3") || !prefixContains(pp.Trust, "192.0.2.7") {
		t.Errorf("trust set does not cover expected addresses: %v", pp.Trust)
	}
}

// No block -> nil (the feature is off; zero cost).
func TestProxyProtocolAbsent(t *testing.T) {
	f := parseFile(t, `example.com {
  cache_ttl default ttl 60s
}`)
	pp, err := proxyProtocolFromFile(f)
	if err != nil {
		t.Fatalf("proxyProtocolFromFile: %v", err)
	}
	if pp != nil {
		t.Fatalf("expected nil (no block), got %v", pp)
	}
}

// An EMPTY trust set is a config error (the forgery-hole guard / spec test 6).
func TestProxyProtocolEmptyTrustIsError(t *testing.T) {
	for name, src := range map[string]string{
		"no trust directive": `{
  proxy_protocol {
  }
}
example.com { cache_ttl default ttl 60s }`,
		"trust with no args": `{
  proxy_protocol {
    trust
  }
}
example.com { cache_ttl default ttl 60s }`,
	} {
		f := parseFile(t, src)
		if _, err := proxyProtocolFromFile(f); err == nil {
			t.Errorf("%s: expected a config error for an empty trust set", name)
		}
	}
}

// A bad CIDR or unknown sub-directive is a config error.
func TestProxyProtocolBadInputIsError(t *testing.T) {
	for name, src := range map[string]string{
		"bad cidr": `{
  proxy_protocol { trust not-a-cidr }
}
example.com { cache_ttl default ttl 60s }`,
		"unknown sub-directive": `{
  proxy_protocol { bogus 1 }
}
example.com { cache_ttl default ttl 60s }`,
	} {
		f := parseFile(t, src)
		if _, err := proxyProtocolFromFile(f); err == nil {
			t.Errorf("%s: expected a config error", name)
		}
	}
}

// ParseProxyProtocolFlag mirrors the block's REQUIRE-non-empty rule.
func TestParseProxyProtocolFlag(t *testing.T) {
	pp, err := ParseProxyProtocolFlag("10.0.0.0/8, 192.0.2.7/32")
	if err != nil {
		t.Fatalf("ParseProxyProtocolFlag: %v", err)
	}
	if len(pp.Trust) != 2 {
		t.Fatalf("trust = %d, want 2", len(pp.Trust))
	}

	if _, err := ParseProxyProtocolFlag(""); err == nil {
		t.Error("expected error for an empty -proxy-protocol-trust flag")
	}
	if _, err := ParseProxyProtocolFlag("  ,  "); err == nil {
		t.Error("expected error for a whitespace/comma-only trust flag")
	}
	if _, err := ParseProxyProtocolFlag("garbage"); err == nil {
		t.Error("expected error for a bad CIDR in the trust flag")
	}
}

// End-to-end through LoadString: the block ends up on Config.ProxyProtocol.
func TestProxyProtocolEndToEnd(t *testing.T) {
	cfg, err := LoadString("test", `{
  proxy_protocol { trust 127.0.0.0/8 }
}
example.com {
  upstream backend { to http://127.0.0.1:9 }
  cache_ttl default ttl 60s
}`)
	if err != nil {
		t.Fatalf("LoadString: %v", err)
	}
	defer cfg.Close()
	if cfg.ProxyProtocol == nil {
		t.Fatal("Config.ProxyProtocol is nil; want the parsed block")
	}
	if !prefixContains(cfg.ProxyProtocol.Trust, "127.0.0.1") {
		t.Errorf("trust does not cover loopback: %v", cfg.ProxyProtocol.Trust)
	}
}

func prefixContains(ps []netip.Prefix, addr string) bool {
	a := netip.MustParseAddr(addr)
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
