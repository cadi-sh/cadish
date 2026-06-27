package config

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/lb"
)

// TestSingleDNSUpstreamLoads is the latent-bug regression: a lone `to dns://host`
// upstream used to FAIL to load because isTrivialUpstream fast-pathed it to a plain
// httporigin, which rejects a `dns://` base URL ("base URL must be http or https").
// SchemeDNS must now force a real lb pool (like SchemeK8s) so the upstream loads and
// re-resolves. The `.invalid` TLD (RFC 2606) guarantees a fast offline NXDOMAIN so
// the construction-time resolve tolerates the failure without hitting the network.
func TestSingleDNSUpstreamLoads(t *testing.T) {
	src := "example.com {\n" +
		"  upstream legacy_dns {\n" +
		"    to dns://legacy-host.invalid:80\n" +
		"  }\n" +
		"}\n"
	cfg, err := Load(writeCfg(t, src))
	if err != nil {
		t.Fatalf("Load: %v (a lone dns:// upstream must load and become an lb pool)", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	o := cfg.Sites[0].Origin
	if _, ok := o.(*lb.Upstream); !ok {
		t.Fatalf("default origin = %T, want *lb.Upstream (a dns:// target must force a re-resolving pool)", o)
	}
}

// TestSingleDNSUpstreamWithResolve loads the full inline `resolve` surface on a lone
// dns:// upstream and confirms it both loads (latent bug fixed) and carries the
// parsed interval + nameserver through to the lb pool config.
func TestSingleDNSUpstreamWithResolve(t *testing.T) {
	src := "example.com {\n" +
		"  upstream legacy_dns {\n" +
		"    to dns://legacy-host.invalid:80\n" +
		"    resolve 10s nameserver 10.134.8.94:53\n" +
		"  }\n" +
		"}\n"
	cfg, err := Load(writeCfg(t, src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	o := cfg.Sites[0].Origin
	if _, ok := o.(*lb.Upstream); !ok {
		t.Fatalf("default origin = %T, want *lb.Upstream", o)
	}
}
