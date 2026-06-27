package lb

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// TestResolveConfigCustomNameserverDialed asserts that when an upstream sets
// `resolve nameserver <ip:port>`, the per-pool resolver dials exactly that
// nameserver (not the system resolv.conf). The dnsDialContext seam is overridden
// so the assertion is deterministic and offline: it records the dial target and
// returns an error (so the lookup fails fast and resolveOnce tolerates it).
func TestResolveConfigCustomNameserverDialed(t *testing.T) {
	const ns = "10.134.8.94:53"

	var mu sync.Mutex
	var dialed []string
	orig := dnsDialContext
	dnsDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, address)
		mu.Unlock()
		return nil, errors.New("test: no dns")
	}
	t.Cleanup(func() { dnsDialContext = orig })

	cfg := Config{
		Name: "legacy_dns", Kind: "upstream", Policy: RoundRobin,
		Backends:    []Target{mustParse(t, "dns://legacy-host.invalid:80")},
		Nameservers: []string{ns},
	}
	// New() runs an initial resolveOnce, which drives the nameserver dial.
	if _, err := New(cfg, WithOriginFactory(stubOriginFactory)); err != nil {
		t.Fatalf("New: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("custom nameserver was never dialed (pool did not use the configured resolver)")
	}
	for _, a := range dialed {
		if a != ns {
			t.Fatalf("dialed %q, want the configured nameserver %q", a, ns)
		}
	}
}

// countingResolver counts Resolve calls and returns a fixed address set.
type countingResolver struct {
	n     atomic.Int64
	addrs []string
}

func (c *countingResolver) Resolve(context.Context, string) ([]string, error) {
	c.n.Add(1)
	return append([]string(nil), c.addrs...), nil
}

// TestResolveConfigIntervalDrivesTicker asserts cfg.ResolveInterval (not the
// hardcoded 30s default) drives the re-resolution ticker. A short interval with a
// counting resolver re-resolves many times in a brief window; the 30s default
// would only run the construction + loop-entry resolves (2 calls).
func TestResolveConfigIntervalDrivesTicker(t *testing.T) {
	res := &countingResolver{addrs: []string{"10.0.0.1"}}
	cfg := Config{
		Name: "legacy_dns", Kind: "upstream", Policy: RoundRobin,
		Backends:        []Target{mustParse(t, "dns://legacy-host.invalid:80")},
		ResolveInterval: 15 * time.Millisecond,
	}
	u, err := New(cfg, WithResolver(res), WithOriginFactory(stubOriginFactory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if u.resolveInterval != 15*time.Millisecond {
		t.Fatalf("resolveInterval = %v, want config-driven 15ms", u.resolveInterval)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.Start(ctx)

	// With a 15ms tick we expect many resolves within 300ms; the 30s default would
	// leave the count at 2 (construction + loop entry).
	waitFor(t, 2*time.Second, func() bool { return res.n.Load() >= 5 })
}

// TestResolveConfigDefaultPathUnchanged asserts that an upstream setting NEITHER
// knob keeps the byte-for-byte default: the process-wide system resolver and the
// 30s re-resolution interval.
func TestResolveConfigDefaultPathUnchanged(t *testing.T) {
	cfg := Config{
		Name: "blog", Kind: "upstream", Policy: RoundRobin,
		Backends: []Target{mustParse(t, "http://10.0.0.1:80")},
	}
	u, err := New(cfg, WithOriginFactory(stubOriginFactory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if u.resolveInterval != defaultResolveInterval {
		t.Fatalf("resolveInterval = %v, want default %v", u.resolveInterval, defaultResolveInterval)
	}
	// The default path now wraps the process-wide system resolver in guardedResolver
	// (Finding 3) so a dynamically-resolved metadata IP is filtered; the inner resolver
	// is still the unchanged net.DefaultResolver-backed netResolver.
	g, ok := u.resolver.(guardedResolver)
	if !ok {
		t.Fatalf("resolver = %T, want guardedResolver wrapping the default", u.resolver)
	}
	nr, ok := g.inner.(netResolver)
	if !ok {
		t.Fatalf("guarded inner = %T, want default netResolver", g.inner)
	}
	if nr.r != net.DefaultResolver {
		t.Fatal("resolver does not wrap net.DefaultResolver (default path changed)")
	}
}

// TestResolveConfigDefaultPathGuardsMetadata is the Finding 3 regression: the DEFAULT
// (system resolv.conf) dns:// path must filter a runtime-resolved cloud-metadata answer
// exactly like the custom-nameserver path, closing the defense-in-depth gap where only
// the custom path was guarded. We stub the SYSTEM resolver (via the guarded default
// wrapper New() installs) to return 169.254.169.254 and assert it is dropped — no
// eligible backend address survives. A normal RFC1918 backend still passes.
func TestResolveConfigDefaultPathGuardsMetadata(t *testing.T) {
	cfg := Config{
		Name: "blog", Kind: "upstream", Policy: RoundRobin,
		Backends: []Target{mustParse(t, "dns://legacy-host.invalid:80")},
	}
	u, err := New(cfg, WithOriginFactory(stubOriginFactory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The default branch must install the guard (this is the behavior under test).
	g, ok := u.resolver.(guardedResolver)
	if !ok {
		t.Fatalf("default resolver = %T, want guardedResolver (system path unguarded — SSRF gap)", u.resolver)
	}
	// Substitute the stubbed SYSTEM resolver underneath the SAME guard New() installed,
	// and assert a metadata answer is filtered while a legitimate backend survives.
	g.inner = &countingResolver{addrs: []string{"169.254.169.254", "10.0.0.7"}}
	addrs, err := g.Resolve(context.Background(), "legacy-host.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "10.0.0.7" {
		t.Fatalf("guarded default addrs = %v, want only [10.0.0.7] (169.254.169.254 must be dropped)", addrs)
	}
}

// TestResolveConfigGuardsLinkLocal asserts the custom-nameserver path filters out
// runtime-resolved link-local/metadata addresses (SSRF defense-in-depth), while a
// normal address passes through.
func TestResolveConfigGuardsLinkLocal(t *testing.T) {
	inner := &countingResolver{addrs: []string{"169.254.169.254", "10.0.0.5"}}
	g := guardedResolver{inner: inner}
	addrs, err := g.Resolve(context.Background(), "host")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "10.0.0.5" {
		t.Fatalf("guarded addrs = %v, want only [10.0.0.5] (169.254.169.254 must be dropped)", addrs)
	}
}

// TestResolveConfigGuardsIPv6Metadata is the Finding 5 regression: the custom-nameserver
// guard must also drop the AWS IPv6 IMDS endpoint fd00:ec2::254 (a ULA, fc00::/7 — NOT
// caught by the link-local filter), so an untrusted nameserver cannot resolve a backend
// onto the v6 cloud-metadata service. A legitimate ULA backend (fd12::1) still passes.
func TestResolveConfigGuardsIPv6Metadata(t *testing.T) {
	inner := &countingResolver{addrs: []string{"fd00:ec2::254", "fd12::1", "10.0.0.5"}}
	g := guardedResolver{inner: inner}
	addrs, err := g.Resolve(context.Background(), "host")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if a == "fd00:ec2::254" {
			t.Fatalf("guarded addrs = %v, want fd00:ec2::254 dropped (IPv6 cloud metadata)", addrs)
		}
	}
	if len(addrs) != 2 {
		t.Fatalf("guarded addrs = %v, want the two legitimate addrs kept", addrs)
	}
}

// keep cadishfile import used even if mustParse signature changes.
var _ = cadishfile.Pos{}
