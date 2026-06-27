package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// k8sUpstreamSrc is a minimal Cadishfile with a single config-owned k8s:// pool, so a
// reload REBUILDS the k8s client (old.k8s != nil → rebuildK8sPools) and the kubeconfig
// the rebuilt client is constructed with is observable via the recording factory.
const k8sUpstreamSrc = "site.local {\n\tupstream a { to k8s://web.prod:8080 }\n}\n"

// writeK8sCadishfile writes k8sUpstreamSrc to a temp Cadishfile and returns its path.
func writeK8sCadishfile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(k8sUpstreamSrc), 0o600); err != nil {
		t.Fatalf("write Cadishfile: %v", err)
	}
	return path
}

// TestReloadPreservesKubeconfig is the regression guard for the
// "--kubeconfig dropped on SIGHUP" bug: a reload must recompile the config with the SAME
// run-time LoadOptions the process started with (Options.ReloadOptions), so the rebuilt
// config-owned k8s client is constructed with the operator's kubeconfig — not the empty
// string (which would silently fall back to the in-cluster/KUBECONFIG/~/.kube/config
// chain). The recording factory captures, in order, the kubeconfig of every client built;
// after Reload the LAST build must carry the sentinel.
func TestReloadPreservesKubeconfig(t *testing.T) {
	const wantKubeconfig = "/sentinel/kubeconfig"

	got, restore := config.SwapK8sClientFactoryForTest()
	defer restore()

	// Keep the post-swap teardown goroutine from outliving the test.
	defer shrinkReloadGrace()()

	path := writeK8sCadishfile(t)
	cfg, err := config.LoadWithOptions(path, config.LoadOptions{Kubeconfig: wantKubeconfig})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	srv, err := NewServer(cfg, ":0", Options{
		Logger:        discardLogger(),
		ReloadOptions: config.LoadOptions{Kubeconfig: wantKubeconfig},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = srv.Shutdown(testCtx(t)) }()

	// Startup built exactly one client, with the sentinel.
	if n := len(*got); n != 1 {
		t.Fatalf("after startup: built %d k8s clients, want 1", n)
	}
	if (*got)[0] != wantKubeconfig {
		t.Fatalf("startup client kubeconfig = %q, want %q", (*got)[0], wantKubeconfig)
	}

	// SIGHUP: the config-owned k8s pool is REBUILT, so a second client is constructed.
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if n := len(*got); n != 2 {
		t.Fatalf("after reload: built %d k8s clients, want 2 (the rebuild)", n)
	}
	if last := (*got)[len(*got)-1]; last != wantKubeconfig {
		t.Fatalf("rebuilt client kubeconfig = %q, want %q (the startup --kubeconfig must survive reload)", last, wantKubeconfig)
	}
}

// TestReloadEmptyKubeconfigStaysDefaultChain is the pass-through regression: with no
// startup --kubeconfig, the rebuilt client must still get "" (the default
// in-cluster/KUBECONFIG/~/.kube/config chain) — the fix preserves the startup value, it
// does not force a non-empty one.
func TestReloadEmptyKubeconfigStaysDefaultChain(t *testing.T) {
	got, restore := config.SwapK8sClientFactoryForTest()
	defer restore()
	defer shrinkReloadGrace()()

	path := writeK8sCadishfile(t)
	cfg, err := config.LoadWithOptions(path, config.LoadOptions{}) // empty kubeconfig
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	srv, err := NewServer(cfg, ":0", Options{Logger: discardLogger()}) // no ReloadOptions
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = srv.Shutdown(testCtx(t)) }()

	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if n := len(*got); n != 2 {
		t.Fatalf("after reload: built %d k8s clients, want 2", n)
	}
	if last := (*got)[len(*got)-1]; last != "" {
		t.Fatalf("rebuilt client kubeconfig = %q, want \"\" (default chain preserved when --kubeconfig unset)", last)
	}
}

// TestApplyConfigInjectedResolverBuildsNoConfigOwnedClient guards the cadish ingress /
// gateway path: when a resolver is INJECTED (LoadOptions.EndpointResolver), the config
// owns no k8s client, and a reload that re-injects the resolver (exactly what the
// controller's reconcile does — translate Ingress objects → load with the resolver →
// ApplyConfig) must still build no config-owned client. The recording factory must be
// called zero times, at startup and across the reload.
func TestApplyConfigInjectedResolverBuildsNoConfigOwnedClient(t *testing.T) {
	got, restore := config.SwapK8sClientFactoryForTest()
	defer restore()
	defer shrinkReloadGrace()()

	path := writeK8sCadishfile(t)
	res := config.InjectedResolverForTest()

	cfg, err := config.LoadWithOptions(path, config.LoadOptions{EndpointResolver: res})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	srv, err := NewServer(cfg, ":0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = srv.Shutdown(testCtx(t)) }()

	if n := len(*got); n != 0 {
		t.Fatalf("injected resolver must build NO config-owned client at startup, built %d", n)
	}

	// Reconcile-style reload: load again with the resolver re-injected, then ApplyConfig.
	next, err := config.LoadWithOptions(path, config.LoadOptions{EndpointResolver: res})
	if err != nil {
		t.Fatalf("reload load: %v", err)
	}
	if err := srv.ApplyConfig(next); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if n := len(*got); n != 0 {
		t.Fatalf("injected resolver must build NO config-owned client across reload, built %d", n)
	}
}

// shrinkReloadGrace shrinks the post-swap drain grace so ApplyConfig's background
// old-config teardown goroutine finishes promptly within the test, then restores it.
func shrinkReloadGrace() func() {
	prev := reloadDrainGrace
	reloadDrainGrace = time.Millisecond
	return func() { reloadDrainGrace = prev }
}
