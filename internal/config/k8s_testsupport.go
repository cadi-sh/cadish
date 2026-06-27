package config

import (
	"context"
	"fmt"
	"sync"

	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/lb"
)

// FailingK8sConfigForTest returns a *Config whose Start(ctx) always fails, as if the
// Kubernetes informer caches never synced. It is a cross-package test seam for the
// server's startup fail-fast path (internal/server); production code never calls it.
func FailingK8sConfigForTest() *Config {
	return &Config{k8s: failingK8sClient{}}
}

type failingK8sClient struct{}

func (failingK8sClient) Resolver() lb.EndpointResolver { return nil }
func (failingK8sClient) Start(context.Context) error {
	return fmt.Errorf("k8s: informer cache failed to sync (test)")
}
func (failingK8sClient) Close() {}

// SwapK8sClientFactoryForTest installs a recording k8s client factory that captures the
// Kubeconfig string of every k8s.Options it is asked to build a client with, in order. It
// returns a pointer to the captured slice and a restore func. Cross-package test seam (the
// server's reload test asserts the kubeconfig survives a SIGHUP recompile); production code
// never calls it. The fake clients it hands back resolve to zero endpoints and never fail
// their cache sync, so a k8s:// config compiles + starts offline.
func SwapK8sClientFactoryForTest() (captured *[]string, restore func()) {
	got := &[]string{}
	var mu sync.Mutex
	prev := k8sClientFactory
	k8sClientFactory = func(opts k8s.Options) (k8sClient, error) {
		mu.Lock()
		*got = append(*got, opts.Kubeconfig)
		mu.Unlock()
		return recordingK8sClient{}, nil
	}
	return got, func() { k8sClientFactory = prev }
}

type recordingK8sClient struct{}

func (recordingK8sClient) Resolver() lb.EndpointResolver { return recordingResolver{} }
func (recordingK8sClient) Start(context.Context) error   { return nil }
func (recordingK8sClient) Close()                        {}

type recordingResolver struct{}

func (recordingResolver) ResolveEndpoints(context.Context, string, string, string) ([]lb.Endpoint, error) {
	return nil, nil
}
func (recordingResolver) Watch(string, string, func()) func() { return func() {} }

// InjectedResolverForTest returns a do-nothing lb.EndpointResolver suitable for
// LoadOptions.EndpointResolver — the ingress/gateway path injects an already-built
// resolver so the config builds NO config-owned k8s client. Cross-package test seam.
func InjectedResolverForTest() lb.EndpointResolver { return recordingResolver{} }
