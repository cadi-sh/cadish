package config

import (
	"context"
	"fmt"

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
