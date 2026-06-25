package config

import (
	"context"
	"testing"

	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/lb"
)

// noopResolver is a do-nothing lb.EndpointResolver for the fake client.
type noopResolver struct{}

func (noopResolver) ResolveEndpoints(context.Context, string, string, string) ([]lb.Endpoint, error) {
	return nil, nil
}
func (noopResolver) Watch(string, string, func()) func() { return nil }

// fakeK8sClient implements the config.k8sClient seam for tests.
type fakeK8sClient struct {
	started bool
	closed  bool
}

func (f *fakeK8sClient) Resolver() lb.EndpointResolver { return noopResolver{} }
func (f *fakeK8sClient) Start(context.Context) error   { f.started = true; return nil }
func (f *fakeK8sClient) Close()                        { f.closed = true }

// swapK8sFactory installs fn as the k8s client factory and returns a restore func.
func swapK8sFactory(fn func(k8s.Options) (k8sClient, error)) func() {
	prev := k8sClientFactory
	k8sClientFactory = fn
	return func() { k8sClientFactory = prev }
}

func TestConfigBuildsK8sClientLazily(t *testing.T) {
	t.Run("no k8s target => no client", func(t *testing.T) {
		c := loadConfig(t, "x.test {\n upstream a { to http://h:80 }\n}\n")
		if c.k8s != nil {
			t.Fatal("expected no k8s client")
		}
	})
	t.Run("k8s target => client built and resolver injected", func(t *testing.T) {
		fake := &fakeK8sClient{}
		restore := swapK8sFactory(func(k8s.Options) (k8sClient, error) { return fake, nil })
		defer restore()
		c := loadConfig(t, "x.test {\n upstream a { to k8s://web.prod:8080 }\n}\n")
		if c.k8s == nil {
			t.Fatal("expected a k8s client")
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !fake.started {
			t.Fatal("expected Start to start the client")
		}
	})
}
