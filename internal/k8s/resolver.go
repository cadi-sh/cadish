package k8s

import (
	"context"

	"github.com/cadi-sh/cadish/internal/lb"
)

// resolver adapts a Client to lb.EndpointResolver.
type resolver struct{ c *Client }

// Resolver returns an lb.EndpointResolver backed by this client's warm cache and
// event fan-out.
func (c *Client) Resolver() lb.EndpointResolver { return resolver{c: c} }

func (r resolver) ResolveEndpoints(_ context.Context, service, namespace, port string) ([]lb.Endpoint, error) {
	return r.c.Cache().Endpoints(namespace, service, port)
}

// Watch registers onChange to fire only for this (service, namespace)'s changes and
// returns a cancel func that deregisters the underlying client listener (FIX 4).
func (r resolver) Watch(service, namespace string, onChange func()) (cancel func()) {
	return r.c.OnServiceChange(func(ns, svc string) {
		if ns == namespace && svc == service {
			onChange()
		}
	})
}
