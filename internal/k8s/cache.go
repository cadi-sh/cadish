package k8s

import (
	"fmt"
	"strconv"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"

	"github.com/cadi-sh/cadish/internal/lb"
)

// serviceNameLabel is the well-known label EndpointSlices carry to associate with
// their Service.
const serviceNameLabel = "kubernetes.io/service-name"

// EndpointCache resolves (namespace, service, port) to ready pod endpoints by
// reading the warm EndpointSlice informer cache (no API call per resolve). Named
// ports are mapped to numbers from the slices' own port list, so no Service watch
// is needed.
type EndpointCache struct {
	slices discoverylisters.EndpointSliceLister
}

// Endpoints returns the ready endpoints for service in namespace at port (a number
// passed through, or a named port resolved via the slice's port list). It unions
// across the service's EndpointSlices and de-duplicates by IP:port.
func (c *EndpointCache) Endpoints(namespace, service, port string) ([]lb.Endpoint, error) {
	sel := labels.SelectorFromSet(labels.Set{serviceNameLabel: service})
	slices, err := c.slices.EndpointSlices(namespace).List(sel)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var out []lb.Endpoint
	portFound := false
	for _, s := range slices {
		num, ok := resolvePort(s, port)
		if !ok {
			continue // this slice doesn't expose the requested port
		}
		portFound = true
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
				continue
			}
			for _, ip := range ep.Addresses {
				key := ip + ":" + strconv.Itoa(num)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, lb.Endpoint{IP: ip, Port: num})
			}
		}
	}
	if len(slices) > 0 && !portFound && !numeric(port) {
		// Slices exist but none exposed the named port — a config/runtime mismatch.
		// (A named port that DOES exist but currently has zero ready pods returns an
		// empty set, not an error, so the pool drops to 503 rather than retaining.)
		return nil, fmt.Errorf("k8s: service %s/%s exposes no port named %q", namespace, service, port)
	}
	return out, nil
}

// resolvePort maps the requested port (a numeric Service port or a named port) to the
// actual endpoint (target) port to dial, using the slice's own port list.
//
// EndpointSlice ports carry the resolved endpoint port keyed by the Service port NAME,
// not its number, so a numeric Service-port reference can only be mapped from the slice
// alone when the Service exposes a SINGLE port — the overwhelmingly common case, incl.
// the standard `port: 80 -> targetPort: 8080` remap (K8S-PORT). cadish dials pod
// endpoints directly, so it must use the endpoint port, never the virtual Service port
// number. For a multi-port Service referenced by number we cannot disambiguate without
// watching the Service spec, so we fall back to the requested number (the prior
// behavior). A named reference is matched exactly. ok is false when a named port is not
// found on this slice.
func resolvePort(s *discoveryv1.EndpointSlice, port string) (int, bool) {
	if n, err := strconv.Atoi(port); err == nil {
		// Numeric Service-port reference: map to the real endpoint port when the slice
		// exposes exactly one port (single-port Service, incl. port->targetPort remap).
		if len(s.Ports) == 1 && s.Ports[0].Port != nil {
			return int(*s.Ports[0].Port), true
		}
		// Multi-port (or portless) slice: cannot map a Service port number from the slice
		// alone — fall back to the requested number rather than guess the wrong endpoint.
		return n, true
	}
	for _, p := range s.Ports {
		if p.Name != nil && *p.Name == port && p.Port != nil {
			return int(*p.Port), true
		}
	}
	return 0, false
}

func numeric(port string) bool { _, err := strconv.Atoi(port); return err == nil }
