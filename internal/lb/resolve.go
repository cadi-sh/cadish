package lb

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// defaultResolveInterval is how often dns:// and k8s:// targets are re-resolved
// when no explicit interval is configured. Matches the vmod_dynamic default the
// VCL used.
const defaultResolveInterval = 30 * time.Second

// perTargetResolveTimeout bounds a SINGLE target's resolution within a reconcile
// pass. resolveOnce resolves targets serially, so without a per-target deadline a
// single slow/hanging resolver (a stuck DNS server, an unresponsive k8s
// EndpointResolver) would block re-resolution of every OTHER target in the pool
// indefinitely — a working backend could not be refreshed because an unrelated
// one is wedged. A bounded timeout turns "hang forever" into "this target keeps
// its previous endpoints this round" (resolveTarget's documented failure mode),
// which is exactly the transient-failure behavior reconcile already tolerates.
// The value is generous relative to any healthy DNS/informer lookup, so it never
// trips on the normal path; it only caps the pathological hang.
const perTargetResolveTimeout = 10 * time.Second

// Resolver resolves a hostname to a set of addresses (IPv4/IPv6 literals). The
// stdlib net resolver satisfies it via netResolver; tests inject a fake so
// dynamic resolution is deterministic and offline.
type Resolver interface {
	// Resolve returns the current addresses for host. An error leaves the
	// previously-known endpoint set in place (resolution failures must not blow
	// away a working backend set).
	Resolve(ctx context.Context, host string) ([]string, error)
}

// netResolver adapts *net.Resolver to the Resolver interface.
type netResolver struct{ r *net.Resolver }

// defaultResolver is the process-wide DNS resolver used when none is injected.
func defaultResolver() Resolver { return netResolver{r: net.DefaultResolver} }

func (n netResolver) Resolve(ctx context.Context, host string) ([]string, error) {
	addrs, err := n.r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	// Sort so endpoint ids are stable across resolutions regardless of the
	// resolver's ordering (some return round-robin-rotated answers).
	sort.Strings(addrs)
	return addrs, nil
}

// Endpoint is one concrete ready pod address for a k8s:// target — both the IP and
// the resolved (numeric) port. Named ports are resolved to their number by the
// EndpointResolver, so the lb pool always works with numbers.
type Endpoint struct {
	IP   string
	Port int
}

// EndpointResolver resolves a k8s:// target to its current ready endpoints and lets
// a pool subscribe to change events (Approach C: informer + warm cache + event
// poke). internal/k8s implements it; tests inject a fake. It is distinct from the
// DNS Resolver because a k8s target needs the (service, namespace, port) triple and
// returns ip:port pairs (named ports already resolved), not bare addresses.
type EndpointResolver interface {
	// ResolveEndpoints returns the current ready endpoints for service in namespace,
	// resolving the requested port (numeric passthrough or named -> number). An error
	// leaves the pool's previous endpoint set in place.
	ResolveEndpoints(ctx context.Context, service, namespace, port string) ([]Endpoint, error)
	// Watch registers onChange to be invoked whenever this (service, namespace)'s
	// endpoints change, so the pool re-resolves within sub-second of pod churn rather
	// than on the periodic timer. The pool calls it exactly once per k8s backend at
	// Start; callers should not register the same onChange repeatedly, as each
	// registration is independent (implementations need not dedupe).
	//
	// Watch returns a cancel func that DEREGISTERS the registration (FIX 4). The pool
	// calls every cancel when its context is cancelled — when a k8s:// pool is rebuilt
	// (fingerprint change) the old pool's listeners must be removed, or the dead
	// *Upstream stays pinned via a never-removed listener (unbounded memory + O(N)
	// fan-out growth over a long-lived controller). cancel is idempotent; an
	// implementation that has nothing to deregister may return nil.
	Watch(service, namespace string, onChange func()) (cancel func())
}

// endpoint is one concrete backend address derived from a Target: a static
// target yields exactly one; a dynamic target yields one per resolved address.
type endpoint struct {
	id      string  // stable identity (preserves health/inflight across reresolve)
	baseURL string  // httporigin base URL
	target  *Target // owning target (for timeouts / scheme)
}

// resolveTargetTimed wraps resolveTarget with a per-target deadline so one slow
// or hanging resolver cannot block the whole serial reconcile pass. Static
// targets do no I/O, so they skip the timeout entirely (zero extra cost on the
// common static-pool path). The bounded ctx is only applied to dns:// and k8s://
// resolution, where a stuck server/informer would otherwise wedge the loop.
func resolveTargetTimed(ctx context.Context, res Resolver, epRes EndpointResolver, t *Target) ([]endpoint, error) {
	if t.Scheme == SchemeStatic {
		return resolveTarget(ctx, res, epRes, t)
	}
	rctx, cancel := context.WithTimeout(ctx, perTargetResolveTimeout)
	defer cancel()
	return resolveTarget(rctx, res, epRes, t)
}

// resolveTarget expands one Target into its current endpoints. Static targets
// ignore both resolvers; dns targets use res; k8s targets use epRes. A dynamic
// target with zero resolved endpoints yields none (reconcile then drops its
// backends unless the resolution errored).
func resolveTarget(ctx context.Context, res Resolver, epRes EndpointResolver, t *Target) ([]endpoint, error) {
	switch t.Scheme {
	case SchemeStatic:
		return []endpoint{{id: "static|" + t.Raw, baseURL: t.endpointURL(""), target: t}}, nil
	case SchemeK8s:
		if epRes == nil {
			return nil, nil // no resolver wired yet ⇒ no endpoints (pool tolerates empty)
		}
		eps, err := epRes.ResolveEndpoints(ctx, t.Service, t.Namespace, t.Port)
		if err != nil {
			return nil, err
		}
		out := make([]endpoint, 0, len(eps))
		for _, e := range eps {
			hostport := net.JoinHostPort(e.IP, strconv.Itoa(e.Port))
			u := url.URL{Scheme: t.ConnScheme, Host: hostport, Path: t.Path}
			out = append(out, endpoint{id: t.Raw + "|" + hostport, baseURL: u.String(), target: t})
		}
		return out, nil
	default: // SchemeDNS
		addrs, err := res.Resolve(ctx, t.Host)
		if err != nil {
			return nil, err
		}
		eps := make([]endpoint, 0, len(addrs))
		for _, a := range addrs {
			eps = append(eps, endpoint{id: t.Raw + "|" + a, baseURL: t.endpointURL(a), target: t})
		}
		return eps, nil
	}
}
