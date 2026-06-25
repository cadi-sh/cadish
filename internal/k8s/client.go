package k8s

import (
	"context"
	"fmt"
	"sync"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const defaultSyncTimeout = 30 * time.Second

// Options configures the K8s client. Kubeconfig empty ⇒ in-cluster first, then
// KUBECONFIG, then ~/.kube/config.
type Options struct {
	Kubeconfig  string
	SyncTimeout time.Duration
}

// Client wraps a clientset and a SharedInformerFactory over EndpointSlices,
// exposing a warm EndpointCache and an event-poke fan-out.
type Client struct {
	cs      kubernetes.Interface
	factory informers.SharedInformerFactory
	cache   *EndpointCache
	timeout time.Duration

	mu         sync.RWMutex
	listeners  map[uint64]func(namespace, service string)
	nextListen uint64

	stop      chan struct{}
	once      sync.Once // guards Close
	startOnce sync.Once // guards Start (a second call is a no-op)
	startErr  error     // result of the first Start, replayed to later callers
}

// NewClient builds a Client with real auth (in-cluster, else kubeconfig).
func NewClient(opts Options) (*Client, error) {
	cfg, err := restConfig(opts.Kubeconfig)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build clientset: %w", err)
	}
	return NewClientWithInterface(cs, opts), nil
}

// NewClientset builds just the typed clientset with real auth (in-cluster, else
// kubeconfig), without any informers. The ingress controller (which builds its own
// informer factories from the clientset) uses this to avoid constructing an unused
// EndpointSlice factory.
func NewClientset(opts Options) (kubernetes.Interface, error) {
	cfg, err := restConfig(opts.Kubeconfig)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s: build clientset: %w", err)
	}
	return cs, nil
}

// Clientset returns the underlying typed clientset. The ingress controller (Layer 2)
// builds its own SharedInformerFactory from this one clientset to add the
// networking/secret/configmap informers, reusing Layer 1's API connection.
func (c *Client) Clientset() kubernetes.Interface { return c.cs }

// Factory returns the EndpointSlice SharedInformerFactory. (The ingress controller
// builds a SEPARATE factory for its own informers because this one is already started
// for EndpointSlices and informers must be registered before Start.)
func (c *Client) Factory() informers.SharedInformerFactory { return c.factory }

// NewClientWithInterface builds a Client over an injected clientset (the test seam
// for fake.NewSimpleClientset).
func NewClientWithInterface(cs kubernetes.Interface, opts Options) *Client {
	to := opts.SyncTimeout
	if to <= 0 {
		to = defaultSyncTimeout
	}
	f := informers.NewSharedInformerFactory(cs, 0) // resync 0 ⇒ event-driven only
	c := &Client{cs: cs, factory: f, timeout: to, stop: make(chan struct{})}
	c.cache = &EndpointCache{
		slices: f.Discovery().V1().EndpointSlices().Lister(),
	}
	return c
}

// OnServiceChange registers fn for endpoint-change pokes and returns a cancel func that
// DEREGISTERS it (FIX 4). Registration is keyed by an opaque token, so a pool that is
// rebuilt (k8s:// fingerprint change) can remove its listener instead of leaking it —
// the append-only registry previously pinned every dead *lb.Upstream forever. Safe to
// call before or during Start (the RLock/copy in fire keeps the fan-out race-clean); the
// returned cancel is idempotent.
func (c *Client) OnServiceChange(fn func(namespace, service string)) (cancel func()) {
	c.mu.Lock()
	if c.listeners == nil {
		c.listeners = map[uint64]func(namespace, service string){}
	}
	tok := c.nextListen
	c.nextListen++
	c.listeners[tok] = fn
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.listeners, tok)
		c.mu.Unlock()
	}
}

// listenerCount returns the number of registered listeners (test observability for the
// FIX-4 leak guard).
func (c *Client) listenerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.listeners)
}

func (c *Client) fire(ns, svc string) {
	c.mu.RLock()
	ls := make([]func(namespace, service string), 0, len(c.listeners))
	for _, fn := range c.listeners {
		ls = append(ls, fn)
	}
	c.mu.RUnlock()
	for _, fn := range ls {
		fn(ns, svc)
	}
}

// Start runs the informers and blocks until caches sync or SyncTimeout elapses. It is
// guarded by a sync.Once: only the first call registers the event handler and starts
// the factory; a second call is a no-op that replays the first call's error (so
// re-registering the event handler / re-starting the factory can never double-fire
// pokes).
func (c *Client) Start(ctx context.Context) error {
	c.startOnce.Do(func() { c.startErr = c.start(ctx) })
	return c.startErr
}

func (c *Client) start(ctx context.Context) error {
	sliceInformer := c.factory.Discovery().V1().EndpointSlices().Informer()
	_, _ = sliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { c.onSlice(o) },
		UpdateFunc: func(_, o any) { c.onSlice(o) },
		DeleteFunc: func(o any) { c.onSlice(o) },
	})

	go func() {
		<-ctx.Done()
		c.Close()
	}()

	c.factory.Start(c.stop)
	ctxSync, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	synced := c.factory.WaitForCacheSync(ctxSync.Done())
	for typ, ok := range synced {
		if !ok {
			return fmt.Errorf("k8s: informer cache for %v failed to sync within %s "+
				"(check RBAC: get/list/watch on endpointslices — see deploy/k8s/rbac-resolver.yaml)", typ, c.timeout)
		}
	}
	return nil
}

func (c *Client) onSlice(o any) {
	s, ok := o.(*discoveryv1.EndpointSlice)
	if !ok {
		// tombstone on delete
		if tomb, ok := o.(cache.DeletedFinalStateUnknown); ok {
			s, ok = tomb.Obj.(*discoveryv1.EndpointSlice)
			if !ok {
				return
			}
		} else {
			return
		}
	}
	svc := s.Labels[serviceNameLabel]
	if svc == "" {
		return
	}
	c.fire(s.Namespace, svc)
}

// Cache returns the warm endpoint cache.
func (c *Client) Cache() *EndpointCache { return c.cache }

// Close stops the informers (idempotent).
func (c *Client) Close() { c.once.Do(func() { close(c.stop) }) }

// RESTConfig resolves auth (explicit kubeconfig, else in-cluster, else KUBECONFIG /
// ~/.kube/config) and returns the rest.Config. The Gateway API controller uses it to
// build its own gateway-api typed clientset over the SAME auth as the core clientset,
// keeping this package the single owner of auth resolution.
func RESTConfig(kubeconfig string) (*rest.Config, error) { return restConfig(kubeconfig) }

// restConfig resolves auth: explicit kubeconfig, else in-cluster, else the kubeconfig
// loading rules (KUBECONFIG / ~/.kube/config).
func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s: no in-cluster config and no usable kubeconfig "+
			"(set --kubeconfig or KUBECONFIG): %w", err)
	}
	return cfg, nil
}
