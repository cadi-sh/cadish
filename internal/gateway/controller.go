package gateway

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/ingress"
	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/tlsacme"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	gwlisters "sigs.k8s.io/gateway-api/pkg/client/listers/apis/v1"
)

const (
	// defaultDebounce coalesces a burst of watch events into one reconcile.
	defaultDebounce = 250 * time.Millisecond
)

// Applier is the swap seam the controller drives: *server.Server satisfies it via
// Server.ApplyConfig (the SAME atomic routing swap the Ingress controller uses).
type Applier interface {
	ApplyConfig(*config.Config) error
}

// Config tunes the Gateway controller.
type Config struct {
	// Namespaces, when non-empty, restricts which namespaces' Gateways/HTTPRoutes are
	// served (informers still watch cluster-wide; reconcile filters). Empty ⇒ all.
	Namespaces []string
	// ResyncDebounce is the quiet window after the last watched change before a reconcile
	// (default 250ms).
	ResyncDebounce time.Duration
	// Kubeconfig is the explicit kubeconfig path for the resolver client (out-of-cluster).
	Kubeconfig string
	// LeaderElection enables the leader-elected status writer. When false the writer runs
	// unconditionally (single-replica / tests). Mirrors the Ingress controller; serving is
	// never gated by leadership.
	LeaderElection  bool
	LeaderNamespace string
	LeaderName      string
	// Identity uniquely names this replica for leader election (e.g. the pod name).
	Identity string
}

// Controller watches GatewayClass/Gateway/HTTPRoute (+ Layer-1 EndpointSlices), debounces
// change events, re-renders the Cadishfile and applies it via Applier. A bad render never
// takes serving down: the last good config stays live. Per-resource graceful degradation
// mirrors the Ingress controller (a bad HTTPRoute does not break others). Status is
// written back as Kubernetes conditions by a leader-elected writer (serving never gated).
type Controller struct {
	cs       kubernetes.Interface
	gwcs     gwclient.Interface
	applier  Applier
	tlsInj   TLSInjector // nil when the applier cannot accept BYO Secret certs
	base     string
	opts     Config
	debounce time.Duration
	log      *slog.Logger

	// resolver is Layer 1's k8s client (resolves k8s:// upstreams to ready pod IPs — the
	// SAME path the Ingress controller's backends use, D53).
	resolverClient *k8s.Client
	resolver       lb.EndpointResolver

	gwFactory   gwinformers.SharedInformerFactory
	classLister gwlisters.GatewayClassLister
	gwLister    gwlisters.GatewayLister
	routeLister gwlisters.HTTPRouteLister
	grantLister gwlisters.ReferenceGrantLister

	// coreFactory holds the Secret + Service informers (BYO TLS certs from listener
	// certificateRefs; Service existence for backendRef resolution — GW1 BackendNotFound).
	coreFactory informers.SharedInformerFactory
	secLister   corelisters.SecretLister
	svcLister   corelisters.ServiceLister

	changes chan struct{}

	mu       sync.Mutex
	lastGood string // last successfully applied rendered text (no-op swap avoidance)

	watched     int
	rejectCount int
	lastErr     string
	isLeader    atomic.Bool

	nsSet map[string]bool // resolved from opts.Namespaces (nil ⇒ all)
}

// Stats is a point-in-time snapshot of the controller's reconcile state.
type Stats struct {
	WatchedRoutes   int
	LastAppliedHash string
	Rejects         int
	LastError       string
	IsLeader        bool
}

// Stats returns the current reconcile snapshot (safe for concurrent use).
func (c *Controller) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		WatchedRoutes:   c.watched,
		LastAppliedHash: shortHash(c.lastGood),
		Rejects:         c.rejectCount,
		LastError:       c.lastErr,
		IsLeader:        c.isLeader.Load(),
	}
}

func shortHash(s string) string {
	if s == "" {
		return ""
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%016x", h.Sum64())
}

// New builds a Controller. cs is the core clientset (Layer-1 resolver + status writes need
// it; the gateway-api objects come from gwcs). applier is the live server; base is the
// globals-only Cadishfile (cache/admin/tls defaults — sites come from HTTPRoutes).
func New(cs kubernetes.Interface, gwcs gwclient.Interface, applier Applier, base string, opts Config) *Controller {
	d := opts.ResyncDebounce
	if d <= 0 {
		d = defaultDebounce
	}
	var nsSet map[string]bool
	if len(opts.Namespaces) > 0 {
		nsSet = make(map[string]bool, len(opts.Namespaces))
		for _, ns := range opts.Namespaces {
			nsSet[ns] = true
		}
	}
	rc := k8s.NewClientWithInterface(cs, k8s.Options{})
	gf := gwinformers.NewSharedInformerFactory(gwcs, 0)
	cf := informers.NewSharedInformerFactory(cs, 0)
	c := &Controller{
		cs:             cs,
		gwcs:           gwcs,
		applier:        applier,
		base:           base,
		opts:           opts,
		debounce:       d,
		log:            slog.Default(),
		resolverClient: rc,
		resolver:       rc.Resolver(),
		gwFactory:      gf,
		classLister:    gf.Gateway().V1().GatewayClasses().Lister(),
		gwLister:       gf.Gateway().V1().Gateways().Lister(),
		routeLister:    gf.Gateway().V1().HTTPRoutes().Lister(),
		grantLister:    gf.Gateway().V1().ReferenceGrants().Lister(),
		coreFactory:    cf,
		secLister:      cf.Core().V1().Secrets().Lister(),
		svcLister:      cf.Core().V1().Services().Lister(),
		changes:        make(chan struct{}, 1),
		nsSet:          nsSet,
	}
	// The live server can accept BYO Secret certs (the SAME path Ingress uses); a
	// bare-Applier test fake cannot — then Gateway BYO-Secret TLS is simply inactive.
	if inj, ok := applier.(TLSInjector); ok {
		c.tlsInj = inj
	}
	return c
}

// SetLogger overrides the controller's logger (defaults to slog.Default()).
func (c *Controller) SetLogger(l *slog.Logger) {
	if l != nil {
		c.log = l
	}
}

// UpdateBase swaps the base (globals-only) Cadishfile and triggers a reconcile (SIGHUP).
func (c *Controller) UpdateBase(base string) {
	c.mu.Lock()
	c.base = base
	c.mu.Unlock()
	c.poke()
}

// Run starts the informers, waits for cache sync, performs an initial reconcile, then
// reconciles on every debounced change until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	if err := c.resolverClient.Start(ctx); err != nil {
		return fmt.Errorf("gateway: start resolver: %w", err)
	}

	classInf := c.gwFactory.Gateway().V1().GatewayClasses().Informer()
	gwInf := c.gwFactory.Gateway().V1().Gateways().Informer()
	routeInf := c.gwFactory.Gateway().V1().HTTPRoutes().Informer()
	grantInf := c.gwFactory.Gateway().V1().ReferenceGrants().Informer()
	secInf := c.coreFactory.Core().V1().Secrets().Informer()
	svcInf := c.coreFactory.Core().V1().Services().Informer()
	h := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { c.poke() },
		UpdateFunc: func(any, any) { c.poke() },
		DeleteFunc: func(any) { c.poke() },
	}
	for _, inf := range []cache.SharedIndexInformer{classInf, gwInf, routeInf, grantInf, secInf, svcInf} {
		_, _ = inf.AddEventHandler(h)
	}

	c.gwFactory.Start(ctx.Done())
	c.coreFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), classInf.HasSynced, gwInf.HasSynced, routeInf.HasSynced, grantInf.HasSynced, secInf.HasSynced, svcInf.HasSynced) {
		return fmt.Errorf("gateway: informer caches failed to sync")
	}

	// The leader-elected status writer runs ALONGSIDE serving and never gates it.
	go c.runStatusWriter(ctx)

	c.reconcile(ctx)

	timer := time.NewTimer(c.debounce)
	if !timer.Stop() {
		<-timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.changes:
			timer.Reset(c.debounce)
		case <-timer.C:
			c.reconcile(ctx)
		}
	}
}

// poke signals a pending change (non-blocking — the channel is a 1-slot coalescer).
func (c *Controller) poke() {
	select {
	case c.changes <- struct{}{}:
	default:
	}
}

// snapshot lists the watched objects (namespace-filtered for Gateways/HTTPRoutes;
// GatewayClasses are cluster-scoped).
func (c *Controller) snapshot() (Inputs, error) {
	classes, err := c.classLister.List(labels.Everything())
	if err != nil {
		return Inputs{}, fmt.Errorf("list gatewayclasses: %w", err)
	}
	gws, err := c.gwLister.List(labels.Everything())
	if err != nil {
		return Inputs{}, fmt.Errorf("list gateways: %w", err)
	}
	routes, err := c.routeLister.List(labels.Everything())
	if err != nil {
		return Inputs{}, fmt.Errorf("list httproutes: %w", err)
	}
	grants, err := c.grantLister.List(labels.Everything())
	if err != nil {
		return Inputs{}, fmt.Errorf("list referencegrants: %w", err)
	}
	in := Inputs{Classes: classes}
	for _, g := range gws {
		if c.nsSet != nil && !c.nsSet[g.Namespace] {
			continue
		}
		in.Gateways = append(in.Gateways, g)
	}
	for _, r := range routes {
		if c.nsSet != nil && !c.nsSet[r.Namespace] {
			continue
		}
		in.Routes = append(in.Routes, r)
	}
	// ReferenceGrants are matched in the TARGET namespace, so they are never namespace-
	// filtered here (a watched route in NS A may rely on a grant in NS B). The translator
	// indexes them by their own namespace.
	in.Grants = append(in.Grants, grants...)
	return in, nil
}

// reconcile snapshots the listers, renders the Cadishfile, applies it, and writes status.
// On any compile/apply error the last good config stays live. A site that breaks the
// combined compile is dropped alone (graceful degradation), mirroring the Ingress
// controller's salvage so one bad HTTPRoute never freezes all routing.
func (c *Controller) reconcile(ctx context.Context) {
	in, err := c.snapshot()
	if err != nil {
		c.log.Error("gateway: snapshot", "err", err)
		return
	}
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()

	// TLS: validate each referenced kubernetes.io/tls Secret once and thread the gate into
	// the pure translator so HTTPS listeners are programmed only for a usable cert that
	// covers the listener hostname (F10). The validated PEM is injected via the SAME
	// Server.SetDynamicCerts side-channel the Ingress controller uses.
	gate := newTLSSecretGate(c.secLister)
	in.secretUsable = gate.usable
	in.certCovers = gate.covers

	// Service existence gate (GW1): a backendRef to a Service that does not exist is
	// BackendNotFound. The Service lister is the SAME informer-backed read the RBAC already
	// grants (services get/list/watch). A lister error is treated as "absent" so a transient
	// read never falsely resolves a missing backend.
	in.serviceExists = func(ns, name string) bool {
		_, err := c.svcLister.Services(ns).Get(name)
		return err == nil
	}

	res := TranslateResult(in)

	// Inject the BYO certs (every reconcile, before the no-op routing check, so a Secret
	// rotation hot-swaps the served cert even when the routing text is byte-identical).
	c.injectDynamicCerts(res.SecretRefs, gate)

	combined := ingress.CombineSites(base, joinRendered(res.Sites))

	c.mu.Lock()
	c.watched = len(in.Routes)
	c.rejectCount = len(res.Rejects)
	noop := combined == c.lastGood
	c.mu.Unlock()

	loadOpts := config.LoadOptions{
		Kubeconfig:       c.opts.Kubeconfig,
		EndpointResolver: c.resolver,
		AllowNoSites:     true,
	}

	if !noop {
		cfg, cerr := config.LoadStringWithOptions("<gateway>", combined, loadOpts)
		if cerr != nil {
			// Salvage: compile each site alone, apply only those that compile, drop the rest
			// (per-resource graceful degradation). Even the salvaged config may fail to
			// compile (broken base) — then keep lastGood.
			salvaged, salvagedText, dropped := c.salvageCompile(base, res.Sites, loadOpts)
			if salvaged == nil {
				c.log.Error("gateway: generated config did not compile and could not be salvaged; keeping last good", "err", cerr)
				c.setLastErr(cerr)
				c.writeStatus(ctx, in, res)
				return
			}
			c.log.Warn("gateway: dropped non-compiling site(s) and applied the rest", "dropped", len(dropped))
			cfg, combined = salvaged, salvagedText
		}
		if aerr := c.applier.ApplyConfig(cfg); aerr != nil {
			c.log.Error("gateway: ApplyConfig failed; keeping last good", "err", aerr)
			c.setLastErr(aerr)
			c.writeStatus(ctx, in, res)
			return
		}
		c.mu.Lock()
		c.lastGood = combined
		c.lastErr = ""
		c.mu.Unlock()
		c.log.Info("gateway: applied config", "routes", len(in.Routes), "rejects", len(res.Rejects))
	}

	// Status is written every reconcile (even on a no-op routing swap) so a status-only
	// change (e.g. a new GatewayClass) is reflected. Status writing never gates serving.
	c.writeStatus(ctx, in, res)
}

// salvageCompile compiles each rendered site in isolation (base + that one site) and
// returns a config built from ONLY the sites that compile, plus the dropped sites. Returns
// a nil config when even the salvaged config does not compile (broken base globals).
func (c *Controller) salvageCompile(base string, sites []ingress.RenderedSite, opts config.LoadOptions) (*config.Config, string, []ingress.RenderedSite) {
	var good, dropped []ingress.RenderedSite
	for _, s := range sites {
		probe, perr := config.LoadStringWithOptions("<gateway-site>", ingress.CombineSites(base, s.Text), opts)
		if probe != nil {
			_ = probe.Close()
		}
		if perr != nil {
			dropped = append(dropped, s)
			continue
		}
		good = append(good, s)
	}
	salvagedText := ingress.CombineSites(base, joinRendered(good))
	cfg, err := config.LoadStringWithOptions("<gateway>", salvagedText, opts)
	if err != nil {
		if cfg != nil {
			_ = cfg.Close()
		}
		return nil, "", dropped
	}
	return cfg, salvagedText, dropped
}

// joinRendered concatenates the rendered site blocks in order.
func joinRendered(sites []ingress.RenderedSite) string {
	var b strings.Builder
	for _, s := range sites {
		b.WriteString(s.Text)
	}
	return b.String()
}

func (c *Controller) setLastErr(err error) {
	c.mu.Lock()
	c.lastErr = err.Error()
	c.mu.Unlock()
}

// injectDynamicCerts hot-swaps the live TLS manager's BYO dynamic cert set from the
// keypairs the gate validated this reconcile (no Secret re-read). No-op when the applier
// has no TLSInjector (a bare-Applier test fake) — Gateway BYO-Secret TLS is then inactive.
func (c *Controller) injectDynamicCerts(refs []SecretRef, gate *tlsSecretGate) {
	if c.tlsInj == nil {
		return
	}
	var certs []tlsacme.DynamicCert
	for _, ref := range refs {
		if pem, ok := gate.good[ref.Namespace+"/"+ref.Name]; ok {
			certs = append(certs, tlsacme.DynamicCert{Hosts: ref.Hosts, CertPEM: pem.cert, KeyPEM: pem.key})
		}
	}
	if err := c.tlsInj.SetDynamicCerts(certs); err != nil {
		c.log.Error("gateway: inject dynamic TLS certs; keeping previous set", "err", err)
		c.setLastErr(err)
	}
}
