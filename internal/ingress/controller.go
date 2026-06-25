package ingress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/tlsacme"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	listersnetworkingv1 "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	// defaultDebounce coalesces a burst of watch events into one reconcile.
	defaultDebounce = 250 * time.Millisecond
	// isDefaultClassAnnotation marks the cluster's default IngressClass.
	isDefaultClassAnnotation = "ingressclass.kubernetes.io/is-default-class"
	// policyConfigMapKey is the preferred ConfigMap data key holding a policy fragment.
	policyConfigMapKey = "cadishfile"
	// eventComponent is the Source.Component stamped on emitted Events.
	eventComponent = "cadish-ingress"
)

// Applier is the swap seam the controller drives: *server.Server satisfies it via
// Server.ApplyConfig (Task 1).
type Applier interface {
	ApplyConfig(*config.Config) error
}

// TLSInjector is the OPTIONAL typed side-channel for BYO / cert-manager certs from
// Ingress spec.tls Secrets (D55). *server.Server satisfies it via SetDynamicCerts.
// When the Applier also implements it, the controller injects Secret certs on every
// reconcile (a hot swap — no restart); a fake applier that does not implement it
// simply disables BYO-Secret TLS (ACME-via-Cadishfile still works).
type TLSInjector interface {
	SetDynamicCerts([]tlsacme.DynamicCert) error
}

// RedirectInjector is the OPTIONAL side-channel for the per-host HTTP→HTTPS redirect
// opt-in (the `cadi.sh/ssl-redirect` annotation). *server.Server satisfies it via
// SetForceRedirectHosts. In Ingress mode the redirect is TLS-gated (only TLS hosts are
// 301'd); this lets an operator force the redirect on a non-TLS host when TLS is
// terminated upstream (LB/Cloudflare). A fake applier that does not implement it simply
// has no forced hosts.
type RedirectInjector interface {
	SetForceRedirectHosts([]string)
}

// Config tunes the controller.
type Config struct {
	// ClassName is the IngressClass this controller serves (e.g. "cadish").
	ClassName string
	// Namespaces, when non-empty, restricts which namespaces' Ingresses are served
	// (the informers still watch cluster-wide; reconcile filters). Empty ⇒ all.
	Namespaces []string
	// PublishService is "ns/name" of the Service whose address is written back to
	// matched Ingresses' status.loadBalancer (Task 7).
	PublishService string
	// ResyncDebounce is the quiet window after the last watched change before a
	// reconcile runs (default 250ms).
	ResyncDebounce time.Duration
	// Kubeconfig is the explicit kubeconfig path for the resolver client (out-of-cluster).
	Kubeconfig string
	// LeaderElection enables the leader-elected status writer (Task 7). When false the
	// status writer runs unconditionally (single-replica / tests).
	LeaderElection bool
	// LeaderNamespace/LeaderName name the coordination.k8s.io Lease (Task 7).
	LeaderNamespace string
	LeaderName      string
	// Identity uniquely names this replica for leader election (e.g. the pod name).
	Identity string
	// ACMEEmail is the ACME account contact rendered into generated `tls acme`
	// directives for spec.tls hosts without a Secret (optional).
	ACMEEmail string
	// ACMEDomainPolicy is the per-namespace ACME domain allow-list (A2,
	// hostile-multi-tenant hardening). When nil/empty the allow-list is OFF and every
	// watched ACME host is eligible (single-trust-domain default — unchanged). When set,
	// a host whose OWNING namespace is not permitted that domain is excluded from the ACME
	// issuer HostPolicy (no `tls acme` directive) and surfaced as a warning Event.
	ACMEDomainPolicy ACMEDomainPolicy
	// Caps holds the operator-configured per-namespace resource caps (B1,
	// hostile-multi-tenant hardening): max sites/routes per namespace and max policy
	// fragment bytes. The zero value disables every cap (default off = unlimited =
	// unchanged behaviour). Excess is rejected oldest-Ingress-first with a per-Ingress
	// Event; other namespaces are unaffected.
	Caps ResourceCaps
	// SecretLabelSelector, when non-empty, is a Kubernetes label selector applied to the
	// Secret informer's list/watch (C1, hostile-multi-tenant hardening: bound the
	// cluster-wide-Secret blast radius). Only Secrets MATCHING the selector ever enter
	// the controller's cache, so a compromise cannot read every Secret in the cluster —
	// only the so-labelled ones cadish is meant to consume (e.g. cadi.sh/managed=true).
	// Empty (default) ⇒ OFF: every Secret is watched (current behaviour, unchanged).
	// When set, operators MUST label their BYO/cert-manager TLS Secrets accordingly or
	// the controller will not see them (the host then falls through to ACME).
	SecretLabelSelector string
	// ConfigMapLabelSelector mirrors SecretLabelSelector for the ConfigMap informer
	// (cadi.sh/policy fragments). Empty (default) ⇒ OFF (watch all). When set, operators
	// MUST label their policy ConfigMaps or the fragment is treated as not-found.
	ConfigMapLabelSelector string
}

// Controller watches Ingress/IngressClass/Secret/ConfigMap (+ Layer-1 EndpointSlices),
// debounces change events, re-renders the Cadishfile and applies it via Applier. A bad
// render never takes serving down: the last good config stays live and a warning Event
// is emitted.
type Controller struct {
	cs       kubernetes.Interface
	applier  Applier
	tlsInj   TLSInjector      // nil when the applier cannot accept BYO Secret certs
	redirInj RedirectInjector // nil when the applier cannot accept force-redirect hosts
	base     string
	opts     Config
	debounce time.Duration
	log      *slog.Logger

	// resolver is Layer 1's k8s client (shared by the configs the controller applies).
	resolverClient *k8s.Client
	resolver       lb.EndpointResolver

	// informers (a SEPARATE factory from Layer 1's — see k8s.Client.Factory doc).
	// factory holds the cluster-wide Ingress/IngressClass informers. secFactory and
	// cmFactory hold the Secret and ConfigMap informers respectively: when a label
	// selector is configured for that resource (C1) they are SEPARATE factories built
	// with WithTweakListOptions so the selector scopes ONLY that resource's list/watch
	// (the per-factory tweak can't distinguish resource types). When no selector is set
	// for a resource its informer lives on `factory` (secFactory/cmFactory == factory),
	// so the default is one factory and unchanged behaviour.
	factory    informers.SharedInformerFactory
	secFactory informers.SharedInformerFactory
	cmFactory  informers.SharedInformerFactory
	ingLister  listersnetworkingv1.IngressLister
	clsLister  listersnetworkingv1.IngressClassLister
	secLister  corelisters.SecretLister
	cmLister   corelisters.ConfigMapLister

	changes chan struct{}

	// lastPublishErr de-dups the publish-Service read-failure Warn (resolvePublishAddress
	// is called once per status-sync tick by the leader's single status-writer goroutine,
	// so this is touched from that one goroutine only — no lock needed).
	lastPublishErr string

	mu          sync.Mutex
	lastGood    string            // last successfully applied rendered text (no-op swap avoidance)
	lastRejects map[string]Reject // rejects surfaced as Events last reconcile (delta de-dup)
	evSeq       atomic.Uint64     // monotonic Event name suffix (the fake clientset ignores GenerateName)

	// lastCertErrs de-dups present-but-corrupt TLS-Secret warning Events across the
	// cluster-wide reconciles (like lastRejects). Guarded by mu.
	lastCertErrs map[string]string

	// lastClusterEvents de-dups standing RenderFailed/ApplyFailed cluster Events
	// (reason → last message) so a persistent render/apply failure, re-derived every
	// cluster-wide reconcile, emits one Event rather than spamming etcd (FIX 3). Cleared
	// on a fully successful apply so a recurrence re-emits. Guarded by mu.
	lastClusterEvents map[string]string

	// observability snapshot (guarded by mu unless noted).
	watched     int
	rejectCount int
	lastErr     string
	isLeader    atomic.Bool

	nsSet map[string]bool // resolved from opts.Namespaces (nil ⇒ all)
}

// Stats is a point-in-time snapshot of the controller's reconcile state, surfaced for
// observability (the admin dashboard reconcile panel; design §20).
type Stats struct {
	// WatchedIngresses is the number of Ingress objects this controller owns.
	WatchedIngresses int
	// LastAppliedHash is a short hash of the last successfully applied rendered config
	// (changes whenever the live routing changes; "" before the first apply).
	LastAppliedHash string
	// Rejects is the number of per-Ingress rejects in the last reconcile.
	Rejects int
	// LastError is the last render/apply error message ("" when healthy).
	LastError string
	// IsLeader reports whether THIS replica currently writes Ingress status.
	IsLeader bool
}

// Stats returns the current reconcile snapshot (safe for concurrent use).
func (c *Controller) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{
		WatchedIngresses: c.watched,
		LastAppliedHash:  shortHash(c.lastGood),
		Rejects:          c.rejectCount,
		LastError:        c.lastErr,
		IsLeader:         c.isLeader.Load(),
	}
}

// shortHash returns a short hex FNV-1a hash of s ("" for empty).
func shortHash(s string) string {
	if s == "" {
		return ""
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%016x", h.Sum64())
}

// New builds a Controller. cs is the shared clientset (the controller builds its own
// informer factory from it); applier is the live server; base is the globals-only
// Cadishfile (cache/admin/tls defaults — sites come from Ingresses).
func New(cs kubernetes.Interface, applier Applier, base string, opts Config) *Controller {
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
	// Layer 1 resolver client over the SAME clientset (resolves k8s:// pods).
	rc := k8s.NewClientWithInterface(cs, k8s.Options{})
	f := informers.NewSharedInformerFactory(cs, 0)
	log := slog.Default()
	// C1 label-scoping: a Secret/ConfigMap with a configured selector gets its OWN
	// factory built with WithTweakListOptions, so the selector scopes ONLY that
	// resource's list/watch and the informer cache holds ONLY matching objects. An
	// unset (or unparseable) selector falls back to the shared cluster-wide factory →
	// unchanged behaviour.
	secFactory := scopedFactory(cs, opts.SecretLabelSelector, f, "secret", log)
	cmFactory := scopedFactory(cs, opts.ConfigMapLabelSelector, f, "configmap", log)
	c := &Controller{
		cs:                cs,
		applier:           applier,
		base:              base,
		opts:              opts,
		debounce:          d,
		log:               log,
		resolverClient:    rc,
		resolver:          rc.Resolver(),
		factory:           f,
		secFactory:        secFactory,
		cmFactory:         cmFactory,
		ingLister:         f.Networking().V1().Ingresses().Lister(),
		clsLister:         f.Networking().V1().IngressClasses().Lister(),
		secLister:         secFactory.Core().V1().Secrets().Lister(),
		cmLister:          cmFactory.Core().V1().ConfigMaps().Lister(),
		changes:           make(chan struct{}, 1),
		nsSet:             nsSet,
		lastCertErrs:      map[string]string{},
		lastClusterEvents: map[string]string{},
	}
	// The live server can accept BYO/cert-manager Secret certs; a bare-Applier test fake
	// cannot — in that case BYO-Secret TLS is simply inactive (ACME-via-Cadishfile works).
	if inj, ok := applier.(TLSInjector); ok {
		c.tlsInj = inj
	}
	if ri, ok := applier.(RedirectInjector); ok {
		c.redirInj = ri
	}
	return c
}

// ValidateLabelSelector reports whether selector is a parseable Kubernetes label selector
// (empty is valid = off). The CLI calls it so a typo fails loudly at startup rather than
// silently degrading to watch-all.
func ValidateLabelSelector(selector string) error {
	if strings.TrimSpace(selector) == "" {
		return nil
	}
	_, err := labels.Parse(selector)
	return err
}

// scopedFactory returns a SharedInformerFactory whose list/watch is restricted to objects
// matching selector (C1: label-scoped Secret/ConfigMap reads). An empty selector returns
// the shared cluster-wide fallback factory unchanged (default off). An UNPARSEABLE
// selector is treated as off (logged once) rather than failing controller construction —
// the CLI validates selectors up front, so this is a defensive fallback. resource names
// the resource for the log line.
func scopedFactory(cs kubernetes.Interface, selector string, fallback informers.SharedInformerFactory, resource string, log *slog.Logger) informers.SharedInformerFactory {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return fallback // off ⇒ watch all (unchanged behaviour)
	}
	if _, err := labels.Parse(selector); err != nil {
		log.Warn("ingress: invalid label selector; watching all "+resource+"s (label-scoping OFF for it)",
			"selector", selector, "err", err)
		return fallback
	}
	return informers.NewSharedInformerFactoryWithOptions(cs, 0,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = selector }))
}

// certPEM is a validated BYO keypair (raw Secret bytes) carried from the per-reconcile
// validation gate to injection so the keypair is not re-read or re-parsed in between.
// leaf is the parsed leaf certificate, retained so the gate can answer per-host SAN
// coverage (F10) without re-parsing.
type certPEM struct {
	cert, key []byte
	leaf      *x509.Certificate
}

// tlsSecretGate validates each referenced kubernetes.io/tls Secret ONCE per reconcile.
// usable() is the predicate passed to TLSPlan: it parses the Secret's tls.crt/tls.key
// and reports whether it is a usable keypair. A present-but-CORRUPT Secret is reported
// UNUSABLE, so its host falls through to ACME issuance (design D61: "absent OR unusable
// → ACME") rather than being classified BYO and left dark. The validated PEM is cached
// in `good` and threaded to injectDynamicCerts (no re-read, no re-parse for
// classification); `bad` records present-but-unparseable Secrets for warning Events.
type tlsSecretGate struct {
	sec  corelisters.SecretLister
	good map[string]certPEM // ns/name → validated keypair PEM
	bad  map[string]string  // ns/name → parse error (present but corrupt)
}

func newTLSSecretGate(sec corelisters.SecretLister) *tlsSecretGate {
	return &tlsSecretGate{sec: sec, good: map[string]certPEM{}, bad: map[string]string{}}
}

// usable reports whether ns/name is an existing Secret carrying a PARSEABLE TLS keypair.
// It is memoized so a Secret referenced by several Ingresses is parsed only once.
func (g *tlsSecretGate) usable(ns, name string) bool {
	k := ns + "/" + name
	if _, ok := g.good[k]; ok {
		return true
	}
	if _, ok := g.bad[k]; ok {
		return false
	}
	s, err := g.sec.Secrets(ns).Get(name)
	if err != nil || s == nil {
		return false // missing → ACME
	}
	crt, key := s.Data["tls.crt"], s.Data["tls.key"]
	if len(crt) == 0 || len(key) == 0 {
		return false // not a TLS Secret → ACME
	}
	pair, perr := tls.X509KeyPair(crt, key)
	if perr != nil {
		g.bad[k] = perr.Error() // present but corrupt → UNUSABLE → ACME (D61)
		return false
	}
	// Parse the leaf so the gate can answer per-host SAN coverage (F10) without a
	// re-parse. tls.X509KeyPair leaves Leaf nil; the first chain entry is the leaf.
	var leaf *x509.Certificate
	if len(pair.Certificate) > 0 {
		if lf, lerr := x509.ParseCertificate(pair.Certificate[0]); lerr == nil {
			leaf = lf
		}
	}
	g.good[k] = certPEM{cert: crt, key: key, leaf: leaf}
	return true
}

// covers reports whether the Secret ns/name's certificate SANs cover host (F10). It is
// only ever consulted for a Secret the gate already classified usable (its leaf is in
// `good`), so a cache miss (defensively) reports false → the host is treated as not
// covered and falls back to ACME.
func (g *tlsSecretGate) covers(ns, name, host string) bool {
	pem, ok := g.good[ns+"/"+name]
	if !ok {
		return false
	}
	return certCoversHost(pem.leaf, host)
}

// SetLogger overrides the controller's logger (defaults to slog.Default()).
func (c *Controller) SetLogger(l *slog.Logger) {
	if l != nil {
		c.log = l
	}
}

// UpdateBase swaps the base (globals-only) Cadishfile and triggers a reconcile. The
// `cadish ingress` SIGHUP handler calls it after re-reading the base file from disk.
func (c *Controller) UpdateBase(base string) {
	c.mu.Lock()
	c.base = base
	c.mu.Unlock()
	c.poke()
}

// Run starts the informers, waits for cache sync, performs an initial reconcile, then
// reconciles on every debounced change until ctx is cancelled. Returns when ctx ends or
// the caches fail to sync.
func (c *Controller) Run(ctx context.Context) error {
	// Start Layer 1's resolver client (EndpointSlice informer + cache sync) so the
	// applied configs' k8s:// pools resolve pods.
	if err := c.resolverClient.Start(ctx); err != nil {
		return fmt.Errorf("ingress: start resolver: %w", err)
	}

	ingInf := c.factory.Networking().V1().Ingresses().Informer()
	clsInf := c.factory.Networking().V1().IngressClasses().Informer()
	// Secret/ConfigMap informers may live on a SEPARATE, label-scoped factory (C1).
	secInf := c.secFactory.Core().V1().Secrets().Informer()
	cmInf := c.cmFactory.Core().V1().ConfigMaps().Informer()
	h := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { c.poke() },
		UpdateFunc: func(any, any) { c.poke() },
		DeleteFunc: func(any) { c.poke() },
	}
	for _, inf := range []cache.SharedIndexInformer{ingInf, clsInf, secInf, cmInf} {
		_, _ = inf.AddEventHandler(h)
	}

	// Start every DISTINCT factory exactly once (secFactory/cmFactory == factory when no
	// selector is configured; a SharedInformerFactory.Start is idempotent but de-duping
	// keeps it clear).
	for _, fct := range distinctFactories(c.factory, c.secFactory, c.cmFactory) {
		fct.Start(ctx.Done())
	}
	if !cache.WaitForCacheSync(ctx.Done(),
		ingInf.HasSynced, clsInf.HasSynced, secInf.HasSynced, cmInf.HasSynced) {
		return fmt.Errorf("ingress: informer caches failed to sync")
	}

	// The leader-elected status writer runs ALONGSIDE serving and never gates it
	// (design §14 L2-5). It is a no-op when no publish service is configured.
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
			timer.Reset(c.debounce) // coalesce bursts: each change pushes the deadline out
		case <-timer.C:
			c.reconcile(ctx)
		}
	}
}

// distinctFactories returns the unique factories among those passed (secFactory/cmFactory
// collapse to factory when no label selector is configured), so each is Start()ed once.
func distinctFactories(fs ...informers.SharedInformerFactory) []informers.SharedInformerFactory {
	var out []informers.SharedInformerFactory
	for _, f := range fs {
		seen := false
		for _, g := range out {
			if g == f {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, f)
		}
	}
	return out
}

// poke signals a pending change (non-blocking — the channel is a 1-slot coalescer).
func (c *Controller) poke() {
	select {
	case c.changes <- struct{}{}:
	default:
	}
}

// reconcile snapshots the listers, renders the Cadishfile, and applies it. On any
// compile/apply error the last good config stays live and a warning Event is emitted;
// per-Ingress translation rejects each emit a warning Event.
func (c *Controller) reconcile(ctx context.Context) {
	ings, err := c.ingLister.List(labels.Everything())
	if err != nil {
		c.log.Error("ingress: list ingresses", "err", err)
		return
	}
	c.mu.Lock()
	base := c.base
	c.mu.Unlock()
	// Namespace filter + class match.
	isDefault := c.weAreDefaultClass()
	matched := make([]*networkingv1.Ingress, 0, len(ings))
	for _, ing := range ings {
		if c.nsSet != nil && !c.nsSet[ing.Namespace] {
			continue
		}
		if Matches(ing, c.opts.ClassName, isDefault) {
			matched = append(matched, ing)
		}
	}
	sortIngresses(matched)

	// Project spec.tls (Secrets-if-present-else-ACME, design §19): a host whose
	// kubernetes.io/tls Secret EXISTS AND PARSES is served a BYO cert via the typed
	// side-channel (injectDynamicCerts below); a host whose Secret is absent OR
	// present-but-corrupt gets a `tls acme` directive in the rendered Cadishfile
	// (→ cfg.TLS → bounded ACME HostPolicy) so it is never left dark. The gate validates
	// each Secret once and threads the parsed PEM to injection. Injection runs on EVERY
	// reconcile, before the no-op routing check, so a Secret rotation hot-swaps the served
	// cert even when the rendered routing is byte-identical.
	gate := newTLSSecretGate(c.secLister)
	acmeHosts, secretRefs, tlsRejects := TLSPlan(matched, gate.usable, gate.covers)
	// Per-namespace ACME domain allow-list (A2): when configured, an ACME host whose
	// OWNING namespace is not permitted that domain is excluded from the issuer HostPolicy
	// (no `tls acme` directive is rendered for it) and surfaced as a reject Event. OFF by
	// default (nil policy → acmeHosts unchanged), preserving the single-trust-domain
	// default. Ownership uses the SAME first-claim helper routing + TLS use, so the
	// allow-list is evaluated against the namespace that actually owns the host.
	if len(c.opts.ACMEDomainPolicy) > 0 {
		var acmeRejects []Reject
		acmeHosts, acmeRejects = FilterACMEDomains(acmeHosts, routingHostOwners(matched), c.opts.ACMEDomainPolicy)
		tlsRejects = append(tlsRejects, acmeRejects...)
	}
	// NOTE: injectDynamicCerts COMMITS the dynamic-cert pointer (SetDynamicCerts) here,
	// BEFORE the routing/ACME-policy apply below. The two are not transactional, so for a
	// brief window the new BYO certs are live against the old routing/ACME HostPolicy
	// (and vice-versa on a failed apply). This is eventually-consistent BY DESIGN: certs
	// are keyed by SNI host independently of routing, and any skew self-heals on the next
	// reconcile (injection runs every reconcile). See docs/ingress-controller.md.
	injErr := c.injectDynamicCerts(secretRefs, gate)
	c.emitCertErrEvents(gate.bad)
	// Opt-in HTTP→HTTPS redirect for non-TLS hosts via `cadi.sh/ssl-redirect` (every
	// reconcile; an empty set clears prior opt-ins). Independent of routing/cert apply.
	c.injectForceRedirect(matched)

	policies := c.gatherPolicies(matched)
	in := Inputs{
		Ingresses:    matched,
		Policies:     policies,
		ClassName:    c.opts.ClassName,
		DefaultClass: isDefault,
		ACMEHosts:    toSet(acmeHosts),
		ACMEEmail:    c.opts.ACMEEmail,
		Caps:         c.opts.Caps,
	}
	sites, rejects := TranslateSites(in)
	// Cross-namespace TLS-ownership rejects (FIX 2) are surfaced as Events alongside the
	// translator's per-Ingress rejects.
	rejects = append(rejects, tlsRejects...)
	combined := Combine(base, joinSites(sites))

	c.mu.Lock()
	c.watched = len(matched)
	c.mu.Unlock()

	c.mu.Lock()
	noop := combined == c.lastGood
	c.mu.Unlock()
	if noop {
		// Routing is unchanged (already-applied lastGood has no error). Surface NEW rejects
		// as warning Events even on a byte-identical render (a duplicate-path conflict
		// produces the SAME text, older wins, yet must be reported); the delta-dedup keeps a
		// standing reject from re-emitting. A dynamic-cert injection failure this round must
		// still surface (FIX 3): don't let a no-op routing reconcile hide it.
		c.surfaceRejects(rejects)
		c.recordErr(injErr)
		return
	}

	loadOpts := config.LoadOptions{
		Kubeconfig:       c.opts.Kubeconfig,
		EndpointResolver: c.resolver,
		AllowNoSites:     true, // no matched Ingresses (or all sites dropped) ⇒ still loads
	}
	cfg, err := config.LoadStringWithOptions("<ingress>", combined, loadOpts)
	if err != nil {
		// The COMBINED compile failed. Rather than freeze ALL routing on lastGood (FIX 3),
		// salvage: compile each site alone and apply only the ones that compile, dropping
		// the offending site(s) with a per-Ingress Event. A site can pass isolated fragment
		// validation yet collide in the combined config (e.g. a policy fragment redefining a
		// generated matcher/upstream name).
		salvaged, salvagedText, dropped := c.salvageCompile(base, sites, loadOpts)
		rejects = append(rejects, dropRejects(dropped)...)
		if salvaged == nil {
			// Even the salvaged config will not compile (e.g. the base globals are broken):
			// keep lastGood and report the original error (deduped so it doesn't spam).
			c.log.Error("ingress: generated config did not compile and could not be salvaged; keeping last good", "err", err)
			c.surfaceRejects(rejects)
			c.setLastErr(err)
			c.emitClusterEventDeduped(corev1.EventTypeWarning, "RenderFailed",
				fmt.Sprintf("generated Cadishfile did not compile: %v", err))
			return
		}
		c.log.Warn("ingress: dropped non-compiling site(s) and applied the rest", "dropped", len(dropped))
		cfg, combined = salvaged, salvagedText
	}

	// Surface rejects (now including any salvage drops) BEFORE applying, deduped.
	c.surfaceRejects(rejects)

	if err := c.applier.ApplyConfig(cfg); err != nil {
		c.log.Error("ingress: ApplyConfig failed; keeping last good", "err", err)
		c.setLastErr(err)
		c.emitClusterEventDeduped(corev1.EventTypeWarning, "ApplyFailed",
			fmt.Sprintf("applying generated config failed: %v", err))
		// ApplyConfig closes cfg on failure (Task 1 contract).
		return
	}

	// Routing applied cleanly. Surface a dynamic-cert injection error if there was one
	// (FIX 3) — a successful routing apply must not clear/mask it — otherwise clear. A
	// clean apply also clears the cluster-event dedup so a future failure re-emits.
	c.mu.Lock()
	c.lastGood = combined
	if injErr != nil {
		c.lastErr = injErr.Error()
	} else {
		c.lastErr = ""
	}
	c.lastClusterEvents = map[string]string{}
	c.mu.Unlock()
	c.log.Info("ingress: applied config", "ingresses", len(matched), "rejects", len(rejects))
}

// joinSites concatenates the rendered site blocks in order (their concatenation is the
// translator's full generated text).
func joinSites(sites []RenderedSite) string {
	var b strings.Builder
	for _, s := range sites {
		b.WriteString(s.Text)
	}
	return b.String()
}

// surfaceRejects records the reject count for Stats and emits delta-deduped warning
// Events for the current reject set. Exactly one call per reconcile path (emitRejectEvents
// replaces the standing-reject set).
func (c *Controller) surfaceRejects(rejects []Reject) {
	c.mu.Lock()
	c.rejectCount = len(rejects)
	c.mu.Unlock()
	c.emitRejectEvents(rejects)
}

// salvageCompile is the FIX-3 graceful-degradation fallback used when the full combined
// config fails to compile: it compiles each rendered site in isolation (base + that one
// site) and returns a config built from ONLY the sites that compile, plus the sites it
// dropped. A site that breaks the combined compile (e.g. a policy-fragment name collision
// with a generated matcher/upstream) is dropped ALONE so the rest still serve. Returns a
// nil config when even the salvaged config does not compile (e.g. broken base globals) —
// the caller then keeps lastGood.
func (c *Controller) salvageCompile(base string, sites []RenderedSite, opts config.LoadOptions) (*config.Config, string, []RenderedSite) {
	var good, dropped []RenderedSite
	for _, s := range sites {
		probe, perr := config.LoadStringWithOptions("<ingress-site>", Combine(base, s.Text), opts)
		if probe != nil {
			_ = probe.Close()
		}
		if perr != nil {
			dropped = append(dropped, s)
			continue
		}
		good = append(good, s)
	}
	salvagedText := Combine(base, joinSites(good))
	cfg, err := config.LoadStringWithOptions("<ingress>", salvagedText, opts)
	if err != nil {
		if cfg != nil {
			_ = cfg.Close()
		}
		return nil, "", dropped
	}
	return cfg, salvagedText, dropped
}

// dropRejects turns salvage-dropped sites into per-Ingress Rejects (one per contributing
// Ingress; falls back to the host name when no Ingress is attributed).
func dropRejects(dropped []RenderedSite) []Reject {
	var out []Reject
	for _, s := range dropped {
		reason := fmt.Sprintf("site %q dropped: it broke the combined config compile (e.g. a policy-fragment name collision with a generated matcher/upstream); other sites still serve", s.Host)
		if len(s.Ingresses) == 0 {
			out = append(out, Reject{Ingress: s.Host, Reason: reason})
			continue
		}
		for _, k := range s.Ingresses {
			out = append(out, Reject{Ingress: k, Reason: reason})
		}
	}
	return out
}

// emitClusterEventDeduped emits a cluster-scoped Event only when (reason → message)
// differs from the last one emitted for that reason, so a standing RenderFailed/
// ApplyFailed (re-derived every reconcile) does not spam etcd (FIX 3).
func (c *Controller) emitClusterEventDeduped(etype, reason, msg string) {
	c.mu.Lock()
	if c.lastClusterEvents[reason] == msg {
		c.mu.Unlock()
		return
	}
	c.lastClusterEvents[reason] = msg
	c.mu.Unlock()
	c.emitClusterEvent(etype, reason, msg)
}

// setLastErr records the most recent render/apply error for Stats.
func (c *Controller) setLastErr(err error) {
	c.mu.Lock()
	c.lastErr = err.Error()
	c.mu.Unlock()
}

// recordErr sets lastErr from err (clearing it when err is nil). Used to surface a
// dynamic-cert injection error on a no-op/clean reconcile (FIX 3).
func (c *Controller) recordErr(err error) {
	c.mu.Lock()
	if err != nil {
		c.lastErr = err.Error()
	} else {
		c.lastErr = ""
	}
	c.mu.Unlock()
}

// toSet turns a host slice into a membership set for the translator's ACMEHosts.
func toSet(hosts []string) map[string]bool {
	if len(hosts) == 0 {
		return nil
	}
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		m[h] = true
	}
	return m
}

// injectDynamicCerts hot-swaps the live TLS manager's BYO/cert-manager dynamic cert set
// (D55) from the keypairs the gate already validated this reconcile — no Secret re-read
// and no re-parse for classification. Every ref came from gate.usable()==true, so its
// PEM is in gate.good. Returns the injection error (nil on success) so reconcile can
// surface it in Stats even when the routing apply succeeds (FIX 3). A no-op (nil) when
// injectForceRedirect collects the hosts of every matched Ingress carrying
// `cadi.sh/ssl-redirect: "true"` and hands them to the redirect side-channel so they
// are 301'd to HTTPS even without local TLS. Runs every reconcile (an empty set clears
// prior opt-ins). No-op when the applier has no RedirectInjector.
func (c *Controller) injectForceRedirect(matched []*networkingv1.Ingress) {
	if c.redirInj == nil {
		return
	}
	seen := map[string]struct{}{}
	var hosts []string
	for _, ing := range matched {
		if !strings.EqualFold(strings.TrimSpace(ing.Annotations[sslRedirectAnnotation]), "true") {
			continue
		}
		for ri := range ing.Spec.Rules {
			h := strings.ToLower(strings.TrimSpace(ing.Spec.Rules[ri].Host))
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	c.redirInj.SetForceRedirectHosts(hosts)
}

// the applier cannot accept dynamic certs (a bare-Applier test fake).
func (c *Controller) injectDynamicCerts(refs []SecretRef, gate *tlsSecretGate) error {
	if c.tlsInj == nil {
		return nil
	}
	var certs []tlsacme.DynamicCert
	for _, ref := range refs {
		if pem, ok := gate.good[ref.Namespace+"/"+ref.Name]; ok {
			certs = append(certs, tlsacme.DynamicCert{Hosts: ref.Hosts, CertPEM: pem.cert, KeyPEM: pem.key})
		}
	}
	if err := c.tlsInj.SetDynamicCerts(certs); err != nil {
		// Defense-in-depth: the gate pre-validated every PEM, so this should not happen;
		// the manager is also transactional (old set kept on error).
		c.log.Error("ingress: inject dynamic TLS certs; keeping previous set", "err", err)
		return err
	}
	return nil
}

// emitCertErrEvents emits a warning Event for each NEWLY corrupt TLS Secret and forgets
// ones that recovered, mirroring emitRejectEvents' delta de-dup so a standing corrupt
// Secret (re-derived on every cluster-wide reconcile) does not spam etcd.
func (c *Controller) emitCertErrEvents(badNow map[string]string) {
	c.mu.Lock()
	prev := c.lastCertErrs
	c.lastCertErrs = badNow
	c.mu.Unlock()
	for k, reason := range badNow {
		if old, seen := prev[k]; seen && old == reason {
			continue // standing bad Secret already surfaced
		}
		ns, name := splitNN(k)
		c.emitSecretEvent(ns, name, "BadTLSSecret",
			fmt.Sprintf("Secret %s is not a usable kubernetes.io/tls keypair: %s (falling back to ACME issuance for its hosts)", k, reason))
	}
}

// emitSecretEvent creates a warning Event referencing the named Secret (best-effort).
func (c *Controller) emitSecretEvent(ns, name, reason, msg string) {
	if ns == "" {
		ns = metav1.NamespaceDefault
	}
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("cadish-ingress-secret-%s.%d", name, c.evSeq.Add(1)),
			Namespace: ns,
		},
		InvolvedObject: corev1.ObjectReference{Kind: "Secret", Namespace: ns, Name: name, APIVersion: "v1"},
		Reason:         reason,
		Message:        msg,
		Type:           corev1.EventTypeWarning,
		Source:         corev1.EventSource{Component: eventComponent},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
		Count:          1,
	}
	c.createEvent(ns, ev, "ingress: emit secret event")
}

// weAreDefaultClass reports whether this controller's IngressClass is marked the
// cluster default (so classless Ingresses are ours).
func (c *Controller) weAreDefaultClass() bool {
	if c.opts.ClassName == "" {
		return false
	}
	cls, err := c.clsLister.Get(c.opts.ClassName)
	if err != nil || cls == nil {
		return false
	}
	return cls.Annotations[isDefaultClassAnnotation] == "true"
}

// gatherPolicies resolves each matched Ingress's cadi.sh/policy ConfigMap into its
// fragment text, keyed "ns/name".
func (c *Controller) gatherPolicies(ings []*networkingv1.Ingress) map[string]string {
	var out map[string]string
	for _, ing := range ings {
		ref := ing.Annotations[policyAnnotation]
		if ref == "" {
			continue
		}
		ns, name := splitNN(ref)
		// Confine the ref to the Ingress's OWN namespace: a cross-namespace (or
		// malformed) ref must never let an Ingress READ a policy ConfigMap from another
		// namespace. Leave it unresolved here — the translator gates host→policy binding
		// on the same rule and emits a reject. (We must NOT cache "" for such a ref:
		// another Ingress may legitimately reference the same "ns/name" from within ns.)
		if ns == "" || name == "" || ns != ing.Namespace {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		if _, done := out[ref]; done {
			continue
		}
		cm, err := c.cmLister.ConfigMaps(ns).Get(name)
		if err != nil || cm == nil {
			out[ref] = "" // missing → fragment empty (nothing layered)
			continue
		}
		out[ref] = fragmentFromConfigMap(cm)
	}
	return out
}

// fragmentFromConfigMap extracts the policy fragment: the "cadishfile" key if present,
// else the sole value, else all values concatenated in key order (deterministic).
func fragmentFromConfigMap(cm *corev1.ConfigMap) string {
	if v, ok := cm.Data[policyConfigMapKey]; ok {
		return v
	}
	if len(cm.Data) == 1 {
		for _, v := range cm.Data {
			return v
		}
	}
	keys := make([]string, 0, len(cm.Data))
	for k := range cm.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(cm.Data[k])
		b.WriteString("\n")
	}
	return b.String()
}

// sortIngresses orders by creationTimestamp then namespace/name (oldest-wins merge).
func sortIngresses(ings []*networkingv1.Ingress) {
	sort.SliceStable(ings, func(i, j int) bool {
		ti, tj := ings[i].CreationTimestamp, ings[j].CreationTimestamp
		if !ti.Equal(&tj) {
			return ti.Before(&tj)
		}
		return key(ings[i]) < key(ings[j])
	})
}

func splitNN(s string) (ns, name string) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// createEvent writes an Event best-effort. An AlreadyExists is NOT a failure:
// Event names are derived deterministically per reject/secret/failure, so when
// two controller replicas reconcile the same rejected object in the same window
// they race to create the identically-named Event — the loser's create returns
// AlreadyExists. The Event already exists (the winner wrote it), so the loser
// treats it as a no-op rather than logging a WARN that reads like a real
// failure (P4).
func (c *Controller) createEvent(ns string, ev *corev1.Event, logCtx string) {
	if _, err := c.cs.CoreV1().Events(ns).Create(context.Background(), ev, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return // another replica already emitted this Event; not an error
		}
		c.log.Warn(logCtx, "err", err)
	}
}

// emitEvent creates a Kubernetes Event referencing the named Ingress (best-effort).
func (c *Controller) emitEvent(ns, name, etype, reason, msg string) {
	if ns == "" {
		ns = "default"
	}
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("cadish-ingress-%s.%d", name, c.evSeq.Add(1)),
			Namespace: ns,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "Ingress",
			Namespace:  ns,
			Name:       name,
			APIVersion: "networking.k8s.io/v1",
		},
		Reason:         reason,
		Message:        msg,
		Type:           etype,
		Source:         corev1.EventSource{Component: eventComponent},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
		Count:          1,
	}
	c.createEvent(ns, ev, "ingress: emit event")
}

// emitRejectEvents emits a warning Event for each reject that is NEW since the previous
// reconcile and forgets rejects that no longer stand. Without this, a persistent reject
// (re-derived on every cluster-wide reconcile) would create a fresh uniquely-named Event
// each time and spam etcd indefinitely.
func (c *Controller) emitRejectEvents(rejects []Reject) {
	current := make(map[string]Reject, len(rejects))
	for _, r := range rejects {
		current[rejectKey(r)] = r
	}
	c.mu.Lock()
	prev := c.lastRejects
	c.lastRejects = current
	c.mu.Unlock()
	for k, r := range current {
		if _, seen := prev[k]; seen {
			continue // standing reject already surfaced; do not re-emit
		}
		ns, name := splitNN(r.Ingress)
		c.emitEvent(ns, name, corev1.EventTypeWarning, "Rejected", r.Reason)
	}
}

// rejectKey identifies a reject by its (Ingress, Reason) so an unchanged standing reject
// compares equal across reconciles.
func rejectKey(r Reject) string { return r.Ingress + "\x00" + r.Reason }

// emitClusterEvent emits a controller-scoped Event for render/apply failures. It is NOT
// tied to a specific Ingress; it references the controller's IngressClass (a real,
// owned, cluster-scoped object) rather than a fabricated Ingress name that would dangle.
func (c *Controller) emitClusterEvent(etype, reason, msg string) {
	ns := metav1.NamespaceDefault
	involved := corev1.ObjectReference{}
	if c.opts.ClassName != "" {
		involved = corev1.ObjectReference{
			Kind:       "IngressClass",
			Name:       c.opts.ClassName,
			APIVersion: "networking.k8s.io/v1",
		}
	}
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("cadish-ingress-controller.%d", c.evSeq.Add(1)),
			Namespace: ns,
		},
		InvolvedObject: involved,
		Reason:         reason,
		Message:        msg,
		Type:           etype,
		Source:         corev1.EventSource{Component: eventComponent},
		FirstTimestamp: metav1.Now(),
		LastTimestamp:  metav1.Now(),
		Count:          1,
	}
	c.createEvent(ns, ev, "ingress: emit cluster event")
}
