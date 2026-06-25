package ingress

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	// statusSyncInterval re-publishes status.loadBalancer periodically (a backstop for a
	// changed publish address; reconcile-driven syncs cover the common case).
	statusSyncInterval = 30 * time.Second

	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

// statusWriter publishes a load-balancer address onto the status.loadBalancer of every
// Ingress this controller owns. ONLY the leader runs it (design §14 L2-5); serving is
// never gated by leadership.
type statusWriter struct {
	cs        kubernetes.Interface
	className string
	address   string          // the published IP or hostname
	nsSet     map[string]bool // served namespaces (nil ⇒ all); mirrors the controller's scope
}

func newStatusWriter(cs kubernetes.Interface, className, address string, nsSet map[string]bool) *statusWriter {
	return &statusWriter{cs: cs, className: className, address: address, nsSet: nsSet}
}

// lbIngress builds the status entry for the publish address (IP vs hostname).
func (w *statusWriter) lbIngress() []networkingv1.IngressLoadBalancerIngress {
	if w.address == "" {
		return nil
	}
	if net.ParseIP(w.address) != nil {
		return []networkingv1.IngressLoadBalancerIngress{{IP: w.address}}
	}
	return []networkingv1.IngressLoadBalancerIngress{{Hostname: w.address}}
}

// sync writes the publish address onto every matched Ingress's status.loadBalancer
// (idempotent: an Ingress already carrying the desired status is skipped). It is a
// best-effort, per-object operation — one failing UpdateStatus does not abort the rest.
func (w *statusWriter) sync(ctx context.Context) error {
	if w.address == "" {
		return nil
	}
	list, err := w.cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("ingress status: list: %w", err)
	}
	isDefault := w.weAreDefaultClass(ctx)
	desired := w.lbIngress()
	var firstErr error
	for i := range list.Items {
		ing := &list.Items[i]
		// Honor the controller's -namespace scoping: never write status onto an
		// Ingress in a namespace this controller does not serve (the informers list
		// cluster-wide, so Matches alone is not enough).
		if w.nsSet != nil && !w.nsSet[ing.Namespace] {
			continue
		}
		if !Matches(ing, w.className, isDefault) {
			continue
		}
		if reflect.DeepEqual(ing.Status.LoadBalancer.Ingress, desired) {
			continue // already up to date
		}
		ing.Status.LoadBalancer.Ingress = desired
		if _, err := w.cs.NetworkingV1().Ingresses(ing.Namespace).UpdateStatus(ctx, ing, metav1.UpdateOptions{}); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// weAreDefaultClass reports whether className's IngressClass is the cluster default.
func (w *statusWriter) weAreDefaultClass(ctx context.Context) bool {
	if w.className == "" {
		return false
	}
	cls, err := w.cs.NetworkingV1().IngressClasses().Get(ctx, w.className, metav1.GetOptions{})
	if err != nil || cls == nil {
		return false
	}
	return cls.Annotations[isDefaultClassAnnotation] == "true"
}

// runStatusWriter runs the leader-elected status writer alongside serving. Leadership
// gates ONLY whether this replica WRITES status; the data plane runs regardless (every
// replica serves). With LeaderElection disabled (single replica / tests) the writer
// runs unconditionally. Returns immediately when there is no publish service.
func (c *Controller) runStatusWriter(ctx context.Context) {
	if c.opts.PublishService == "" {
		return // nothing to publish (status writing disabled)
	}

	run := func(ctx context.Context) {
		t := time.NewTicker(statusSyncInterval)
		defer t.Stop()
		c.syncStatusOnce(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.syncStatusOnce(ctx)
			}
		}
	}

	if !c.opts.LeaderElection {
		c.isLeader.Store(true) // single replica / tests: this replica writes status
		run(ctx)
		return
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      c.leaseName(),
			Namespace: c.leaseNamespace(),
		},
		Client: c.cs.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: c.identity(),
		},
	}
	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   leaseDuration,
		RenewDeadline:   renewDeadline,
		RetryPeriod:     retryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				c.isLeader.Store(true)
				c.log.Info("ingress: became status-writer leader", "identity", c.identity())
				run(ctx)
			},
			OnStoppedLeading: func() {
				c.isLeader.Store(false)
				c.log.Info("ingress: lost status-writer leadership", "identity", c.identity())
			},
		},
	})
}

// syncStatusOnce resolves the current publish address and writes it to owned Ingresses.
func (c *Controller) syncStatusOnce(ctx context.Context) {
	addr := c.resolvePublishAddress(ctx)
	if addr == "" {
		return // address not yet known (e.g. LB IP not provisioned)
	}
	w := newStatusWriter(c.cs, c.opts.ClassName, addr, c.nsSet)
	if err := w.sync(ctx); err != nil {
		c.log.Warn("ingress: status sync", "err", err)
	}
}

// resolvePublishAddress resolves the publish Service's EXTERNALLY reachable address:
// its LoadBalancer ingress (IP or hostname) when provisioned. It deliberately does NOT
// fall back to the Service's ClusterIP — that is cluster-internal and not reachable by
// the clients that read status.loadBalancer, so advertising it would be misleading.
// Returns "" when no real load-balancer address exists yet (the status write is then
// skipped until one is provisioned).
func (c *Controller) resolvePublishAddress(ctx context.Context) string {
	ns, name := splitNN(c.opts.PublishService)
	if ns == "" || name == "" {
		return ""
	}
	svc, err := c.cs.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// Distinguish an operator-actionable failure (RBAC denial, wrong name, API
		// error) from the legitimate not-yet-provisioned case below: a GET error means
		// status.loadBalancer will NEVER populate. Warn once per distinct error so a
		// misconfigured deploy is visible, without spamming every sync tick.
		if msg := err.Error(); msg != c.lastPublishErr {
			c.lastPublishErr = msg
			c.log.Warn("ingress: cannot read publish-service for status (check RBAC `services` get + the -publish-service name)",
				"service", c.opts.PublishService, "err", err)
		}
		return ""
	}
	c.lastPublishErr = ""
	if svc == nil {
		return ""
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			return ing.IP
		}
		if ing.Hostname != "" {
			return ing.Hostname
		}
	}
	return ""
}

func (c *Controller) leaseName() string {
	if c.opts.LeaderName != "" {
		return c.opts.LeaderName
	}
	return "cadish-ingress-leader"
}

func (c *Controller) leaseNamespace() string {
	if c.opts.LeaderNamespace != "" {
		return c.opts.LeaderNamespace
	}
	return metav1.NamespaceDefault
}

func (c *Controller) identity() string {
	if c.opts.Identity != "" {
		return c.opts.Identity
	}
	return "cadish-ingress"
}
