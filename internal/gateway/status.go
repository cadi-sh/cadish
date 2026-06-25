package gateway

import (
	"context"
	"fmt"
	"sort"
	"time"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// (status writer below)

const (
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

// runStatusWriter runs the leader-elected status writer alongside serving. Leadership
// gates ONLY whether this replica WRITES status; the data plane runs regardless. With
// LeaderElection disabled (single replica / tests) the writer runs unconditionally. The
// writer itself runs INSIDE reconcile (writeStatus); this goroutine only manages the
// leader flag so writeStatus is a no-op on followers.
func (c *Controller) runStatusWriter(ctx context.Context) {
	if !c.opts.LeaderElection {
		c.isLeader.Store(true)
		return
	}
	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Name: c.leaseName(), Namespace: c.leaseNamespace()},
		Client:     c.cs.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: c.identity()},
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
				c.log.Info("gateway: became status-writer leader", "identity", c.identity())
				<-ctx.Done()
			},
			OnStoppedLeading: func() {
				c.isLeader.Store(false)
				c.log.Info("gateway: lost status-writer leadership", "identity", c.identity())
			},
		},
	})
}

// writeStatus publishes status conditions on the owned GatewayClasses/Gateways and the
// attached HTTPRoutes, from the translation Result. ONLY the leader writes (serving is
// never gated). Best-effort and idempotent: an object already carrying the desired
// conditions is skipped, and one failing update does not abort the rest.
func (c *Controller) writeStatus(ctx context.Context, in Inputs, res Result) {
	if !c.isLeader.Load() {
		return
	}
	c.writeClassStatus(ctx, in)
	c.writeGatewayStatus(ctx, in, res)
	c.writeRouteStatus(ctx, in, res)
}

// writeClassStatus sets Accepted=True on every GatewayClass this controller owns.
func (c *Controller) writeClassStatus(ctx context.Context, in Inputs) {
	gen := func(o metav1.Object) int64 { return o.GetGeneration() }
	for _, gc := range in.Classes {
		if !OwnsClass(gc) {
			continue // not ours; another controller writes its status
		}
		cur := gc.DeepCopy()
		cond := metav1.Condition{
			Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gatewayv1.GatewayClassReasonAccepted),
			Message:            "GatewayClass accepted by cadish",
			ObservedGeneration: gen(cur),
		}
		if !apimeta.SetStatusCondition(&cur.Status.Conditions, cond) {
			continue // already up to date
		}
		if _, err := c.gwcs.GatewayV1().GatewayClasses().UpdateStatus(ctx, cur, metav1.UpdateOptions{}); err != nil {
			c.log.Warn("gateway: update GatewayClass status", "class", gc.Name, "err", err)
		}
	}
}

// writeGatewayStatus sets Accepted + Programmed on owned Gateways and per-listener status
// (attachedRoutes + Accepted/Programmed/ResolvedRefs). A Gateway whose class we do not own
// is skipped.
func (c *Controller) writeGatewayStatus(ctx context.Context, in Inputs, res Result) {
	ownedClass := map[string]bool{}
	for _, gc := range in.Classes {
		if OwnsClass(gc) {
			ownedClass[gc.Name] = true
		}
	}
	for _, gw := range in.Gateways {
		if !ownedClass[string(gw.Spec.GatewayClassName)] {
			continue
		}
		gwKey := gw.Namespace + "/" + gw.Name
		cur := gw.DeepCopy()
		gen := cur.Generation
		programmed := res.ProgrammedGateways[gwKey]

		accStatus := metav1.ConditionTrue
		accReason := string(gatewayv1.GatewayReasonAccepted)
		accMsg := "Gateway accepted by cadish"
		progStatus := metav1.ConditionTrue
		progReason := string(gatewayv1.GatewayReasonProgrammed)
		progMsg := "Gateway HTTP listeners programmed"
		if !programmed {
			// No programmable listener (every listener failed to program — e.g. HTTPS
			// listeners with missing/mismatched certs and no HTTP listener).
			progStatus = metav1.ConditionFalse
			progReason = string(gatewayv1.GatewayReasonListenersNotValid)
			progMsg = "Gateway has no programmable listener (check per-listener conditions)"
		}
		changed := apimeta.SetStatusCondition(&cur.Status.Conditions, metav1.Condition{
			Type: string(gatewayv1.GatewayConditionAccepted), Status: accStatus,
			Reason: accReason, Message: accMsg, ObservedGeneration: gen,
		})
		changed = apimeta.SetStatusCondition(&cur.Status.Conditions, metav1.Condition{
			Type: string(gatewayv1.GatewayConditionProgrammed), Status: progStatus,
			Reason: progReason, Message: progMsg, ObservedGeneration: gen,
		}) || changed

		// Per-listener status: an HTTP listener is Accepted+Programmed+ResolvedRefs; an
		// HTTPS listener whose certificateRefs resolved (a usable cert covering its
		// hostname) is Programmed too; an HTTPS/TLS listener that did NOT program (missing/
		// mismatched cert, unpermitted cross-ns ref, unsupported mode/protocol) reports
		// Programmed=False (and ResolvedRefs=False for a cert-ref failure) with the reason.
		var lstatuses []gatewayv1.ListenerStatus
		for li := range gw.Spec.Listeners {
			l := &gw.Spec.Listeners[li]
			lkey := gwKey + "\x00" + string(l.Name)
			ls := gatewayv1.ListenerStatus{
				Name:           l.Name,
				SupportedKinds: []gatewayv1.RouteGroupKind{{Kind: "HTTPRoute"}},
			}
			switch {
			case res.ProgrammedListeners[lkey]:
				// Per-listener count (GW2): the number of routes actually attached to THIS
				// listener (honoring its hostname / a route's sectionName), not the per-Gateway
				// total which over-counts hostname-scoped listeners.
				ls.AttachedRoutes = int32(res.AttachedRoutesByListener[lkey])
				setCond(&ls.Conditions, gatewayv1.ListenerConditionAccepted, metav1.ConditionTrue, gatewayv1.ListenerReasonAccepted, "Listener accepted", gen)
				setCond(&ls.Conditions, gatewayv1.ListenerConditionProgrammed, metav1.ConditionTrue, gatewayv1.ListenerReasonProgrammed, "Listener programmed", gen)
				setCond(&ls.Conditions, gatewayv1.ListenerConditionResolvedRefs, metav1.ConditionTrue, gatewayv1.ListenerReasonResolvedRefs, "Listener refs resolved", gen)
			default:
				reason := res.ListenerRejects[lkey]
				switch {
				case l.Protocol != gatewayv1.HTTPProtocolType && l.Protocol != gatewayv1.HTTPSProtocolType:
					// An UNSUPPORTED protocol (TLS passthrough, TCP, …) is NOT accepted — per
					// GW-API the listener is rejected with UnsupportedProtocol, not Accepted=True.
					if reason == "" {
						reason = fmt.Sprintf("protocol %s is not served in this release", l.Protocol)
					}
					setCond(&ls.Conditions, gatewayv1.ListenerConditionAccepted, metav1.ConditionFalse, gatewayv1.ListenerReasonUnsupportedProtocol, reason, gen)
					setCond(&ls.Conditions, gatewayv1.ListenerConditionProgrammed, metav1.ConditionFalse, gatewayv1.ListenerReasonInvalid, reason, gen)
				case reason == listenerRejectInvalidHostname:
					// An INVALID listener hostname is a config error → Accepted=False (Invalid).
					setCond(&ls.Conditions, gatewayv1.ListenerConditionAccepted, metav1.ConditionFalse, gatewayv1.ListenerReasonInvalid, reason, gen)
					setCond(&ls.Conditions, gatewayv1.ListenerConditionProgrammed, metav1.ConditionFalse, gatewayv1.ListenerReasonInvalid, reason, gen)
				default:
					// A SUPPORTED HTTPS listener whose cert is not yet resolved: the listener
					// config IS valid (Accepted=True), it is simply not Programmed yet, and the
					// cert ref is the ResolvedRefs problem.
					if reason == "" {
						reason = "listener not programmed"
					}
					setCond(&ls.Conditions, gatewayv1.ListenerConditionAccepted, metav1.ConditionTrue, gatewayv1.ListenerReasonAccepted, "Listener accepted", gen)
					setCond(&ls.Conditions, gatewayv1.ListenerConditionProgrammed, metav1.ConditionFalse, gatewayv1.ListenerReasonInvalid, reason, gen)
					if l.Protocol == gatewayv1.HTTPSProtocolType {
						setCond(&ls.Conditions, gatewayv1.ListenerConditionResolvedRefs, metav1.ConditionFalse, gatewayv1.ListenerReasonRefNotPermitted, reason, gen)
					}
				}
			}
			lstatuses = append(lstatuses, ls)
		}
		if !listenerStatusEqual(cur.Status.Listeners, lstatuses) {
			cur.Status.Listeners = lstatuses
			changed = true
		}

		if !changed {
			continue
		}
		if _, err := c.gwcs.GatewayV1().Gateways(gw.Namespace).UpdateStatus(ctx, cur, metav1.UpdateOptions{}); err != nil {
			c.log.Warn("gateway: update Gateway status", "gateway", gwKey, "err", err)
		}
	}
}

// writeRouteStatus sets the per-parent Accepted + ResolvedRefs conditions on each HTTPRoute
// that referenced one of our Gateways, for the parentRef(s) that named our Gateways.
func (c *Controller) writeRouteStatus(ctx context.Context, in Inputs, res Result) {
	// Build the set of owned Gateway keys (class ownership) so we only claim parentRefs to
	// our Gateways (never write a foreign controller's parent status).
	ownedClass := map[string]bool{}
	for _, gc := range in.Classes {
		if OwnsClass(gc) {
			ownedClass[gc.Name] = true
		}
	}
	ourGW := map[string]bool{}
	for _, gw := range in.Gateways {
		if ownedClass[string(gw.Spec.GatewayClassName)] {
			ourGW[gw.Namespace+"/"+gw.Name] = true
		}
	}

	for _, rt := range in.Routes {
		rk := rt.Namespace + "/" + rt.Name
		// Which parentRefs name one of OUR Gateways?
		var ours []gatewayv1.ParentReference
		for pi := range rt.Spec.ParentRefs {
			pr := rt.Spec.ParentRefs[pi]
			if pr.Group != nil && *pr.Group != "" && *pr.Group != gatewayv1.GroupName {
				continue
			}
			if pr.Kind != nil && *pr.Kind != "Gateway" {
				continue
			}
			ns := rt.Namespace
			if pr.Namespace != nil && string(*pr.Namespace) != "" {
				ns = string(*pr.Namespace)
			}
			if ourGW[ns+"/"+string(pr.Name)] {
				ours = append(ours, pr)
			}
		}
		if len(ours) == 0 {
			continue // this route does not reference any of our Gateways
		}

		cur := rt.DeepCopy()
		gen := cur.Generation
		accStatus := metav1.ConditionTrue
		accReason := string(gatewayv1.RouteReasonAccepted)
		accMsg := "Route accepted by cadish"
		if !res.AcceptedRoutes[rk] {
			accStatus = metav1.ConditionFalse
			if res.HostOwnedRoutes[rk] {
				// Fix #3: every effective host's routing is owned by another namespace
				// (oldest-Gateway first-claim); the route may not serve any of them.
				accReason = string(gatewayv1.RouteReasonNotAllowedByListeners)
				accMsg = "Route hostname(s) are owned by another namespace's Gateway (cross-namespace routing claim rejected)"
			} else {
				accReason = string(gatewayv1.RouteReasonNoMatchingParent)
				accMsg = "Route did not attach to any HTTP listener (check parentRefs / listener protocol)"
			}
		}
		resStatus := metav1.ConditionTrue
		resReason := string(gatewayv1.RouteReasonResolvedRefs)
		resMsg := "All backendRefs resolved"
		if !res.ResolvedRoutes[rk] {
			resStatus = metav1.ConditionFalse
			if res.RefNotPermittedRoutes[rk] {
				resReason = string(gatewayv1.RouteReasonRefNotPermitted)
				resMsg = "A cross-namespace ref is not permitted by a ReferenceGrant"
			} else {
				resReason = string(gatewayv1.RouteReasonBackendNotFound)
				resMsg = "One or more backendRefs did not resolve to a Service:port"
			}
		}

		changed := false
		for _, pr := range ours {
			ps := findOrAppendParent(&cur.Status.Parents, pr, ControllerName)
			changed = apimeta.SetStatusCondition(&ps.Conditions, metav1.Condition{
				Type: string(gatewayv1.RouteConditionAccepted), Status: accStatus,
				Reason: accReason, Message: accMsg, ObservedGeneration: gen,
			}) || changed
			changed = apimeta.SetStatusCondition(&ps.Conditions, metav1.Condition{
				Type: string(gatewayv1.RouteConditionResolvedRefs), Status: resStatus,
				Reason: resReason, Message: resMsg, ObservedGeneration: gen,
			}) || changed
		}
		if !changed {
			continue
		}
		if _, err := c.gwcs.GatewayV1().HTTPRoutes(rt.Namespace).UpdateStatus(ctx, cur, metav1.UpdateOptions{}); err != nil {
			c.log.Warn("gateway: update HTTPRoute status", "route", rk, "err", err)
		}
	}
}

// findOrAppendParent returns a pointer to the RouteParentStatus for (parentRef, controller)
// in parents, appending a fresh one when absent. Identity is by the parentRef Name +
// SectionName + our controller name.
func findOrAppendParent(parents *[]gatewayv1.RouteParentStatus, pr gatewayv1.ParentReference, controller gatewayv1.GatewayController) *gatewayv1.RouteParentStatus {
	for i := range *parents {
		p := &(*parents)[i]
		if p.ControllerName != controller {
			continue
		}
		if p.ParentRef.Name != pr.Name {
			continue
		}
		if sectionEqual(p.ParentRef.SectionName, pr.SectionName) {
			return p
		}
	}
	*parents = append(*parents, gatewayv1.RouteParentStatus{ParentRef: pr, ControllerName: controller})
	return &(*parents)[len(*parents)-1]
}

func sectionEqual(a, b *gatewayv1.SectionName) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// setCond is a small wrapper around apimeta.SetStatusCondition for listener conditions.
func setCond(conds *[]metav1.Condition, t gatewayv1.ListenerConditionType, status metav1.ConditionStatus, reason gatewayv1.ListenerConditionReason, msg string, gen int64) {
	apimeta.SetStatusCondition(conds, metav1.Condition{
		Type: string(t), Status: status, Reason: string(reason), Message: msg, ObservedGeneration: gen,
	})
}

// listenerStatusEqual compares listener status slices ignoring condition LastTransitionTime
// (which SetStatusCondition stamps), so an unchanged status is not re-written every tick.
func listenerStatusEqual(a, b []gatewayv1.ListenerStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].AttachedRoutes != b[i].AttachedRoutes {
			return false
		}
		if !condsEqual(a[i].Conditions, b[i].Conditions) {
			return false
		}
	}
	return true
}

func condsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	idx := func(cs []metav1.Condition) map[string]metav1.Condition {
		m := map[string]metav1.Condition{}
		for _, c := range cs {
			m[c.Type] = c
		}
		return m
	}
	ai, bi := idx(a), idx(b)
	keys := make([]string, 0, len(ai))
	for k := range ai {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		x, y := ai[k], bi[k]
		if x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message {
			return false
		}
	}
	return true
}

func (c *Controller) leaseName() string {
	if c.opts.LeaderName != "" {
		return c.opts.LeaderName
	}
	return "cadish-gateway-leader"
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
	return "cadish-gateway"
}
