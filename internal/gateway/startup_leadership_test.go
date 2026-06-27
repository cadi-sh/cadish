package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
)

// TestAcquiredLeadershipTriggersReconcile pins the startup/failover ordering invariant:
// when this replica gains leadership it MUST queue a reconcile, because Gateway status is
// written only from reconcile and only while isLeader is set.
//
// The bug this guards against: the initial reconcile(s) run as a follower (writeStatus is
// a no-op when !isLeader) and, with resync=0, nothing re-triggers a reconcile once
// leadership is acquired — so a freshly started or just-promoted leader would leave every
// owned Gateway / HTTPRoute / GatewayClass with NO Accepted/Programmed conditions until
// the next spec change. onAcquiredLeadership must mark the replica leader AND poke a
// reconcile so the desired status is published immediately.
func TestAcquiredLeadershipTriggersReconcile(t *testing.T) {
	c := &Controller{changes: make(chan struct{}, 1)}

	if c.isLeader.Load() {
		t.Fatal("controller should not start as the status-writer leader")
	}

	c.onAcquiredLeadership()

	if !c.isLeader.Load() {
		t.Fatal("onAcquiredLeadership did not mark the replica the status-writer leader")
	}
	select {
	case <-c.changes:
		// A reconcile was queued: writeStatus will run with isLeader=true and publish the
		// desired Gateway/HTTPRoute/GatewayClass conditions.
	default:
		t.Fatal("gaining leadership did not queue a reconcile; owned Gateway/HTTPRoute/" +
			"GatewayClass status would never be written after startup or failover")
	}
}

// TestLeaderElectionPublishesStatusAfterStartup is a positive smoke test that the
// controller publishes status when leader election is ENABLED (the production default) —
// the existing controller tests run with leader election OFF. It exercises the real
// leaderelection.RunOrDie path feeding the leader flag that gates writeStatus.
//
// NOTE: it is NOT a reliable reproduction of the startup-ordering bug. Against the fake
// clientset the (uncontended) lease is acquired almost instantly, so leadership often wins
// the race against the first reconcile and status is written even without the poke. The
// deterministic guard for the actual bug is TestAcquiredLeadershipTriggersReconcile, which
// pins that gaining leadership MUST queue a reconcile regardless of timing.
func TestLeaderElectionPublishesStatusAfterStartup(t *testing.T) {
	gc := gatewayClass("cadish", ControllerName)
	g := gw("prod", "gw", "cadish", "")
	rt := httpRoute("prod", "api", "gw", "example.com", "web", 80, []match{{"/api", gatewayv1.PathMatchPathPrefix}})

	gwcs := gwfake.NewSimpleClientset()
	mustCreate(t, gwcs, gc, g, rt)
	cs := k8sfake.NewSimpleClientset(svc("prod", "web"), sliceFor("web", "prod", "10.0.0.1", 80))

	applier := applierFunc(func(*config.Config) error { return nil })
	ctrl := New(cs, gwcs, applier, ``, Config{
		ResyncDebounce: 10 * time.Millisecond,
		LeaderElection: true,
		LeaderName:     "cadish-gateway-leader-startup-test",
		Identity:       "replica-a",
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ctrl.Run(ctx) }()

	// Leader election against the fake clientset acquires the (uncontended) lease within a
	// couple of retry periods; allow generous slack so the test is not timing-fragile.
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, err := gwcs.GatewayV1().GatewayClasses().Get(ctx, "cadish", metav1.GetOptions{})
		if err == nil && condTrue(got.Status.Conditions, string(gatewayv1.GatewayClassConditionStatusAccepted)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("leader never published GatewayClass status after startup " +
				"(gaining leadership must re-trigger a reconcile)")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
