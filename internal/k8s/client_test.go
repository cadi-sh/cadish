package k8s

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestClientStartAndSync(t *testing.T) {
	ready := true
	cs := fake.NewSimpleClientset(
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.1", ready: &ready}}, portSpec{name: "http", num: 8080}),
	)
	c := NewClientWithInterface(cs, Options{SyncTimeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	eps, err := c.Cache().Endpoints("prod", "web", "http")
	if err != nil || len(eps) != 1 {
		t.Fatalf("eps=%v err=%v", eps, err)
	}
}

func TestClientOnServiceChangeFires(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := NewClientWithInterface(cs, Options{SyncTimeout: 5 * time.Second})
	got := make(chan [2]string, 4)
	c.OnServiceChange(func(ns, svc string) { got <- [2]string{ns, svc} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ready := true
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Create(ctx,
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.9", ready: &ready}}, portSpec{name: "http", num: 80}),
		metav1.CreateOptions{})
	select {
	case ev := <-got:
		if ev != [2]string{"prod", "web"} {
			t.Fatalf("got %v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnServiceChange never fired")
	}
}

// TestClientOnServiceChangeUnregister is the FIX-4 leak guard: the cancel func returned
// by OnServiceChange must remove the listener (the registry was previously append-only,
// pinning every dead pool's listener forever). After cancel the listener count returns to
// baseline and the listener no longer fires.
func TestClientOnServiceChangeUnregister(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := NewClientWithInterface(cs, Options{SyncTimeout: 5 * time.Second})
	if c.listenerCount() != 0 {
		t.Fatalf("baseline listener count should be 0, got %d", c.listenerCount())
	}
	var fires int32
	cancel := c.OnServiceChange(func(_, _ string) { atomic.AddInt32(&fires, 1) })
	if c.listenerCount() != 1 {
		t.Fatalf("after register want 1 listener, got %d", c.listenerCount())
	}
	c.fire("prod", "web")
	if atomic.LoadInt32(&fires) != 1 {
		t.Fatalf("listener should have fired once, got %d", atomic.LoadInt32(&fires))
	}
	cancel()
	if c.listenerCount() != 0 {
		t.Fatalf("after cancel listener count should return to baseline 0, got %d", c.listenerCount())
	}
	c.fire("prod", "web") // must NOT reach the cancelled listener
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Fatalf("cancelled listener fired again: count=%d", got)
	}
	cancel() // idempotent
	if c.listenerCount() != 0 {
		t.Fatalf("second cancel changed count: %d", c.listenerCount())
	}
}

// TestClientStartIdempotent verifies a second Start is a no-op: it neither
// re-registers the event handler (which would double-fire pokes) nor errors.
func TestClientStartIdempotent(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := NewClientWithInterface(cs, Options{SyncTimeout: 5 * time.Second})
	var fires int32
	c.OnServiceChange(func(_, _ string) { atomic.AddInt32(&fires, 1) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatalf("second start (should be a no-op): %v", err)
	}
	ready := true
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Create(ctx,
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.9", ready: &ready}}, portSpec{name: "http", num: 80}),
		metav1.CreateOptions{})
	// Give the (single) handler time to fire, then assert it fired exactly once.
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&fires); got != 1 {
		t.Fatalf("poke fired %d times, want exactly 1 (handler registered twice?)", got)
	}
}
