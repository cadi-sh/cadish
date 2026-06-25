package k8s

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolverWatchFiltersByService(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c := NewClientWithInterface(cs, Options{SyncTimeout: 5 * time.Second})
	res := c.Resolver()
	fired := make(chan struct{}, 4)
	res.Watch("web", "prod", func() { fired <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ready := true
	// A change to a DIFFERENT service must NOT fire the web/prod watcher.
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Create(ctx,
		sliceFor("api", "prod", []epSpec{{ip: "10.0.0.5", ready: &ready}}, portSpec{name: "http", num: 80}),
		metav1.CreateOptions{})
	// A change to web/prod MUST fire it.
	_, _ = cs.DiscoveryV1().EndpointSlices("prod").Create(ctx,
		sliceFor("web", "prod", []epSpec{{ip: "10.0.0.6", ready: &ready}}, portSpec{name: "http", num: 80}),
		metav1.CreateOptions{})

	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("web/prod watcher never fired")
	}
}
