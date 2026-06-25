//go:build integration

// Layer-1 envtest integration test: prove the EndpointSlice informer cache and the
// event-poke fan-out work against a REAL Kubernetes apiserver (not the fake clientset
// the unit tests use).
//
// REQUIREMENTS — a real apiserver + etcd binary, obtained via controller-runtime's
// setup-envtest. This file is gated behind the `integration` build tag so it is EXCLUDED
// from the default build and the green gate (`go test ./...`); it runs only in a CI lane
// (or locally) that has the binary:
//
//	# one-time: download the apiserver/etcd/kubectl binaries
//	go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use
//	# point the tests at them and run
//	export KUBEBUILDER_ASSETS="$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@latest use -i -p path)"
//	go test -tags integration ./internal/k8s
//
// When the apiserver binary cannot be located the bootstrap SKIPS (rather than fails),
// so a lane without setup-envtest is a clean skip, never a red build.
package k8s

import (
	"context"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// startAPIServer boots a real apiserver+etcd via envtest and returns its rest.Config.
// It SKIPS the test when the binary is unavailable (no setup-envtest assets), so the
// `integration` lane degrades gracefully instead of going red.
func startAPIServer(t *testing.T) *rest.Config {
	t.Helper()
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		if os.Getenv("KUBEBUILDER_ASSETS") == "" {
			t.Skipf("envtest apiserver unavailable; run `setup-envtest use` and set KUBEBUILDER_ASSETS (%v)", err)
		}
		t.Fatalf("start envtest apiserver: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	return cfg
}

// TestEndpointSliceInformerReflectsCluster: create an EndpointSlice in a live apiserver
// and assert (1) the informer event handler fires a service-change poke and (2) the warm
// cache / resolver re-resolves the new endpoint — the Layer-1 contract end-to-end.
func TestEndpointSliceInformerReflectsCluster(t *testing.T) {
	cfg := startAPIServer(t)
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}

	cl := NewClientWithInterface(cs, Options{SyncTimeout: 30 * time.Second})
	pokes := make(chan string, 8)
	cl.OnServiceChange(func(ns, svc string) { pokes <- ns + "/" + svc })

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := cl.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}

	ready := true
	slice := sliceFor("web", "default", []epSpec{{ip: "10.1.2.3", ready: &ready}}, portSpec{name: "http", num: 8080})
	if _, err := cs.DiscoveryV1().EndpointSlices("default").Create(ctx, slice, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create endpointslice: %v", err)
	}

	// (1) the informer event handler fires a poke for this (namespace, service). The
	// apiserver ships its own default/kubernetes EndpointSlice, so drain unrelated pokes
	// until ours arrives.
	pokeDeadline := time.After(30 * time.Second)
	for {
		select {
		case got := <-pokes:
			if got == "default/web" {
				goto poked
			}
		case <-pokeDeadline:
			t.Fatal("no endpoint-change poke fired for default/web")
		}
	}
poked:

	// (2) the resolver (over the warm cache) re-resolves the new endpoint.
	res := cl.Resolver()
	deadline := time.Now().Add(30 * time.Second)
	for {
		eps, rerr := res.ResolveEndpoints(ctx, "web", "default", "http")
		if rerr == nil && len(eps) == 1 && eps[0].IP == "10.1.2.3" && eps[0].Port == 8080 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolver never reflected the endpoint: eps=%+v err=%v", eps, rerr)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Deleting the slice fires another poke and empties the resolution (pool → 503).
	if err := cs.DiscoveryV1().EndpointSlices("default").Delete(ctx, slice.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete endpointslice: %v", err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		eps, rerr := res.ResolveEndpoints(ctx, "web", "default", "http")
		if rerr == nil && len(eps) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolver never reflected the deletion: eps=%+v err=%v", eps, rerr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
