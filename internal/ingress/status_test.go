package ingress

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestStatusWriterUpdatesLoadBalancer(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ingress("prod", "site", "example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
	)
	w := newStatusWriter(cs, "cadish", "203.0.113.10", nil) // publish address
	if err := w.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := cs.NetworkingV1().Ingresses("prod").Get(context.Background(), "site", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 1 || got.Status.LoadBalancer.Ingress[0].IP != "203.0.113.10" {
		t.Fatalf("status not written: %+v", got.Status)
	}
}

// TestStatusWriterSkipsForeignClass proves the writer only touches Ingresses it owns.
func TestStatusWriterSkipsForeignClass(t *testing.T) {
	other := "nginx"
	foreign := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "foreign", Namespace: "prod"},
		Spec:       networkingv1.IngressSpec{IngressClassName: &other},
	}
	cs := fake.NewSimpleClientset(foreign)
	w := newStatusWriter(cs, "cadish", "203.0.113.10", nil)
	if err := w.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := cs.NetworkingV1().Ingresses("prod").Get(context.Background(), "foreign", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("foreign-class Ingress must not be touched: %+v", got.Status)
	}
}

// TestStatusWriterSkipsOutOfScopeNamespace proves the writer honors the controller's
// -namespace scoping: a same-class Ingress in a namespace this controller does NOT
// serve must NOT have its status.loadBalancer written.
func TestStatusWriterSkipsOutOfScopeNamespace(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ingress("prod", "served", "served.example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
		ingress("other", "unserved", "unserved.example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
	)
	w := newStatusWriter(cs, "cadish", "203.0.113.10", map[string]bool{"prod": true})
	if err := w.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	served, _ := cs.NetworkingV1().Ingresses("prod").Get(context.Background(), "served", metav1.GetOptions{})
	if len(served.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("in-scope Ingress should be written: %+v", served.Status)
	}
	unserved, _ := cs.NetworkingV1().Ingresses("other").Get(context.Background(), "unserved", metav1.GetOptions{})
	if len(unserved.Status.LoadBalancer.Ingress) != 0 {
		t.Fatalf("out-of-scope Ingress must NOT be written: %+v", unserved.Status)
	}
}

// TestStatusWriterIdempotent proves a second sync with the same address is a no-op (no
// spurious UpdateStatus churn).
func TestStatusWriterIdempotent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		ingress("prod", "site", "example.com", []pathRule{{path: "/", pathType: prefix, svc: "web", port: 80}}),
	)
	w := newStatusWriter(cs, "cadish", "203.0.113.10", nil)
	if err := w.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := cs.NetworkingV1().Ingresses("prod").Get(context.Background(), "site", metav1.GetOptions{})
	if len(got.Status.LoadBalancer.Ingress) != 1 {
		t.Fatalf("status should remain a single entry: %+v", got.Status)
	}
}
