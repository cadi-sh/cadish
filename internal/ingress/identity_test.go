package ingress

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func withClassName(name string) *networkingv1.Ingress {
	return &networkingv1.Ingress{Spec: networkingv1.IngressSpec{IngressClassName: &name}}
}

func withAnnotation(k, v string) *networkingv1.Ingress {
	return &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{k: v}}}
}

func noClass() *networkingv1.Ingress { return &networkingv1.Ingress{} }

func TestIngressClassMatching(t *testing.T) {
	cases := []struct {
		name      string
		ing       *networkingv1.Ingress
		isDefault bool
		want      bool
	}{
		{"explicit spec class", withClassName("cadish"), false, true},
		{"other spec class", withClassName("nginx"), false, false},
		{"legacy annotation", withAnnotation("kubernetes.io/ingress.class", "cadish"), false, true},
		{"legacy annotation other", withAnnotation("kubernetes.io/ingress.class", "nginx"), false, false},
		{"no class, we are default", noClass(), true, true},
		{"no class, we are not default", noClass(), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Matches(c.ing, "cadish", c.isDefault); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}
