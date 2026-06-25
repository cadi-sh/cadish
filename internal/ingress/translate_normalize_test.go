package ingress

import (
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
)

// TestNormalizePathExactPreservesTrailingSlash: an Exact path must keep a meaningful trailing
// slash (Exact "/foo/" matches only "/foo/"), while Prefix trims it.
func TestNormalizePathExactPreservesTrailingSlash(t *testing.T) {
	if got := normalizePath("/foo/", networkingv1.PathTypeExact); got != "/foo/" {
		t.Errorf("Exact /foo/ = %q, want /foo/ (trailing slash is significant)", got)
	}
	if got := normalizePath("/foo/", networkingv1.PathTypePrefix); got != "/foo" {
		t.Errorf("Prefix /foo/ = %q, want /foo (trimmed)", got)
	}
	if got := normalizePath("/", networkingv1.PathTypeExact); got != "/" {
		t.Errorf("Exact / = %q, want /", got)
	}
	if got := normalizePath("", networkingv1.PathTypeExact); got != "/" {
		t.Errorf("empty = %q, want /", got)
	}
}
