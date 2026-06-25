package pipeline

import (
	"strings"
	"testing"
)

// TestCacheKeyTenant: the {tenant} token renders the site's `tenant NAME`, so two
// tenant sites get different cache keys for the same request (brands don't share).
func TestCacheKeyTenant(t *testing.T) {
	pa := compileSrc(t, "example.com {\n tenant brand-a\n cache_key {tenant} host path\n}")
	if pa.Tenant() != "brand-a" {
		t.Fatalf("Tenant() = %q, want brand-a", pa.Tenant())
	}
	ka := pa.EvalRequest(&Request{Host: "h", Path: "/x"}).CacheKey
	if !strings.Contains(ka, "brand-a") {
		t.Errorf("key %q should contain the tenant", ka)
	}

	pb := compileSrc(t, "example.com {\n tenant brand-b\n cache_key {tenant} host path\n}")
	kb := pb.EvalRequest(&Request{Host: "h", Path: "/x"}).CacheKey
	if ka == kb {
		t.Errorf("different tenants must not share a key: both %q", ka)
	}
}

// TestTenantEmpty: a site with no `tenant` directive renders {tenant} as "".
func TestTenantEmpty(t *testing.T) {
	p := compileSrc(t, "example.com {\n cache_key {tenant} host path\n}")
	if p.Tenant() != "" {
		t.Errorf("Tenant() = %q, want empty", p.Tenant())
	}
	// Must not panic; {tenant} is just empty.
	_ = p.EvalRequest(&Request{Host: "h", Path: "/x"}).CacheKey
}

// TestTenantReserved: `tenant` cannot be redefined as a normalizer name.
func TestTenantReserved(t *testing.T) {
	if compileErr(t, "example.com {\n normalize tenant {\n from header X\n default a\n }\n}") == nil {
		t.Error("normalize tenant should be a reserved-name compile error")
	}
}

func TestTenantNeedsName(t *testing.T) {
	if compileErr(t, "example.com {\n tenant\n cache_key {tenant}\n}") == nil {
		t.Error("a `tenant` directive with no name should be a compile error")
	}
}
