package pipeline

import (
	"net/http"
	"testing"
)

// TestTenantFromHost: a `tenant { from host; map … }` block derives the tenant
// from the request Host (with *.suffix wildcards), so brands get separate cache
// namespaces while all hosts of one brand share.
func TestTenantFromHost(t *testing.T) {
	p := compileSrc(t, `example.com {
    tenant {
        from    host
        map     *.brand-a.com -> brand-a
        map     brand-b.com   -> brand-b
        default other
    }
    cache_key {tenant} path
}`)
	key := func(host string) string { return p.EvalRequest(&Request{Host: host, Path: "/x"}).CacheKey }

	// All brand-a hosts share one namespace.
	if key("www.brand-a.com") != key("shop.brand-a.com") {
		t.Error("same brand (different subdomains) should share a cache key")
	}
	if key("brand-a.com") != key("www.brand-a.com") {
		t.Error("bare apex should match *.brand-a.com too")
	}
	// Different brands → different keys.
	if key("www.brand-a.com") == key("brand-b.com") {
		t.Error("different brands must not share a cache key")
	}
	// Unmatched host → default tenant (key = "other" + sep + path).
	if got := key("random.example"); got != "other\x1f/x" {
		t.Errorf("unmatched host => %q, want the default tenant 'other'", got)
	}
	// Host matching ignores port + case.
	if key("WWW.BRAND-A.COM:8443") != key("www.brand-a.com") {
		t.Error("host match should be case/port-insensitive")
	}
}

// TestTenantFromHeader: derive the tenant from a request header.
func TestTenantFromHeader(t *testing.T) {
	p := compileSrc(t, `example.com {
    tenant {
        from    header X-Tenant
        map     acme   -> t-acme
        map     globex -> t-globex
        default t-none
    }
    cache_key {tenant}
}`)
	key := func(v string) string {
		h := http.Header{}
		if v != "" {
			h.Set("X-Tenant", v)
		}
		return p.EvalRequest(&Request{Header: h}).CacheKey
	}
	if key("acme") != "t-acme" {
		t.Errorf("X-Tenant=acme => %q, want t-acme", key("acme"))
	}
	if key("zzz") != "t-none" || key("") != "t-none" {
		t.Error("unmapped/absent header => default t-none")
	}
}

func TestTenantBlockErrors(t *testing.T) {
	cases := map[string]string{
		"no from":         "example.com {\n tenant {\n map a -> b\n }\n}",
		"bad from":        "example.com {\n tenant {\n from cookie X\n default a\n }\n}",
		"no map/default":  "example.com {\n tenant {\n from host\n }\n}",
		"bad map":         "example.com {\n tenant {\n from host\n map a b\n }\n}",
		"unknown setting": "example.com {\n tenant {\n from host\n frob x\n }\n}",
		"two blocks":      "example.com {\n tenant {\n from host\n default a\n }\n tenant {\n from host\n default b\n }\n}",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if compileErr(t, src) == nil {
				t.Errorf("expected a compile error for %s", name)
			}
		})
	}
}
