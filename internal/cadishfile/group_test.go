package cadishfile

import "testing"

// firstDirective returns the first directive named name in body, or nil.
func firstDirective(body []Node, name string) *Directive {
	for _, n := range body {
		if d, ok := n.(*Directive); ok && d.Name == name {
			return d
		}
	}
	return nil
}

func countDirective(body []Node, name string) int {
	c := 0
	for _, n := range body {
		if d, ok := n.(*Directive); ok && d.Name == name {
			c++
		}
	}
	return c
}

func TestExpandGroups(t *testing.T) {
	src := `group {
    cache_key {tenant} host path
    header X-Base yes
    upstream web { to http://base-origin }
    cache_ttl default ttl 2s

    tenant brand-a {
        host brand-a.com www.brand-a.com
        upstream web { to http://a-origin }
        cache_ttl default ttl 60s
    }
    tenant brand-b {
        host brand-b.com
        header X-Brand b
    }
}`
	f, err := Parse("t.cadish", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	sites, err := ExpandGroups(f.Sites)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 {
		t.Fatalf("expanded to %d sites, want 2", len(sites))
	}

	a := sites[0]
	if len(a.Addresses) != 2 || a.Addresses[0] != "brand-a.com" || a.Addresses[1] != "www.brand-a.com" {
		t.Errorf("brand-a addresses = %v", a.Addresses)
	}
	// Injected `tenant brand-a` drives {tenant}.
	if td := firstDirective(a.Body, "tenant"); td == nil || td.Args[0].Raw != "brand-a" {
		t.Errorf("brand-a missing injected `tenant brand-a` directive")
	}
	// The tenant's `upstream web` overrides (replaces) the base's — exactly one,
	// pointing at a-origin.
	if n := countDirective(a.Body, "upstream"); n != 1 {
		t.Errorf("brand-a has %d upstream directives, want 1 (base dropped)", n)
	}
	up := firstDirective(a.Body, "upstream")
	if to := firstDirective(up.Block, "to"); to == nil || to.Args[0].Raw != "http://a-origin" {
		t.Errorf("brand-a upstream not overridden to a-origin: %+v", up)
	}
	// Base header X-Base and cache_key are inherited.
	if firstDirective(a.Body, "cache_key") == nil {
		t.Error("brand-a should inherit the base cache_key")
	}
	if firstDirective(a.Body, "header") == nil {
		t.Error("brand-a should inherit the base header")
	}
	// Two cache_ttl: the tenant's 60s (first) and the base 2s (fallback).
	if n := countDirective(a.Body, "cache_ttl"); n != 2 {
		t.Errorf("brand-a cache_ttl count = %d, want 2 (override first + base fallback)", n)
	}
	// Tenant override must come before the inherited base for first-match-wins.
	idxTenantTTL, idxBaseTTL := -1, -1
	seen := 0
	for i, n := range a.Body {
		if d, ok := n.(*Directive); ok && d.Name == "cache_ttl" {
			if seen == 0 {
				idxTenantTTL = i
			} else {
				idxBaseTTL = i
			}
			seen++
		}
	}
	if !(idxTenantTTL >= 0 && idxBaseTTL > idxTenantTTL) {
		t.Errorf("tenant cache_ttl (%d) must precede base cache_ttl (%d)", idxTenantTTL, idxBaseTTL)
	}

	b := sites[1]
	if len(b.Addresses) != 1 || b.Addresses[0] != "brand-b.com" {
		t.Errorf("brand-b addresses = %v", b.Addresses)
	}
	// brand-b inherits the base upstream (no override) and adds its own header.
	up = firstDirective(b.Body, "upstream")
	if to := firstDirective(up.Block, "to"); to == nil || to.Args[0].Raw != "http://base-origin" {
		t.Errorf("brand-b should inherit the base upstream (base-origin)")
	}
	if n := countDirective(b.Body, "header"); n != 2 { // base X-Base + tenant X-Brand
		t.Errorf("brand-b header count = %d, want 2 (additive)", n)
	}
}

func TestExpandGroupsErrors(t *testing.T) {
	cases := map[string]string{
		"no tenants":     "group {\n cache_key host\n}",
		"tenant no host": "group {\n tenant a {\n upstream web { to http://x }\n }\n}",
		"tenant no name": "group {\n tenant {\n host x.com\n }\n}",
		"dup tenant":     "group {\n tenant a {\n host x.com\n }\n tenant a {\n host y.com\n }\n}",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := Parse("t.cadish", []byte(src))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := ExpandGroups(f.Sites); err == nil {
				t.Errorf("expected expansion error for %s", name)
			}
		})
	}
}

// TestExpandGroupsPassthrough: a non-group site is returned unchanged.
func TestExpandGroupsPassthrough(t *testing.T) {
	f, err := Parse("t.cadish", []byte("example.com {\n cache_key host path\n}"))
	if err != nil {
		t.Fatal(err)
	}
	sites, err := ExpandGroups(f.Sites)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Addresses[0] != "example.com" {
		t.Errorf("non-group site should pass through unchanged, got %v", sites)
	}
}
