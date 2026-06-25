package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadConfig(t *testing.T, src string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v\n%s", err, src)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	return cfg
}

// TestGroupExpandsToTenantSites: a `group` config loads into one runtime Site per
// tenant, each carrying its tenant name and host addresses.
func TestGroupExpandsToTenantSites(t *testing.T) {
	cfg := loadConfig(t, `group {
    cache { ram 32MiB }
    cache_ttl default ttl 2s
    upstream web { to http://base-origin:8080 }
    cache_key {tenant} host path

    tenant brand-a {
        host brand-a.com www.brand-a.com
        upstream web { to http://a-origin:8080 }
    }
    tenant brand-b {
        host brand-b.com
    }
}`)

	if len(cfg.Sites) != 2 {
		t.Fatalf("loaded %d sites, want 2", len(cfg.Sites))
	}
	byTenant := map[string]*Site{}
	for _, s := range cfg.Sites {
		byTenant[s.Pipeline.Tenant()] = s
	}
	a, ok := byTenant["brand-a"]
	if !ok {
		t.Fatal("missing brand-a site")
	}
	if len(a.Addresses) != 2 || a.Addresses[0] != "brand-a.com" {
		t.Errorf("brand-a addresses = %v", a.Addresses)
	}
	b, ok := byTenant["brand-b"]
	if !ok {
		t.Fatal("missing brand-b site")
	}
	if len(b.Addresses) != 1 || b.Addresses[0] != "brand-b.com" {
		t.Errorf("brand-b addresses = %v", b.Addresses)
	}

	// Both have an origin (brand-a's overridden, brand-b's inherited from base).
	if a.Origin == nil || b.Origin == nil {
		t.Error("both tenant sites should have a default origin")
	}
}

func TestGroupBadConfigError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	// tenant without a host → expansion error surfaced by Load.
	_ = os.WriteFile(path, []byte("group {\n tenant a {\n cache_key host\n }\n}"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("a malformed group should make Load fail")
	}
}
