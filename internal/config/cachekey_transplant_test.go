package config

import "testing"

// siteByHost finds the loaded site whose primary host matches, or nil.
func siteByHost(c *Config, host string) *Site {
	for _, s := range c.Sites {
		if primaryHost(s) == host {
			return s
		}
	}
	return nil
}

// TestTransplantStoresFrom_KeepsStoreWhenKeySchemeUnchanged proves the warm store is
// carried across a reload whose cache-key namespace is UNCHANGED (only an unrelated
// directive — a header op — differs). The new site must end up serving from the OLD
// (warm) store instance, so the hit ratio survives.
func TestTransplantStoresFrom_KeepsStoreWhenKeySchemeUnchanged(t *testing.T) {
	const a = `s.local {
	cache { ram 8MiB }
	upstream u { to http://o:80 }
	cache_key host path
}
`
	const b = `s.local {
	cache { ram 8MiB }
	upstream u { to http://o:80 }
	cache_key host path
	header +X-Extra hi
}
`
	old := loadStr(t, "<old>", a)
	t.Cleanup(func() { _ = old.Close() })
	next := loadStr(t, "<next>", b)
	t.Cleanup(func() { _ = next.Close() })

	oldStore := siteByHost(old, "s.local").Store
	coldStore := siteByHost(next, "s.local").Store
	if oldStore == nil || coldStore == nil || oldStore == coldStore {
		t.Fatal("expected distinct non-nil stores before transplant")
	}
	next.TransplantStoresFrom(old)
	if got := siteByHost(next, "s.local").Store; got != oldStore {
		t.Fatalf("unchanged key scheme must transplant the warm store: got %p, want %p", got, oldStore)
	}
}

// TestTransplantStoresFrom_FlushesStoreWhenKeySchemeChanged proves the warm store is
// NOT carried when the cache-key recipe CHANGES — the new site keeps its fresh cold
// store (a fail-safe flush) so an entry keyed under the old recipe can never be served
// for a key that now addresses different content.
func TestTransplantStoresFrom_FlushesStoreWhenKeySchemeChanged(t *testing.T) {
	const a = `s.local {
	cache { ram 8MiB }
	upstream u { to http://o:80 }
	cache_key host path
}
`
	const b = `s.local {
	cache { ram 8MiB }
	upstream u { to http://o:80 }
	cache_key host url
}
`
	old := loadStr(t, "<old>", a)
	t.Cleanup(func() { _ = old.Close() })
	next := loadStr(t, "<next>", b)
	t.Cleanup(func() { _ = next.Close() })

	oldStore := siteByHost(old, "s.local").Store
	coldStore := siteByHost(next, "s.local").Store
	next.TransplantStoresFrom(old)
	got := siteByHost(next, "s.local").Store
	if got == oldStore {
		t.Fatal("changed key scheme must NOT transplant the old store (wrong-object risk)")
	}
	if got != coldStore {
		t.Fatalf("changed key scheme must keep the fresh cold store: got %p, want %p", got, coldStore)
	}
}

// TestCacheKeyFingerprint_SensitiveToReferencedBlocks proves the fingerprint changes
// when a block the recipe REFERENCES (here a `normalize`) changes, even if the
// `cache_key` line itself is identical — so editing a normalizer's buckets also
// triggers the fail-safe flush.
func TestCacheKeyFingerprint_SensitiveToReferencedBlocks(t *testing.T) {
	const a = `s.local {
	normalize plan {
		from header X-Plan
		map premium -> pro
		default free
	}
	upstream u { to http://o:80 }
	cache_key host path {plan}
}
`
	const b = `s.local {
	normalize plan {
		from header X-Plan
		map premium -> pro
		map trial -> trial
		default free
	}
	upstream u { to http://o:80 }
	cache_key host path {plan}
}
`
	old := loadStr(t, "<old>", a)
	t.Cleanup(func() { _ = old.Close() })
	next := loadStr(t, "<next>", b)
	t.Cleanup(func() { _ = next.Close() })
	if siteByHost(old, "s.local").cacheKeyFP == siteByHost(next, "s.local").cacheKeyFP {
		t.Fatal("fingerprint must change when a referenced normalize block changes")
	}
}
