package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/config"
)

// TestReloadCacheKeyTightenNoWrongObject proves that CHANGING the cache_key recipe
// across a reload does NOT serve a stale object that was stored under the OLD recipe
// to a request the NEW recipe wants keyed distinctly.
//
// A→B transition:
//
//	A: cache_key host path   (query ignored — /p and /p?x=1 share key "host␟/p")
//	B: cache_key host url    (url = path+query; for a query-less /p it renders "/p")
//
// The key string encodes the token COUNT via 0x1f separators, so changing the token
// count is self-protecting (different separator count ⇒ no collision). But `path`
// and `url` are BOTH single tokens that render IDENTICALLY for a query-less request:
// under A, `/p?x=1` populates "host␟/p" with the x=1 content (query ignored); under
// B, a bare `/p` also keys to "host␟/p" and HITS that leftover — yet B keys /p and
// /p?x=1 distinctly, so serving the x=1 content for bare /p is a cross-content
// wrong-object serve. Fail-safe: a recipe change must not let the reused store serve
// an object keyed under the OLD recipe.
func TestReloadCacheKeyTightenNoWrongObject(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		// Distinguishable content: echo the full request URI so the body reveals
		// which request actually populated the entry.
		_, _ = w.Write([]byte("served:" + r.URL.RequestURI()))
	})

	const cfgA = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	cache_key host path
	header +cache_status X-Cache
}
`
	dir := t.TempDir()
	path := writeCfg(t, dir, cfgA, origin.srv.URL)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	h := NewHandler(loaded, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)

	// Under recipe A, populate the key "host␟/p" via /p?x=1 (query ignored).
	rec := doHost(h, "test.local", "http://test.local/p?x=1")
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("warm /p?x=1: X-Cache=%q want MISS", rec.Header().Get("X-Cache"))
	}
	if got := rec.Body.String(); got != "served:/p?x=1" {
		t.Fatalf("warm body=%q", got)
	}

	// Reload to recipe B: key on the whole url (path+query).
	const cfgB = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	cache_key host url
	header +cache_status X-Cache
}
`
	if err := os.WriteFile(path, []byte(fmt.Sprintf(cfgB, origin.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	reloaded.TransplantStoresFrom(loaded)
	h.Reload(reloaded)
	keep := map[*cache.Store]bool{}
	for _, st := range reloaded.Sites {
		if st.Store != nil {
			keep[st.Store] = true
		}
	}
	_ = loaded.CloseExcept(keep)
	t.Cleanup(func() { _ = reloaded.Close() })

	// Under recipe B, a bare `/p` must be its OWN object — it must NOT be served the
	// leftover `/p?x=1` content keyed "host␟/p" under recipe A.
	rec = doHost(h, "test.local", "http://test.local/p")
	if body := rec.Body.String(); body == "served:/p?x=1" {
		t.Fatalf("CROSS-CONTENT: bare /p served the stale recipe-A entry %q (wrong object after cache_key change)", body)
	} else if body != "served:/p" {
		t.Fatalf("bare /p body=%q want served:/p", body)
	}
}

// TestApplyConfigCacheKeyChangeFlushesAndTearsDownOldStore drives the FULL Server
// path (ApplyConfig): a cache_key change must (a) not serve a wrong object after the
// swap and (b) tear down the old (non-transplanted) store — its scratch dir is
// removed after the drain grace, proving no store leak on the flush path.
func TestApplyConfigCacheKeyChangeFlushesAndTearsDownOldStore(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("served:" + r.URL.RequestURI()))
	})
	cfgA := fmt.Sprintf(`test.local {
	cache { ram 32MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	cache_key host path
	header +cache_status X-Cache
}
`, origin.srv.URL)
	loaded, err := config.LoadString("<a>", cfgA)
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	srv, err := NewServer(loaded, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	// The old store's scratch dir is the filesystem proof of its lifetime.
	oldDir := loaded.Sites[0].Store.DiskDir()
	if oldDir == "" {
		t.Fatal("old store has no scratch dir")
	}

	// Warm "host␟/p" via /p?x=1 under recipe A.
	if rec := doHost(srv.handler, "test.local", "http://test.local/p?x=1"); rec.Body.String() != "served:/p?x=1" {
		t.Fatalf("warm body=%q", rec.Body.String())
	}

	old := reloadDrainGrace
	reloadDrainGrace = 20 * time.Millisecond
	t.Cleanup(func() { reloadDrainGrace = old })

	next, err := config.LoadString("<b>", fmt.Sprintf(`test.local {
	cache { ram 32MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	cache_key host url
	header +cache_status X-Cache
}
`, origin.srv.URL))
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	if err := srv.ApplyConfig(next); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	// No wrong object: bare /p must not be served the recipe-A /p?x=1 entry.
	if rec := doHost(srv.handler, "test.local", "http://test.local/p"); rec.Body.String() == "served:/p?x=1" {
		t.Fatalf("CROSS-CONTENT after ApplyConfig: bare /p served stale recipe-A entry")
	}

	// The old (flushed, non-transplanted) store is torn down after the drain grace —
	// its scratch dir is removed. Proves no store leak on the recipe-change flush path.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(oldDir); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("old store scratch dir %s still present — flushed store not closed", oldDir)
}

// TestReloadStormNoWrongObjectOrPanic fires many back-to-back ApplyConfig calls that
// ALTERNATE the cache_key recipe (forcing a flush each time) and asserts every reload
// completes and the cache never serves a cross-recipe wrong object.
func TestReloadStormNoWrongObjectOrPanic(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("served:" + r.URL.RequestURI()))
	})
	mk := func(recipe string) *config.Config {
		c, err := config.LoadString("<storm>", fmt.Sprintf(`test.local {
	cache { ram 16MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	cache_key %s
	header +cache_status X-Cache
}
`, origin.srv.URL, recipe))
		if err != nil {
			t.Fatalf("load %q: %v", recipe, err)
		}
		return c
	}
	srv, err := NewServer(mk("host path"), "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	old := reloadDrainGrace
	reloadDrainGrace = time.Millisecond
	t.Cleanup(func() { reloadDrainGrace = old })

	recipes := []string{"host url", "host path", "host path query", "host path"}
	for i := 0; i < 24; i++ {
		// Warm something, then reload to a recipe that may or may not change the scheme.
		_ = doHost(srv.handler, "test.local", "http://test.local/p?x=1")
		if err := srv.ApplyConfig(mk(recipes[i%len(recipes)])); err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		// A bare /p must never be served the /p?x=1 content under any recipe whose key
		// for /p differs from its key for /p?x=1 (host url / host path query).
		rec := doHost(srv.handler, "test.local", "http://test.local/p")
		if rec.Body.String() == "served:/p?x=1" && recipes[i%len(recipes)] != "host path" {
			t.Fatalf("reload %d (%s): cross-content wrong object", i, recipes[i%len(recipes)])
		}
	}
}

// TestReloadCacheKeyChangeFlushesDiskTier is the DISK-tier counterpart of the
// wrong-object test. With a persistent disk path, the reload's freshly-opened cold
// store reloads the previous run's on-disk blobs (keyed under the OLD recipe). The
// disk index is pre-seeded (a prior closed store) so the cold store DETERMINISTICALLY
// loads the stale blob — independent of the 5s flush interval. After a cache_key
// change the flush must empty that disk tier too, so a colliding new-recipe key
// misses instead of serving the stale blob.
func TestReloadCacheKeyChangeFlushesDiskTier(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("served:" + r.URL.RequestURI()))
	})
	diskDir := t.TempDir()

	// Pre-seed the disk index with a blob keyed "test.local␟/p" (what `cache_key host
	// path` produces for /p?x=1) and persist it (Close flushes), simulating a prior run.
	seed, err := cache.NewStore(cache.RouterConfig{DiskDir: diskDir, DiskMaxBytes: 100 << 20, RAMMaxBytes: 0})
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}
	seedKey := "test.local\x1f/p"
	wr, err := seed.Writer(cache.ObjectMeta{Key: seedKey, Size: int64(len("served:/p?x=1")), Tier: "disk"})
	if err != nil {
		t.Fatalf("seed writer: %v", err)
	}
	_, _ = wr.Write([]byte("served:/p?x=1"))
	if err := wr.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	cfgA := fmt.Sprintf(`test.local {
	cache { ram 8MiB
		disk %s 100MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	storage default -> disk
	cache_key host path
	header +cache_status X-Cache
}
`, diskDir, origin.srv.URL)
	dir := t.TempDir()
	path := writeCfg(t, dir, cfgA, "")
	if err := os.WriteFile(path, []byte(cfgA), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load A: %v", err)
	}
	h := NewHandler(loaded, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)

	// Establish the freshness marker for "test.local␟/p" by serving /p?x=1 through the
	// handler (the loaded store already has the seeded blob; this sets h.fresh). The
	// handler re-stores but does NOT reflush the on-disk index, so the cold store built
	// on reload still loads the seeded blob.
	if rec := doHost(h, "test.local", "http://test.local/p?x=1"); rec.Body.String() != "served:/p?x=1" {
		t.Fatalf("warm body=%q", rec.Body.String())
	}

	cfgB := fmt.Sprintf(`test.local {
	cache { ram 8MiB
		disk %s 100MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	storage default -> disk
	cache_key host url
	header +cache_status X-Cache
}
`, diskDir, origin.srv.URL)
	if err := os.WriteFile(path, []byte(cfgB), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	// Precondition: the cold store actually reloaded the stale disk blob (else the test
	// would pass trivially and prove nothing about the flush).
	if _, _, ok := reloaded.Sites[0].Store.GetTier(seedKey); !ok {
		t.Fatal("precondition: cold store did not reload the seeded disk blob")
	}
	reloaded.TransplantStoresFrom(loaded)
	h.Reload(reloaded)
	keep := map[*cache.Store]bool{}
	for _, st := range reloaded.Sites {
		if st.Store != nil {
			keep[st.Store] = true
		}
	}
	_ = loaded.CloseExcept(keep)
	t.Cleanup(func() { _ = reloaded.Close() })

	// Bare /p under recipe B keys to "test.local␟/p" too — it must NOT be served the
	// stale disk blob from recipe A.
	if rec := doHost(h, "test.local", "http://test.local/p"); rec.Body.String() == "served:/p?x=1" {
		t.Fatalf("DISK CROSS-CONTENT: bare /p served the stale recipe-A disk blob (flush did not clear the disk tier)")
	}
}
