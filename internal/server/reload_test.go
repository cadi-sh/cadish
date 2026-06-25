package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/config"
)

// writeCfg writes a Cadishfile with originURL spliced in and returns its path.
func writeCfg(t *testing.T, dir, body, originURL string) string {
	t.Helper()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(body, originURL)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// doHost performs one request against the handler for the given host.
func doHost(h *Handler, host, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestReloadPreservesCache proves a reload swaps routing while a pre-reload cached
// object STAYS a HIT (the cache.Store is preserved, not cold-started).
func TestReloadPreservesCache(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.URL.Path))
	})

	const cfg1 = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`
	dir := t.TempDir()
	path := writeCfg(t, dir, cfg1, origin.srv.URL)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h := NewHandler(loaded, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)

	// Warm the cache: MISS then HIT.
	if rec := doHost(h, "test.local", "http://test.local/a.txt"); rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("warm: X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	if rec := doHost(h, "test.local", "http://test.local/a.txt"); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("warm: X-Cache = %q, want HIT", rec.Header().Get("X-Cache"))
	}
	beforeHits := origin.hits.Load()

	// Reload with a config that ADDS a second host alias (routing change).
	const cfg2 = `test.local, alias.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`
	if err := os.WriteFile(path, []byte(fmt.Sprintf(cfg2, origin.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload load: %v", err)
	}
	reloaded.TransplantStoresFrom(loaded)
	h.Reload(reloaded)
	// Mirror Server.Reload's teardown: close the old config but keep the warm stores
	// now living under reloaded; clean reloaded up at test end.
	keep := map[*cache.Store]bool{}
	for _, st := range reloaded.Sites {
		if st.Store != nil {
			keep[st.Store] = true
		}
	}
	_ = loaded.CloseExcept(keep)
	t.Cleanup(func() { _ = reloaded.Close() })

	// The pre-reload object is STILL a HIT (cache preserved, no extra origin fetch).
	if rec := doHost(h, "test.local", "http://test.local/a.txt"); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("post-reload: X-Cache = %q, want HIT (cache must be preserved)", rec.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != beforeHits {
		t.Fatalf("post-reload origin hits = %d, want %d (no cold start)", origin.hits.Load(), beforeHits)
	}

	// The new routing took effect: the alias now resolves to the same site and
	// shares the preserved cache.
	if rec := doHost(h, "alias.local", "http://alias.local/a.txt"); rec.Code != 200 {
		t.Fatalf("alias after reload: code = %d, want 200", rec.Code)
	}
	if rec := doHost(h, "alias.local", "http://alias.local/a.txt"); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("alias shares preserved cache: X-Cache = %q, want HIT", rec.Header().Get("X-Cache"))
	}
}

// TestApplyConfigSwapsRoutingPreservingCache proves Server.ApplyConfig swaps in an
// already-loaded config (the ingress-controller seam): a new site goes live while a
// pre-swap cached object on a surviving site stays a HIT (warm store transplanted).
func TestApplyConfigSwapsRoutingPreservingCache(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body " + r.URL.Path))
	})
	cfg1 := fmt.Sprintf(`a.test {
	cache { ram 64MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`, origin.srv.URL)
	loaded, err := config.LoadString("<base>", cfg1)
	if err != nil {
		t.Fatalf("load base: %v", err)
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

	// Warm a.test: MISS then HIT.
	if rec := doHost(srv.handler, "a.test", "http://a.test/x"); rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("warm: X-Cache = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	if rec := doHost(srv.handler, "a.test", "http://a.test/x"); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("warm: X-Cache = %q, want HIT", rec.Header().Get("X-Cache"))
	}

	// Apply a NEW config that keeps a.test and adds b.test.
	next, err := config.LoadString("<next>", cfg1+fmt.Sprintf(`b.test {
	cache { ram 64MiB }
	upstream u { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`, origin.srv.URL))
	if err != nil {
		t.Fatalf("load next: %v", err)
	}
	if err := srv.ApplyConfig(next); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}

	// New site live (this legitimately fetches origin once).
	if rec := doHost(srv.handler, "b.test", "http://b.test/y"); rec.Code != 200 {
		t.Fatalf("b.test after apply: code = %d, want 200", rec.Code)
	}
	before := origin.hits.Load()

	// Old cache preserved (HIT, no extra origin fetch).
	if rec := doHost(srv.handler, "a.test", "http://a.test/x"); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("post-apply a.test: X-Cache = %q, want HIT (cache must be preserved)", rec.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != before {
		t.Fatalf("post-apply origin hits = %d, want %d (no cold start)", origin.hits.Load(), before)
	}
}

// TestServerReloadRemovesSite proves a reload that DROPS a site stops routing that
// host and (after the drain grace) closes its cache store, while the surviving site
// keeps its warm cache.
func TestServerReloadRemovesSite(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok " + r.Host))
	})
	// Two sites; the reload drops the second.
	const two = `keep.local {
	cache { ram 32MiB }
	upstream backend { to %s }
}

drop.local {
	cache { ram 32MiB }
	upstream backend { to %[1]s }
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(two, origin.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
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

	// The dropped site is RAM-only, so its store is backed by a scratch temp dir. After
	// the drain grace, CloseExcept removes that dir — a filesystem-visible proof the
	// removed store was torn down (without racing the store by touching it concurrently).
	var droppedDir string
	for _, s := range loaded.Sites {
		if s.Name == "drop.local" {
			droppedDir = s.Store.DiskDir()
		}
	}
	if droppedDir == "" {
		t.Fatal("drop.local store dir not found")
	}
	if _, err := os.Stat(droppedDir); err != nil {
		t.Fatalf("drop.local dir not present before reload: %v", err)
	}

	// Shrink the drain grace so the test does not wait 5s for the removed-store close.
	old := reloadDrainGrace
	reloadDrainGrace = 20 * time.Millisecond
	t.Cleanup(func() { reloadDrainGrace = old })

	const one = `keep.local {
	cache { ram 32MiB }
	upstream backend { to %s }
}
`
	if err := os.WriteFile(path, []byte(fmt.Sprintf(one, origin.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// keep.local still serves after the reload.
	if rec := doHost(srv.handler, "keep.local", "http://keep.local/x"); rec.Code != 200 {
		t.Fatalf("keep.local after reload: code = %d, want 200", rec.Code)
	}

	// After the drain grace, the dropped site's scratch dir is gone (store closed).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(droppedDir); os.IsNotExist(err) {
			return // removed store torn down; success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dropped site's scratch dir %s still present — store not closed after drain", droppedDir)
}

// TestServerReloadFailSafe proves Server.Reload rejects a bad config (returns an
// error) and keeps serving the previous config.
func TestServerReloadFailSafe(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	const good = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
}
`
	dir := t.TempDir()
	path := writeCfg(t, dir, good, origin.srv.URL)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
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

	// Write a syntactically broken Cadishfile and reload from disk.
	if err := os.WriteFile(path, []byte("test.local { upstream backend { to "), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err == nil {
		t.Fatalf("Server.Reload: expected error for bad config, got nil")
	}

	// The old config still serves: the live handler routes test.local.
	rec := doHost(srv.handler, "test.local", "http://test.local/x")
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("after failed reload: code=%d body=%q, want 200 ok", rec.Code, rec.Body.String())
	}
}

// TestServerReloadLivePreservesCache drives a Server.Reload over a real listener:
// it warms the cache, reloads with a routing change (new alias) from disk, and proves
// the pre-reload object is STILL a HIT (warm store transplanted through the swap) and
// the new routing took effect — the full SIGHUP path including lb-pool restart.
func TestServerReloadLivePreservesCache(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body " + r.URL.Path))
	})
	const cfg1 = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`
	dir := t.TempDir()
	path := writeCfg(t, dir, cfg1, origin.srv.URL)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := NewServer(loaded, "127.0.0.1:0", Options{Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	base := "http://" + ln.Addr().String()

	get := func(host, p string) (int, string, string) {
		req, _ := http.NewRequest("GET", base+p, nil)
		req.Host = host
		resp, gerr := http.DefaultClient.Do(req)
		if gerr != nil {
			t.Fatalf("get %s%s: %v", host, p, gerr)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("X-Cache"), string(b)
	}

	// Warm: MISS then HIT.
	if _, xc, _ := get("test.local", "/a"); xc != "MISS" {
		t.Fatalf("warm: X-Cache = %q, want MISS", xc)
	}
	if _, xc, _ := get("test.local", "/a"); xc != "HIT" {
		t.Fatalf("warm: X-Cache = %q, want HIT", xc)
	}
	before := origin.hits.Load()

	// Reload with an added alias.
	const cfg2 = `test.local, alias.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`
	if err := os.WriteFile(path, []byte(fmt.Sprintf(cfg2, origin.srv.URL)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.Reload(); err != nil {
		t.Fatalf("Server.Reload: %v", err)
	}

	// Pre-reload object still a HIT; no extra origin fetch (cache preserved).
	if code, xc, body := get("test.local", "/a"); code != 200 || xc != "HIT" || body != "body /a" {
		t.Fatalf("post-reload /a: code=%d xc=%q body=%q, want 200 HIT 'body /a'", code, xc, body)
	}
	if origin.hits.Load() != before {
		t.Fatalf("post-reload origin hits = %d, want %d (no cold start)", origin.hits.Load(), before)
	}
	// New routing: alias serves and shares the preserved cache.
	if code, _, _ := get("alias.local", "/a"); code != 200 {
		t.Fatalf("alias after reload: code=%d, want 200", code)
	}
	if _, xc, _ := get("alias.local", "/a"); xc != "HIT" {
		t.Fatalf("alias shares cache: X-Cache = %q, want HIT", xc)
	}
}
