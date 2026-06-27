package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// Coverage for the TWO origin-forwarding boundaries a cache_credentialed (D101) request can
// reach BESIDES the foreground origin fetch: the cluster owner-routing peer forward
// (cluster.go proxyToPeer) and the background grace revalidation (handler.go revalidate).
// Both must still carry the request's ORIGINAL (pre-cookie_allow) Cookie to origin even after
// the cookie-norm parity fix makes EvalResponse evaluate the NORMALIZED request. Neither path
// had cred coverage before this file.

// cookieRecorder is a thread-safe record of the Cookie header value seen on each origin fetch.
type cookieRecorder struct {
	mu      sync.Mutex
	cookies []string
}

func (c *cookieRecorder) add(v string) {
	c.mu.Lock()
	c.cookies = append(c.cookies, v)
	c.mu.Unlock()
}

func (c *cookieRecorder) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.cookies))
	copy(out, c.cookies)
	return out
}

func (c *cookieRecorder) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cookies)
}

// TestCredentialedClusterForwardsOriginalCookieToPeer proves the SAFETY NET for the cluster
// owner-routing path: a cache_credentialed request that lands on a NON-owner node and is
// reverse-proxied to the owning peer must carry the ORIGINAL client cookie (incl. the cookie
// that cookie_allow strips for the shared key) all the way to the origin behind the owner. The
// owner is a full cadish that re-derives everything from the cookie it receives, so dropping
// the original on the peer hop would make the per-user routes authenticate as anonymous.
func TestCredentialedClusterForwardsOriginalCookieToPeer(t *testing.T) {
	rec := &cookieRecorder{}
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Header.Get("Cookie"))
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "shared")
	}))
	defer originSrv.Close()

	nodes := buildCredCluster(t, 3, originSrv.URL)

	const path = "/v3/readmodel/cache/home"
	ownerURL := ownerOf(nodes, path)
	var owner, nonOwner *clusterNode
	for _, nd := range nodes {
		if nd.srv.URL == ownerURL {
			owner = nd
		}
	}
	for _, nd := range nodes {
		if nd != owner {
			nonOwner = nd
			break
		}
	}
	if owner == nil || nonOwner == nil {
		t.Fatalf("owner/non-owner selection failed (owner=%s)", ownerURL)
	}

	// Request lands on the NON-owner with the FULL original cookie. It is routed to the owner,
	// which fetches origin. The origin must observe the original cookie (session + tracking).
	req, _ := http.NewRequest("GET", nonOwner.srv.URL+path, nil)
	req.Header.Set("Cookie", "session=alice; tracking=xyz")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET via non-owner: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "shared" {
		t.Fatalf("routed request: %d %q", resp.StatusCode, string(body))
	}

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("origin fetches = %d (%v), want 1 (owner fetched once)", len(got), got)
	}
	if got[0] != "session=alice; tracking=xyz" {
		t.Fatalf("origin (behind owner peer) saw Cookie %q, want the ORIGINAL full cookie forwarded across the peer hop", got[0])
	}
}

// TestCredentialedBgRevalForwardsOriginalCookie proves the SAFETY NET for the background grace
// revalidation: when a stored cache_credentialed object goes stale and a request triggers a
// background refresh, the detached origin fetch must still carry the triggering request's
// ORIGINAL cookie (incl. the cookie cookie_allow strips), not the normalized one.
func TestCredentialedBgRevalForwardsOriginalCookie(t *testing.T) {
	clk := newFakeClock()
	rec := &cookieRecorder{}
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Header.Get("Cookie"))
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "shared")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cookie_allow session
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl grace 1h
	cache_ttl default hit_for_miss 0s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)

	// MISS stores the shared object; origin sees alice's original cookie.
	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice; tracking=xyz"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("req1 X-Cache = %q, want MISS", got)
	}

	// Advance past the 60s TTL but within the 1h grace: req2 is served STALE from cache and
	// triggers a background revalidation. The detached refresh must forward req2's ORIGINAL
	// cookie (session=carol; tracking=qqq), not the cookie_allow-normalized one.
	clk.advance(2 * time.Minute)
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=carol; tracking=qqq"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("req2 X-Cache = %q, want HIT-STALE (served from grace)", got)
	}

	// Wait for the background revalidation fetch to land.
	deadline := time.Now().Add(2 * time.Second)
	for rec.len() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	got := rec.snapshot()
	if len(got) < 2 {
		t.Fatalf("origin fetches = %d (%v), want 2 (MISS + background revalidation)", len(got), got)
	}
	if got[0] != "session=alice; tracking=xyz" {
		t.Fatalf("MISS fetch saw Cookie %q, want alice's original full cookie", got[0])
	}
	if got[1] != "session=carol; tracking=qqq" {
		t.Fatalf("background revalidation saw Cookie %q, want carol's ORIGINAL full cookie forwarded on the detached refresh", got[1])
	}
}

// buildCredCluster spins up n cadish nodes sharing one origin, each configured with a
// cache_credentialed scope + cookie_allow + owner-mode cluster, so a request landing on a
// non-owner is reverse-proxied to the owning peer.
func buildCredCluster(t *testing.T, n int, origin string) []*clusterNode {
	t.Helper()
	nodes := make([]*clusterNode, n)
	for i := range nodes {
		sh := &settableHandler{}
		srv := httptest.NewServer(sh)
		nodes[i] = &clusterNode{srv: srv, sh: sh, name: fmt.Sprintf("node%d", i)}
		t.Cleanup(srv.Close)
	}

	peerList := ""
	for _, nd := range nodes {
		peerList += " " + nd.srv.URL
	}

	for i, nd := range nodes {
		cfgText := fmt.Sprintf(`test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 127.0.0.0/8 ::1/128
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cookie_allow session
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl
	cache_ttl default hit_for_miss 0s
	cluster {
		self   %s
		peers %s
		region gra
		mode   owner
		fallback degraded
	}
	header +cache_status X-Cache
}
`, origin, nd.srv.URL, peerList)

		dir := t.TempDir()
		path := filepath.Join(dir, "Cadishfile")
		if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("node %d load: %v\n%s", i, err, cfgText)
		}
		t.Cleanup(func() { _ = cfg.Close() })
		hh := NewHandler(cfg, Options{Logger: discardLogger()})
		t.Cleanup(hh.Shutdown)
		nd.h = hh
		nd.cfg = cfg
		nd.sh.h.Store(hh)
	}
	return nodes
}
