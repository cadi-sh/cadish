package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cadi-sh/cadish/internal/config"
)

// settableHandler lets us stand up an httptest.Server BEFORE the cadish Handler
// that will serve it exists (we need the server URL to write the peer config, then
// build the Handler that references its own URL as `self`).
type settableHandler struct{ h atomic.Pointer[Handler] }

func (s *settableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := s.h.Load()
	if h == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	h.ServeHTTP(w, r)
}

// clusterNode is one in-process cadish node fronted by a real httptest.Server.
type clusterNode struct {
	srv  *httptest.Server
	sh   *settableHandler
	h    *Handler
	cfg  *config.Config
	name string
}

// buildCluster spins up n cadish nodes that all share one origin, each configured
// with a `cluster { … }` block listing all node URLs (so any node can reach any
// peer) and the given mode/fallback. Returns the nodes; cleanup is registered.
func buildClusterNodes(t *testing.T, n int, origin string, mode, fallback string) []*clusterNode {
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
		fbLine := ""
		if fallback != "" {
			fbLine = "\n\t\tfallback " + fallback
		}
		cfgText := fmt.Sprintf(`test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 127.0.0.0/8 ::1/128
	cluster {
		self   %s
		peers %s
		region gra
		mode   %s%s
	}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`, origin, nd.srv.URL, peerList, mode, fbLine)

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
		h := NewHandler(cfg, Options{Logger: discardLogger()})
		t.Cleanup(h.Shutdown)
		nd.h = h
		nd.cfg = cfg
		nd.sh.h.Store(h)
	}
	return nodes
}

// getVia issues a GET to a specific node's httptest server (a fresh client
// request, no hop header) and returns status + body.
func getVia(t *testing.T, node *clusterNode, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(node.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s via %s: %v", path, node.name, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// ownerOf reports which node owns a key (by consulting node0's membership ring;
// all nodes share the same ring topology).
func ownerOf(nodes []*clusterNode, key string) string {
	m := nodes[0].h.route.Load().sites[0].Cluster
	owner, _ := m.Owner(key)
	return owner
}

// TestCluster_ReadThrough_MissServedFromPeer proves #7: a MISS on node A is served
// from node B's cache. We warm B by fetching the key through B (B caches it from
// origin). Then we fetch the SAME key through A. In read_through mode A's local
// miss consults the owning peer; the object is on whichever node already cached it.
func TestCluster_ReadThrough_MissServedFromPeer(t *testing.T) {
	var originHits atomic.Int64
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "payload "+r.URL.Path)
	}))
	defer originSrv.Close()

	nodes := buildClusterNodes(t, 3, originSrv.URL, "read_through", "")

	const key = "/videos/clip.mp4"
	// The owning node for this key (its read-through peer fetch targets the owner).
	ownerURL := ownerOf(nodes, key)
	var owner, asker *clusterNode
	for _, nd := range nodes {
		if nd.srv.URL == ownerURL {
			owner = nd
		}
	}
	for _, nd := range nodes {
		if nd != owner {
			asker = nd
			break
		}
	}
	if owner == nil || asker == nil {
		t.Fatalf("could not pick owner/asker (owner=%s)", ownerURL)
	}

	// 1) Warm the OWNER's cache from origin (one origin hit).
	code, body := getVia(t, owner, key)
	if code != 200 || body != "payload "+key {
		t.Fatalf("warm owner: %d %q", code, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Fatalf("origin hits after warming owner = %d, want 1", got)
	}

	// 2) Fetch the SAME key through the ASKER. Its local cache misses; read-through
	// asks the owning peer, which serves from its cache — NO new origin hit.
	code, body = getVia(t, asker, key)
	if code != 200 || body != "payload "+key {
		t.Fatalf("asker read-through: %d %q", code, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin hits after asker read-through = %d, want 1 (served from peer cache)", got)
	}
}

// TestCluster_Owner_RoutesToOwnerCachedOnce proves #8: a request for a B-owned key
// landing on A is routed to B and the object is cached once per region. We send the
// request to a NON-owner node; ownership routing reverse-proxies it to the owner,
// which caches it from origin. A second request anywhere for the same key hits the
// owner's cache — origin is touched exactly once.
func TestCluster_Owner_RoutesToOwnerCachedOnce(t *testing.T) {
	var originHits atomic.Int64
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "owned "+r.URL.Path)
	}))
	defer originSrv.Close()

	nodes := buildClusterNodes(t, 3, originSrv.URL, "owner", "degraded")

	const key = "/assets/app.js"
	ownerURL := ownerOf(nodes, key)
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
		t.Fatalf("owner/non-owner selection failed")
	}

	// 1) Request lands on the NON-owner: it must route to the owner, which fetches
	// from origin and caches.
	code, body := getVia(t, nonOwner, key)
	if code != 200 || body != "owned "+key {
		t.Fatalf("non-owner routed request: %d %q", code, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Fatalf("origin hits after first request = %d, want 1", got)
	}

	// 2) Another request, this time straight to the owner: served from the owner's
	// cache — no new origin hit. Cached ONCE per region.
	code, body = getVia(t, owner, key)
	if code != 200 || body != "owned "+key {
		t.Fatalf("owner direct: %d %q", code, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin hits after owner hit = %d, want 1 (cached once)", got)
	}

	// 3) A third request through ANOTHER non-owner also routes to the owner's cache.
	var other *clusterNode
	for _, nd := range nodes {
		if nd != owner && nd != nonOwner {
			other = nd
			break
		}
	}
	if other != nil {
		code, body = getVia(t, other, key)
		if code != 200 || body != "owned "+key {
			t.Fatalf("other non-owner: %d %q", code, body)
		}
		if got := originHits.Load(); got != 1 {
			t.Errorf("origin hits after third request = %d, want 1", got)
		}
	}
}

// TestCluster_HopGuard_NoReforward proves loop safety: a request already carrying
// the hop header is served locally and never re-forwarded, even on a non-owner.
func TestCluster_HopGuard_NoReforward(t *testing.T) {
	var originHits atomic.Int64
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(w, "x "+r.URL.Path)
	}))
	defer originSrv.Close()

	nodes := buildClusterNodes(t, 3, originSrv.URL, "owner", "degraded")
	const key = "/k"
	ownerURL := ownerOf(nodes, key)
	var nonOwner *clusterNode
	for _, nd := range nodes {
		if nd.srv.URL != ownerURL {
			nonOwner = nd
			break
		}
	}

	// Hand the non-owner a request already stamped as a same-region hop: it must
	// serve locally (fetch from origin itself) rather than re-route to the owner.
	req, _ := http.NewRequest("GET", nonOwner.srv.URL+key, nil)
	req.Header.Set("X-Cadish-Peer", "gra")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("hop request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "x "+key {
		t.Fatalf("hop served: %d %q", resp.StatusCode, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin hits = %d, want 1 (served locally, not re-forwarded)", got)
	}
}

// TestCluster_HopGuard_TrustBoundary (R10): the X-Cadish-Peer loop guard is honored
// only from a TRUSTED socket peer. The single-node cluster falls through to its origin
// in both cases (its only peer is itself), so the origin observes the inbound hop
// header verbatim — a clean probe of the trust-boundary strip:
//   - a forged hop from an UNTRUSTED/direct peer is stripped (origin sees no hop), so a
//     client cannot suppress a peer fetch; while
//   - a real hop from a TRUSTED peer (loopback ∈ trust_proxy) is preserved end-to-end
//     (legitimate inter-node forwarding still works).
func TestCluster_HopGuard_TrustBoundary(t *testing.T) {
	var gotHop atomic.Value // string
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHop.Store(r.Header.Get("X-Cadish-Peer"))
		_, _ = io.WriteString(w, "ok")
	}))
	defer originSrv.Close()

	sh := &settableHandler{}
	srv := httptest.NewServer(sh)
	t.Cleanup(srv.Close)
	cfgText := fmt.Sprintf(`test.local {
	cache { ram 16MiB }
	upstream backend { to %s }
	trust_proxy 127.0.0.0/8 ::1/128
	cluster {
		self   %s
		peers  %s
		region gra
		mode   read_through
	}
	cache_ttl default ttl 60s
}
`, originSrv.URL, srv.URL, srv.URL)
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, cfgText)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	h := NewHandler(cfg, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)
	sh.h.Store(h)

	probe := func(remoteAddr, path string) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test.local"+path, nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Cadish-Peer", "gra")
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("probe %s: status %d", remoteAddr, rec.Code)
		}
	}

	// Forged hop from an untrusted/direct peer → stripped → origin sees no hop header.
	probe("203.0.113.9:51000", "/a")
	if got := gotHop.Load(); got != "" {
		t.Errorf("untrusted peer: origin saw X-Cadish-Peer=%q, want stripped (\"\")", got)
	}
	// Real hop from a trusted peer (loopback) → preserved → origin sees it (different
	// path so it is a fresh miss that reaches the origin again).
	probe("127.0.0.1:50000", "/b")
	if got := gotHop.Load(); got != "gra" {
		t.Errorf("trusted peer: origin saw X-Cadish-Peer=%q, want \"gra\" (preserved)", got)
	}
}
