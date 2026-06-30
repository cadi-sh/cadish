package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// getViaHost issues a GET to a specific node but with a SHARED client Host header
// (as a real deployment behind DNS round-robin does: every node answers the same
// hostname). This is what exposes cache-key divergence between a direct request and
// a peer-proxied one — getVia uses the node's own address as Host, which masks it.
func getViaHost(t *testing.T, node *clusterNode, path, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", node.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s via %s (Host %s): %v", path, node.name, host, err)
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

// TestCluster_ReadThrough_PassSkipsPeer proves the v0.2.2 fix: in read_through mode a
// request whose URL is defined `pass` goes STRAIGHT to origin and must NOT hop to the
// owning peer (the response is never stored, so the detour is pure wasted latency). We
// send a `pass` request to a NON-owner node and assert the origin saw NO X-Cadish-Peer
// header — i.e. the asker fetched origin directly rather than via PeerOrigin (which would
// stamp the hop, and the owner would forward it to origin as "gra", as the trust-boundary
// test demonstrates). Without the fix the pass flows through the chained PeerOrigin and
// the origin observes the hop.
func TestCluster_ReadThrough_PassSkipsPeer(t *testing.T) {
	var gotHop atomic.Value // string: the X-Cadish-Peer the origin observed
	gotHop.Store("")
	var originHits atomic.Int64
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		gotHop.Store(r.Header.Get("X-Cadish-Peer"))
		_, _ = io.WriteString(w, "live "+r.URL.Path)
	}))
	defer originSrv.Close()

	// Two read_through nodes sharing the origin, with /live/* defined `pass`.
	nodes := make([]*clusterNode, 2)
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
	pass path /live/*
	cluster {
		self   %s
		peers %s
		region gra
		mode   read_through
	}
	cache_ttl default ttl 60s
}
`, originSrv.URL, nd.srv.URL, peerList)
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

	const key = "/live/stream.m3u8"
	ownerURL := ownerOf(nodes, key)
	var asker *clusterNode
	for _, nd := range nodes {
		if nd.srv.URL != ownerURL {
			asker = nd
			break
		}
	}
	if asker == nil {
		t.Fatal("could not pick a non-owner asker")
	}

	code, body := getVia(t, asker, key)
	if code != 200 || body != "live "+key {
		t.Fatalf("pass request: %d %q", code, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Fatalf("origin hits = %d, want 1", got)
	}
	if got := gotHop.Load().(string); got != "" {
		t.Errorf("origin saw X-Cadish-Peer=%q for a pass request: it hopped to the peer; a pass must go straight to origin", got)
	}
}

// TestCluster_Owner_StoreOnce_SharedHost proves the v0.2.2 store-once fix: in owner
// mode, when every node answers the SAME client hostname (a real DNS-round-robin
// deployment) and the cache key includes the host (the DEFAULT cache_key), an object
// must be fetched from origin EXACTLY ONCE per region. Before the fix, proxyToPeer
// dropped the client Host, so the owner keyed a peer-proxied request under the peer's
// URL host but a direct request under the client host — two cache entries on the
// owner, two origin fetches. (TestCluster_Owner_RoutesToOwnerCachedOnce masks this by
// connecting to each node by its own address, so proxied and direct Host coincide.)
func TestCluster_Owner_StoreOnce_SharedHost(t *testing.T) {
	var originHits atomic.Int64
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "owned "+r.URL.Path)
	}))
	defer originSrv.Close()

	// buildClusterNodes uses the DEFAULT cache key (method host path query) — host is keyed.
	nodes := buildClusterNodes(t, 3, originSrv.URL, "owner", "degraded")
	const host = "shared.example.com"
	const key = "/assets/app.js"

	ownerURL := ownerOf(nodes, key)
	var owner, nonOwner *clusterNode
	for _, nd := range nodes {
		if nd.srv.URL == ownerURL {
			owner = nd
		} else if nonOwner == nil {
			nonOwner = nd
		}
	}
	if owner == nil || nonOwner == nil {
		t.Fatal("owner/non-owner selection failed")
	}

	// 1) Request lands on a NON-owner with the shared Host → routed to the owner, which
	// fetches origin once and caches.
	if code, body := getViaHost(t, nonOwner, key, host); code != 200 || body != "owned "+key {
		t.Fatalf("non-owner routed: %d %q", code, body)
	}
	// 2) Same object, now DIRECT to the owner with the same shared Host → MUST be the
	// owner's cached copy, NOT a second origin fetch under a different (host) key.
	if code, body := getViaHost(t, owner, key, host); code != 200 || body != "owned "+key {
		t.Fatalf("owner direct: %d %q", code, body)
	}
	if got := originHits.Load(); got != 1 {
		t.Errorf("origin hits = %d, want 1 (cached ONCE per region; the peer proxy must preserve the client Host so the owner's cache key matches)", got)
	}
}

// TestCluster_Owner_ProxyForwardsClientIP proves the v0.2.2 client-IP fix: when an
// owner-mode node reverse-proxies a request to the owning peer, it must carry the
// ORIGINAL client IP in X-Forwarded-For. Otherwise the owner derives the PEER's IP
// (the dial source), which both diverges the cache key for IP-based tokens ({geo},
// {sticky}) — a store-multiple bug — and feeds the wrong IP to ACL / rate-limit / geo
// decisions. We invoke a real non-owner node with a distinct, untrusted client
// RemoteAddr and a recorder standing in as the owning peer, then assert the recorder
// received X-Forwarded-For = the original client IP.
func TestCluster_Owner_ProxyForwardsClientIP(t *testing.T) {
	gotXFF := make(chan string, 1)
	recorder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotXFF <- r.Header.Get("X-Forwarded-For"):
		default:
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer recorder.Close()

	// One real cadish node; its cluster peers are [self, recorder]. We then pick a key
	// the ring assigns to the recorder so the node reverse-proxies to it.
	sh := &settableHandler{}
	srv := httptest.NewServer(sh)
	defer srv.Close()
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer originSrv.Close()

	cfgText := fmt.Sprintf(`test.local {
	cache { ram 16MiB }
	upstream backend { to %s }
	trust_proxy 127.0.0.0/8 ::1/128
	cluster {
		self   %s
		peers  %s %s
		region gra
		mode   owner
	}
	cache_ttl default ttl 60s
}
`, originSrv.URL, srv.URL, srv.URL, recorder.URL)
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

	// Find a key the ring assigns to the recorder (so the node proxies to it).
	m := h.route.Load().sites[0].Cluster
	key := ""
	for i := 0; i < 200; i++ {
		k := fmt.Sprintf("/obj-%d", i)
		if owner, ok := m.Owner(k); ok && owner == recorder.URL {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatal("could not find a key owned by the recorder peer")
	}

	// Direct client request with a DISTINCT, untrusted RemoteAddr (so RealClientIP is
	// the socket IP, carried only in RemoteAddr — exactly the case proxyToPeer dropped).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test.local"+key, nil)
	req.RemoteAddr = "198.51.100.7:40000"
	h.ServeHTTP(rec, req)

	select {
	case xff := <-gotXFF:
		if xff != "198.51.100.7" {
			t.Errorf("peer received X-Forwarded-For=%q, want %q (the original client IP must be forwarded so the owner derives the same IP / cache key)", xff, "198.51.100.7")
		}
	default:
		t.Fatalf("recorder peer was not reached (status %d) — owner routing did not proxy", rec.Code)
	}
}

// TestCluster_Owner_WriteNotRoutedToPeer proves the F-D3 fix: an unsafe (write) method
// is NEVER owner-routed, even when the ring assigns its key to another node. Owner
// routing streams r.Body to the peer with no GetBody replay, so a peer that accepts
// then fails mid-upload would leave the body consumed and the local fallback would
// forward a truncated body to origin. Writes therefore take the local origin path,
// where the body is read exactly once. We assert the would-be peer (a recorder) is
// NOT reached and the local origin receives the FULL POST body.
func TestCluster_Owner_WriteNotRoutedToPeer(t *testing.T) {
	peerHit := make(chan struct{}, 1)
	recorder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case peerHit <- struct{}{}:
		default:
		}
		_, _ = io.WriteString(w, "peer")
	}))
	defer recorder.Close()

	gotBody := make(chan string, 1)
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case gotBody <- string(b):
		default:
		}
		_, _ = io.WriteString(w, "origin")
	}))
	defer originSrv.Close()

	sh := &settableHandler{}
	srv := httptest.NewServer(sh)
	defer srv.Close()
	cfgText := fmt.Sprintf(`test.local {
	cache { ram 16MiB }
	upstream backend { to %s }
	trust_proxy 127.0.0.0/8 ::1/128
	cluster {
		self   %s
		peers  %s %s
		region gra
		mode   owner
	}
	cache_ttl default ttl 60s
}
`, originSrv.URL, srv.URL, srv.URL, recorder.URL)
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

	// A key the ring assigns to the recorder peer (a GET here WOULD be proxied).
	m := h.route.Load().sites[0].Cluster
	key := ""
	for i := 0; i < 200; i++ {
		k := fmt.Sprintf("/obj-%d", i)
		if owner, ok := m.Owner(k); ok && owner == recorder.URL {
			key = k
			break
		}
	}
	if key == "" {
		t.Fatal("could not find a key owned by the recorder peer")
	}

	const payload = "the full request body that must not be truncated"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test.local"+key, strings.NewReader(payload))
	h.ServeHTTP(rec, req)

	select {
	case <-peerHit:
		t.Fatal("write method was owner-routed to the peer — writes must serve locally (F-D3)")
	default:
	}
	select {
	case b := <-gotBody:
		if b != payload {
			t.Errorf("origin received body %q, want the full %q", b, payload)
		}
	default:
		t.Fatal("local origin never received the POST — write was not served locally")
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
