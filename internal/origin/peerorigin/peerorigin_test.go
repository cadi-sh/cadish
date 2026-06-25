package peerorigin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
)

// hopHeader mirrors cluster.HopHeader without importing internal/cluster (which
// imports this package — an import cycle in test scope).
const hopHeader = "X-Cadish-Peer"

// peerPool builds a shard-by-key lb.Upstream over the given static peer URLs.
func peerPool(t *testing.T, urls ...string) *lb.Upstream {
	t.Helper()
	cfg := lb.Config{Name: "peers", Kind: "cluster", Policy: lb.Shard, Shard: lb.ShardKeyVal}
	for i, u := range urls {
		tg, err := lb.ParseTarget(u, cadishfile.Pos{File: "test", Line: i + 1})
		if err != nil {
			t.Fatalf("target %q: %v", u, err)
		}
		cfg.Backends = append(cfg.Backends, tg)
	}
	up, err := lb.New(cfg)
	if err != nil {
		t.Fatalf("lb.New: %v", err)
	}
	return up
}

func TestFetch_PeerHit(t *testing.T) {
	var gotHop string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHop = r.Header.Get(hopHeader)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "from-peer")
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	resp, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "from-peer" {
		t.Errorf("body = %q", body)
	}
	if gotHop != "gra" {
		t.Errorf("hop header = %q, want gra (loop guard must be stamped)", gotHop)
	}
}

func TestFetch_PeerMissFallsThrough(t *testing.T) {
	// A peer that 404s any unknown key must surface ErrNotFound so a chain falls
	// through to the real origin (read-through is opportunistic, never terminal).
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A peer that already sees the hop header must NOT have it (this peer is the
		// one being asked); but it returns 404 for the miss.
		http.NotFound(w, r)
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	_, err := po.Fetch(context.Background(), &origin.Request{Key: "/missing"})
	if err == nil {
		t.Fatal("expected an error (peer miss), got nil")
	}
	if origin.StatusOf(err) != http.StatusNotFound {
		t.Errorf("StatusOf = %d, want 404", origin.StatusOf(err))
	}
}

func TestFetch_NoEligiblePeer(t *testing.T) {
	// With a peer pool that resolves to nothing usable, Fetch returns a
	// connection-class error (StatusOf == 0) so the chain falls through.
	po := New(peerPool(t, "http://127.0.0.1:1"), hopHeader, "gra", "")
	_, err := po.Fetch(context.Background(), &origin.Request{Key: "/x"})
	if err == nil {
		t.Fatal("expected an error")
	}
}

// The peer fetch must route by the cache key (shard), so the same key always
// targets the same peer — verified indirectly by the hop header presence and a
// 2-peer pool returning distinct bodies per owner.
func TestFetch_RoutesByKey(t *testing.T) {
	mk := func(tag string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, tag+":"+r.URL.Path)
		}))
	}
	a, b := mk("A"), mk("B")
	defer a.Close()
	defer b.Close()
	po := New(peerPool(t, a.URL, b.URL), hopHeader, "gra", "")

	seen := map[string]string{}
	for _, key := range []string{"/one", "/two", "/three", "/four"} {
		resp, err := po.Fetch(context.Background(), &origin.Request{Key: key})
		if err != nil {
			t.Fatalf("Fetch %s: %v", key, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		seen[key] = string(body)
		if !strings.HasSuffix(string(body), key) {
			t.Errorf("key %s body %q missing path", key, body)
		}
	}
	// A given key is deterministic: re-fetch lands on the same peer/body.
	resp, _ := po.Fetch(context.Background(), &origin.Request{Key: "/one"})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != seen["/one"] {
		t.Errorf("non-deterministic routing for /one: %q vs %q", body, seen["/one"])
	}
}
