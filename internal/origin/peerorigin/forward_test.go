package peerorigin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// TestFetch_SelfRouteServesLocal: when the ring assigns a key to THIS node, Fetch
// must NOT read-through (a self-fetch deadlocks against request coalescing). It
// surfaces ErrNotFound so the chain falls through to the local origin — and must
// never touch the network for that key.
func TestFetch_SelfRouteServesLocal(t *testing.T) {
	hit := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		_, _ = io.WriteString(w, "should-not-be-reached")
	}))
	defer peer.Close()

	pool := peerPool(t, peer.URL)
	// Single-peer pool: that peer owns every key. Set self = that peer so every key
	// self-routes.
	owner, ok := pool.Owner("/obj", false)
	if !ok {
		t.Fatal("no owner")
	}
	po := New(pool, hopHeader, "gra", owner)

	_, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj"})
	if err != origin.ErrNotFound {
		t.Fatalf("self-route Fetch err = %v, want ErrNotFound", err)
	}
	if hit {
		t.Error("self-route must not contact the peer over the network")
	}
}

// TestFetch_ForwardsCredentialedCookie pins the cache_credentialed peer path: the
// ORIGINAL request's Cookie (the credential that keys a per-user variant) must be
// forwarded to the owning peer verbatim, alongside the hop guard, so the peer keys
// and serves the SAME credentialed variant — without it the peer would serve the
// wrong user's object.
func TestFetch_ForwardsCredentialedCookie(t *testing.T) {
	var gotCookie, gotHop string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotHop = r.Header.Get(hopHeader)
		_, _ = io.WriteString(w, "ok")
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	in := http.Header{"Cookie": {"session=abc123"}}
	resp, err := po.Fetch(context.Background(), &origin.Request{Key: "/obj", Header: in})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()

	if gotCookie != "session=abc123" {
		t.Errorf("peer Cookie = %q, want session=abc123 (credentialed cookie not forwarded)", gotCookie)
	}
	if gotHop != "gra" {
		t.Errorf("peer hop = %q, want gra", gotHop)
	}
	// The caller's header map must not be mutated (Fetch clones before stamping).
	if in.Get(hopHeader) != "" {
		t.Errorf("Fetch mutated the caller's header map (hop leaked back): %v", in)
	}
}

// TestFetch_HopGuardServesLocal: a request that ALREADY carries the hop header was
// forwarded to us by a peer — we must not re-forward (loop/storm guard). Surface
// ErrNotFound without touching the network.
func TestFetch_HopGuardServesLocal(t *testing.T) {
	hit := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer peer.Close()

	po := New(peerPool(t, peer.URL), hopHeader, "gra", "")
	req := &origin.Request{Key: "/obj", Header: http.Header{hopHeader: {"gra"}}}
	_, err := po.Fetch(context.Background(), req)
	if err != origin.ErrNotFound {
		t.Fatalf("hop-guarded Fetch err = %v, want ErrNotFound", err)
	}
	if hit {
		t.Error("a hop-guarded request must not be re-forwarded to a peer")
	}
}
