package lb

import (
	"testing"
	"time"
)

// HealthSnapshot must enumerate every backend with its current health/ejection
// state, without exposing the unexported backend type. It is the read seam the
// admin dashboard uses to render upstream tiles.
func TestHealthSnapshot(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://a:80", "http://b:80")
	cfg.Name = "web"
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	snap := u.HealthSnapshot()
	if snap.Name != "web" {
		t.Errorf("Name = %q, want web", snap.Name)
	}
	if snap.Policy != "round_robin" {
		t.Errorf("Policy = %q, want round_robin", snap.Policy)
	}
	if len(snap.Backends) != 2 {
		t.Fatalf("Backends = %d, want 2", len(snap.Backends))
	}
	// Fresh backends start healthy (no health spec ⇒ always up) and not ejected.
	for _, b := range snap.Backends {
		if !b.Healthy {
			t.Errorf("backend %q not healthy at start", b.ID)
		}
		if b.Ejected {
			t.Errorf("backend %q ejected at start", b.ID)
		}
		if b.InFlight != 0 {
			t.Errorf("backend %q inflight = %d, want 0", b.ID, b.InFlight)
		}
		if b.BaseURL == "" {
			t.Errorf("backend %q has empty BaseURL", b.ID)
		}
	}
}

// A passively-ejected backend must surface Ejected=true in the snapshot.
func TestHealthSnapshotReflectsEjection(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://a:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	backends, _, _ := u.snapshot()
	if len(backends) == 0 {
		t.Fatal("no backends")
	}
	// Force an ejection.
	backends[0].passiveFailure(1, time.Now(), time.Hour)

	snap := u.HealthSnapshot()
	if !snap.Backends[0].Ejected {
		t.Fatalf("backend not reported ejected after passiveFailure")
	}
}
