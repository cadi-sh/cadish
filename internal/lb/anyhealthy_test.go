package lb

import (
	"testing"
	"time"
)

// AnyHealthy is the O(1)-ish liveness signal behind the `upstream_healthy` matcher
// (the AWS /aws-health-check probe): true when the pool has ≥1 ELIGIBLE backend
// (health-FSM up AND not passively ejected) — Varnish's nbsrv()>0.
func TestAnyHealthyFreshPoolIsLive(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://a:80", "http://b:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// No health spec ⇒ both backends start UP ⇒ pool is live.
	if !u.AnyHealthy() {
		t.Fatal("a fresh pool with two healthy backends must be AnyHealthy")
	}
}

// AnyHealthy flips false when the pool's only backend is ejected, and back true
// when it recovers — the kill→503→recover→200 probe flip.
func TestAnyHealthyFlipsOnEjectAndRecover(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://only:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !u.AnyHealthy() {
		t.Fatal("single healthy backend ⇒ live")
	}
	backends, _, _ := u.snapshot()
	if len(backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(backends))
	}
	// Eject the only backend ⇒ no live backend ⇒ not AnyHealthy.
	backends[0].passiveFailure(1, time.Now(), time.Hour)
	if u.AnyHealthy() {
		t.Fatal("pool with its only backend ejected must NOT be AnyHealthy")
	}
	// Recover (clears ejection) ⇒ live again.
	backends[0].passiveSuccess()
	if !u.AnyHealthy() {
		t.Fatal("pool must be AnyHealthy again after the backend recovers")
	}
}

// Multi-backend ANY semantics: with one of two backends ejected the pool is still
// live; only when BOTH are down does AnyHealthy go false.
func TestAnyHealthyMultiBackendANY(t *testing.T) {
	factory, _ := fakeFactory()
	cfg := staticCfg(t, RoundRobin, "http://a:80", "http://b:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	backends, _, _ := u.snapshot()
	if len(backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(backends))
	}
	backends[0].passiveFailure(1, time.Now(), time.Hour)
	if !u.AnyHealthy() {
		t.Fatal("one of two backends ejected ⇒ pool still live (ANY semantics)")
	}
	backends[1].passiveFailure(1, time.Now(), time.Hour)
	if u.AnyHealthy() {
		t.Fatal("both backends ejected ⇒ pool not live")
	}
}
