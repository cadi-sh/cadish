package cluster

import (
	"context"
	"testing"
)

// TestMembership_StartLifecycle: Start is nil-safe (so a non-clustered node can
// `defer m.Close()` / Start uniformly without a nil check) and, on a real
// Membership, launches the peer pool's background workers bound to ctx.
func TestMembership_StartLifecycle(t *testing.T) {
	var nilM *Membership
	nilM.Start(context.Background()) // must not panic
	nilM.Close()                     // must not panic

	a := "http://10.0.0.1:6081"
	m, err := New(staticCfg(t, a, ModeOwner, FallbackDegraded, a))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx) // launches background workers bound to ctx
	cancel()     // stop them
	m.Close()
}

// TestMembership_OwnsKeyAndSelfRouting verifies the ownership-decision logic (#8):
// for every key, OwnsKey is true on exactly the node the ring assigns it to, and
// false on every other node. A wrong answer here routes (or fails to route) a key,
// duplicating or mis-locating a cached object across the region.
func TestMembership_OwnsKeyAndSelfRouting(t *testing.T) {
	a := "http://10.0.0.1:6081"
	b := "http://10.0.0.2:6081"
	c := "http://10.0.0.3:6081"
	peers := []string{a, b, c}

	// One Membership per node, all over the same peer set.
	mem := map[string]*Membership{}
	for _, self := range peers {
		m, err := New(staticCfg(t, self, ModeOwner, FallbackDegraded, a, b, c))
		if err != nil {
			t.Fatalf("New(%s): %v", self, err)
		}
		defer m.Close()
		mem[self] = m
	}

	for i := 0; i < 200; i++ {
		key := "/videos/" + itoa(i) + ".mp4"
		owner, ok := mem[a].Owner(key)
		if !ok {
			t.Fatalf("no owner for %q", key)
		}
		// Exactly one node claims ownership, and it is the ring owner.
		claims := 0
		for self, m := range mem {
			owns := m.OwnsKey(key)
			if owns && self != owner {
				t.Errorf("key %q: node %s claims ownership but ring owner is %s", key, self, owner)
			}
			if owns {
				claims++
			}
		}
		if claims != 1 {
			t.Errorf("key %q: %d nodes claim ownership, want exactly 1", key, claims)
		}
		// The owning node agrees it owns the key.
		if !mem[owner].OwnsKey(key) {
			t.Errorf("key %q: ring owner %s does not report OwnsKey()=true", key, owner)
		}
	}
}

// TestMembership_IntendedOwnerMatchesHealthyOwner: with every peer healthy, the
// health-aware Owner() and the health-ignoring IntendedOwner() agree. (IntendedOwner
// is what the fallback path uses to detect "the owner is down" — it must equal the
// real owner in the all-healthy case, else strict/degraded fallback misfires.)
func TestMembership_IntendedOwnerMatchesHealthyOwner(t *testing.T) {
	a := "http://10.0.0.1:6081"
	b := "http://10.0.0.2:6081"
	m, err := New(staticCfg(t, a, ModeOwner, FallbackDegraded, a, b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()
	for i := 0; i < 100; i++ {
		key := itoa(i)
		want, ok1 := m.Owner(key)
		got, ok2 := m.IntendedOwner(key)
		if ok1 != ok2 || want != got {
			t.Errorf("key %q: Owner=(%q,%v) IntendedOwner=(%q,%v) — must agree when all healthy", key, want, ok1, got, ok2)
		}
	}
}

// TestMembership_Accessors pins the small accessors used by the routing layer.
func TestMembership_Accessors(t *testing.T) {
	a := "http://10.0.0.1:6081"
	b := "http://10.0.0.2:6081"
	cfg := staticCfg(t, a, ModeOwner, FallbackDegraded, a, b)
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()
	if m.Region() != "gra" {
		t.Errorf("Region() = %q, want gra", m.Region())
	}
	if m.Self() != cfg.Self {
		t.Errorf("Self() = %q, want %q", m.Self(), cfg.Self)
	}
	if m.PeerCount() != 2 {
		t.Errorf("PeerCount() = %d, want 2", m.PeerCount())
	}
}

// TestModeAndFallbackString round-trips the keyword<->enum mapping that Parse and
// String share, so a rename on one side can't silently diverge from the other.
func TestModeAndFallbackString(t *testing.T) {
	if ModeReadThrough.String() != "read_through" || ModeOwner.String() != "owner" {
		t.Errorf("Mode strings: %q %q", ModeReadThrough.String(), ModeOwner.String())
	}
	if Mode(99).String() != "read_through" {
		t.Errorf("unknown Mode should render as the default keyword")
	}
	if FallbackDegraded.String() != "degraded" || FallbackStrict.String() != "strict" {
		t.Errorf("Fallback strings: %q %q", FallbackDegraded.String(), FallbackStrict.String())
	}
	if Fallback(99).String() != "degraded" {
		t.Errorf("unknown Fallback should render as the default keyword")
	}
}
