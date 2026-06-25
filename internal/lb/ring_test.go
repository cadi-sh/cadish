package lb

import (
	"fmt"
	"testing"
)

// TestRingDistribution checks that keys spread reasonably evenly across backends
// (no backend gets a wildly disproportionate share with the default replica
// count).
func TestRingDistribution(t *testing.T) {
	ids := []string{"a", "b", "c", "d", "e"}
	r := newRing(0, ids)
	counts := map[string]int{}
	const n = 50000
	for i := 0; i < n; i++ {
		id, ok := r.lookup(fmt.Sprintf("key-%d", i), nil)
		if !ok {
			t.Fatal("lookup failed on non-empty ring")
		}
		counts[id]++
	}
	ideal := float64(n) / float64(len(ids))
	for _, id := range ids {
		got := float64(counts[id])
		dev := (got - ideal) / ideal
		if dev < -0.30 || dev > 0.30 {
			t.Errorf("backend %q got %d keys (%.1f%% off ideal %.0f)", id, counts[id], dev*100, ideal)
		}
	}
}

// TestRingStabilityOnRemove verifies the core consistent-hashing property: when
// a backend is removed, only keys that belonged to it move; every other key
// stays on its original backend.
func TestRingStabilityOnRemove(t *testing.T) {
	ids := []string{"a", "b", "c", "d", "e"}
	r1 := newRing(0, ids)
	// Remove "c".
	r2 := newRing(0, []string{"a", "b", "d", "e"})

	const n = 20000
	moved, movedFromC, movedFromOther := 0, 0, 0
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("user-%d", i)
		before, _ := r1.lookup(k, nil)
		after, _ := r2.lookup(k, nil)
		if before == after {
			continue
		}
		moved++
		if before == "c" {
			movedFromC++
		} else {
			movedFromOther++
		}
	}
	if movedFromOther != 0 {
		t.Errorf("removing c moved %d keys that were NOT on c (should be 0)", movedFromOther)
	}
	if movedFromC == 0 {
		t.Error("expected c's keys to move, none did")
	}
	// Sanity: moved share is roughly 1/N.
	frac := float64(moved) / float64(n)
	if frac < 0.10 || frac > 0.30 {
		t.Errorf("moved fraction %.3f not near 1/5=0.2", frac)
	}
}

// TestRingStabilityOnAdd verifies that adding a backend only pulls keys onto the
// new backend; no key moves between two pre-existing backends.
func TestRingStabilityOnAdd(t *testing.T) {
	r1 := newRing(0, []string{"a", "b", "c", "d"})
	r2 := newRing(0, []string{"a", "b", "c", "d", "e"})

	const n = 20000
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("obj-%d", i)
		before, _ := r1.lookup(k, nil)
		after, _ := r2.lookup(k, nil)
		if before != after && after != "e" {
			t.Fatalf("key %q moved %s->%s but new backend is e", k, before, after)
		}
	}
}

// TestRingEligibleSkipsDead checks that lookup walks clockwise past ineligible
// backends (the health-aware rehash) and that a key whose owner is alive is
// unaffected.
func TestRingEligibleSkipsDead(t *testing.T) {
	ids := []string{"a", "b", "c"}
	r := newRing(0, ids)

	// Find a key owned by "a".
	var keyOnA string
	for i := 0; i < 1000; i++ {
		k := fmt.Sprintf("k%d", i)
		if id, _ := r.lookup(k, nil); id == "a" {
			keyOnA = k
			break
		}
	}
	if keyOnA == "" {
		t.Fatal("no key found owned by a")
	}

	// With a dead, the key must rehash to b or c (not fail, not stay on a).
	dead := map[string]bool{"a": true}
	got, ok := r.lookup(keyOnA, func(id string) bool { return !dead[id] })
	if !ok || got == "a" {
		t.Fatalf("expected rehash off dead a, got %q ok=%v", got, ok)
	}

	// A key whose owner is alive is unaffected by a being dead.
	for i := 0; i < 1000; i++ {
		k := fmt.Sprintf("k%d", i)
		full, _ := r.lookup(k, nil)
		if full == "a" {
			continue
		}
		filtered, _ := r.lookup(k, func(id string) bool { return !dead[id] })
		if full != filtered {
			t.Fatalf("key %q owner changed %s->%s when only a died", k, full, filtered)
		}
	}
}

// TestRingAllDead returns not-ok when nothing is eligible.
func TestRingAllDead(t *testing.T) {
	r := newRing(0, []string{"a", "b"})
	_, ok := r.lookup("anything", func(string) bool { return false })
	if ok {
		t.Error("expected ok=false when no backend eligible")
	}
}

// TestRingEmpty handles the zero-backend ring.
func TestRingEmpty(t *testing.T) {
	r := newRing(0, nil)
	if _, ok := r.lookup("x", nil); ok {
		t.Error("empty ring should return ok=false")
	}
	if r.len() != 0 {
		t.Errorf("empty ring len = %d, want 0", r.len())
	}
}
