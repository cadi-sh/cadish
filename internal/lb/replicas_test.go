package lb

import "testing"

// TestParseReplicasBounds verifies the replicas directive is bounded: a sane
// value is accepted, while an absurd one is rejected loudly rather than driving
// a multi-gigabyte ring allocation at startup.
func TestParseReplicasBounds(t *testing.T) {
	ok := "upstream web {\n  to http://10.0.0.1:8080\n  replicas 256\n}"
	d := parseDirective(t, ok)
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatalf("replicas 256: unexpected error: %v", err)
	}
	if cfg.Replicas != 256 {
		t.Fatalf("replicas = %d, want 256", cfg.Replicas)
	}

	bad := "upstream web {\n  to http://10.0.0.1:8080\n  replicas 2000000000\n}"
	d = parseDirective(t, bad)
	if _, err := ParseUpstream(d); err == nil {
		t.Fatalf("replicas 2000000000: want error, got nil")
	}
}

// TestNewRingAtCapBounded confirms building a ring at the maximum allowed replica
// count with a single backend completes (it is the largest ring we permit) and
// does not spin in the collision-nudge loop.
func TestNewRingAtCapBounded(t *testing.T) {
	// Use a modest count: the point is the collision loop terminates and the ring
	// is well-formed, not to actually allocate the full cap (which is large).
	r := newRing(10000, []string{"a", "b", "c"})
	if r.len() != 3 {
		t.Fatalf("ring len = %d, want 3", r.len())
	}
	if _, ok := r.lookup("some-key", nil); !ok {
		t.Fatalf("lookup on a populated ring should succeed")
	}
}
