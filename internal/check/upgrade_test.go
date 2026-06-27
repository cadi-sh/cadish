package check

import "testing"

// TestUpgradeIsRecvPhase: `upgrade @scope` is a RECV-phase directive (it decides the
// connection-upgrade tunnel before LOOKUP/ORIGIN), so `cadish check` counts it in RECV.
func TestUpgradeIsRecvPhase(t *testing.T) {
	src := `chat.example {
	upstream ws { to http://chat:80 }
	@sock path /socket.io/*
	route @sock -> ws
	upgrade @sock
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	s := firstSite(t, r)
	// route (RECV) + upgrade (RECV) = 2.
	if got := s.PhaseCounts[PhaseRECV]; got != 2 {
		t.Errorf("PhaseCounts[RECV] = %d, want 2 (route + upgrade)\n%s", got, render(t, r))
	}
}

// TestUpgradeScopeMatcherNotUnused: a matcher referenced ONLY by an `upgrade @scope`
// (here also by `route`, but the principle mirrors pass/strip_cookies) must not be
// flagged unused, and `cadish check` must be clean (no unknown-directive warning for
// `upgrade`).
func TestUpgradeScopeMatcherNotUnused(t *testing.T) {
	src := `chat.example {
	upstream ws { to http://chat:80 }
	@sock path /socket.io/*
	upgrade @sock
	route @sock -> ws
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-matcher"]; n != 0 {
		t.Fatalf("unused-matcher warnings = %d, want 0 (@sock is used by upgrade/route)\n%s", n, render(t, r))
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Fatalf("unknown-directive warnings = %d, want 0 (upgrade is a known directive)\n%s", n, render(t, r))
	}
	if n := codes(r)["undefined-matcher"]; n != 0 {
		t.Fatalf("undefined-matcher warnings = %d, want 0\n%s", n, render(t, r))
	}
}
