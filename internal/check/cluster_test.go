package check

import "testing"

// A `cluster { peers … }` membership block (the clustering feature, #7/#8) is the
// pre-existing `cluster` SETUP keyword and must lint cleanly: it is parsed once
// (not per request), and its inner directives (peers/region/mode/fallback/self)
// live inside the block, so the directive walk neither flags it as unknown nor
// counts it toward per-request cost.
func TestCheck_ClusterMembershipBlock(t *testing.T) {
	src := []byte(`example.com {
	cache { ram 64MiB }
	upstream backend { to http://origin.example.com }
	cluster {
		self     http://10.0.0.1:6081
		peers    http://10.0.0.1:6081 http://10.0.0.2:6081
		region   gra
		mode     owner
		fallback degraded
	}
	cache_ttl default ttl 60s
}
`)
	r, err := CheckSource("test.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if c := codes(r); c["unknown-directive"] != 0 {
		t.Errorf("cluster membership block flagged unknown-directive: %v", c)
	}
	s := firstSite(t, r)
	if s.PhaseCounts[PhaseSetup] == 0 {
		t.Errorf("cluster not counted as a setup directive")
	}
}
