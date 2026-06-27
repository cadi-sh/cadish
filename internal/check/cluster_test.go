package check

import (
	"strings"
	"testing"
)

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

// TestCheck_ClusterMembershipMalformed is the R08 regression: a malformed `cluster { … }`
// membership block (here an unknown `mode`) is built by `run` via cluster.Parse, but
// `cadish check`'s origin-structure pass SKIPPED the membership block — so the config
// passed check (exit 0) then failed at `cadish run` config-build (the exact failure check
// exists to pre-empt). check now reproduces cluster.Parse, surfacing the SAME positioned
// build-error.
func TestCheck_ClusterMembershipMalformed(t *testing.T) {
	src := []byte(`example.com {
	cache { ram 64MiB }
	upstream backend { to http://origin.example.com }
	cluster {
		self     http://10.0.0.1:6081
		peers    http://10.0.0.1:6081 http://10.0.0.2:6081
		region   gra
		mode     sideways
		fallback degraded
	}
	cache_ttl default ttl 60s
}
`)
	r, err := CheckSource("test.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	var found *Diagnostic
	for i := range r.Diagnostics {
		if d := &r.Diagnostics[i]; d.Code == "build-error" && strings.Contains(d.Message, "mode") {
			found = d
		}
	}
	if found == nil {
		t.Fatalf("expected a build-error for the bad cluster mode; diagnostics=%v", r.Diagnostics)
	}
	if found.Severity != SevError {
		t.Errorf("severity = %v, want error", found.Severity)
	}
	if !strings.Contains(found.Position, ":") {
		t.Errorf("position = %q, want file:line:col", found.Position)
	}
}

// TestCheck_ClusterMembershipMissingRegion covers another cluster.Parse error class —
// the required `region` is absent — confirming it too surfaces at check (not only run).
func TestCheck_ClusterMembershipMissingRegion(t *testing.T) {
	src := []byte(`example.com {
	cache { ram 64MiB }
	upstream backend { to http://origin.example.com }
	cluster {
		self  http://10.0.0.1:6081
		peers http://10.0.0.1:6081 http://10.0.0.2:6081
	}
	cache_ttl default ttl 60s
}
`)
	r, err := CheckSource("test.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	var found bool
	for _, d := range r.Diagnostics {
		if d.Code == "build-error" && strings.Contains(d.Message, "region") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a build-error for the missing cluster region; diagnostics=%v", r.Diagnostics)
	}
}
