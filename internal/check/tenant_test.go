package check

import "testing"

// TestGroupExpandedInCheck: `cadish check` expands a group and reports one site
// per tenant, with `tenant` recognized (no unknown-directive warning).
func TestGroupExpandedInCheck(t *testing.T) {
	src := []byte(`group {
    cache { ram 16MiB }
    cache_key {tenant} host path
    upstream web { to http://base:8080 }

    tenant brand-a {
        host brand-a.com
        upstream web { to http://a:8080 }
    }
    tenant brand-b {
        host brand-b.com
    }
}`)
	r, err := CheckSource("group.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if len(r.Sites) != 2 {
		t.Fatalf("report has %d sites, want 2 (one per tenant)", len(r.Sites))
	}
	if c := codes(r); c["unknown-directive"] != 0 {
		t.Errorf("tenant/group should be recognized, got unknown-directive=%d", c["unknown-directive"])
	}
	// The expanded sites should carry the tenant hosts as addresses.
	addrs := map[string]bool{}
	for _, s := range r.Sites {
		for _, a := range s.Addresses {
			addrs[a] = true
		}
	}
	if !addrs["brand-a.com"] || !addrs["brand-b.com"] {
		t.Errorf("expanded site addresses missing tenant hosts: %v", addrs)
	}
}

// TestTenantDirectiveRecognized: a standalone `tenant NAME` is a known SETUP
// directive (no unknown warning).
func TestTenantDirectiveRecognized(t *testing.T) {
	r, err := CheckSource("t.cadish", []byte("example.com {\n tenant acme\n cache_key {tenant} host path\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if codes(r)["unknown-directive"] != 0 {
		t.Errorf("`tenant` should be a known directive")
	}
	if r.Sites[0].PhaseCounts[PhaseSetup] < 1 {
		t.Errorf("`tenant` should count in SETUP")
	}
}
