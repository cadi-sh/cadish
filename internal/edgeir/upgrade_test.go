package edgeir

import "testing"

// TestProjectUpgradeIsDelegated: an `upgrade @scope` directive is inherently
// server-only (a live, hijacked WebSocket tunnel a stateless worker cannot host). It
// must NOT be projected into the worker IR — it lands in delegate[] with a reason
// (never silently dropped), like `rewrite`/`encode`, so the coverage report records
// it and `-strict` fails.
func TestProjectUpgradeIsDelegated(t *testing.T) {
	src := `chat.example {
    upstream ws { to http://chat:80 }
    @sock path /socket.io/*
    route @sock -> ws
    upgrade @sock
    cache_ttl default ttl 1m
}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	found := false
	for _, d := range ir.Delegate {
		if d.Directive == "upgrade" {
			found = true
			if d.Reason == "" {
				t.Error("delegate upgrade has empty reason")
			}
			if d.Scope == nil {
				t.Error("delegate upgrade has no scope (should carry @sock)")
			}
		}
	}
	if !found {
		t.Errorf("upgrade not delegated; delegate = %+v", ir.Delegate)
	}
	if !containsReason(rep.DelegatedItems, "upgrade") {
		t.Errorf("upgrade not in coverage report; report = %+v", rep.DelegatedItems)
	}
}
