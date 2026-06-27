package edgeir

import (
	"strings"
	"testing"
)

// TestUpstreamHealthyIsServerOnlyDelegated: live upstream-pool health is a property of
// the Cadish server's lb state with NO edge analogue (like the security gate, D49). The
// projector must (1) mark the `upstream_healthy` matcher ServerOnly in the IR so the
// worker fails it closed, and (2) record an EXPLICIT Delegate entry (never silently
// drop it). The rest of the site must still project cleanly.
func TestUpstreamHealthyIsServerOnlyDelegated(t *testing.T) {
	const src = `example.com {
		@probe path /aws-health-check
		@live  upstream_healthy cache_pool
		respond @probe @live 200 "OK"
		respond @probe 503
		respond /ping 200 "pong"
		cache_key url host
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}

	// (1) The matcher is projected with its kind, but flagged server-only so the worker
	// runtime fails it closed (rather than silently mis-projecting a meaningless matcher).
	m, ok := ir.Matchers["live"]
	if !ok {
		t.Fatal("@live matcher missing from IR")
	}
	if m.Kind != "upstream_healthy" {
		t.Errorf("@live kind = %q, want upstream_healthy", m.Kind)
	}
	if !m.ServerOnly {
		t.Error("@live (upstream_healthy) must be marked ServerOnly in the edge IR")
	}

	// (2) Explicit delegation — never silently dropped: there is a Delegate entry naming
	// the matcher, and the coverage report counts it.
	foundDelegate := false
	for _, d := range ir.Delegate {
		if d.Directive == "upstream_healthy" {
			foundDelegate = true
			if d.Reason == "" {
				t.Error("upstream_healthy delegate has empty reason")
			}
		}
	}
	if !foundDelegate {
		t.Errorf("upstream_healthy not in Delegate list (must be explicit, not silently dropped); delegate = %+v", ir.Delegate)
	}
	if rep.Delegated == 0 {
		t.Error("coverage report must count the delegated upstream_healthy matcher")
	}

	// The rest of the site still projects cleanly: the exact-path `respond /ping` is
	// edge-native, and the cache_key recipe (url, host) projects.
	foundPing := false
	for _, r := range ir.Recv.Respond {
		if r.Path == "/ping" && r.Status == 200 {
			foundPing = true
		}
	}
	if !foundPing {
		t.Error("exact-path `respond /ping` should still project edge-native alongside a server-only matcher")
	}
	if len(ir.Key.Tokens) == 0 {
		t.Error("cache_key recipe should still project to the edge IR")
	}

	// A coverage warning must mention the server-only matcher so the operator knows it
	// runs on the Cadish server behind.
	foundWarn := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "live") && strings.Contains(strings.ToLower(w), "server") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Errorf("expected a SERVER-ONLY warning naming @live; warnings = %v", rep.Warnings)
	}
}
