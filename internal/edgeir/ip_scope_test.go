package edgeir

import (
	"strings"
	"testing"
)

// TestIPScopedPassFailsOpen (R02): an `ip` matcher is GENERAL — it can scope ANY directive,
// not just the security gate. `pass @internal_ips` previously SKIPPED the ip matcher from the
// IR while scopeView still emitted its name, leaving a dangling scope reference the runtime
// silently treated as a non-match → the edge STORED a request the server passes. The ip matcher
// is now ServerOnly, so the pass scope fails closed → the projector forces a site-wide fail-open
// pass + records a Delegate + bumps ForcedPass (so `cadish edge build` fails non-zero).
func TestIPScopedPassFailsOpen(t *testing.T) {
	const src = `example.com {
		@internal ip 10.0.0.0/8
		pass @internal
		cache_key host path
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	// The ip matcher is projected ServerOnly carrying no IP/CIDR data.
	m, ok := ir.Matchers["internal"]
	if !ok || m.Kind != "ip" || !m.ServerOnly {
		t.Fatalf("@internal must project as a ServerOnly `ip` matcher, got %+v (ok=%v)", m, ok)
	}
	if len(m.Patterns) != 0 || len(m.Values) != 0 {
		t.Errorf("the `ip` matcher must carry no data, got %+v", m)
	}
	// Fail OPEN: a site-wide unconditional pass replaces the precise `pass @internal`.
	sawAlwaysPass := false
	for _, sc := range ir.Recv.Pass {
		if sc.Always {
			sawAlwaysPass = true
		}
	}
	if !sawAlwaysPass {
		t.Errorf("an ip-scoped `pass` must force a site-wide fail-open pass; recv.pass = %+v", ir.Recv.Pass)
	}
	// And it fails the build loudly: ForcedPass > 0 (gates `cadish edge build` non-zero, R02/R16).
	if rep.ForcedPass == 0 {
		t.Error("an ip-scoped selecting directive must increment ForcedPass (so the build fails non-zero)")
	}
}

// TestIPScopedCacheKeyFailsOpen (R02): a scoped `cache_key @ip` recipe whose selector fails
// closed at the edge would otherwise fall through to a DIFFERENT recipe → a divergent key. The
// projector drops the recipe and fails open (site-wide pass) + bumps ForcedPass.
func TestIPScopedCacheKeyFailsOpen(t *testing.T) {
	const src = `example.com {
		@internal ip 10.0.0.0/8
		cache_key @internal host path
		cache_key default  host url
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if rep.ForcedPass == 0 {
		t.Error("an ip-scoped cache_key recipe must increment ForcedPass")
	}
	// The ip-scoped recipe must NOT be shipped (its selector references a ServerOnly matcher).
	for _, rc := range ir.Key.Recipes {
		if len(rc.Selector.Names) == 1 && rc.Selector.Names[0] == "internal" {
			t.Error("the ip-scoped cache_key recipe must be dropped (fail-open), not shipped to the worker")
		}
	}
	sawAlwaysPass := false
	for _, sc := range ir.Recv.Pass {
		if sc.Always {
			sawAlwaysPass = true
		}
	}
	if !sawAlwaysPass {
		t.Errorf("an ip-scoped cache_key must force a site-wide fail-open pass; recv.pass = %+v", ir.Recv.Pass)
	}
}

// TestInlineIPDoesNotPanic (R02): an INLINE `ip` matcher (`pass ip 10.0.0.0/8`) previously
// PANICKED edgeView() and crashed `cadish edge build`. It now projects as a ServerOnly inline
// `ip` matcher; the pass fails open. No panic, ForcedPass bumped.
func TestInlineIPDoesNotPanic(t *testing.T) {
	const src = `example.com {
		pass ip 10.0.0.0/8
		cache_key host path
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	ir, rep, err := Project(p) // must not panic
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if rep.ForcedPass == 0 {
		t.Error("an inline-ip-scoped pass must increment ForcedPass")
	}
	sawAlwaysPass := false
	for _, sc := range ir.Recv.Pass {
		if sc.Always {
			sawAlwaysPass = true
		}
	}
	if !sawAlwaysPass {
		t.Errorf("an inline ip-scoped `pass` must fail open to a site-wide pass; recv.pass = %+v", ir.Recv.Pass)
	}
}

// TestSecurityOnlyIPDelegatesNoForcedPass (R02): an `ip` matcher used ONLY by the security gate
// (allow/deny) is delegated (the gate is already server-only) but does NOT trip ForcedPass —
// no SELECTING directive references it, so a non-strict build still succeeds for such a site.
func TestSecurityOnlyIPDelegatesNoForcedPass(t *testing.T) {
	const src = `example.com {
		@office ip 203.0.113.43/32
		allow @office
		cache_key host path
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	irOut, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if rep.ForcedPass != 0 {
		t.Errorf("a security-only ip matcher must NOT trip ForcedPass (no selecting directive references it); got %d", rep.ForcedPass)
	}
	// It is still delegated (server-only) so -strict trips: an `ip` delegate is recorded.
	sawIPDelegate := false
	for _, d := range irOut.Delegate {
		if strings.Contains(d.Reason, "ip") {
			sawIPDelegate = true
		}
	}
	if !sawIPDelegate {
		t.Errorf("a server-only ip matcher must be explicitly delegated; delegates = %+v", irOut.Delegate)
	}
	if rep.Delegated == 0 {
		t.Error("a server-only ip matcher must be counted as delegated (so -strict trips)")
	}
}
