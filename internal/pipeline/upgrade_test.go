package pipeline

import "testing"

// TestEvalRequestUpgradeSetsUpgradeAndPass verifies that an `upgrade @scope` rule
// marks a matching request Upgrade AND implies Pass (a tunnel is off the cache
// path), while a non-matching request is neither.
func TestEvalRequestUpgradeSetsUpgradeAndPass(t *testing.T) {
	p := compileSrc(t, `x {
		@sock path /ws/*
		route @sock -> chat
		upgrade @sock
		upstream chat { to http://chat:80 }
	}
`)
	t.Run("match", func(t *testing.T) {
		dec := p.EvalRequest(&Request{Method: "GET", Path: "/ws/socket"})
		if !dec.Upgrade {
			t.Fatalf("Upgrade = false, want true")
		}
		if !dec.Pass {
			t.Fatalf("Pass = false, want true (upgrade implies pass)")
		}
		if dec.Upstream != "chat" {
			t.Fatalf("Upstream = %q, want chat", dec.Upstream)
		}
	})
	t.Run("no-match", func(t *testing.T) {
		dec := p.EvalRequest(&Request{Method: "GET", Path: "/home"})
		if dec.Upgrade {
			t.Fatalf("Upgrade = true, want false for a non-matching path")
		}
		if dec.Pass {
			t.Fatalf("Pass = true, want false for a non-matching path")
		}
	})
}

// TestUpgradeNeedsScope rejects a bare `upgrade` with no matcher/condition (it must
// be scoped, exactly like `pass`).
func TestUpgradeNeedsScope(t *testing.T) {
	ce := compileErr(t, `x {
		upgrade
		upstream chat { to http://chat:80 }
	}
`)
	if ce.Msg == "" {
		t.Fatalf("want a compile error message for bare upgrade")
	}
}

// TestUpgradeRejectsResponsePhaseMatcher ensures `upgrade` is a RECV-phase directive:
// a response-phase matcher (set_cookie/content_type) is rejected like `pass`.
func TestUpgradeRejectsResponsePhaseMatcher(t *testing.T) {
	_ = compileErr(t, `x {
		@ct content_type text/html
		upgrade @ct
		upstream chat { to http://chat:80 }
	}
`)
}
