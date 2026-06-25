package cli

import (
	"strings"
	"testing"
)

// TestLogSocketPathPerInstance: the DEFAULT access-log socket path is per-instance
// (derived from the listen address) so two co-located cadish instances on different
// addresses do not clash on one process-global socket (the 2nd silently losing
// `cadish logs` live streaming).
func TestLogSocketPathPerInstance(t *testing.T) {
	t.Setenv("CADISH_ACCESS_SOCKET", "") // ensure no override in effect
	a := defaultLogSocketPathFor(":80")
	b := defaultLogSocketPathFor(":8080")
	if a == b {
		t.Fatalf("two distinct listen addrs produced the SAME default socket path %q — co-located instances would clash", a)
	}
	if !strings.HasSuffix(a, ".sock") {
		t.Errorf("default socket path %q does not look like a .sock path", a)
	}
}

// TestLogSocketPathStableForAddr: the per-instance default must be DETERMINISTIC for
// a given address so `cadish run` and `cadish logs` derive the same path and the
// no-flag live-tail workflow keeps working.
func TestLogSocketPathStableForAddr(t *testing.T) {
	t.Setenv("CADISH_ACCESS_SOCKET", "")
	if defaultLogSocketPathFor(":80") != defaultLogSocketPathFor(":80") {
		t.Fatalf("default socket path is not stable for the same addr")
	}
}

// TestLogSocketEnvOverride: CADISH_ACCESS_SOCKET overrides the per-instance default
// (kept as the explicit escape hatch).
func TestLogSocketEnvOverride(t *testing.T) {
	t.Setenv("CADISH_ACCESS_SOCKET", "/run/custom.sock")
	if got := defaultLogSocketPathFor(":80"); got != "/run/custom.sock" {
		t.Fatalf("CADISH_ACCESS_SOCKET override = %q, want /run/custom.sock", got)
	}
}
