package config

import "testing"

// TestAdminExposureWarning verifies that a non-loopback admin bind is flagged
// (the admin API is plain HTTP gated only by a bearer token, so exposing it past
// loopback sends the token across the network in cleartext), while loopback binds
// are silent.
func TestAdminExposureWarning(t *testing.T) {
	safe := []string{"127.0.0.1:9090", "localhost:9090", "[::1]:9090", "127.0.0.5:0"}
	for _, a := range safe {
		if w := AdminExposureWarning(a); w != "" {
			t.Errorf("AdminExposureWarning(%q) = %q, want empty (loopback is safe)", a, w)
		}
	}
	exposed := []string{":9090", "0.0.0.0:9090", "[::]:9090", "192.168.1.5:9090", "10.0.0.1:9090"}
	for _, a := range exposed {
		if w := AdminExposureWarning(a); w == "" {
			t.Errorf("AdminExposureWarning(%q) = empty, want a warning (non-loopback bind)", a)
		}
	}
	// A malformed address is the validator's job, not ours — stay silent.
	if w := AdminExposureWarning("not an addr"); w != "" {
		t.Errorf("AdminExposureWarning(malformed) = %q, want empty", w)
	}
}
