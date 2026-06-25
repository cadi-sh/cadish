package version

import "testing"

// The package must expose Commit and Date vars (stamped via -ldflags at release
// time), and String() must include the version, commit, and date so `cadish
// version` shows the full build provenance.
func TestStringIncludesCommitAndDate(t *testing.T) {
	// Override the stamped vars to known values for a deterministic assertion.
	origV, origC, origD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = origV, origC, origD })

	Version = "v1.2.3"
	Commit = "abc1234def567"
	Date = "2026-06-24T00:00:00Z"

	got := String()
	for _, want := range []string{"v1.2.3", "abc1234def567", "2026-06-24T00:00:00Z"} {
		if !contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
