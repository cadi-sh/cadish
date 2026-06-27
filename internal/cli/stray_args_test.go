package cli

import "testing"

// A stray positional argument on a -config subcommand must FAIL LOUDLY (exit 2),
// not be silently ignored — otherwise `cadish check site.Cadishfile` would load the
// default ./Cadishfile and the operator would validate/serve a file they did not name.
func TestStrayPositionalArgRejected(t *testing.T) {
	cases := []struct {
		name string
		fn   func([]string) int
	}{
		{"check", Check},
		{"run", Run},
		{"edge build", EdgeBuild},
		{"edge deploy", EdgeDeploy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn([]string{"some-stray-file.Cadishfile"}); got != 2 {
				t.Fatalf("%s with a stray positional: got exit %d, want 2 (must reject, not silently use ./Cadishfile)", tc.name, got)
			}
		})
	}
	t.Run("edge enable", func(t *testing.T) {
		if got := EdgeManageRoutes([]string{"stray"}, "enable"); got != 2 {
			t.Fatalf("edge enable with a stray positional: got exit %d, want 2", got)
		}
	})
}

// Control: a normal -config to a missing file must surface the file error (exit 1),
// NOT trip the stray-arg guard — the guard must only fire on unconsumed positionals.
func TestConfigFlagDoesNotTripStrayGuard(t *testing.T) {
	if got := Check([]string{"-config", "this-file-does-not-exist-9f3c.Cadishfile"}); got != 1 {
		t.Fatalf("check -config <missing>: got exit %d, want 1 (file error, not the stray-arg guard)", got)
	}
}
