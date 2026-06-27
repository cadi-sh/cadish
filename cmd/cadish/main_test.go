package main

import "testing"

// TestRunDispatch pins the top-level command dispatch: an unknown command and a
// no-args invocation must print usage and exit non-zero (2); help/version variants
// exit 0. An operator scripts against these exit codes.
func TestRunDispatch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, 2},
		{"unknown command", []string{"bogus-subcommand"}, 2},
		{"help", []string{"help"}, 0},
		{"-h", []string{"-h"}, 0},
		{"--help", []string{"--help"}, 0},
		{"version", []string{"version"}, 0},
		{"-v", []string{"-v"}, 0},
		{"--version", []string{"--version"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}
