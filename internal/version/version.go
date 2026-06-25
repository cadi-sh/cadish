// Package version exposes cadish's build/version information.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is the released version string. It is overridden at release time via
// -ldflags "-X github.com/cadi-sh/cadish/internal/version.Version=vX.Y.Z".
// For development builds it stays "dev"; String() then falls back to the module
// version embedded by the Go toolchain (so `go install …@vX.Y.Z` reports vX.Y.Z),
// and to the VCS revision/time, from the embedded build info.
var Version = "dev"

// Commit is the full git commit the binary was built from, stamped at release
// time via -ldflags "-X .../internal/version.Commit={{.FullCommit}}". When unset
// (a plain `go build`), the VCS revision from the embedded build info is used.
var Commit = ""

// Date is the build/commit date (RFC3339), stamped at release time via
// -ldflags "-X .../internal/version.Date={{.CommitDate}}". When unset, the VCS
// time from the embedded build info is used.
var Date = ""

// String returns a human-readable version line, e.g.
// "cadish v1.2.3 (abc1234def567, 2026-06-24T00:00:00Z, go1.26.0)".
// When the release-time Commit/Date vars are not stamped (a plain `go build`), it
// falls back to the VCS revision/time embedded by the Go toolchain.
func String() string {
	ver, commit, date, gover := Version, Commit, Date, "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		gover = bi.GoVersion
		// An unstamped install (`go install …@vX.Y.Z`) carries its release tag as the
		// module version; prefer it over the bare "dev" default. Keep "dev" for a
		// local/dirty build: "(devel)", a "…+dirty" marker, or a pseudo-version (which
		// has two '-' segments: a timestamp and a hash) — a clean tag has at most one.
		if mv := bi.Main.Version; ver == "dev" && mv != "" && mv != "(devel)" &&
			!strings.Contains(mv, "+") && strings.Count(mv, "-") <= 1 {
			ver = mv
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if commit == "" {
					commit = s.Value
				}
			case "vcs.time":
				if date == "" {
					date = s.Value
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	if date == "" {
		date = "unknown"
	}
	return "cadish " + ver + " (" + commit + ", " + date + ", " + gover + ")"
}
