package check

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// TestServerDirectiveNotFlagged: a global `server { … }` block (the inbound
// maxconn/timeout knobs) must NOT produce an unknown-directive warning and must be
// classified as a Setup directive (zero per-request cost).
func TestServerDirectiveNotFlagged(t *testing.T) {
	src := "{\n  server {\n    maxconn 40960\n    read_timeout 30s\n    idle_timeout 120s\n  }\n}\nexample.com {\n  upstream app { to http://127.0.0.1:8080 }\n}\n"
	rep, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if c := codes(rep); c["unknown-directive"] != 0 {
		t.Errorf("server block produced unknown-directive warning(s): %+v", rep.Diagnostics)
	}
	if rep.ExitCode(true) != 0 {
		t.Errorf("strict ExitCode = %d, want 0 for a valid server config", rep.ExitCode(true))
	}
	if got := phaseOf("server"); got != PhaseSetup {
		t.Errorf("phaseOf(server) = %v, want PhaseSetup", got)
	}
	if !defaultDirectives["server"] {
		t.Error("server should be a known default directive")
	}
	// A stray `server` in a site body is flagged unknown like its global peers? No —
	// it is a registered directive name, so it is never flagged unknown anywhere; that
	// is the documented trade-off (consistent with admin/proxy_protocol).
	_ = cadishfile.DefaultDirectives
}

// TestServerBlockBadValueSurfaced: a malformed `server` block (bad maxconn) must be
// surfaced by `cadish check` as a build-error, the same way `cadish run` rejects it
// (check↔run parity on the global block).
func TestServerBlockBadValueSurfaced(t *testing.T) {
	src := "{\n  server { maxconn nope }\n}\nexample.com {\n  upstream app { to http://127.0.0.1:8080 }\n}\n"
	rep, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if codes(rep)["build-error"] == 0 {
		t.Errorf("a bad `server { maxconn nope }` should surface a build-error, got %+v", rep.Diagnostics)
	}
}
