package check

import (
	"testing"
)

// TestAdminDirectiveNotFlagged: a global `admin { … }` block must NOT produce
// an unknown-directive warning — admin is a real, documented global block.
func TestAdminDirectiveNotFlagged(t *testing.T) {
	src := "{\n  admin {\n    auth_token sekret\n  }\n}\nexample.com {\n  upstream app { to http://127.0.0.1:8080 }\n}\n"
	rep, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	c := codes(rep)
	if c["unknown-directive"] != 0 {
		t.Errorf("admin block produced unknown-directive warning(s): %+v", rep.Diagnostics)
	}
	if rep.ExitCode(true) != 0 {
		t.Errorf("strict ExitCode = %d, want 0 for a valid admin config", rep.ExitCode(true))
	}
}
