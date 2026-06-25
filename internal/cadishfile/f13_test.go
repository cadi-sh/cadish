package cadishfile

import (
	"strings"
	"testing"
)

// TestLexRejectsNUL: a NUL byte (and other C0 control characters) inside a token
// must be a parse error, not silently accepted — a NUL in a site address would
// otherwise register the wrong host (F13 bug 3).
func TestLexRejectsNUL(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"in site address", "examp\x00le.com {\n}\n"},
		{"in directive arg", "x {\n  header A val\x00ue\n}\n"},
		{"in quoted string", "x {\n  header A \"oo\x00ps\"\n}\n"},
		{"in placeholder", "x {\n  cache_key {de\x00vice}\n}\n"},
		{"other control char", "x {\n  header A va\x01ue\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("c", []byte(tc.src))
			if err == nil {
				t.Fatalf("expected a parse error for a control character, got nil")
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if !strings.Contains(pe.Msg, "control character") {
				t.Errorf("error msg = %q, want it to mention a control character", pe.Msg)
			}
		})
	}
}

// TestLexNULErrorNaming: a NUL is named "NUL" (consistent rendering), not an
// arbitrary escape, so check and compile output agree (F13 bug 3).
func TestLexNULErrorNaming(t *testing.T) {
	_, err := Parse("c", []byte("examp\x00le.com {\n}\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("error = %q, want it to name NUL", err.Error())
	}
}

// TestFormatPreservesTrailingCommentOnBraceLines: a trailing comment on a "{" or
// "}" line must stay on that line through a fmt round-trip (F13 bug 5).
func TestFormatPreservesTrailingCommentOnBraceLines(t *testing.T) {
	// fmt normalizes the gap before a trailing comment to a single space (the
	// house style, matching trailing comments on statement lines), but keeps the
	// comment on the brace's line rather than relocating it.
	in := "example.com {  # site\n    cache_key url\n}  # end\n"
	got := mustFormat(t, in)
	want := "example.com { # site\n    cache_key url\n} # end\n"
	if got != want {
		t.Errorf("trailing brace comments moved\n got: %q\nwant: %q", got, want)
	}
	// Idempotent.
	if again := mustFormat(t, got); again != got {
		t.Errorf("not idempotent\n once: %q\ntwice: %q", got, again)
	}
}

// TestFormatRejectsUnterminatedBlock: fmt must FAIL (return an error, write
// nothing) for a config with an unterminated block, never emit truncated output
// (F13 bug 6).
func TestFormatRejectsUnterminatedBlock(t *testing.T) {
	out, err := Format([]byte("example.com {\n    cache_key url\n"))
	if err == nil {
		t.Fatalf("expected an error for an unterminated block; got output %q", out)
	}
	if out != nil {
		t.Errorf("expected nil output on error, got %q", out)
	}
}
