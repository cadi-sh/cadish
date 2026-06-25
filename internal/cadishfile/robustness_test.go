package cadishfile

import (
	"strings"
	"testing"
)

// TestDeepNestingRejected verifies that a pathologically deep block nesting is
// rejected with a clean *ParseError rather than crashing the process with an
// uncatchable "goroutine stack exceeds" fatal error. Before the depth cap this
// input grew the parser's recursion until the runtime aborted.
func TestDeepNestingRejected(t *testing.T) {
	// Comfortably above maxBlockDepth so the cap definitely trips, yet small
	// enough to stay fast.
	n := maxBlockDepth + 100
	var b strings.Builder
	b.WriteString("x ")
	for i := 0; i < n; i++ {
		b.WriteString("d {")
	}
	for i := 0; i < n; i++ {
		b.WriteString("}")
	}
	_, err := Parse("deep", []byte(b.String()))
	if err == nil {
		t.Fatalf("expected a ParseError for deeply nested config, got nil")
	}
	if _, ok := err.(*ParseError); !ok {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "nesting too deep") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestModerateNestingAccepted ensures the cap does not reject legitimate,
// realistically-nested configs.
func TestModerateNestingAccepted(t *testing.T) {
	n := 100 // far more nesting than any real Cadishfile uses
	var b strings.Builder
	b.WriteString("x ")
	for i := 0; i < n; i++ {
		b.WriteString("d {\n")
	}
	for i := 0; i < n; i++ {
		b.WriteString("}\n")
	}
	if _, err := Parse("moderate", []byte(b.String())); err != nil {
		t.Fatalf("moderate nesting (%d) should parse, got error: %v", n, err)
	}
}

// TestBracePlaceholderBombBounded verifies that a long run of nested braces that
// looks like a placeholder is handled in bounded time without recursion in the
// lexer (scanPlaceholder / looksLikePlaceholder are iterative). It must not
// crash; whether it parses or errors is irrelevant.
func TestBracePlaceholderBombBounded(t *testing.T) {
	n := 100000
	src := "x " + strings.Repeat("{", n) + strings.Repeat("}", n) + "\n"
	// Must return (no panic, no hang); result is don't-care.
	_, _ = Parse("bomb", []byte(src))
}

// TestFormatRoundTripRegressions pins two FuzzParse-discovered round-trip bugs:
// the formatter must never emit output that Format/Parse then rejects.
//
//  1. "@0 0\"": a matcher type containing a quote was accepted as a bare word but
//     re-emitted quoted, which the parser rejects (a matcher type must be bare).
//     Fixed by rejecting a quote-forcing matcher type at parse time.
//  2. "\"\\\x05\"": a disallowed control char (0x05) smuggled into a quoted
//     string via a backslash escape was accepted, then the formatter doubled the
//     backslash — unescaping the control char — so re-parse rejected it. Fixed by
//     rejecting a disallowed control char even when it follows a backslash.
func TestFormatRoundTripRegressions(t *testing.T) {
	for _, src := range []string{
		"@0 0\"",        // matcher type with embedded quote
		"\"\\\x05\"",    // control char after backslash inside a quoted string
		"@m \"path\"",   // a quoted matcher type must be rejected
		"\"\\\x00\"",    // NUL after backslash
		"x {\n @m h;\n", // unterminated block still errors cleanly
	} {
		// 1) Parsing must not panic.
		_, perr := Parse("rt", []byte(src))
		_ = perr

		// 2) If Format succeeds, its output must Parse and re-Format identically.
		out, ferr := Format([]byte(src))
		if ferr != nil {
			continue // refusing to format an invalid config is fine.
		}
		if _, err := Parse("rt-out", out); err != nil {
			t.Fatalf("Format(%q) = %q which then fails to Parse: %v", src, out, err)
		}
		out2, ferr2 := Format(out)
		if ferr2 != nil {
			t.Fatalf("re-Format of %q (from %q) errored: %v", out, src, ferr2)
		}
		if string(out) != string(out2) {
			t.Fatalf("Format not idempotent for %q: once=%q twice=%q", src, out, out2)
		}
	}
}

// TestControlCharAfterBackslashRejected nails the specific lexer fix: a
// disallowed control character inside a quoted string is rejected whether or not
// it is preceded by a backslash.
func TestControlCharAfterBackslashRejected(t *testing.T) {
	for _, src := range []string{
		"\"\\\x05\"", // ESC-style control after backslash
		"\"\\\x00\"", // NUL after backslash
		"\"\\\x1f\"", // unit separator after backslash
	} {
		if _, err := Parse("ctl", []byte(src)); err == nil {
			t.Fatalf("expected a ParseError for %q, got nil", src)
		}
	}
}

// TestMismatchedBracesNoPanic covers the recon "{{ {" hypothesis: truncated /
// mismatched braces must produce an error, never an index panic in cur().
func TestMismatchedBracesNoPanic(t *testing.T) {
	for _, src := range []string{
		"{{ {",
		"{",
		"}",
		"{ {",
		"x { y {",
		"x {}}",
		"{{{{{",
		"}}}}}",
	} {
		// The only invariant: no panic. Errors are expected and fine.
		_, _ = Parse("mismatch", []byte(src))
	}
}
