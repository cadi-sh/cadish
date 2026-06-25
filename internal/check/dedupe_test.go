package check

import "testing"

// TestCheckDeduplicatesOneIssue is the PF1 guard: a single underlying problem (an
// unknown directive) used to be reported THREE times — a preamble [build-error], a
// per-site [unknown-directive] warning, and a per-site [compile-error] — inflating
// the summary to "2 errors, 1 warning" for one mistake. After dedup the same
// position+message collapses to a single error.
func TestCheckDeduplicatesOneIssue(t *testing.T) {
	src := []byte("example.com {\n  bogusdirective foo\n  upstream app { to http://localhost:8080 }\n}\n")
	r, err := CheckSource("pf1.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	errs, warns := r.Counts()
	if errs != 1 || warns != 0 {
		t.Fatalf("one unknown directive should count once: got %d errors, %d warnings\nall diags: %v", errs, warns, allDiagnostics(r))
	}
	// And it must appear exactly once across the whole report.
	if n := len(allDiagnostics(r)); n != 1 {
		t.Errorf("expected exactly 1 diagnostic, got %d: %v", n, allDiagnostics(r))
	}
}

// allDiagnostics flattens preamble + per-site diagnostics for assertions.
func allDiagnostics(r *Report) []Diagnostic {
	out := append([]Diagnostic(nil), r.Diagnostics...)
	for _, s := range r.Sites {
		out = append(out, s.Diagnostics...)
	}
	return out
}

// TestCheckKeepsDistinctDiagnostics ensures dedup does NOT collapse genuinely
// different findings (different position OR different message) into one: two distinct
// unknown directives must remain two distinct diagnostics (one per position).
func TestCheckKeepsDistinctDiagnostics(t *testing.T) {
	src := []byte("example.com {\n  bogusone foo\n  bogustwo bar\n  upstream app { to http://localhost:8080 }\n}\n")
	r, err := CheckSource("pf1b.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	all := allDiagnostics(r)
	if len(all) != 2 {
		t.Fatalf("two distinct unknown directives should yield 2 diagnostics, got %d: %v", len(all), all)
	}
	if all[0].Position == all[1].Position {
		t.Errorf("the two diagnostics should be at distinct positions: %v", all)
	}
}
