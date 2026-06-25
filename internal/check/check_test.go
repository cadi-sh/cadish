package check

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// td returns the path to a testdata fixture.
func td(name string) string { return filepath.Join("testdata", name) }

// firstSite returns the first site report (fatal if absent).
func firstSite(t *testing.T, r *Report) *SiteReport {
	t.Helper()
	if len(r.Sites) == 0 {
		t.Fatal("report has no sites")
	}
	return r.Sites[0]
}

// codes returns the set of diagnostic codes (with counts) across the report.
func codes(r *Report) map[string]int {
	m := map[string]int{}
	add := func(ds []Diagnostic) {
		for _, d := range ds {
			m[d.Code]++
		}
	}
	add(r.Diagnostics)
	for _, s := range r.Sites {
		add(s.Diagnostics)
	}
	return m
}

func hasSuggestion(s *SiteReport, substr string) bool {
	for _, sg := range s.Suggestions {
		if strings.Contains(sg, substr) {
			return true
		}
	}
	return false
}

// TestStorefrontMetrics pins the headline numbers for the canonical config.
func TestStorefrontMetrics(t *testing.T) {
	r, err := Check(td("storefront.A-flat.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := firstSite(t, r)

	if got, want := s.MatcherCount, 5; got != want {
		t.Errorf("MatcherCount = %d, want %d", got, want)
	}
	if got, want := s.DirectiveCount, 28; got != want {
		t.Errorf("DirectiveCount = %d, want %d", got, want)
	}
	if got, want := s.RegexEvalsPerRequest, 4; got != want {
		t.Errorf("RegexEvalsPerRequest = %d, want %d", got, want)
	}
	wantPhases := map[Phase]int{PhaseSetup: 5, PhaseRECV: 6, PhaseKEY: 1, PhaseORIGIN: 7, PhaseDELIVER: 9}
	for p, want := range wantPhases {
		if got := s.PhaseCounts[p]; got != want {
			t.Errorf("PhaseCounts[%s] = %d, want %d", p, got, want)
		}
	}
	if got, want := s.EstimatedCost, 50; got != want {
		t.Errorf("EstimatedCost = %d, want %d", got, want)
	}
	wantCB := CostBreakdown{Exact: 6, Glob: 2, Regex: 4}
	if s.CostBreakdown != wantCB {
		t.Errorf("CostBreakdown = %+v, want %+v", s.CostBreakdown, wantCB)
	}
	if errs, warns := r.Counts(); errs != 0 || warns != 0 {
		t.Errorf("counts = %d errors, %d warnings; want 0/0", errs, warns)
	}
	if !hasSuggestion(s, "@nocache collapses 24 paths") {
		t.Errorf("missing @nocache collapse suggestion; got %v", s.Suggestions)
	}
	if code := r.ExitCode(true); code != 0 {
		t.Errorf("strict ExitCode = %d, want 0", code)
	}
}

// TestDeadRules verifies first-match-wins dead-rule detection.
func TestDeadRules(t *testing.T) {
	r, err := Check(td("dead_rules.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if n := codes(r)["dead-rule"]; n != 5 {
		t.Errorf("dead-rule count = %d, want 5\n%s", n, render(t, r))
	}
	// The fixture's catch-all `pass` (bare, no matcher) also fails to compile —
	// `cadish check` now compiles the pipeline, so it surfaces a compile-error
	// (this is the safety-net: a bare `pass` would refuse to `cadish run`). The
	// dead-rule warnings are still produced; the compile-error makes exit non-zero
	// even without -strict.
	if n := codes(r)["compile-error"]; n != 1 {
		t.Errorf("compile-error count = %d, want 1\n%s", n, render(t, r))
	}
	if code := r.ExitCode(false); code != 1 {
		t.Errorf("ExitCode(false) = %d, want 1 (compile-error present)", code)
	}
	if code := r.ExitCode(true); code != 1 {
		t.Errorf("ExitCode(true) = %d, want 1", code)
	}
}

// TestWarnings verifies unknown-name, arity, duplicate and unused diagnostics.
func TestWarnings(t *testing.T) {
	r, err := Check(td("warnings.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	c := codes(r)
	for code, want := range map[string]int{
		"duplicate-matcher":    1,
		"unknown-matcher-type": 1,
		"unknown-directive":    1,
		"undefined-matcher":    1,
		"unused-matcher":       2, // @lonely and @weird
	} {
		if c[code] != want {
			t.Errorf("code %q = %d, want %d\n%s", code, c[code], want, render(t, r))
		}
	}
	if c["arity"] < 1 {
		t.Errorf("arity count = %d, want >= 1 (respond /health)", c["arity"])
	}
	// `cache_key` with no tokens has its own dedicated warning (it silently falls back
	// to the default key — a likely typo), distinct from the generic arity warning.
	if c["cache-key-empty"] != 1 {
		t.Errorf("cache-key-empty count = %d, want 1\n%s", c["cache-key-empty"], render(t, r))
	}
}

// TestSuggestions verifies collapse and regex→glob optimization hints.
func TestSuggestions(t *testing.T) {
	r, err := Check(td("collapse.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	s := firstSite(t, r)
	if !hasSuggestion(s, "collapse into one matcher") {
		t.Errorf("missing pass-collapse suggestion: %v", s.Suggestions)
	}
	if !hasSuggestion(s, "path /legacy*") {
		t.Errorf("missing regex→glob suggestion: %v", s.Suggestions)
	}
}

// TestImportResolution verifies that imported fragments are spliced in and their
// matchers become referenceable.
func TestImportResolution(t *testing.T) {
	r, err := Check(td("import_main.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if errs, _ := r.Counts(); errs != 0 {
		t.Fatalf("unexpected errors:\n%s", render(t, r))
	}
	s := firstSite(t, r)
	// @local + imported @frag = 2 matchers, both referenced (no unused warning).
	if s.MatcherCount != 2 {
		t.Errorf("MatcherCount = %d, want 2", s.MatcherCount)
	}
	if codes(r)["undefined-matcher"] != 0 {
		t.Errorf("imported @frag should resolve; got undefined-matcher\n%s", render(t, r))
	}
}

// TestImportMissing verifies a missing import is an error with position.
func TestImportMissing(t *testing.T) {
	r, err := Check(td("import_missing.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes(r)["missing-import"] != 1 {
		t.Fatalf("want one missing-import error\n%s", render(t, r))
	}
	if len(r.Diagnostics) == 0 || !strings.Contains(r.Diagnostics[0].Position, "import_missing.cadish:2:") {
		t.Errorf("missing-import diagnostic lacks position: %+v", r.Diagnostics)
	}
	if r.ExitCode(false) != 1 {
		t.Errorf("ExitCode = %d, want 1 (errors)", r.ExitCode(false))
	}
}

// TestImportCycle verifies cycle detection.
func TestImportCycle(t *testing.T) {
	r, err := Check(td("cycle_a.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes(r)["import-cycle"] != 1 {
		t.Fatalf("want one import-cycle error\n%s", render(t, r))
	}
	// PF-P1: the cycle must be reported ONCE as a clean `import-cycle`, never
	// double-counted as a `build-error`, and the internal "call SpliceImports before
	// Compile" message must never leak to the user.
	if n := codes(r)["build-error"]; n != 0 {
		t.Errorf("import cycle leaked %d build-error(s): %s", n, render(t, r))
	}
	for _, d := range r.Diagnostics {
		if strings.Contains(d.Message, "SpliceImports") || strings.Contains(d.Message, "before Compile") {
			t.Errorf("import-cycle diagnostic leaks internal message: %q", d.Message)
		}
	}
	if r.ExitCode(false) != 1 {
		t.Errorf("ExitCode = %d, want 1", r.ExitCode(false))
	}
}

// TestImportGlob verifies `import <glob>` splices every matching fragment (PF-D2).
func TestImportGlob(t *testing.T) {
	dir := t.TempDir()
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	must("10-a.Cadishfile", "@a path /a/*\n")
	must("20-b.Cadishfile", "@b path /b/*\n")
	must("root.Cadishfile", "example.com {\n upstream o { to http://127.0.0.1:8080 }\n import *.Cadishfile\n pass @a\n pass @b\n}\n")
	r, err := Check(filepath.Join(dir, "root.Cadishfile"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Both globbed matchers must be defined (so `pass @a`/`pass @b` are not flagged
	// `undefined-matcher`) and there must be no import error.
	if n := codes(r)["undefined-matcher"]; n != 0 {
		t.Errorf("glob import left %d undefined matcher(s): %s", n, render(t, r))
	}
	if n := codes(r)["missing-import"]; n != 0 {
		t.Errorf("glob import reported %d missing-import: %s", n, render(t, r))
	}
}

// TestImportGlobNoMatch verifies a glob matching zero files is reported ONCE as a
// clear error, not a silent empty splice nor a double-counted build-error (PF-D2).
func TestImportGlobNoMatch(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root.Cadishfile")
	if err := os.WriteFile(root, []byte("example.com {\n upstream o { to http://127.0.0.1:8080 }\n import conf.d/*.Cadishfile\n}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := Check(root)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if n := codes(r)["missing-import"]; n != 1 {
		t.Errorf("glob no-match: want 1 missing-import, got %d: %s", n, render(t, r))
	}
	if n := codes(r)["build-error"]; n != 0 {
		t.Errorf("glob no-match double-counted as %d build-error(s): %s", n, render(t, r))
	}
}

// TestEmptyPortTarget verifies an empty-port `to` target warns but does not error
// (PF-P3), while a real port and a portless host stay clean.
func TestEmptyPortTarget(t *testing.T) {
	cases := []struct {
		name     string
		to       string
		wantWarn int
	}{
		{"empty-port", "http://localhost:", 1},
		{"empty-port-with-path", "http://localhost:/api", 1},
		{"bare-host-empty-port", "localhost:", 1},
		{"real-port", "http://localhost:8080", 0},
		{"portless", "http://localhost", 0},
		{"ipv6-portless", "http://[::1]", 0},
		{"ipv6-real-port", "http://[::1]:8080", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "example.com {\n upstream o { to " + tc.to + " }\n}\n"
			r, err := CheckSource("c.cadish", []byte(src))
			if err != nil {
				t.Fatalf("CheckSource: %v", err)
			}
			if n := codes(r)["empty-port"]; n != tc.wantWarn {
				t.Errorf("to %q: empty-port warnings = %d, want %d\n%s", tc.to, n, tc.wantWarn, render(t, r))
			}
			// Never a hard error for an empty port (the runtime fills the default).
			if n := codes(r)["invalid-upstream-url"]; n != 0 {
				t.Errorf("to %q unexpectedly errored: %s", tc.to, render(t, r))
			}
		})
	}
}

// TestRootParseError verifies that a malformed root file is returned as err.
func TestRootParseError(t *testing.T) {
	_, err := CheckSource("bad.cadish", []byte(`x { header A "unterminated`))
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if _, ok := err.(*cadishfile.ParseError); !ok {
		t.Errorf("err type = %T, want *cadishfile.ParseError", err)
	}
}

// TestFragmentNoUnusedWarnings verifies that a bare imported fragment (no
// directives) does not spuriously warn that its matchers are unused.
func TestFragmentNoUnusedWarnings(t *testing.T) {
	r, err := Check(td("nocache.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if codes(r)["unused-matcher"] != 0 {
		t.Errorf("fragment should not warn unused-matcher\n%s", render(t, r))
	}
	s := firstSite(t, r)
	if s.MatcherCount != 2 {
		t.Errorf("MatcherCount = %d, want 2 (@nocache, @listings)", s.MatcherCount)
	}
}

// TestHeaderRegexClassification verifies a regex-valued header matcher is counted
// as a regex eval while a literal one is not.
func TestHeaderRegexClassification(t *testing.T) {
	src := `example.com {
    @re  header X-Foo ^bar.*baz$
    @lit header X-Bar plainvalue
    pass @re
    pass @lit
}`
	r, err := CheckSource("h.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	s := firstSite(t, r)
	if s.RegexEvalsPerRequest != 1 {
		t.Errorf("RegexEvalsPerRequest = %d, want 1 (only @re)", s.RegexEvalsPerRequest)
	}
}

// TestJSONShape verifies the -json projection is valid and carries the headline
// fields.
func TestJSONShape(t *testing.T) {
	r, err := Check(td("storefront.A-flat.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf, false); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var v struct {
		Path     string `json:"path"`
		Errors   int    `json:"errors"`
		Warnings int    `json:"warnings"`
		Sites    []struct {
			MatcherCount         int            `json:"matcher_count"`
			RegexEvalsPerRequest int            `json:"regex_evals_per_request"`
			PhaseCounts          map[string]int `json:"phase_counts"`
			EstimatedCost        int            `json:"estimated_cost"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if len(v.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(v.Sites))
	}
	if v.Sites[0].RegexEvalsPerRequest != 4 || v.Sites[0].EstimatedCost != 50 {
		t.Errorf("json site = %+v, want regex 4 / cost 50", v.Sites[0])
	}
	if v.Sites[0].PhaseCounts["DELIVER"] != 9 {
		t.Errorf("json DELIVER = %d, want 9", v.Sites[0].PhaseCounts["DELIVER"])
	}
}

// TestTextRenderStable verifies WriteText produces the expected headline lines.
func TestTextRenderStable(t *testing.T) {
	r, err := Check(td("storefront.A-flat.cadish"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	out := render(t, r)
	for _, want := range []string{
		"Regex evals / request:  4",
		"Est. per-request cost:  50",
		"Directives by phase:    SETUP 5  RECV 6  KEY 1  ORIGIN 7  DELIVER 9",
		"Summary: 1 site, 0 errors, 0 warnings",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
}

func render(t *testing.T, r *Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	return buf.String()
}
