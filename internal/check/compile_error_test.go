package check

import (
	"strings"
	"testing"
)

// TestCompileError: `cadish check` must reject configs that lint clean at the AST
// level but fail pipeline.Compile (i.e. would refuse to `cadish run`). Each failing
// fixture must surface a SevError with code "compile-error", carrying the real
// file:line:col from the compiler so check output matches what run prints.
func TestCompileError(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
		// substr is a fragment of the compiler message expected in the diagnostic.
		substr string
	}{
		{
			// A classify-matcher @regulated references token {regulated}, but no
			// `classify {regulated} { … }` directive defines it. Since Part 2, a
			// classify-matcher CAN feed another classifier in dependency order, so this
			// is no longer "undefined matcher @regulated" — it is the genuine
			// unknown-token error from the missing classifier. Still AST-clean, still a
			// hard compile-error in `check`.
			name: "classify-matcher references an undefined classifier token",
			src: "site.local {\n" +
				"  classify {ageverify} { when @regulated -> 1 ; default -> 0 }\n" +
				"  @regulated classify {regulated}==1\n" +
				"  upstream b { to http://127.0.0.1:8080 }\n" +
				"}\n",
			wantErr: true,
			substr:  "unknown token {regulated}",
		},
		{
			// classify with an empty default value: rejected by the compiler
			// ("classify value must be non-empty"), but AST-clean.
			name: "classify with empty default value",
			src: "site.local {\n" +
				"  classify {tier} { when @vip -> gold ; default -> \"\" }\n" +
				"  @vip header X-VIP yes\n" +
				"  upstream b { to http://127.0.0.1:8080 }\n" +
				"}\n",
			wantErr: true,
			substr:  "classify value must be non-empty",
		},
		{
			// Finding I1: an `upstream_healthy NAME…` matcher naming an UNDECLARED pool
			// is AST-clean but a hard compile-error (it would otherwise fail closed at
			// runtime → a probe answers 503 forever). `cadish check` must reject it
			// identically to `cadish run` (both reach pipeline.Compile).
			name: "upstream_healthy names an undeclared pool",
			src: "site.local {\n" +
				"  upstream cache_pool { to http://127.0.0.1:8080 }\n" +
				"  @probe path /aws-health-check\n" +
				"  @live  upstream_healthy cache_poool\n" +
				"  respond @probe @live 200 \"OK\"\n" +
				"  respond @probe 503\n" +
				"}\n",
			wantErr: true,
			substr:  "not a declared upstream/cluster",
		},
		{
			// The same probe naming the REAL pool compiles clean — no over-rejection.
			name: "upstream_healthy names the declared pool",
			src: "site.local {\n" +
				"  upstream cache_pool { to http://127.0.0.1:8080 }\n" +
				"  @probe path /aws-health-check\n" +
				"  @live  upstream_healthy cache_pool\n" +
				"  respond @probe @live 200 \"OK\"\n" +
				"  respond @probe 503\n" +
				"}\n",
			wantErr: false,
		},
		{
			// Regression: a valid, compilable config produces NO compile-error.
			// The classifier references only plain matchers (the supported pattern
			// until Part 2 lands), so it compiles cleanly.
			name: "valid config compiles clean",
			src: "site.local {\n" +
				"  @vip header X-VIP yes\n" +
				"  classify {tier} { when @vip -> gold ; default -> silver }\n" +
				"  cache_key host path {tier}\n" +
				"  upstream b { to http://127.0.0.1:8080 }\n" +
				"}\n",
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := CheckSource("Cadishfile", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource parse error: %v", err)
			}
			d, found := findDiag(rep, "compile-error")
			if tc.wantErr {
				if !found {
					t.Fatalf("expected a compile-error diagnostic, got none; report=%+v", rep)
				}
				if d.Severity != SevError {
					t.Errorf("compile-error severity = %q, want %q", d.Severity, SevError)
				}
				if rep.ExitCode(false) != 1 {
					t.Errorf("ExitCode = 0, want 1 for a compile-error")
				}
				if d.Position == "" {
					t.Errorf("compile-error diagnostic has no position (must carry file:line:col)")
				}
				if !strings.Contains(d.Position, "Cadishfile:") {
					t.Errorf("compile-error position %q lacks file:line:col", d.Position)
				}
				if tc.substr != "" && !strings.Contains(d.Message, tc.substr) {
					t.Errorf("compile-error message %q does not contain %q", d.Message, tc.substr)
				}
			} else {
				if found {
					t.Fatalf("expected no compile-error, got one: %+v", d)
				}
			}
		})
	}
}

// TestCompileErrorSandboxed: the sandboxed path (admin playground) must also run
// pipeline.Compile (it is pure — no I/O), so it catches the same compile failures.
func TestCompileErrorSandboxed(t *testing.T) {
	src := "site.local {\n" +
		"  classify {ageverify} { when @regulated -> 1 ; default -> 0 }\n" +
		"  @regulated classify {regulated}==1\n" +
		"  upstream b { to http://127.0.0.1:8080 }\n" +
		"}\n"
	rep, err := CheckSourceSandboxed("Cadishfile", []byte(src))
	if err != nil {
		t.Fatalf("CheckSourceSandboxed parse error: %v", err)
	}
	if _, found := findDiag(rep, "compile-error"); !found {
		t.Fatalf("sandboxed check did not surface compile-error; report=%+v", rep)
	}
	if rep.ExitCode(false) != 1 {
		t.Errorf("ExitCode = 0, want 1 for a compile-error")
	}
}

// findDiag returns the first diagnostic with the given code, scanning both the
// file-level and per-site diagnostics.
func findDiag(rep *Report, code string) (Diagnostic, bool) {
	for _, d := range rep.Diagnostics {
		if d.Code == code {
			return d, true
		}
	}
	for _, s := range rep.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == code {
				return d, true
			}
		}
	}
	return Diagnostic{}, false
}
