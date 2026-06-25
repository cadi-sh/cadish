package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckJSONParseErrorEmitsJSON: on a parse error in -json mode, stdout must
// carry a valid, structured JSON error object (never empty) so a JSON consumer
// always gets machine-readable output (F13 bug 1).
func TestCheckJSONParseErrorEmitsJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.cadish")
	// Unterminated block => parse error on the root file.
	if err := os.WriteFile(path, []byte("example.com {\n  cache_key url\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runCheck(path, false, true, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if out.Len() == 0 {
		t.Fatal("stdout is empty; -json must emit a structured error on parse failure")
	}
	var v struct {
		Path        string `json:"path"`
		Ok          bool   `json:"ok"`
		Errors      int    `json:"errors"`
		Diagnostics []struct {
			Severity string `json:"severity"`
			Code     string `json:"code"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if v.Ok {
		t.Errorf("ok = true, want false on parse error")
	}
	if v.Errors < 1 || len(v.Diagnostics) < 1 {
		t.Errorf("expected at least one error diagnostic, got %+v", v)
	}
}

// TestCheckJSONStrictAgreesWithExit: under -strict a warnings-only config exits 1;
// the emitted JSON must reflect that (ok=false, strict=true) instead of claiming
// success with errors:0 (F13 bug 2).
func TestCheckJSONStrictAgreesWithExit(t *testing.T) {
	p := filepath.Join("..", "check", "testdata", "warns_only.cadish")

	// Non-strict: warnings allowed, exit 0, ok=true.
	var out, errOut bytes.Buffer
	if code := runCheck(p, false, true, &out, &errOut); code != 0 {
		t.Fatalf("non-strict exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	var nv struct {
		Ok       bool `json:"ok"`
		Strict   bool `json:"strict"`
		Warnings int  `json:"warnings"`
	}
	if err := json.Unmarshal(out.Bytes(), &nv); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !nv.Ok || nv.Strict {
		t.Errorf("non-strict json = %+v, want ok=true strict=false", nv)
	}
	if nv.Warnings < 1 {
		t.Fatalf("fixture must have warnings; got %d", nv.Warnings)
	}

	// Strict: same warnings now fail, exit 1, JSON must say ok=false strict=true.
	out.Reset()
	errOut.Reset()
	code := runCheck(p, true, true, &out, &errOut)
	if code != 1 {
		t.Fatalf("strict exit = %d, want 1", code)
	}
	var sv struct {
		Ok       bool `json:"ok"`
		Strict   bool `json:"strict"`
		Errors   int  `json:"errors"`
		Warnings int  `json:"warnings"`
	}
	if err := json.Unmarshal(out.Bytes(), &sv); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if sv.Ok {
		t.Errorf("strict json ok = true, want false (exit was 1)")
	}
	if !sv.Strict {
		t.Errorf("strict json strict = false, want true")
	}
}
