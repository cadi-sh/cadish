package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func storefront(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "check", "testdata", "storefront.A-flat.cadish")
}

func TestRunCheckText(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCheck(storefront(t), false, false, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Regex evals / request:  4") {
		t.Errorf("unexpected report:\n%s", out.String())
	}
}

func TestRunCheckJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCheck(storefront(t), false, true, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if v["path"] == nil || v["sites"] == nil {
		t.Errorf("JSON missing keys: %v", v)
	}
}

func TestRunCheckParseErrorExit(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runCheck(filepath.Join("testdata-missing-xyz.cadish"), false, false, &out, &errOut)
	if code != 1 {
		t.Errorf("exit = %d, want 1 on missing file", code)
	}
	if !strings.Contains(errOut.String(), "cadish check:") {
		t.Errorf("missing error message: %s", errOut.String())
	}
}

func TestRunCheckStrict(t *testing.T) {
	// warns_only compiles cleanly but has a lint warning (unused matcher): exit 0
	// normally, 1 under -strict. (dead_rules also carries a compile-error now that
	// check compiles the pipeline, so it is no longer a warnings-only fixture.)
	p := filepath.Join("..", "check", "testdata", "warns_only.cadish")
	var out, errOut bytes.Buffer
	if code := runCheck(p, false, false, &out, &errOut); code != 0 {
		t.Errorf("non-strict exit = %d, want 0", code)
	}
	out.Reset()
	errOut.Reset()
	if code := runCheck(p, true, false, &out, &errOut); code != 1 {
		t.Errorf("strict exit = %d, want 1", code)
	}
}
