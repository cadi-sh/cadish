package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFmtWriteInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cadishfile")
	unformatted := "example.com {\ncache_key   url  host\n}\n"
	if err := os.WriteFile(path, []byte(unformatted), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Fmt([]string{"-w", path}); code != 0 {
		t.Fatalf("Fmt exit = %d, want 0", code)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "example.com {\n    cache_key url host\n}\n"
	if string(got) != want {
		t.Errorf("formatted file =\n%q\nwant\n%q", got, want)
	}
}

func TestFmtParseErrorNonZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.cadish")
	if err := os.WriteFile(path, []byte(`x { header A "oops`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Fmt([]string{path}); code == 0 {
		t.Fatal("expected non-zero exit on parse error")
	}
}

func TestFmtMissingFileNonZero(t *testing.T) {
	if code := Fmt([]string{filepath.Join(t.TempDir(), "nope.cadish")}); code == 0 {
		t.Fatal("expected non-zero exit for missing file")
	}
}

// TestFmtMultipleFilesToStdoutSeparated verifies PF-P2: two files printed to stdout
// are separated by a per-file header so the second file's first line never glues
// onto the first file's last line.
func TestFmtMultipleFilesToStdoutSeparated(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.cadish")
	b := filepath.Join(dir, "b.cadish")
	if err := os.WriteFile(a, []byte("a.example {\ncache_key url\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b.example {\ncache_key host\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := fmtFiles([]string{a, b}, false, &out, &errOut); code != 0 {
		t.Fatalf("fmtFiles exit = %d, stderr = %s", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "# --- "+a+" ---") || !strings.Contains(got, "# --- "+b+" ---") {
		t.Errorf("missing per-file headers:\n%s", got)
	}
	// The two blocks must not be glued: the first site's closing brace must be
	// followed by a newline before the second file's header.
	if strings.Contains(got, "}b.example") || strings.Contains(got, "}# ---") {
		t.Errorf("file outputs glued together:\n%s", got)
	}
	// Header for b must come after a's content (order preserved).
	if strings.Index(got, "# --- "+a) > strings.Index(got, "# --- "+b) {
		t.Errorf("file order not preserved:\n%s", got)
	}
}

// TestFmtSingleFileToStdoutNoHeader verifies a single file to stdout is NOT
// prefixed with a header (only multi-file output is separated).
func TestFmtSingleFileToStdoutNoHeader(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.cadish")
	if err := os.WriteFile(a, []byte("a.example {\ncache_key url\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := fmtFiles([]string{a}, false, &out, &errOut); code != 0 {
		t.Fatalf("fmtFiles exit = %d", code)
	}
	if strings.Contains(out.String(), "# ---") {
		t.Errorf("single-file output should have no header:\n%s", out.String())
	}
}

// TestFmtWriteMultipleNoHeader verifies -w never emits a separator header (it
// rewrites files in place; nothing goes to stdout).
func TestFmtWriteMultipleNoHeader(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.cadish")
	b := filepath.Join(dir, "b.cadish")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x {\ncache_key url\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := fmtFiles([]string{a, b}, true, &out, &errOut); code != 0 {
		t.Fatalf("fmtFiles -w exit = %d, stderr = %s", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("-w wrote to stdout: %q", out.String())
	}
	got, _ := os.ReadFile(a)
	if string(got) != "x {\n    cache_key url\n}\n" {
		t.Errorf("a not formatted in place: %q", got)
	}
}
