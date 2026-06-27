package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/logs"
)

// TestFmtDirectoryArgNonZero proves a directory passed where a Cadishfile is expected
// is a clean error (exit 1), not a panic or a silent success.
func TestFmtDirectoryArgNonZero(t *testing.T) {
	dir := t.TempDir()
	if code := Fmt([]string{dir}); code != 1 {
		t.Fatalf("Fmt <directory>: exit = %d, want 1", code)
	}
}

// TestFmtWriteReadOnlyFileNonZero proves `fmt -w` on a read-only file surfaces the
// write (permission) error as exit 1 rather than swallowing it. Skipped under root,
// which bypasses the file mode.
func TestFmtWriteReadOnlyFileNonZero(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions; the read-only write would succeed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ro.cadish")
	// Unformatted content so fmt actually attempts an in-place rewrite (a no-op when
	// already formatted would never try to write).
	if err := os.WriteFile(path, []byte("example.com {\ncache_key   url\n}\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := fmtFiles([]string{path}, true, &out, &errOut); code != 1 {
		t.Fatalf("fmt -w <read-only>: exit = %d, want 1; stderr=%q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "cadish fmt:") {
		t.Errorf("error should be reported on stderr with the cadish fmt prefix; got %q", errOut.String())
	}
	if out.Len() != 0 {
		t.Errorf("-w must not write the formatted body to stdout on failure; got %q", out.String())
	}
}

// TestLogsFlagsAfterFileRejected proves the actionable error when an operator places a
// flag AFTER the FILE positional (flag.Parse silently stops at the first non-flag, so
// the flag would otherwise be dropped). The message must point at flags-before-FILE.
func TestLogsFlagsAfterFileRejected(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runLogs([]string{"access.log", "-host", "x"}, false, false, "", logs.Filter{}, logs.FormatText, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("runLogs FILE then -flag: exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "flags must come before the FILE") {
		t.Errorf("expected a flags-before-FILE hint; got %q", errOut.String())
	}
}

// TestLogsTwoFilesRejected proves two genuine FILE positionals still get the
// at-most-one-FILE error (the flag-detection branch must not swallow this).
func TestLogsTwoFilesRejected(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runLogs([]string{"a.log", "b.log"}, false, false, "", logs.Filter{}, logs.FormatText, nil, &out, &errOut)
	if code != 2 {
		t.Fatalf("runLogs two files: exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "at most one FILE") {
		t.Errorf("expected the at-most-one-FILE error; got %q", errOut.String())
	}
}

// TestStreamSocketRegularFile proves dialing a path that is a regular file (not a
// socket) is a clean error (exit 1), not a crash.
func TestStreamSocketRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := streamSocket(path, logs.Filter{}, logs.FormatText, &out, &errOut); code != 1 {
		t.Fatalf("streamSocket <regular file>: exit = %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "cannot reach access-log socket") {
		t.Errorf("expected a dial error on stderr; got %q", errOut.String())
	}
}

// TestGatewayStrayPositionalRejected proves `cadish gateway` rejects a stray positional
// (the `-leader-elect true` two-token mistake) fast, before any cluster connection.
func TestGatewayStrayPositionalRejected(t *testing.T) {
	if code := Gateway([]string{"stray"}); code != 2 {
		t.Fatalf("gateway <stray positional>: exit = %d, want 2", code)
	}
	if code := Gateway([]string{"-leader-elect", "true"}); code != 2 {
		t.Fatalf("gateway -leader-elect true (bool with value): exit = %d, want 2", code)
	}
}

// TestIngressStrayPositionalRejected proves `cadish ingress` rejects a stray positional
// (mirrors the gateway guard; the recorded staging bug).
func TestIngressStrayPositionalRejected(t *testing.T) {
	if code := Ingress([]string{"stray"}); code != 2 {
		t.Fatalf("ingress <stray positional>: exit = %d, want 2", code)
	}
	if code := Ingress([]string{"-leader-elect", "true"}); code != 2 {
		t.Fatalf("ingress -leader-elect true (bool with value): exit = %d, want 2", code)
	}
}
