package cli

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/logs"
)

const lineHit = `{"time":"2026-06-23T13:00:00Z","level":"INFO","msg":"request","method":"GET","host":"example.com","path":"/a","status":200,"bytes":10,"cache":"HIT","upstream":"cache:ram","dur_ms":1}`
const lineMiss = `{"time":"2026-06-23T13:00:01Z","level":"INFO","msg":"request","method":"GET","host":"other.com","path":"/b","status":404,"bytes":0,"cache":"MISS","upstream":"backend","dur_ms":5}`

// runLogs reading from stdin streams every line (no file, no follow).
func TestRunLogsStdin(t *testing.T) {
	in := strings.NewReader(lineHit + "\n" + lineMiss + "\n")
	var out, errOut bytes.Buffer
	code := runLogs(nil, false, false, "", logs.Filter{}, logs.FormatText, in, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "/a") || !strings.Contains(out.String(), "/b") {
		t.Errorf("expected both lines; out=%q", out.String())
	}
}

// runLogs with a filter only emits matching lines.
func TestRunLogsStdinFiltered(t *testing.T) {
	in := strings.NewReader(lineHit + "\n" + lineMiss + "\n")
	var out, errOut bytes.Buffer
	code := runLogs(nil, false, false, "", logs.Filter{Cache: "MISS"}, logs.FormatNCSA, in, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := out.String()
	if strings.Contains(got, "/a") || !strings.Contains(got, "/b") {
		t.Errorf("filter wrong; out=%q", got)
	}
	if !strings.Contains(got, `"GET /b HTTP/1.1" 404`) {
		t.Errorf("ncsa format wrong; out=%q", got)
	}
}

// runLogs over a file (non-follow) streams to EOF.
func TestRunLogsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.json")
	if err := os.WriteFile(path, []byte(lineHit+"\n"+lineMiss+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runLogs([]string{path}, false, false, "", logs.Filter{StatusClass: 4}, logs.FormatText, nil, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "/b") || strings.Contains(out.String(), "/a") {
		t.Errorf("status-class filter wrong; out=%q", out.String())
	}
}

// -f on stdin is rejected.
func TestRunLogsFollowStdinRejected(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runLogs(nil, true, false, "", logs.Filter{}, logs.FormatText, strings.NewReader(""), &out, &errOut)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "cannot tail stdin") {
		t.Errorf("expected stdin-tail error; got %q", errOut.String())
	}
}

// A missing file is a clean error.
func TestRunLogsMissingFile(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runLogs([]string{"/no/such/file.json"}, false, false, "", logs.Filter{}, logs.FormatText, nil, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}

// streamSocket dials a unix socket and renders the NDJSON it streams through the
// same logs pipeline used for files (the live `cadish logs` source, D44).
func TestStreamSocket(t *testing.T) {
	// A short socket path (macOS sun_path limit; t.TempDir is too deep).
	dir, err := os.MkdirTemp("", "cad")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "a.sock")

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = conn.Write([]byte(lineHit + "\n" + lineMiss + "\n"))
		_ = conn.Close()
	}()

	var out, errOut bytes.Buffer
	code := streamSocket(path, logs.Filter{Cache: "HIT"}, logs.FormatText, &out, &errOut)
	if code != 0 {
		t.Fatalf("streamSocket exit %d, stderr=%s", code, errOut.String())
	}
	got := out.String()
	if !strings.Contains(got, "/a") || strings.Contains(got, "/b") {
		t.Errorf("filtered socket stream wrong; out=%q", got)
	}
}

// streamSocket reports a clean error (exit 1) when the socket is unreachable.
func TestStreamSocketUnreachable(t *testing.T) {
	var out, errOut bytes.Buffer
	code := streamSocket("/no/such/cadish.sock", logs.Filter{}, logs.FormatText, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errOut.String(), "cannot reach access-log socket") {
		t.Errorf("expected a dial error; got %q", errOut.String())
	}
}

// parseAccessLogFlag accepts only "" (hub on) and "off" (hub disabled); a FILE
// value is now an error with a migration hint (the -access-log FILE removal, D44).
func TestParseAccessLogFlag(t *testing.T) {
	if off, err := parseAccessLogFlag(""); err != nil || off {
		t.Errorf(`"" => off=%v err=%v, want off=false nil`, off, err)
	}
	if off, err := parseAccessLogFlag("off"); err != nil || !off {
		t.Errorf(`"off" => off=%v err=%v, want off=true nil`, off, err)
	}
	if off, err := parseAccessLogFlag("OFF"); err != nil || !off {
		t.Errorf(`"OFF" => off=%v err=%v, want off=true nil`, off, err)
	}
	off, err := parseAccessLogFlag("/var/log/cadish/access.json")
	if err == nil {
		t.Fatalf("a FILE value must be rejected (the -access-log FILE removal); off=%v", off)
	}
	if !strings.Contains(err.Error(), "cadish logs >") {
		t.Errorf("error should carry the migration hint; got %q", err.Error())
	}
}

// TestDefaultLogSocketPath: the per-instance default socket path is an absolute
// cadish-access-<hash>.sock under the temp dir.
func TestDefaultLogSocketPath(t *testing.T) {
	t.Setenv("CADISH_ACCESS_SOCKET", "")
	p := defaultLogSocketPathFor(":80")
	base := filepath.Base(p)
	if !strings.HasPrefix(base, "cadish-access-") || !strings.HasSuffix(base, ".sock") {
		t.Errorf("default socket path = %q, want basename cadish-access-<hash>.sock", p)
	}
	if !filepath.IsAbs(p) {
		t.Errorf("default socket path should be absolute; got %q", p)
	}
}
