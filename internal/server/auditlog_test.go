package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe writer the writer goroutine writes to and the test
// reads from.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// drainLines closes the log (flushing the writer goroutine) and returns the decoded
// NDJSON records written to buf.
func drainLines(t *testing.T, log *AuditLog, buf *syncBuffer) []auditWire {
	t.Helper()
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var out []auditWire
	for _, line := range bytes.Split([]byte(buf.String()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var w auditWire
		if err := json.Unmarshal(line, &w); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		out = append(out, w)
	}
	return out
}

// A deny / ratelimit / monitor event each produces one correct JSON record.
func TestAuditLogRecordShape(t *testing.T) {
	buf := &syncBuffer{}
	log := newAuditLogWriter(buf, nil, 16)

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	log.Record(AuditRecord{Time: now, Action: "deny", Enforced: true, Rule: "scanners", Method: "GET", Host: "example.com", Path: "/.env", ClientIP: "1.2.3.4", Status: 403})
	log.Record(AuditRecord{Time: now, Action: "ratelimit", Enforced: true, Rule: "api", Method: "POST", Host: "example.com", Path: "/api", ClientIP: "5.6.7.8", Status: 429})
	log.Record(AuditRecord{Time: now, Action: "deny", Enforced: false, Rule: "ru_cn", Method: "GET", Host: "example.com", Path: "/", ClientIP: "9.9.9.9", Status: 403})

	recs := drainLines(t, log, buf)
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}

	if recs[0].Msg != "security" || recs[0].Action != "deny" || recs[0].Monitor || recs[0].Rule != "scanners" ||
		recs[0].Client != "1.2.3.4" || recs[0].Status != 403 || recs[0].Path != "/.env" || recs[0].Method != "GET" {
		t.Errorf("deny record wrong: %+v", recs[0])
	}
	if recs[1].Action != "ratelimit" || recs[1].Status != 429 || recs[1].Monitor {
		t.Errorf("ratelimit record wrong: %+v", recs[1])
	}
	if !recs[2].Monitor || recs[2].Action != "deny" {
		t.Errorf("monitor record should have monitor=true: %+v", recs[2])
	}
}

// OFF by default: NewAuditLog("") and ("off") return a nil log that writes nothing
// and creates no file, and a nil *AuditLog is a no-op on Record/Close.
func TestAuditLogOffByDefault(t *testing.T) {
	for _, path := range []string{"", "off"} {
		log, err := NewAuditLog(path)
		if err != nil {
			t.Fatalf("NewAuditLog(%q): %v", path, err)
		}
		if log != nil {
			t.Fatalf("NewAuditLog(%q) = non-nil, want nil (off)", path)
		}
		if log.Enabled() {
			t.Errorf("nil audit log reports Enabled()=true")
		}
		log.Record(AuditRecord{Action: "deny"}) // must not panic
		if err := log.Close(); err != nil {     // must not panic / error
			t.Errorf("Close on nil log: %v", err)
		}
	}
}

// A directory target creates <dir>/security-audit.log; a file target appends to it.
func TestAuditLogPathResolution(t *testing.T) {
	dir := t.TempDir()
	log, err := NewAuditLog(dir)
	if err != nil {
		t.Fatalf("NewAuditLog(dir): %v", err)
	}
	log.Record(AuditRecord{Time: time.Now(), Action: "deny", Enforced: true, Status: 403})
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	want := filepath.Join(dir, auditFileName)
	b, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("expected audit file %s: %v", want, err)
	}
	if !bytes.Contains(b, []byte(`"action":"deny"`)) {
		t.Errorf("audit file missing deny record: %s", b)
	}
}

// The audit log records attacker IPs + matched WAF rules — operator-sensitive — so
// the created directory must be private (0o700) and the file owner-only (0o600),
// never world-readable. Mirrors internal/cache/disk.go's 0o700/0o600 choice.
func TestAuditLogPrivatePerms(t *testing.T) {
	// Trailing separator marks this as a DIRECTORY target cadish must create
	// (a not-yet-existing path), so we exercise the MkdirAll perm path.
	dir := filepath.Join(t.TempDir(), "audit") + string(os.PathSeparator)
	log, err := NewAuditLog(dir)
	if err != nil {
		t.Fatalf("NewAuditLog(dir): %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("audit dir mode = %o, want 0700", got)
	}

	fi, err := os.Stat(filepath.Join(dir, auditFileName))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("audit file mode = %o, want 0600", got)
	}
}

// blockingWriter blocks the writer goroutine on its first write, so the channel
// fills and subsequent Record calls must DROP (never block the caller).
type blockingWriter struct{ release chan struct{} }

func (w *blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// Non-blocking: a slow/full sink drops + counts, never blocks the request path
// (mirrors the accesshub drop-on-full guarantee).
func TestAuditLogDropsOnFull(t *testing.T) {
	bw := &blockingWriter{release: make(chan struct{})}
	log := newAuditLogWriter(bw, nil, 2) // tiny buffer; writer goroutine is stuck

	// Give the writer goroutine a moment to pull one record and block on Write.
	// Publish enough that the channel saturates and the rest drop. Record must
	// return immediately each time (no blocking) regardless.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			log.Record(AuditRecord{Action: "deny"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record blocked: the audit writer is on the hot path")
	}

	if got := log.dropped.Load(); got == 0 {
		t.Errorf("expected drops with a stuck writer, got 0")
	}

	close(bw.release) // unblock the writer goroutine so Close can drain+exit
	if err := log.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
