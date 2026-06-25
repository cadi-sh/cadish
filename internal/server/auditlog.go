package server

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// auditChanBuffer is the in-flight backlog of the async security-audit writer. At
// one JSON line per ENFORCED/MONITORED security event this is a generous burst
// cushion: a normal sink keeps up and loses nothing, a slow/full sink drops +
// counts rather than ever blocking the serve path (mirrors accesshub's D44
// philosophy — security must never stall request serving).
const auditChanBuffer = 8192

// AuditRecord is one structured security-audit fact, emitted for each ENFORCED or
// MONITORED security-gate action (deny / ratelimit / monitored would-block). It is
// built on the request path but serialized off it, in the writer goroutine.
//
// PRIVACY: unlike the access log (which deliberately OMITS the client IP and query
// — signed-URL signatures are sensitive, D18), the security audit log's whole point
// is recording WHO was blocked, so it MAY carry the real client IP. The query
// string (and its signed-URL signature) is NEVER recorded here either.
type AuditRecord struct {
	Time     time.Time
	Action   string // "deny" | "ratelimit"
	Enforced bool   // true = action taken; false = monitor mode (would-block)
	Rule     string // matched rule identity ("" when inline/unnamed)
	Method   string
	Host     string
	Path     string
	ClientIP string // resolved real client IP (trusted-proxy aware)
	Status   int    // HTTP status returned (or that WOULD have been, in monitor)
}

// auditWire is the on-the-wire JSON shape (one NDJSON line per event). The `msg`
// key is constant ("security") so a downstream parser can demux it from other
// NDJSON streams; the `monitor` key flags a would-block (enforced == false).
type auditWire struct {
	Time    time.Time `json:"time"`
	Msg     string    `json:"msg"`
	Action  string    `json:"action"`
	Monitor bool      `json:"monitor"`
	Rule    string    `json:"rule,omitempty"`
	Method  string    `json:"method"`
	Host    string    `json:"host"`
	Path    string    `json:"path"`
	Client  string    `json:"client"`
	Status  int       `json:"status"`
}

// marshalLine renders the record as one NDJSON line (trailing '\n'). It runs in
// the writer goroutine, never on the request hot path.
func (r AuditRecord) marshalLine() ([]byte, error) {
	b, err := json.Marshal(auditWire{
		Time:    r.Time,
		Msg:     "security",
		Action:  r.Action,
		Monitor: !r.Enforced,
		Rule:    r.Rule,
		Method:  r.Method,
		Host:    r.Host,
		Path:    r.Path,
		Client:  r.ClientIP,
		Status:  r.Status,
	})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// AuditLog is the async, non-blocking security-audit sink. Records are enqueued on
// a buffered channel and serialized to the underlying writer by a single goroutine,
// so a slow/full disk NEVER blocks request serving: a full channel drops + counts.
//
// It is NIL when no audit log is configured (the default — `security { audit_log
// off }` / no security block / no flag). A nil *AuditLog is a no-op on every method
// (Record drops nothing because Enabled() is false first), so the datapath pays the
// cost of exactly one nil/branch check when the audit log is off.
type AuditLog struct {
	ch      chan AuditRecord
	w       io.Writer
	closer  io.Closer // non-nil when we own a file we must Close
	dropped atomic.Uint64

	// mu guards the channel against a send-on-closed-channel race: Record takes the
	// RLock around its non-blocking send, Close takes the write Lock before closing
	// the channel. Record's critical section is a single non-blocking select (it
	// never blocks under the lock), so concurrent Records still fan in lock-free in
	// practice; the lock only serializes against the one-shot Close.
	mu     sync.RWMutex
	wg     sync.WaitGroup
	closed bool
}

// auditFileName is the file an AuditLog writes inside a configured DIRECTORY.
// (Rotate-by-directory is fine for v1; full log rotation is out of scope — D52.)
const auditFileName = "security-audit.log"

// NewAuditLog builds an audit log from a configured path. The path is either:
//   - "" or "off"  → returns (nil, nil): the audit log is DISABLED (zero cost).
//   - a directory   → writes <dir>/security-audit.log (created/appended).
//   - a file path    → appends to that file (its parent dir must exist).
//
// A directory is detected by an existing dir OR a trailing separator; otherwise the
// path is treated as a file. The returned log owns a background writer goroutine;
// the caller MUST Close it at shutdown to flush and release the file.
func NewAuditLog(path string) (*AuditLog, error) {
	if path == "" || path == "off" {
		return nil, nil
	}
	target := path
	if isDirTarget(path) {
		// 0o700: the audit log records attacker IPs + matched WAF rules — it is
		// operator-sensitive, so the dir is private to the cadish process (not
		// world-listable), matching internal/cache/disk.go's blob dir.
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		target = filepath.Join(path, auditFileName)
	}
	// 0o600: owner-only — the audit lines carry client IPs + rule identities and
	// must never be world-readable (consistent with the disk-cache index).
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return newAuditLogWriter(f, f, auditChanBuffer), nil
}

// isDirTarget reports whether path should be treated as a DIRECTORY to write the
// audit file into: an existing directory, or a path ending in a separator.
func isDirTarget(path string) bool {
	if os.IsPathSeparator(path[len(path)-1]) {
		return true
	}
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return true
	}
	return false
}

// newAuditLogWriter builds an AuditLog over an arbitrary writer with an explicit
// channel buffer (tests use a tiny buffer + a blocking writer to exercise the
// drop-on-full path deterministically). closer may be nil when the writer is not
// owned (e.g. a test buffer).
func newAuditLogWriter(w io.Writer, closer io.Closer, bufSize int) *AuditLog {
	a := &AuditLog{
		ch:     make(chan AuditRecord, bufSize),
		w:      w,
		closer: closer,
	}
	a.wg.Add(1)
	go a.run()
	return a
}

// Enabled reports whether the audit log accepts records (false when nil / off).
func (a *AuditLog) Enabled() bool { return a != nil }

// Record enqueues one audit record with a NON-BLOCKING send: a full channel drops
// the record and bumps the dropped counter rather than ever blocking the caller
// (the request hot path). A nil *AuditLog (audit off) is a no-op.
func (a *AuditLog) Record(rec AuditRecord) {
	if a == nil {
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return
	}
	select {
	case a.ch <- rec:
	default:
		a.dropped.Add(1)
	}
}

// run is the single writer goroutine: it serializes each queued record to the
// underlying writer off the request path. A marshal/write error is dropped
// (counted) rather than retried — the audit sink is best-effort, like the access
// log. It exits when the channel is closed (by Close).
func (a *AuditLog) run() {
	defer a.wg.Done()
	for rec := range a.ch {
		line, err := rec.marshalLine()
		if err != nil {
			a.dropped.Add(1)
			continue
		}
		if _, err := a.w.Write(line); err != nil {
			a.dropped.Add(1)
		}
	}
}

// Close stops accepting records, drains the queue, waits for the writer goroutine
// to flush, then closes any owned file. Safe to call once; nil-safe.
func (a *AuditLog) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	close(a.ch)
	a.mu.Unlock()
	a.wg.Wait()
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}
