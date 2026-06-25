// Package logs implements `cadish logs` — the NCSA-style access-log tail.
//
// Source design (the "clean source" decision, DECISIONS D18): cadish already
// emits one structured slog line per request (internal/server/accesslog.go). The
// simplest robust streaming source is therefore a *file cadish writes*, not a new
// admin IPC channel: point cadish's access log at a file (the slog JSON handler),
// then `cadish logs -f FILE` tails it. This keeps `logs` a pure, decoupled reader
// (stdlib only, no fsnotify) that also works on a pipe or on stdin — an operator
// can `cadish run 2>access.json` and `cadish logs -f access.json` in another shell,
// or pipe directly. The reader parses each JSON line into a Record, applies
// host/path/status/cache filters, and renders it as text, JSON, or NCSA
// (Apache-combined) — all of which are pure functions tested in isolation.
package logs

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Record is one parsed access-log line. The field names mirror the slog access
// line keys emitted by internal/server/accesslog.go (method/host/path/status/
// bytes/cache/upstream/dur_ms), plus the slog envelope's time/level/msg. Unknown
// keys are ignored; missing keys default to their zero value.
type Record struct {
	Time     time.Time `json:"-"`
	Msg      string    `json:"msg"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Bytes    int64     `json:"bytes"`
	Cache    string    `json:"cache"`
	Upstream string    `json:"upstream"`
	DurMs    int64     `json:"dur_ms"`
	// raw retains the original decoded object so the JSON formatter can echo it
	// verbatim (including any extra operator-added fields) and so the time can be
	// recovered from the slog "time" key without a fixed field.
	raw map[string]any
}

// ParseLine parses one NDJSON access-log line into a Record. A blank line, or a
// slog line that is NOT a per-request access line (cadish's access line carries
// msg:"request"; startup/info/warn lines do not), yields (rec, false, nil) so
// callers skip it — this filters the non-request slog noise that shares the same
// file. A malformed JSON line returns an error. The slog *text* handler is NOT
// supported — configure the JSON handler when feeding `cadish logs` (see
// docs/logs.md).
func ParseLine(line []byte) (Record, bool, error) {
	trimmed := strings.TrimSpace(string(line))
	if trimmed == "" {
		return Record{}, false, nil
	}
	var rec Record
	if err := json.Unmarshal([]byte(trimmed), &rec); err != nil {
		return Record{}, false, fmt.Errorf("parse log line: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return Record{}, false, fmt.Errorf("parse log line: %w", err)
	}
	rec.raw = raw
	if ts, ok := raw["time"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			rec.Time = t
		}
	}
	// Only emit the per-request access line. A line carrying a "msg" that is not
	// "request" (a startup/serving/info/warn slog line written to the same file) is
	// not an access record. Tolerate a missing "msg" (a hand-piped/minimal line)
	// only when it carries request fields (a method), so `cadish logs` still works
	// on logs that omit the slog envelope.
	if rec.Msg != "" && rec.Msg != "request" {
		return rec, false, nil
	}
	return rec, true, nil
}

// Filter is a set of predicates a Record must satisfy to be emitted. A zero Filter
// matches everything. Host/Path are case-insensitive substring matches; Cache is an
// exact (case-insensitive) match against the cache-status token; Status, when set,
// matches either an exact code (e.g. 404) or a class (e.g. 4 -> 4xx, via StatusClass).
type Filter struct {
	Host        string
	Path        string
	Cache       string
	Status      int // exact status, 0 = any
	StatusClass int // 1..5 for 1xx..5xx, 0 = any
	MinStatus   int // inclusive lower bound, 0 = none
}

// Matches reports whether rec passes every set predicate in f.
func (f Filter) Matches(rec Record) bool {
	if f.Host != "" && !strings.Contains(strings.ToLower(rec.Host), strings.ToLower(f.Host)) {
		return false
	}
	if f.Path != "" && !strings.Contains(strings.ToLower(rec.Path), strings.ToLower(f.Path)) {
		return false
	}
	if f.Cache != "" && !strings.EqualFold(rec.Cache, f.Cache) {
		return false
	}
	if f.Status != 0 && rec.Status != f.Status {
		return false
	}
	if f.StatusClass != 0 && rec.Status/100 != f.StatusClass {
		return false
	}
	if f.MinStatus != 0 && rec.Status < f.MinStatus {
		return false
	}
	return true
}

// Format selects the output rendering for a Record.
type Format int

const (
	// FormatText is the default compact, human-readable one-line rendering.
	FormatText Format = iota
	// FormatNCSA is the Apache "combined"-style log line (varnishncsa default).
	FormatNCSA
	// FormatJSON echoes the original JSON object verbatim (a filter pass-through).
	FormatJSON
)

// ParseFormat resolves a -format flag value to a Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return FormatText, nil
	case "ncsa", "combined", "apache":
		return FormatNCSA, nil
	case "json":
		return FormatJSON, nil
	default:
		return FormatText, fmt.Errorf("unknown format %q (want text|ncsa|json)", s)
	}
}

// Render formats one Record per the chosen Format, returning a single line WITHOUT
// a trailing newline (the caller adds it). For FormatJSON it re-marshals the raw
// object (compact) so any extra operator fields survive.
func Render(rec Record, format Format) string {
	switch format {
	case FormatNCSA:
		return renderNCSA(rec)
	case FormatJSON:
		if rec.raw != nil {
			if b, err := json.Marshal(rec.raw); err == nil {
				return string(b)
			}
		}
		b, _ := json.Marshal(rec)
		return string(b)
	default:
		return renderText(rec)
	}
}

// renderText is the compact human line: "TIME METHOD host path -> STATUS CACHE
// bytes dur_ms upstream".
func renderText(rec Record) string {
	var b strings.Builder
	if !rec.Time.IsZero() {
		b.WriteString(rec.Time.Format("15:04:05.000"))
		b.WriteByte(' ')
	}
	b.WriteString(orDash(rec.Method))
	b.WriteByte(' ')
	b.WriteString(sanitizeLogField(rec.Host))
	b.WriteString(sanitizeLogField(rec.Path))
	b.WriteString(" -> ")
	b.WriteString(strconv.Itoa(rec.Status))
	b.WriteByte(' ')
	b.WriteString(orDash(rec.Cache))
	b.WriteByte(' ')
	b.WriteString(strconv.FormatInt(rec.Bytes, 10))
	b.WriteString("B ")
	b.WriteString(strconv.FormatInt(rec.DurMs, 10))
	b.WriteString("ms")
	if rec.Upstream != "" {
		b.WriteString(" via ")
		b.WriteString(rec.Upstream)
	}
	return b.String()
}

// renderNCSA renders the Apache "combined"-ish access line. cadish's access log
// deliberately omits the client IP and the query string (signed-URL signatures are
// sensitive), so those fields are rendered as "-"; the cache status + upstream are
// appended as extra quoted fields (the varnishncsa convention for proxy detail).
func renderNCSA(rec Record) string {
	ts := "-"
	if !rec.Time.IsZero() {
		// Apache CLF time: [10/Oct/2000:13:55:36 -0700]
		ts = rec.Time.Format("02/Jan/2006:15:04:05 -0700")
	}
	reqLine := fmt.Sprintf("%s %s HTTP/1.1", orDash(rec.Method), rec.Path) // path is %q-escaped below
	// host - - [time] "METHOD path HTTP/1.1" status bytes "-" "-" "cache" "upstream". The Host
	// is written %s (unquoted, per CLF), so sanitize its control bytes; the request line is
	// %q-escaped so its (decoded) path cannot inject CR/LF/ANSI.
	return fmt.Sprintf("%s - - [%s] %q %d %d %q %q %q %q",
		orDash(sanitizeLogField(rec.Host)), ts, reqLine, rec.Status, rec.Bytes, "-", "-",
		orDash(rec.Cache), orDash(rec.Upstream))
}

// sanitizeLogField strips control bytes (C0 + DEL) from a field written to the human-readable
// text/NCSA log renderers. An attacker-controlled Host or (percent-DECODED) Path can carry
// CR/LF — forging extra log lines — or ESC (0x1b) — injecting ANSI terminal-escape sequences
// into an operator's `cadish logs` view. The structured JSON sink already escapes via slog;
// this guards only the plain-text renderers. The common (clean) field returns unchanged.
func sanitizeLogField(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c != 0x7f {
			b = append(b, c)
		}
	}
	return string(b)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Stream reads NDJSON access lines from r, applies filter, renders each surviving
// record per format, and writes them (newline-terminated) to out. It returns on
// EOF (the non-follow path). Malformed lines are written to errOut as a warning and
// skipped, so a single bad line does not abort the stream. It returns the number of
// records emitted.
func Stream(r io.Reader, out io.Writer, errOut io.Writer, filter Filter, format Format) (int, error) {
	sc := newLineScanner(r)
	emitted := 0
	for sc.Scan() {
		rec, ok, err := ParseLine(sc.Bytes())
		if err != nil {
			if errOut != nil {
				fmt.Fprintf(errOut, "cadish logs: %v\n", err)
			}
			continue
		}
		if !ok || !filter.Matches(rec) {
			continue
		}
		if _, werr := io.WriteString(out, Render(rec, format)+"\n"); werr != nil {
			return emitted, werr
		}
		emitted++
	}
	return emitted, sc.Err()
}
