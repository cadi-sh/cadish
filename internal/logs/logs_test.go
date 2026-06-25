package logs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const sampleLine = `{"time":"2026-06-23T13:00:00.123456789Z","level":"INFO","msg":"request","method":"GET","host":"example.com","path":"/img/a.png","status":200,"bytes":1024,"cache":"HIT","upstream":"cache:ram","dur_ms":3}`

func TestParseLine(t *testing.T) {
	rec, ok, err := ParseLine([]byte(sampleLine))
	if err != nil || !ok {
		t.Fatalf("ParseLine ok=%v err=%v", ok, err)
	}
	if rec.Method != "GET" || rec.Host != "example.com" || rec.Path != "/img/a.png" {
		t.Errorf("fields: %+v", rec)
	}
	if rec.Status != 200 || rec.Bytes != 1024 || rec.Cache != "HIT" || rec.DurMs != 3 {
		t.Errorf("numeric fields: %+v", rec)
	}
	if rec.Upstream != "cache:ram" {
		t.Errorf("upstream = %q", rec.Upstream)
	}
	if rec.Time.IsZero() {
		t.Error("time not parsed from slog envelope")
	}
}

func TestParseLineBlankAndBad(t *testing.T) {
	if _, ok, err := ParseLine([]byte("   ")); ok || err != nil {
		t.Errorf("blank: ok=%v err=%v", ok, err)
	}
	if _, _, err := ParseLine([]byte("{not json")); err == nil {
		t.Error("malformed line should error")
	}
}

func TestParseLineSkipsNonRequest(t *testing.T) {
	startup := `{"time":"2026-06-23T13:00:00Z","level":"INFO","msg":"cadish serving","addr":"127.0.0.1:80","sites":1}`
	if _, ok, err := ParseLine([]byte(startup)); ok || err != nil {
		t.Errorf("non-request slog line should be skipped: ok=%v err=%v", ok, err)
	}
	// A request line still passes.
	if _, ok, err := ParseLine([]byte(sampleLine)); !ok || err != nil {
		t.Errorf("request line should pass: ok=%v err=%v", ok, err)
	}
}

func TestFilterMatches(t *testing.T) {
	rec, _, _ := ParseLine([]byte(sampleLine))
	cases := []struct {
		name string
		f    Filter
		want bool
	}{
		{"empty matches", Filter{}, true},
		{"host substring", Filter{Host: "example"}, true},
		{"host case-insensitive", Filter{Host: "EXAMPLE.com"}, true},
		{"host miss", Filter{Host: "other"}, false},
		{"path substring", Filter{Path: "/img/"}, true},
		{"path miss", Filter{Path: "/css/"}, false},
		{"cache exact", Filter{Cache: "hit"}, true},
		{"cache miss", Filter{Cache: "MISS"}, false},
		{"status exact", Filter{Status: 200}, true},
		{"status exact miss", Filter{Status: 404}, false},
		{"status class 2xx", Filter{StatusClass: 2}, true},
		{"status class 4xx miss", Filter{StatusClass: 4}, false},
		{"min status ok", Filter{MinStatus: 200}, true},
		{"min status excludes", Filter{MinStatus: 400}, false},
		{"combined and", Filter{Host: "example", Cache: "HIT", Status: 200}, true},
		{"combined one fails", Filter{Host: "example", Cache: "MISS"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.f.Matches(rec); got != c.want {
				t.Errorf("Matches = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	for in, want := range map[string]Format{
		"": FormatText, "text": FormatText,
		"ncsa": FormatNCSA, "combined": FormatNCSA, "APACHE": FormatNCSA,
		"json": FormatJSON,
	} {
		got, err := ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("unknown format should error")
	}
}

func TestRenderText(t *testing.T) {
	rec, _, _ := ParseLine([]byte(sampleLine))
	out := Render(rec, FormatText)
	for _, want := range []string{"GET", "example.com/img/a.png", "-> 200", "HIT", "1024B", "3ms", "via cache:ram"} {
		if !strings.Contains(out, want) {
			t.Errorf("text render missing %q in %q", want, out)
		}
	}
}

func TestRenderNCSA(t *testing.T) {
	rec, _, _ := ParseLine([]byte(sampleLine))
	out := Render(rec, FormatNCSA)
	// example.com - - [23/Jun/2026:...] "GET /img/a.png HTTP/1.1" 200 1024 "-" "-" "HIT" "cache:ram"
	for _, want := range []string{
		`example.com - - [`,
		`"GET /img/a.png HTTP/1.1" 200 1024`,
		`"HIT"`,
		`"cache:ram"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ncsa render missing %q in %q", want, out)
		}
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	rec, _, _ := ParseLine([]byte(sampleLine))
	out := Render(rec, FormatJSON)
	// Re-parse the rendered JSON; the core fields must survive.
	rec2, ok, err := ParseLine([]byte(out))
	if err != nil || !ok {
		t.Fatalf("re-parse rendered json: ok=%v err=%v out=%s", ok, err, out)
	}
	if rec2.Method != "GET" || rec2.Status != 200 || rec2.Cache != "HIT" {
		t.Errorf("json round-trip lost fields: %+v", rec2)
	}
}

func TestStreamFiltersAndRenders(t *testing.T) {
	miss := strings.Replace(sampleLine, `"cache":"HIT"`, `"cache":"MISS"`, 1)
	miss = strings.Replace(miss, `"path":"/img/a.png"`, `"path":"/api/x"`, 1)
	input := sampleLine + "\n" + miss + "\n" + "\n" + "{bad line}\n"
	var out, errOut bytes.Buffer
	n, err := Stream(strings.NewReader(input), &out, &errOut, Filter{Cache: "HIT"}, FormatText)
	if err != nil {
		t.Fatalf("Stream err: %v", err)
	}
	if n != 1 {
		t.Errorf("emitted = %d, want 1 (only the HIT)", n)
	}
	if !strings.Contains(out.String(), "/img/a.png") || strings.Contains(out.String(), "/api/x") {
		t.Errorf("filter wrong; out=%q", out.String())
	}
	if !strings.Contains(errOut.String(), "cadish logs:") {
		t.Errorf("bad line should warn on errOut; got %q", errOut.String())
	}
}

// Follow must emit lines APPENDED after it starts (default tail-from-end), filter
// them, and stop on ctx cancellation.
func TestFollowTailsAppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.json")
	// Seed a pre-existing line that must NOT be emitted (tail-from-end default).
	if err := os.WriteFile(path, []byte(sampleLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, &out, nil, Filter{}, FormatText,
			FollowOptions{PollInterval: 5 * time.Millisecond})
	}()

	// Append two new lines after Follow has started tailing.
	time.Sleep(30 * time.Millisecond)
	appendLine(t, path, strings.Replace(sampleLine, "/img/a.png", "/new/1", 1))
	appendLine(t, path, strings.Replace(sampleLine, "/img/a.png", "/new/2", 1))

	// Wait for both to appear.
	waitFor(t, &out, func(s string) bool {
		return strings.Contains(s, "/new/1") && strings.Contains(s, "/new/2")
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow err: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "/img/a.png") {
		t.Errorf("tail-from-end emitted a pre-existing line:\n%s", got)
	}
}

// Follow with FromStart must emit the existing file content too.
func TestFollowFromStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.json")
	if err := os.WriteFile(path, []byte(sampleLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, &out, nil, Filter{}, FormatText,
			FollowOptions{FromStart: true, PollInterval: 5 * time.Millisecond})
	}()
	waitFor(t, &out, func(s string) bool { return strings.Contains(s, "/img/a.png") })
	cancel()
	<-done
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, buf *syncBuffer, cond func(string) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond(buf.String()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met; buffer:\n%s", buf.String())
}

// syncBuffer is a goroutine-safe buffer for capturing Follow output concurrently.
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
