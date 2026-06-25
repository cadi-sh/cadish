package cache

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// TestDiskOversizeDiscardLogsAndCounts: an object larger than its shard's cap is
// discarded by DiskTier.commit (streams through uncached). Before, that discard was
// silent (return nil) — the operator had no signal a large object was never cached.
// It must now (a) be counted, and (b) emit a log when a logger is attached, so the
// per-shard-cap discard is observable (F6).
func TestDiskOversizeDiscardLogsAndCounts(t *testing.T) {
	dir := t.TempDir()
	// A tiny tier: shardCount collapses to 1 shard whose cap is the whole budget.
	// 1 KiB budget; commit a 4 KiB object → exceeds the shard cap → discarded.
	d, err := NewDiskTier(dir, 1<<10)
	if err != nil {
		t.Fatalf("NewDiskTier: %v", err)
	}
	defer d.Close()

	var buf bytes.Buffer
	d.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	meta := ObjectMeta{Key: "/big.mp4"}
	w, err := d.Writer(meta)
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader(strings.Repeat("x", 4<<10))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The object must NOT be cached (it exceeded the shard cap).
	if _, ok := d.Get("/big.mp4"); ok {
		t.Fatalf("oversized object was unexpectedly cached")
	}
	// It must be counted.
	if n := d.OversizeDiscards(); n != 1 {
		t.Errorf("OversizeDiscards = %d, want 1", n)
	}
	// And a log must have been emitted.
	if !strings.Contains(buf.String(), "oversize") && !strings.Contains(buf.String(), "discard") {
		t.Errorf("expected an oversize-discard log line; got: %q", buf.String())
	}
}

// TestDiskOversizeDiscardSilentWithoutLogger: with no logger attached, an oversize
// discard must still count but never panic (nil-logger safe — the common path).
func TestDiskOversizeDiscardSilentWithoutLogger(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 1<<10)
	if err != nil {
		t.Fatalf("NewDiskTier: %v", err)
	}
	defer d.Close()

	meta := ObjectMeta{Key: "/big.mp4"}
	w, err := d.Writer(meta)
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader(strings.Repeat("x", 4<<10))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if n := d.OversizeDiscards(); n != 1 {
		t.Errorf("OversizeDiscards = %d, want 1", n)
	}
}
