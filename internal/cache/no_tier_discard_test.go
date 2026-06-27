package cache

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// TestNoTierDiscardChunkedRAMOnly is the regression guard for the silent
// cache-degradation footgun: on a RAM-only deployment (cache { ram … } with NO disk
// tier, so DiskMaxBytes == 0), an unknown-length / chunked response (Content-Length
// -1, the value the server records from resp.ContentLength) is routed by the automatic
// size policy (pickTier) to the disk tier — which has zero budget — and is therefore
// cached NOWHERE, streaming through uncached. That used to be invisible (and, when it
// did reach the disk commit, was mislabeled as an "oversize" discard). It must now be
// counted and logged as a DISTINCT "no tier" signal so an operator can see that a
// chunked/dynamic origin is getting zero caching.
func TestNoTierDiscardChunkedRAMOnly(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          1 << 20, // a real RAM tier…
		DiskMaxBytes:         0,       // …but NO disk tier (RAM-only deployment)
		DiskDir:              t.TempDir(),
		SmallObjectThreshold: 1 << 10,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var buf bytes.Buffer
	st.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// 1. The footgun: a chunked / unknown-length response (Size == -1) on a non-RAM
	//    extension. pickTier routes it to the zero-budget disk tier → cached nowhere.
	meta := ObjectMeta{Key: "/api/stream.json", Size: -1}
	w, err := st.Writer(meta)
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader("dynamic chunked body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// It must NOT be cached.
	if _, ok := st.Get("/api/stream.json"); ok {
		t.Fatalf("chunked response was unexpectedly cached on a RAM-only deployment")
	}
	// It must be counted as a NO-TIER discard, and NOT as an oversize discard
	// (the two signals must not be conflated).
	if got := st.Stats().DiskNoTierDiscards; got != 1 {
		t.Errorf("DiskNoTierDiscards = %d, want 1", got)
	}
	if got := st.Stats().DiskOversizeDiscards; got != 0 {
		t.Errorf("DiskOversizeDiscards = %d, want 0 (must not mislabel a no-tier discard as oversize)", got)
	}
	// And it must be observable in the log, with the RAM-only / disk-tier hint.
	if !strings.Contains(buf.String(), "no disk tier") {
		t.Errorf("expected a no-tier discard log line; got: %q", buf.String())
	}

	// 2. A NORMAL cached response (known small Content-Length) routes to RAM and is
	//    cached — it must NOT increment the no-tier counter.
	wn, err := st.Writer(ObjectMeta{Key: "/small.json", Size: 4})
	if err != nil {
		t.Fatalf("Writer(small): %v", err)
	}
	if _, err := io.WriteString(wn, "data"); err != nil {
		t.Fatalf("write(small): %v", err)
	}
	if err := wn.Commit(); err != nil {
		t.Fatalf("Commit(small): %v", err)
	}
	if _, ok := st.Get("/small.json"); !ok {
		t.Fatalf("normal small response was not cached")
	}
	if got := st.Stats().DiskNoTierDiscards; got != 1 {
		t.Errorf("DiskNoTierDiscards = %d after caching a normal response, want still 1", got)
	}
}

// TestNoTierDiscardNotCountedWithDiskTier proves precision: with a REAL disk tier
// configured, the same chunked / unknown-length response IS cached and does NOT
// increment the no-tier counter — the signal fires ONLY for the RAM-only footgun, not
// for normal two-tier operation.
func TestNoTierDiscardNotCountedWithDiskTier(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          1 << 20,
		DiskMaxBytes:         1 << 20, // a real disk tier exists
		DiskDir:              t.TempDir(),
		SmallObjectThreshold: 1 << 10,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	w, err := st.Writer(ObjectMeta{Key: "/api/stream.json", Size: -1})
	if err != nil {
		t.Fatalf("Writer: %v", err)
	}
	if _, err := io.Copy(w, strings.NewReader("dynamic chunked body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if _, ok := st.Get("/api/stream.json"); !ok {
		t.Fatalf("chunked response was not cached despite a configured disk tier")
	}
	if got := st.Stats().DiskNoTierDiscards; got != 0 {
		t.Errorf("DiskNoTierDiscards = %d with a real disk tier, want 0", got)
	}
}
