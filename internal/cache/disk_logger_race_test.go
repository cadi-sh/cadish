package cache

import (
	"io"
	"log/slog"
	"sync"
	"testing"
)

// TestDiskTierSetLoggerCommitRace is the R33 -race pin: SetLogger (re-invoked on every
// reload via attachStoreLoggers) must not race the oversize-commit path that reads the
// logger under a shard lock SetLogger never holds. Before the atomic.Pointer fix this is
// a data race on DiskTier.log. Run under -race; it must be clean.
//
// A tiny per-shard budget makes every commit oversize, so each commit hits
// logOversizeDiscard (the d.log read). Concurrently we hammer SetLogger as a reload
// would. The rate-limiter means most reads return early, but the READ of d.log itself is
// what races the WRITE — so the access pattern is what matters, not whether it logs.
func TestDiskTierSetLoggerCommitRace(t *testing.T) {
	dir := t.TempDir()
	// shardCount(maxBytes) shards each get an even slice of maxBytes; a 1-byte object
	// exceeds any realistic per-shard cap only if the cap is < 1, which it is not. Use a
	// budget small enough that the per-shard cap is below our object size: pick a large
	// object and a small tier so n > s.maxBytes always holds.
	d, err := NewDiskTier(dir, 4096)
	if err != nil {
		t.Fatalf("NewDiskTier: %v", err)
	}
	defer d.Close()

	body := make([]byte, 64*1024) // 64 KiB >> any per-shard cap of a 4 KiB tier

	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	// Writer: repeatedly commit an oversize object (hits logOversizeDiscard → reads d.log).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			w, werr := d.Writer(ObjectMeta{Key: "k", Size: int64(len(body))})
			if werr != nil {
				continue
			}
			_, _ = w.Write(body)
			_ = w.Commit() // oversize → discarded, logOversizeDiscard runs
		}
	}()
	// Reloader: repeatedly (re)attach the logger, as attachStoreLoggers does on SIGHUP.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			if i%2 == 0 {
				d.SetLogger(discardLogger)
			} else {
				d.SetLogger(nil)
			}
		}
	}()
	wg.Wait()

	if got := d.OversizeDiscards(); got == 0 {
		t.Fatal("expected oversize discards to exercise the logger-read path, got 0")
	}
}
