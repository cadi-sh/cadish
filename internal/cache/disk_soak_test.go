package cache

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDiskTier_EvictionFsyncSoak (OBS-1) hammers the disk tier's commit / eviction /
// per-shard-cap-discard / LRU-touch paths from many goroutines while the background
// index flusher (fsync path) runs underneath, and asserts the tier:
//
//   - never panics or deadlocks (the whole soak completes within a hard deadline);
//   - never blocks an individual commit/get unboundedly (each op finishes well under a
//     generous per-op bound — i.e. a full/slow shard cannot wedge a writer behind the
//     index flush, which is exactly the OBS-1 worry);
//   - stays size-consistent (aggregate Bytes never exceeds maxBytes, and the post-drain
//     accounting matches a fresh-reopen recount);
//   - evicts correctly (it accepts far more data than it holds and the survivors are
//     byte-exact, with a clean reopen).
//
// It is deterministic: fixed bodies, a fixed key space, no rand-dependent timing or
// sleeps that gate assertions. It is skipped under `-short` (it churns ~GBs of temp
// I/O). The motivating environmental observation (macOS UE-state processes under
// over-parallel orchestration) is NOT what this reproduces — this confirms the cadish
// eviction/fsync code path itself makes forward progress and stays consistent under
// pressure.
func TestDiskTier_EvictionFsyncSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test: skipped under -short")
	}

	dir := t.TempDir()
	// A modest budget so eviction churns hard: many shards, each small relative to the
	// working set the goroutines push through it.
	maxBytes := int64(16 << 20)
	d, err := NewDiskTier(dir, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.shards) < 2 {
		t.Fatalf("expected a multi-shard tier to exercise per-shard eviction, got %d", len(d.shards))
	}

	const (
		workers      = 16
		opsPerWorker = 2500
		keyspace     = 512 // shared key space → collisions → replace + cross-goroutine LRU churn
		// wedgeBudget is the per-op latency that signals a real WEDGE (an unbounded block
		// on the eviction/fsync path) — the OBS-1 concern. It is deliberately large: a
		// single op stalling a few seconds is NORMAL I/O contention when the whole test
		// suite runs in parallel under -race (CPU/disk saturation — exactly the
		// environmental effect OBS-1 identified as NOT a cadish defect). Only a stall
		// approaching the overall deadline means the path actually wedged.
		wedgeBudget   = 30 * time.Second
		overallBudget = 90 * time.Second
	)
	// Body that is a meaningful fraction of a shard cap so a handful per shard forces
	// eviction. shardCap ≈ maxBytes/shards; pick ~1/8 of the smallest shard cap.
	smallestCap, largestCap := maxBytes, int64(0)
	for _, s := range d.shards {
		if s.maxBytes < smallestCap {
			smallestCap = s.maxBytes
		}
		if s.maxBytes > largestCap {
			largestCap = s.maxBytes
		}
	}
	bodyLen := int(smallestCap / 8)
	if bodyLen < 4096 {
		bodyLen = 4096
	}
	body := strings.Repeat("x", bodyLen)
	// An object just over the LARGEST shard cap, so commit's per-shard-cap guard
	// discards it no matter which shard a "huge-" key hashes to. Sizing it ~one-shard
	// rather than whole-tier keeps the soak's temp I/O bounded while still hitting the
	// discard branch on every shard.
	oversize := strings.Repeat("X", int(largestCap)+1)

	var (
		maxOp     atomic.Int64 // max single-op latency observed (ns)
		commits   atomic.Int64
		gets      atomic.Int64
		oversizes atomic.Int64
	)
	recordOp := func(start time.Time) {
		ns := time.Since(start).Nanoseconds()
		for {
			cur := maxOp.Load()
			if ns <= cur || maxOp.CompareAndSwap(cur, ns) {
				break
			}
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; i < opsPerWorker; i++ {
					// Deterministic per-(worker,i) choice of operation and key.
					sel := (w*7 + i*13)
					key := fmt.Sprintf("seg-%d.ts", sel%keyspace)
					switch {
					case sel%17 == 0:
						// Oversize commit → must be discarded, never wedge the shard.
						start := time.Now()
						soakPut(t, d, "huge-"+key, oversize)
						recordOp(start)
						oversizes.Add(1)
					case sel%3 == 0:
						// Read (LRU MoveToFront = a write under the shard lock).
						start := time.Now()
						if r, ok := d.Get(key); ok {
							_, _ = io.Copy(io.Discard, r)
							_ = r.Close()
						}
						recordOp(start)
						gets.Add(1)
					default:
						start := time.Now()
						soakPut(t, d, key, body)
						recordOp(start)
						commits.Add(1)
					}
					// Continuous size invariant: the tier must NEVER exceed its budget,
					// no matter how eviction interleaves with concurrent commits.
					if b := d.Bytes(); b > maxBytes {
						t.Errorf("disk bytes %d exceeded maxBytes %d (worker %d op %d)", b, maxBytes, w, i)
						return
					}
				}
			}(w)
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(overallBudget):
		t.Fatalf("soak did not complete within %s — possible wedge/deadlock in the eviction/fsync path", overallBudget)
	}

	if t.Failed() {
		_ = d.Close()
		return
	}

	// Wedge assertion: no single commit/get may block UNBOUNDEDLY behind the index
	// flush or a full shard (the OBS-1 concern). The bound is the wedge threshold, not a
	// performance SLA — a multi-second op under full-suite -race contention is normal
	// disk saturation, not a defect; only a stall approaching the overall deadline means
	// the path genuinely wedged. The max op latency is logged below for visibility.
	if mx := time.Duration(maxOp.Load()); mx > wedgeBudget {
		t.Errorf("a single op took %s, exceeding the %s wedge bound — the eviction/fsync path may block writers unboundedly", mx, wedgeBudget)
	}

	// Consistency: drain the tier (final synchronous flush) and reopen. The reopen recount
	// (which re-validates every blob against its recorded size) must match a tier that
	// stayed internally consistent, and must stay within budget.
	preLen := d.Len()
	preBytes := d.Bytes()
	if preBytes > maxBytes {
		t.Fatalf("post-soak bytes %d exceed maxBytes %d", preBytes, maxBytes)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close (final flush): %v", err)
	}

	d2, err := NewDiskTier(dir, maxBytes)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()
	if got := d2.Bytes(); got > maxBytes {
		t.Fatalf("after reopen bytes %d exceed maxBytes %d", got, maxBytes)
	}
	// The reopen Len must not exceed the pre-close Len (load drops any blob whose size
	// disagrees with the index — a torn/inconsistent write would show up as a shrink we
	// can at least observe; an OVER-count would mean phantom entries, a real bug).
	if d2.Len() > preLen {
		t.Fatalf("reopen Len %d > pre-close Len %d — index/blob inconsistency", d2.Len(), preLen)
	}
	// Every survivor must be byte-exact (no truncation/torn blob served as a hit).
	survivors := 0
	bad := 0
	for i := 0; i < keyspace; i++ {
		k := fmt.Sprintf("seg-%d.ts", i)
		got, _, ok := getTier(t, d2, k)
		if !ok {
			continue
		}
		survivors++
		if got != body {
			bad++
		}
	}
	if bad != 0 {
		t.Fatalf("%d/%d survivors were corrupt after reopen", bad, survivors)
	}

	t.Logf("soak ok: commits=%d gets=%d oversize-discards=%d; survivors=%d; preBytes=%d/%d; reopenBytes=%d; maxOp=%s; oversizeDiscards(stat)=%d",
		commits.Load(), gets.Load(), oversizes.Load(), survivors, preBytes, maxBytes, d2.Bytes(),
		time.Duration(maxOp.Load()), d2.OversizeDiscards()+d.OversizeDiscards())
}

// soakPut commits body under key, failing the test on a non-discard error. (An
// oversize body is discarded by commit() with a nil error, so this never fails on it.)
func soakPut(t *testing.T, d *DiskTier, key, body string) {
	t.Helper()
	w, err := d.Writer(ObjectMeta{Key: key, ContentType: "video/mp2t"})
	if err != nil {
		t.Errorf("Writer(%s): %v", key, err)
		return
	}
	if _, err := io.WriteString(w, body); err != nil {
		_ = w.Abort()
		t.Errorf("write(%s): %v", key, err)
		return
	}
	if err := w.Commit(); err != nil {
		t.Errorf("commit(%s): %v", key, err)
	}
}
