package cache

import (
	"bytes"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// TestRAMWriter_PerObjectCapOverflow verifies B2's per-object bound: a single object
// larger than maxObjectBytes routed to RAM overflows — its buffer is freed, nothing is
// committed, a Get is a miss, and the tier's byte count is unchanged. The client stream
// is unaffected (every Write reports full success).
func TestRAMWriter_PerObjectCapOverflow(t *testing.T) {
	// Tier capacity is generous; the PER-OBJECT cap (16 bytes) is what trips.
	r := NewRAMTier(1<<20, 16, 1<<20)

	w, err := r.Writer(ObjectMeta{Key: "big.m3u8", ContentType: "application/vnd.apple.mpegurl"})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("x"), 64) // 64 > 16-byte per-object cap
	n, werr := w.Write(body)
	if werr != nil || n != len(body) {
		t.Fatalf("Write returned (%d,%v); the client stream must see full success", n, werr)
	}
	if err := w.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if _, ok := r.Get("big.m3u8"); ok {
		t.Fatal("over-cap object must NOT be cached (overflow => no commit)")
	}
	if r.Bytes() != 0 {
		t.Fatalf("tier bytes = %d, want 0 (overflowed object must not count)", r.Bytes())
	}
	if got := atomic.LoadInt64(&r.inflightBytes); got != 0 {
		t.Fatalf("in-flight reservation leaked: %d, want 0 after Commit", got)
	}
}

// TestRAMWriter_UnderCapStillCaches is the control: an object UNDER the per-object cap
// caches normally and is readable (the bound must not regress small objects).
func TestRAMWriter_UnderCapStillCaches(t *testing.T) {
	r := NewRAMTier(1<<20, 1<<20, 1<<20)
	putTier(t, r, "ok.m3u8", "small-playlist", "application/vnd.apple.mpegurl")
	if body, _, ok := getTier(t, r, "ok.m3u8"); !ok || body != "small-playlist" {
		t.Fatalf("under-cap object should cache: got (%q,%v)", body, ok)
	}
	if got := atomic.LoadInt64(&r.inflightBytes); got != 0 {
		t.Fatalf("in-flight reservation leaked after Commit: %d", got)
	}
}

// TestStore_KnownLargeRamExtensionRoutesToDisk verifies B2's size-aware routing: a
// ram-extension (.m3u8) whose size is KNOWN and exceeds the per-object RAM cap is
// routed to DISK by pickTier, while an unknown-size (-1) ram-extension still starts in
// RAM (protected by the bounded writer).
func TestStore_KnownLargeRamExtensionRoutesToDisk(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(RouterConfig{
		RAMMaxBytes: 1 << 20, DiskMaxBytes: 1 << 20, DiskDir: dir,
		SmallObjectThreshold: 100, RAMMaxObjectBytes: 1024, RAMInflightBudget: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if tier := st.pickTier("huge.m3u8", 4096); tier != st.disk {
		t.Error("known-large .m3u8 (4096 > 1024 cap) must route to DISK")
	}
	if tier := st.pickTier("small.m3u8", 512); tier != st.ram {
		t.Error("known-small .m3u8 (512 <= 1024 cap) must route to RAM")
	}
	if tier := st.pickTier("unknown.m3u8", -1); tier != st.ram {
		t.Error("unknown-size .m3u8 must still start in RAM (bounded writer protects it)")
	}
}

// TestRAMWriter_GlobalBudgetOverflow verifies B2's process-wide reservation: with
// several concurrent ramWriters whose COMBINED buffering exceeds the budget, the later
// ones overflow (stream-through, no allocation beyond budget) rather than busting the
// budget. Each writer is individually under the per-object cap — only the global total
// trips. We hold the writers open (do not Commit) so all reservations are live at once.
func TestRAMWriter_GlobalBudgetOverflow(t *testing.T) {
	const objSize = 1000
	const budget = 2500 // fits 2 objects (2000) but not 3 (3000)
	r := NewRAMTier(1<<20, objSize, budget)

	body := bytes.Repeat([]byte("y"), objSize)
	writers := make([]TierWriter, 4)
	overflowed := 0
	for i := range writers {
		w, err := r.Writer(ObjectMeta{Key: "k" + strconv.Itoa(i) + ".m3u8"})
		if err != nil {
			t.Fatal(err)
		}
		writers[i] = w
		if _, err := w.Write(body); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		if w.(*ramWriter).overflow {
			overflowed++
		}
	}

	// Live reservation must never exceed the budget.
	if got := atomic.LoadInt64(&r.inflightBytes); got > budget {
		t.Fatalf("in-flight bytes %d exceeded budget %d", got, budget)
	}
	// 2 fit (2000 <= 2500), the 3rd and 4th (would be 3000/4000) must overflow.
	if overflowed != 2 {
		t.Fatalf("overflowed = %d, want 2 (only 2 of 4 fit the %d budget)", overflowed, budget)
	}

	// Commit all; releasing reservations must drain the budget back to zero, and the
	// two non-overflowed objects must be the ones actually cached.
	for _, w := range writers {
		if err := w.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
	if got := atomic.LoadInt64(&r.inflightBytes); got != 0 {
		t.Fatalf("budget not fully released: %d in-flight bytes remain", got)
	}
	if r.Len() != 2 {
		t.Fatalf("cached objects = %d, want 2 (the in-budget writers)", r.Len())
	}
}

// TestRAMWriter_ReservationReleasedOnAbort makes sure Abort releases the reservation
// exactly once (a leak would permanently shrink the usable budget).
func TestRAMWriter_ReservationReleasedOnAbort(t *testing.T) {
	r := NewRAMTier(1<<20, 1<<20, 4096)
	w, err := r.Writer(ObjectMeta{Key: "a.m3u8"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("z"), 2000)); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&r.inflightBytes); got != 2000 {
		t.Fatalf("expected 2000 reserved mid-write, got %d", got)
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&r.inflightBytes); got != 0 {
		t.Fatalf("Abort must release the reservation; %d bytes leaked", got)
	}
}

// TestRAMWriter_ConcurrentStress hammers many concurrent bounded writers (mixed sizes,
// commits + aborts) against a tight global budget. It must be race-free (run -race),
// never exceed the budget, and end with the in-flight reservation fully drained.
func TestRAMWriter_ConcurrentStress(t *testing.T) {
	const budget = 64 << 10
	r := NewRAMTier(256<<10, 8<<10, budget)

	var maxSeen int64
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				w, err := r.Writer(ObjectMeta{Key: "g" + strconv.Itoa(g) + "-" + strconv.Itoa(i%8) + ".m3u8"})
				if err != nil {
					return
				}
				// Sizes straddle the per-object cap so some overflow on the cap and
				// some on the budget.
				size := 1 << (10 + (i % 4)) // 1KiB..8KiB
				_, _ = io.Copy(w, bytes.NewReader(bytes.Repeat([]byte("q"), size)))
				if cur := atomic.LoadInt64(&r.inflightBytes); cur > atomic.LoadInt64(&maxSeen) {
					atomic.StoreInt64(&maxSeen, cur)
				}
				if i%3 == 0 {
					_ = w.Abort()
				} else {
					_ = w.Commit()
				}
			}
		}(g)
	}
	wg.Wait()

	if got := atomic.LoadInt64(&r.inflightBytes); got != 0 {
		t.Fatalf("in-flight reservation not drained after stress: %d", got)
	}
	if maxSeen > budget {
		t.Fatalf("observed in-flight bytes %d exceeded budget %d", maxSeen, budget)
	}
}
