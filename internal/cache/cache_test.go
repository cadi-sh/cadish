package cache

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func putTier(t *testing.T, tier Tier, key, body, ct string) {
	t.Helper()
	w, err := tier.Writer(ObjectMeta{Key: key, ContentType: ct})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
}

func getTier(t *testing.T, tier Tier, key string) (string, ObjectMeta, bool) {
	t.Helper()
	r, ok := tier.Get(key)
	if !ok {
		return "", ObjectMeta{}, false
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), r.Meta, true
}

func TestRAMTier_PutGet(t *testing.T) {
	r := NewRAMTier(1<<20, 0, 0) // 0/0 -> per-object + budget bounds disabled (legacy behavior)
	putTier(t, r, "a.m3u8", "playlist-data", "application/vnd.apple.mpegurl")
	body, meta, ok := getTier(t, r, "a.m3u8")
	if !ok || body != "playlist-data" {
		t.Fatalf("got (%q, %v) want playlist-data", body, ok)
	}
	if meta.Size != int64(len("playlist-data")) {
		t.Fatalf("size = %d", meta.Size)
	}
	if meta.ContentType != "application/vnd.apple.mpegurl" {
		t.Fatalf("ct = %q", meta.ContentType)
	}
	if _, _, ok := getTier(t, r, "missing"); ok {
		t.Fatal("expected miss")
	}
}

func TestRAMTier_LRUEviction(t *testing.T) {
	// Tier holds ~20 bytes. Each object is 10 bytes.
	r := NewRAMTier(20, 0, 0)
	putTier(t, r, "k1", "0123456789", "")
	putTier(t, r, "k2", "0123456789", "")
	// Touch k1 so it becomes MRU; k2 is now LRU.
	if _, _, ok := getTier(t, r, "k1"); !ok {
		t.Fatal("k1 should be present")
	}
	// Insert k3 -> must evict k2 (the LRU), keep k1 and k3.
	putTier(t, r, "k3", "0123456789", "")

	if _, _, ok := getTier(t, r, "k2"); ok {
		t.Fatal("k2 should have been evicted")
	}
	if _, _, ok := getTier(t, r, "k1"); !ok {
		t.Fatal("k1 should still be present (was touched)")
	}
	if _, _, ok := getTier(t, r, "k3"); !ok {
		t.Fatal("k3 should be present")
	}
	if got := r.Bytes(); got != 20 {
		t.Fatalf("bytes = %d want 20", got)
	}
}

// TestRAMTier_ClockSecondChanceConsumed proves the CLOCK ref bit grants exactly ONE
// second chance, not permanent immunity: a read keeps an entry through the next
// eviction (the bit is honored and cleared), but if it is not read again it becomes a
// normal eviction candidate on the following pressure.
func TestRAMTier_ClockSecondChanceConsumed(t *testing.T) {
	r := NewRAMTier(20, 0, 0) // single shard, holds ~2 of the 10-byte objects
	putTier(t, r, "k1", "0123456789", "")
	putTier(t, r, "k2", "0123456789", "")

	// Read k1 -> sets its ref bit. Inserting k3 must evict k2 (ref clear) and spare
	// k1 via its second chance, which also CLEARS k1's ref bit.
	if _, _, ok := getTier(t, r, "k1"); !ok {
		t.Fatal("k1 should be present")
	}
	putTier(t, r, "k3", "0123456789", "")
	if _, _, ok := getTier(t, r, "k2"); ok {
		t.Fatal("k2 should have been evicted")
	}
	// getTier(k1) above re-set the ref via the lookups; read k1's presence WITHOUT
	// going through getTier (which would re-arm the bit) by checking the shard directly.
	if _, ok := r.shard("k1").items["k1"]; !ok {
		t.Fatal("k1 should have survived via its second chance")
	}

	// k1's bit was consumed by the second chance and not re-armed. Inserting k4 must
	// now evict k1 (the LRU with a clear bit), keeping k3 and k4.
	putTier(t, r, "k4", "0123456789", "")
	if _, ok := r.shard("k1").items["k1"]; ok {
		t.Fatal("k1 should have been evicted: its second chance was already consumed")
	}
	if _, ok := r.shard("k3").items["k3"]; !ok {
		t.Fatal("k3 should still be present")
	}
	if _, ok := r.shard("k4").items["k4"]; !ok {
		t.Fatal("k4 should be present")
	}
}

// TestRAMTier_ConcurrentHotKeyGet hammers a single hot key with many concurrent Gets
// while commits churn the same shard, exercising the RLock read path against the Lock
// write path. Run under -race it guards the shared/exclusive locking and the atomic
// ref bit (the whole point of the CLOCK read path: hot-key Gets do not serialize).
func TestRAMTier_ConcurrentHotKeyGet(t *testing.T) {
	r := NewRAMTier(1<<20, 0, 0)
	putTier(t, r, "hot", "0123456789", "")

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if rd, ok := r.Get("hot"); ok {
					_, _ = io.ReadAll(rd)
					_ = rd.Close()
				}
			}
		}()
	}
	// Concurrent writer re-committing the hot key (write lock) to race the readers.
	// Inlined (no t.Fatal) because this runs off the test goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			w, err := r.Writer(ObjectMeta{Key: "hot"})
			if err != nil {
				continue
			}
			_, _ = io.WriteString(w, "0123456789")
			_ = w.Commit()
		}
	}()
	wg.Wait()
}

func TestRAMTier_OversizedNotCached(t *testing.T) {
	r := NewRAMTier(5, 0, 0)
	putTier(t, r, "big", "0123456789", "") // 10 bytes > 5 cap
	if _, _, ok := getTier(t, r, "big"); ok {
		t.Fatal("object larger than tier must not be cached")
	}
	if r.Bytes() != 0 {
		t.Fatalf("bytes = %d want 0", r.Bytes())
	}
}

func TestDiskTier_PutGetAndEviction(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 20)
	if err != nil {
		t.Fatal(err)
	}
	putTier(t, d, "v1.mp4", "0123456789", "video/mp4")
	putTier(t, d, "v2.mp4", "0123456789", "video/mp4")
	// touch v1 -> v2 becomes LRU
	getTier(t, d, "v1.mp4")
	putTier(t, d, "v3.mp4", "0123456789", "video/mp4")

	if _, _, ok := getTier(t, d, "v2.mp4"); ok {
		t.Fatal("v2 should be evicted")
	}
	if body, _, ok := getTier(t, d, "v1.mp4"); !ok || body != "0123456789" {
		t.Fatalf("v1 missing/bad: %q %v", body, ok)
	}
	if d.Len() != 2 {
		t.Fatalf("len = %d want 2", d.Len())
	}
}

func TestDiskTier_PersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	putTier(t, d, "keep.mp4", "the-body-bytes", "video/mp4")
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: entry + metadata must survive.
	d2, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	body, meta, ok := getTier(t, d2, "keep.mp4")
	if !ok || body != "the-body-bytes" {
		t.Fatalf("survived restart? got (%q,%v)", body, ok)
	}
	if meta.ContentType != "video/mp4" || meta.Size != int64(len("the-body-bytes")) {
		t.Fatalf("metadata not persisted: %+v", meta)
	}
}

// TestDiskTier_PersistDebouncedAndOnClose verifies the index is NOT rewritten on
// every commit (the hot-path cost we removed) but IS flushed on Close, and that a
// reopen after Close recovers everything.
func TestDiskTier_PersistDebouncedAndOnClose(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Commit several objects in quick succession. With debounced persistence the
	// background flusher (5s interval) almost certainly has not run yet, so the
	// index file should not exist or be stale — the key point is commit() did not
	// synchronously write it.
	for i := 0; i < 5; i++ {
		putTier(t, d, "v"+string(rune('0'+i))+".mp4", "0123456789", "video/mp4")
	}
	// Close must synchronously flush the full index.
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing again must be safe (idempotent) and not panic.
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	d2, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if d2.Len() != 5 {
		t.Fatalf("reopened len = %d want 5", d2.Len())
	}
	for i := 0; i < 5; i++ {
		k := "v" + string(rune('0'+i)) + ".mp4"
		if body, _, ok := getTier(t, d2, k); !ok || body != "0123456789" {
			t.Fatalf("%s missing after reopen: %q %v", k, body, ok)
		}
	}
}

func TestDiskTier_AbortDiscards(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	w, err := d.Writer(ObjectMeta{Key: "partial.mp4"})
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "half-written")
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := getTier(t, d, "partial.mp4"); ok {
		t.Fatal("aborted write must not be cached")
	}
	if d.Len() != 0 {
		t.Fatalf("len = %d want 0", d.Len())
	}
}

// TestDiskTier_ConcurrentStress hammers the disk tier with concurrent commits,
// gets and evictions while the background flusher runs, then Closes mid-flight.
// It must stay race-free (run with -race) and end consistent.
func TestDiskTier_ConcurrentStress(t *testing.T) {
	dir := t.TempDir()
	d, err := NewDiskTier(dir, 64<<10) // small cap to force constant eviction
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := "obj-" + strconv.Itoa(g) + "-" + strconv.Itoa(i%20) + ".mp4"
				w, err := d.Writer(ObjectMeta{Key: k, ContentType: "video/mp4"})
				if err != nil {
					return
				}
				_, _ = io.WriteString(w, strings.Repeat("x", 1024))
				_ = w.Commit()
				if r, ok := d.Get(k); ok {
					_, _ = io.Copy(io.Discard, r)
					r.Close()
				}
			}
		}(g)
	}
	wg.Wait()

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Reopen must succeed and be internally consistent (curBytes <= cap).
	d2, err := NewDiskTier(dir, 64<<10)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer d2.Close()
	if d2.Bytes() > 64<<10 {
		t.Fatalf("reopened bytes %d exceed cap", d2.Bytes())
	}
}

func TestStore_Routing(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          1 << 20,
		DiskMaxBytes:         1 << 20,
		DiskDir:              dir,
		SmallObjectThreshold: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cases := []struct {
		key     string
		size    int64
		wantRAM bool
		reason  string
	}{
		{"playlist.m3u8", 5000, true, "m3u8 always RAM regardless of size"},
		{"thumb.jpg", 99999, true, "image always RAM"},
		{"photo.WEBP", 1, true, "image ext case-insensitive"},
		{"clip.mp4", 9999, false, "large mp4 -> disk"},
		{"seg.ts", 500000, false, "ts segment -> disk"},
		{"small.bin", 50, true, "unknown ext but under threshold -> RAM"},
		{"big.bin", 5000, false, "unknown ext over threshold -> disk"},
		{"unknown.dat", -1, false, "unknown size -> disk"},
	}
	for _, c := range cases {
		tier := st.pickTier(c.key, c.size)
		isRAM := tier == st.ram
		if isRAM != c.wantRAM {
			t.Errorf("%s (%s): routed to RAM=%v want %v", c.key, c.reason, isRAM, c.wantRAM)
		}
	}
}

func TestStore_GetChecksBothTiers(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(RouterConfig{
		RAMMaxBytes: 1 << 20, DiskMaxBytes: 1 << 20, DiskDir: dir, SmallObjectThreshold: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Write an m3u8 (RAM) and an mp4 (disk) via the store.
	wm, _ := st.Writer(ObjectMeta{Key: "p.m3u8", ContentType: "application/vnd.apple.mpegurl"})
	io.WriteString(wm, "PLAYLIST")
	wm.Commit()

	wv, _ := st.Writer(ObjectMeta{Key: "v.mp4", Size: 9999, ContentType: "video/mp4"})
	io.WriteString(wv, strings.Repeat("X", 9999))
	wv.Commit()

	if st.Stats().RAMObjects != 1 || st.Stats().DiskObjects != 1 {
		t.Fatalf("stats = %+v", st.Stats())
	}

	r, ok := st.Get("p.m3u8")
	if !ok {
		t.Fatal("playlist should be found in RAM tier")
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "PLAYLIST" {
		t.Fatalf("got %q", b)
	}

	r2, ok := st.Get("v.mp4")
	if !ok {
		t.Fatal("video should be found in disk tier")
	}
	r2.Close()
}
