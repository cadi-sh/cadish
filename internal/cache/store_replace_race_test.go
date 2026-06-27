package cache

import (
	"fmt"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
)

// genBody builds a body whose CONTENT is a pure function of its LENGTH: byte i is
// (length+i) mod 251. So a reader holding only the served Reader.Meta.Size can
// recompute the exact bytes the body MUST contain. Any torn read — a body whose
// bytes belong to a different generation than its own declared Size, or a Size that
// disagrees with the byte count — is therefore detectable without out-of-band state.
func genBody(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = byte((length + i) % 251)
	}
	return b
}

// verifyBody reports whether body is exactly the canonical content for its own
// length (the genBody invariant). size is the served Meta.Size and must equal the
// byte count.
func verifyBody(size int64, body []byte) bool {
	if int64(len(body)) != size {
		return false
	}
	for i, c := range body {
		if c != byte((len(body)+i)%251) {
			return false
		}
	}
	return true
}

// TestStoreReplaceServeIntegrity hammers concurrent same-key REPLACES (each routed
// RAM or disk, deliberately FLIPPING tiers to exercise the cross-tier dedup + blob
// swap) against concurrent GetTier+full-read serves, under -race. The invariant: a
// served object is ALWAYS self-consistent — the body read out matches the canonical
// content for its own served Meta.Size (verifyBody). This catches a torn read where
// the served body and its metadata (Size/Content-Length) come from different
// generations, an os.File opened across a blob remove→rename gap, or a RAM entry
// whose bytes are swapped under the reader. A key may legitimately read as absent
// (a cross-tier dedup race can momentarily leave it in neither tier); that is safe
// (the server revalidates) and is NOT a failure — only a self-INCONSISTENT served
// body is.
func TestStoreReplaceServeIntegrity(t *testing.T) {
	st, err := NewStore(RouterConfig{
		RAMMaxBytes:          8 << 20,
		DiskMaxBytes:         8 << 20,
		SmallObjectThreshold: 4 << 10,
		DiskDir:              t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const (
		keys     = 8
		writers  = 8
		readers  = 8
		duration = 4000 // iterations per goroutine
	)
	keyName := func(i int) string { return fmt.Sprintf("/obj-%d.bin", i) }

	// A spread of sizes straddling the RAM/disk threshold (4 KiB) so replaces flip
	// tiers, while staying well under each shard's cap so every commit actually stores.
	sizes := []int{1, 64, 512, 4095, 4096, 4097, 16 << 10, 64 << 10}

	var stop atomic.Bool
	var torn atomic.Int64
	var wg sync.WaitGroup

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			for i := 0; i < duration && !stop.Load(); i++ {
				k := keyName(rng.Intn(keys))
				size := sizes[rng.Intn(len(sizes))]
				body := genBody(size)
				// Alternate tier to force cross-tier replace (the dedup delete + swap path).
				tier := TierRAM
				if rng.Intn(2) == 0 {
					tier = TierDisk
				}
				cw, err := st.Writer(ObjectMeta{Key: k, Size: int64(size), Tier: tier})
				if err != nil {
					continue
				}
				if _, err := cw.Write(body); err != nil {
					_ = cw.Abort()
					continue
				}
				_ = cw.Commit()
			}
		}(w + 1)
	}

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(1000 + seed)))
			for i := 0; i < duration && !stop.Load(); i++ {
				k := keyName(rng.Intn(keys))
				rd, _, ok := st.GetTier(k)
				if !ok {
					continue // absent is allowed (cross-tier dedup race); not a torn read
				}
				size := rd.Meta.Size
				body, err := io.ReadAll(rd)
				_ = rd.Close()
				if err != nil {
					torn.Add(1)
					continue
				}
				if !verifyBody(size, body) {
					torn.Add(1)
					stop.Store(true)
				}
			}
		}(r + 1)
	}

	wg.Wait()
	if n := torn.Load(); n != 0 {
		t.Fatalf("observed %d torn/inconsistent served bodies (a HIT served bytes that do not match its own Meta.Size)", n)
	}

	// Accounting sanity after the storm: neither tier may exceed its byte budget, and a
	// final deterministic store→read round-trips exactly (no drift left the store wedged).
	if b := st.Stats().RAMBytes; b > 8<<20 {
		t.Errorf("RAM bytes %d exceeds budget", b)
	}
	if b := st.Stats().DiskBytes; b > 8<<20 {
		t.Errorf("disk bytes %d exceeds budget", b)
	}
	final := genBody(777)
	cw, err := st.Writer(ObjectMeta{Key: keyName(0), Size: 777, Tier: TierDisk})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cw.Write(final)
	if err := cw.Commit(); err != nil {
		t.Fatal(err)
	}
	rd, _, ok := st.GetTier(keyName(0))
	if !ok {
		t.Fatal("final read: key absent after deterministic store")
	}
	body, _ := io.ReadAll(rd)
	_ = rd.Close()
	if !verifyBody(777, body) {
		t.Fatalf("final read mismatch: got %d bytes", len(body))
	}
}
