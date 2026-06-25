package cache

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

// benchSizes are the representative object-size bands: a tiny playlist/control
// object, a media segment, and a large segment/file.
var benchSizes = []struct {
	name string
	size int
	n    int // working-set object count (kept ~16-32 MiB total)
}{
	{"1KiB", 1 << 10, 4096},
	{"64KiB", 64 << 10, 256},
	{"4MiB", 4 << 20, 8},
}

// newBenchStore builds a Store with a temp disk dir, sized so the working set
// fits without eviction. smallThreshold routes non-RAM-extension objects: 0
// forces everything to disk, a large value lets small objects into RAM.
func newBenchStore(b *testing.B, ramBytes, smallThreshold int64) *Store {
	b.Helper()
	s, err := NewStore(RouterConfig{
		RAMMaxBytes:          ramBytes,
		DiskMaxBytes:         2 << 30,
		DiskDir:              b.TempDir(),
		SmallObjectThreshold: smallThreshold,
		RAMMaxObjectBytes:    ramBytes, // allow any single object up to the tier size
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })
	return s
}

func putObj(b *testing.B, s *Store, key, ct string, body []byte) {
	b.Helper()
	w, err := s.Writer(ObjectMeta{Key: key, Size: int64(len(body)), ContentType: ct})
	if err != nil {
		b.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		b.Fatal(err)
	}
	if err := w.Commit(); err != nil {
		b.Fatal(err)
	}
}

func drainGet(b *testing.B, s *Store, key string) {
	r, ok := s.Get(key)
	if !ok {
		b.Fatal("cache miss")
	}
	_, _ = io.Copy(io.Discard, r)
	_ = r.Close()
}

// BenchmarkStoreGetRAM measures the RAM-tier cache-hit read path (shard lookup +
// LRU MoveToFront under the shard lock + Reader open + body drain) across object
// sizes. `.m3u8` keys always route to RAM.
func BenchmarkStoreGetRAM(b *testing.B) {
	for _, sz := range benchSizes {
		body := bytes.Repeat([]byte("x"), sz.size)
		// The RAM tier shards its budget across up to 64 shards; an object larger
		// than a single shard's cap is refused. Size the budget at 128×object so
		// every shard comfortably holds the object (and the working set fits).
		ramBytes := int64(128) * int64(sz.size)
		if ramBytes < 64<<20 {
			ramBytes = 64 << 20
		}
		s := newBenchStore(b, ramBytes, 2<<20)
		keys := make([]string, sz.n)
		for i := range keys {
			keys[i] = fmt.Sprintf("playlist/seg-%d.m3u8", i)
			putObj(b, s, keys[i], "application/vnd.apple.mpegurl", body)
		}
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				drainGet(b, s, keys[i&(sz.n-1)])
			}
		})
	}
}

// BenchmarkStoreGetDisk measures the disk-tier cache-hit read path (index lookup
// + blob file open + streamed body) across object sizes. SmallObjectThreshold=0
// forces the `.ts` segments onto disk regardless of size.
func BenchmarkStoreGetDisk(b *testing.B) {
	for _, sz := range benchSizes {
		body := bytes.Repeat([]byte("y"), sz.size)
		s := newBenchStore(b, 64<<20, 0)
		keys := make([]string, sz.n)
		for i := range keys {
			keys[i] = fmt.Sprintf("video/seg-%d.ts", i)
			putObj(b, s, keys[i], "video/mp2t", body)
		}
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				drainGet(b, s, keys[i&(sz.n-1)])
			}
		})
	}
}

// BenchmarkStorePut measures the write path (Writer open + buffered/streamed
// body + Commit, incl. LRU insert/evict bookkeeping) across sizes. Small/medium
// land in RAM; 4MiB exceeds the 2MiB small-object threshold and lands on disk —
// so this spans both tiers' write paths.
func BenchmarkStorePut(b *testing.B) {
	for _, sz := range benchSizes {
		body := bytes.Repeat([]byte("z"), sz.size)
		// Big RAM + disk budgets so the tier churns under budget, not OOM-guard.
		s := newBenchStore(b, 512<<20, 2<<20)
		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sz.size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				putObj(b, s, fmt.Sprintf("seg/w-%d.ts", i), "video/mp2t", body)
			}
		})
	}
}

// BenchmarkStoreMixedParallel approximates a serving mix: mostly concurrent
// reads with ~1-in-8 writes, on small hot objects — the steady-state contention
// profile that justifies the per-shard (not global) LRU locking.
func BenchmarkStoreMixedParallel(b *testing.B) {
	const n = 4096
	body := bytes.Repeat([]byte("m"), 1<<10)
	s := newBenchStore(b, 256<<20, 2<<20)
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("playlist/m-%d.m3u8", i)
		putObj(b, s, keys[i], "application/vnd.apple.mpegurl", body)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i&7 == 0 {
				w, err := s.Writer(ObjectMeta{Key: keys[i&(n-1)], Size: int64(len(body)), ContentType: "application/vnd.apple.mpegurl"})
				if err != nil {
					b.Fatal(err)
				}
				_, _ = w.Write(body)
				_ = w.Commit()
			} else {
				r, ok := s.Get(keys[i&(n-1)])
				if ok {
					_, _ = io.Copy(io.Discard, r)
					_ = r.Close()
				}
			}
			i++
		}
	})
}
