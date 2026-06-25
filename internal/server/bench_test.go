package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// discardResponseWriter is a minimal, allocation-free http.ResponseWriter for the
// server benchmarks: it owns a single reusable header map and throws bytes away, so
// the measured allocations are the handler's own (not httptest.NewRecorder's
// per-request recorder + buffer). reset() clears the header between iterations.
type discardResponseWriter struct {
	hdr    http.Header
	status int
}

func newDiscardRW() *discardResponseWriter {
	return &discardResponseWriter{hdr: make(http.Header, 8)}
}

func (d *discardResponseWriter) Header() http.Header         { return d.hdr }
func (d *discardResponseWriter) WriteHeader(code int)        { d.status = code }
func (d *discardResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func (d *discardResponseWriter) reset() {
	for k := range d.hdr {
		delete(d.hdr, k)
	}
	d.status = 0
}

// benchHandler builds a Handler from a Cadishfile body (with the origin URL
// spliced in) without depending on *testing.T (so it works under Benchmark).
func benchHandler(b *testing.B, body, originURL string) (*Handler, *config.Config) {
	b.Helper()
	dir := b.TempDir()
	cfgText := fmt.Sprintf(body, originURL)
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		b.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		b.Fatalf("load config: %v\n%s", err, cfgText)
	}
	b.Cleanup(func() { _ = cfg.Close() })
	h := NewHandler(cfg, Options{Logger: discardLogger()})
	b.Cleanup(h.Shutdown)
	return h, cfg
}

// benchOrigin is an in-process origin serving a fixed body of the given size.
func benchOrigin(b *testing.B, size int) *httptest.Server {
	b.Helper()
	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		_, _ = w.Write(body)
	}))
	b.Cleanup(srv.Close)
	return srv
}

const benchCfg = `bench.local {
	cache { ram 256MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`

// BenchmarkServeHTTPHit measures a full cache HIT through Handler.ServeHTTP: site
// selection, EvalRequest + cache-key, the freshness-index lookup, the RAM-tier
// serve, EvalDeliver header ops, the access-log + metrics + tracer (nil) seams.
// The cache is primed once; every measured iteration is a fresh-HIT serve that
// never touches the origin.
func BenchmarkServeHTTPHit(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10} {
		b.Run(sizeName(size), func(b *testing.B) {
			origin := benchOrigin(b, size)
			h, _ := benchHandler(b, benchCfg, origin.URL)

			// Prime the cache with one MISS so subsequent serves are HITs.
			req := httptest.NewRequest(http.MethodGet, "http://bench.local/asset", nil)
			req.Host = "bench.local"
			prime := httptest.NewRecorder()
			h.ServeHTTP(prime, req)
			if prime.Code != http.StatusOK {
				b.Fatalf("prime: got status %d", prime.Code)
			}

			rw := newDiscardRW()
			hitReq := httptest.NewRequest(http.MethodGet, "http://bench.local/asset", nil)
			hitReq.Host = "bench.local"

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rw.reset()
				h.ServeHTTP(rw, hitReq)
			}
			b.StopTimer()
			if rw.status != http.StatusOK {
				b.Fatalf("hit: got status %d", rw.status)
			}
		})
	}
}

// BenchmarkServeHTTPHitParallel measures the HIT path under concurrency to surface
// any lock contention in the freshness index, the cache RAM-tier shard locks, and
// the metrics atomics. Each goroutine owns its own ResponseWriter and request.
func BenchmarkServeHTTPHitParallel(b *testing.B) {
	origin := benchOrigin(b, 1<<10)
	h, _ := benchHandler(b, benchCfg, origin.URL)

	req := httptest.NewRequest(http.MethodGet, "http://bench.local/asset", nil)
	req.Host = "bench.local"
	prime := httptest.NewRecorder()
	h.ServeHTTP(prime, req)
	if prime.Code != http.StatusOK {
		b.Fatalf("prime: got status %d", prime.Code)
	}

	b.SetBytes(1 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rw := newDiscardRW()
		hitReq := httptest.NewRequest(http.MethodGet, "http://bench.local/asset", nil)
		hitReq.Host = "bench.local"
		for pb.Next() {
			rw.reset()
			h.ServeHTTP(rw, hitReq)
		}
	})
}

// BenchmarkServeHTTPMiss measures a full MISS -> origin fetch -> store -> deliver
// each iteration by using a distinct key per request (so it never hits cache). The
// origin is in-process, so the absolute ns/op includes loopback HTTP, but the alloc
// count isolates the handler's own per-MISS allocations (header copy to/from origin,
// the tee, the freshness store).
func BenchmarkServeHTTPMiss(b *testing.B) {
	origin := benchOrigin(b, 1<<10)
	h, _ := benchHandler(b, benchCfg, origin.URL)

	rw := newDiscardRW()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw.reset()
		// Distinct path per iteration => always a MISS.
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://bench.local/m/%d", i), nil)
		req.Host = "bench.local"
		h.ServeHTTP(rw, req)
	}
}

// BenchmarkFreshnessLookup isolates the sharded freshness-index read under heavy
// concurrency (the per-HIT classify step), to surface shard-lock contention apart
// from the rest of the serve path.
func BenchmarkFreshnessLookup(b *testing.B) {
	f := newFreshness(time.Now)
	const key = "bench.local|GET|/asset"
	f.store(key, 300*time.Second, 0, 0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = f.lookup(key)
		}
	})
}

func sizeName(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// BenchmarkFreshnessLookupSpread models realistic traffic: many distinct keys
// spread across the 64 shards, so concurrent lookups rarely contend on the same
// shard mutex (unlike the single-key BenchmarkFreshnessLookup worst case).
func BenchmarkFreshnessLookupSpread(b *testing.B) {
	f := newFreshness(time.Now)
	const n = 4096
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("bench.local|GET|/asset/%d", i)
		f.store(keys[i], 300*time.Second, 0, 0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = f.lookup(keys[i&(n-1)])
			i++
		}
	})
}
