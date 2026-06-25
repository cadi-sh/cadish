package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBgRevalidateGlobalCap verifies the global stale-while-revalidate concurrency cap: a
// flood of requests across many DISTINCT stale keys must not launch an unbounded number of
// concurrent background origin refreshes. With a blocking origin, the number of in-flight bg
// fetches must never exceed maxConcurrentBgRevalidations (the rest skip — the object is still
// served from grace).
func TestBgRevalidateGlobalCap(t *testing.T) {
	clk := newFakeClock()
	var blocking atomic.Bool
	var inflight, peak int64
	release := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if blocking.Load() {
			n := atomic.AddInt64(&inflight, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
					break
				}
			}
			<-release // hold the slot so concurrent bg refreshes pile up
			atomic.AddInt64(&inflight, -1)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("v"))
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 1s grace 1h
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)

	const nKeys = maxConcurrentBgRevalidations + 64
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local"+path, nil)
		req.Host = "test.local"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Prime nKeys distinct entries (MISS → stored). The origin does not block while priming.
	for i := 0; i < nKeys; i++ {
		if got := get("/p" + strconv.Itoa(i)).Header().Get("X-Cache"); got != "MISS" {
			t.Fatalf("prime /p%d X-Cache=%q, want MISS", i, got)
		}
	}

	// From now on, every (background) origin fetch blocks on `release`.
	blocking.Store(true)
	// Age every entry into the grace window (ttl 1s elapsed).
	clk.advance(2 * time.Second)

	// Fire one request per key concurrently: each is a stale HIT that triggers a bg refresh.
	var wg sync.WaitGroup
	for i := 0; i < nKeys; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _ = get("/p" + strconv.Itoa(i)) }(i)
	}
	wg.Wait()
	// Give the launched bg goroutines a moment to reach the (blocked) origin.
	time.Sleep(200 * time.Millisecond)

	p := atomic.LoadInt64(&peak)
	close(release) // let the blocked bg fetches finish
	if p > maxConcurrentBgRevalidations {
		t.Errorf("peak concurrent bg revalidations = %d, want <= %d (global cap not enforced)", p, maxConcurrentBgRevalidations)
	}
	if p == 0 {
		t.Errorf("no background revalidations ran; the cap test did not exercise the path")
	}
}
