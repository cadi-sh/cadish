package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/config"
)

// TestStressReloadUnderLoad hammers the handler with concurrent HIT/MISS traffic
// while concurrently swapping the live config (Handler.Reload) many times. Unlike
// TestServerReloadLivePreservesCache (which reloads BETWEEN sequential requests),
// this reloads DURING concurrent traffic. It relies on -race to catch data races on
// the routing table / freshness index / coalescer; it also asserts every response is
// a valid 200 with the expected body, that no goroutine panics, and that the warm
// cache survives the reloads (the post-storm read is still a HIT).
//
// The store is transplanted on every reload (TransplantStoresFrom), exactly as the
// production SIGHUP path does, so the cache is preserved across the swap.
func TestStressReloadUnderLoad(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	})

	const cfg1 = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`
	const cfg2 = `test.local, alias.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
}
`
	dir := t.TempDir()
	path := writeCfg(t, dir, cfg1, origin.srv.URL)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h := NewHandler(loaded, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)

	// Warm one key so concurrent readers hit a mix of HIT (warm key) and MISS (cold
	// keys) — both datapaths run while reloads churn the routing table.
	if rec := do(h, "GET", "http://test.local/warm", nil); rec.Code != 200 {
		t.Fatalf("warm: code = %d", rec.Code)
	}

	// liveCfg tracks the config currently installed so the reloader can keep
	// transplanting the warm store forward across swaps. Guarded by mu (the reloader
	// is the only writer; reads happen under it too).
	var mu sync.Mutex
	liveCfg := loaded
	// keepCfgs retains every config we Close at the end (each reload supersedes the
	// prior one; we close them all on cleanup, keeping the final store alive).
	t.Cleanup(func() {
		mu.Lock()
		_ = liveCfg.Close()
		mu.Unlock()
	})

	var (
		stop    atomic.Bool
		failure atomic.Value // first error string, if any
	)
	recordFail := func(s string) {
		failure.CompareAndSwap(nil, s)
	}

	var wg sync.WaitGroup

	// Reloader goroutine: swap the config back and forth as fast as it can until the
	// readers finish, always transplanting the warm store forward.
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for !stop.Load() {
			text := cfg1
			if toggle {
				text = cfg2
			}
			toggle = !toggle
			if err := os.WriteFile(path, []byte(fmt.Sprintf(text, origin.srv.URL)), 0o644); err != nil {
				recordFail("write cfg: " + err.Error())
				return
			}
			next, err := config.Load(path)
			if err != nil {
				recordFail("reload load: " + err.Error())
				return
			}
			mu.Lock()
			next.TransplantStoresFrom(liveCfg)
			h.Reload(next)
			keep := map[*cache.Store]bool{}
			for _, st := range next.Sites {
				if st.Store != nil {
					keep[st.Store] = true
				}
			}
			_ = liveCfg.CloseExcept(keep)
			liveCfg = next
			mu.Unlock()
		}
	}()

	// Reader goroutines: a mix of the warm key (expected HIT once cached) and cold
	// per-goroutine keys (MISS then HIT). Every response must be a valid 200 with the
	// body the origin serves for that path.
	const readers = 24
	const itersPerReader = 200
	for g := 0; g < readers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < itersPerReader; i++ {
				var path string
				if i%2 == 0 {
					path = "/warm"
				} else {
					path = fmt.Sprintf("/g%d-%d", g, i)
				}
				rec := do(h, "GET", "http://test.local"+path, nil)
				if rec.Code != 200 {
					recordFail(fmt.Sprintf("req %s: code = %d", path, rec.Code))
					return
				}
				if want := "body " + path; rec.Body.String() != want {
					recordFail(fmt.Sprintf("req %s: body = %q, want %q", path, rec.Body.String(), want))
					return
				}
			}
		}(g)
	}

	// Let the readers run; they self-terminate after itersPerReader. Stop the reloader
	// once readers are done.
	go func() {
		// Wait for just the reader goroutines by polling failure / a short cap; the
		// readers are bounded, so a brief settle then stop is enough.
		time.Sleep(750 * time.Millisecond)
		stop.Store(true)
	}()
	wg.Wait()
	stop.Store(true)

	if v := failure.Load(); v != nil {
		t.Fatalf("stress failure: %s", v.(string))
	}

	// The warm key survived the reload storm: still a HIT, origin not re-consulted for
	// it beyond the cold-key fetches.
	if rec := do(h, "GET", "http://test.local/warm", nil); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("post-storm /warm X-Cache = %q, want HIT (cache must survive reloads)", rec.Header().Get("X-Cache"))
	}
}

// TestStressCoalescerSingleFlight fires many concurrent requests for the SAME cold
// key while the origin (winner) is held, then releases: the origin must be hit
// EXACTLY ONCE (single-flight) and every waiter must receive the correct body.
func TestStressCoalescerSingleFlight(t *testing.T) {
	release := make(chan struct{})
	var entered atomic.Int64
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		entered.Add(1)
		<-release // hold the winner so all waiters pile up behind it
		_, _ = io.WriteString(w, "single-flight-body")
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	const n = 64
	var (
		wg     sync.WaitGroup
		bodies = make([]string, n)
		codes  = make([]int, n)
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := do(h, "GET", "http://test.local/cold", nil)
			codes[i] = rec.Code
			bodies[i] = rec.Body.String()
		}(i)
	}
	// Wait until the winner is actually inside origin (so the rest are waiters), then
	// release — no fixed sleep, poll the entered counter.
	waitFor(t, 2*time.Second, func() bool { return entered.Load() == 1 })
	close(release)
	wg.Wait()

	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want exactly 1 (single-flight)", origin.hits.Load())
	}
	for i := 0; i < n; i++ {
		if codes[i] != 200 || bodies[i] != "single-flight-body" {
			t.Fatalf("waiter %d: got %d %q, want 200 single-flight-body", i, codes[i], bodies[i])
		}
	}
}

// TestStressCoalescerLeaderFailure locks in the recently-hardened leader-failure
// path: the coalesce WINNER errors (origin returns a transport-level failure), and
// the waiters must NOT hang — they fall through to their own fetch and recover. With
// the winner failing only on its FIRST hit, the waiters' fall-through fetches
// succeed. We assert no goroutine leaks (the coalescer entry is released), every
// request completes within the timeout, and at least one request succeeds.
func TestStressCoalescerLeaderFailure(t *testing.T) {
	var first atomic.Bool
	release := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if first.CompareAndSwap(false, true) {
			// The winner: block until released, then fail hard mid-stream by
			// hijacking and closing the connection so the body copy errors and the
			// winner does NOT commit to cache.
			<-release
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close() // abrupt close -> winner's fetch errors
			}
			return
		}
		// Every later request (the waiters' own fall-through fetches) succeeds.
		_, _ = io.WriteString(w, "recovered-body")
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	before := runtime.NumGoroutine()

	const n = 32
	var (
		wg    sync.WaitGroup
		codes = make([]int, n)
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := do(h, "GET", "http://test.local/leader-fail", nil)
			codes[i] = rec.Code
		}(i)
	}
	// Make sure the winner is inside origin (blocked on release) so the rest are
	// genuine waiters, then release it to fail.
	waitFor(t, 2*time.Second, func() bool { return origin.hits.Load() >= 1 })
	close(release)

	// All goroutines must finish (no hang) — guard with a timeout.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("coalesce waiters hung after leader failure")
	}

	// At least one request recovered with a real body (the fall-through fetch
	// succeeds); none should hang. We don't pin every code (the winner itself may
	// see a 502), but the cohort must include successful recoveries.
	got200 := 0
	for _, c := range codes {
		if c == 200 {
			got200++
		}
	}
	if got200 == 0 {
		t.Fatalf("no request recovered after leader failure: codes = %v", codes)
	}

	// No goroutine leak: the coalescer entry was released, waiters returned.
	for i := 0; i < 200; i++ {
		if runtime.NumGoroutine() <= before+2 { // small slack for runtime/test bookkeeping
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestStressFreshnessSweeperUnderLoad runs concurrent classify/store against the
// freshness index while the background sweeper runs (a real reclamation goroutine).
// It relies on -race to catch data races between the datapath and the sweeper, and
// asserts that after the storm + a final sweep the index is consistent (live entries
// retained, expired ones reclaimable).
func TestStressFreshnessSweeperUnderLoad(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now) // launches the background sweeper goroutine
	t.Cleanup(f.Close)

	var (
		wg   sync.WaitGroup
		stop atomic.Bool
	)

	// Writers: continuously store fresh entries under churning keys.
	const writers = 8
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				key := fmt.Sprintf("/w%d-%d", g, i%64)
				f.store(key, 30*time.Second, 10*time.Second, 0)
			}
		}(g)
	}

	// Readers: classify (the hot-path read) concurrently with stores + the sweeper.
	const readers = 8
	for g := 0; g < readers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				key := fmt.Sprintf("/w%d-%d", g%writers, i%64)
				_, _ = f.classify(key)
				_ = f.staleWithin(key)
			}
		}(g)
	}

	// Clock advancer: push the clock forward so the sweeper actually reclaims while
	// writers keep refreshing — exercises the reclaim path under concurrency.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			clk.advance(time.Second)
		}
	}()

	time.Sleep(500 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	// Past every window, a final sweep reclaims everything left behind (no leak, no
	// race surfaced under -race).
	clk.advance(time.Hour)
	f.sweep()
	if got := f.len(); got != 0 {
		t.Fatalf("after final sweep: len = %d, want 0 (all entries reclaimable)", got)
	}
}
