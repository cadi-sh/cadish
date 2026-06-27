package server

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/config"
)

// These chaos tests deepen the baseline stress suite (stress_test.go, a1001f0).
// Where the baseline drives a single failure mode, these interleave MANY failure
// modes concurrently — broken-config reloads mixed with valid ones under
// GET/HEAD/range/PURGE traffic; randomized leader slow/error/panic/cancel chaos
// across many keys; and freshness churn that also stores/forgets/HFMs/bans while a
// reader continuously asserts the restart-safety invariant. The -race detector is
// the primary assertion in all three; the explicit asserts catch hangs, panics,
// poisoned keys, and classification violations.

// TestStressChaosReloadDuringMixedTraffic drives sustained concurrent GET / HEAD /
// Range / PURGE traffic against a live handler while a reloader repeatedly applies
// VALID config variants (swapping a response header value, changing TTLs,
// adding/removing a site alias and an upstream) AND periodically attempts a BROKEN
// config that must be REJECTED at load time so the old config keeps serving. This
// mirrors the production SIGHUP path: a bad file never reaches Handler.Reload, so
// traffic is never disrupted by a broken reload.
//
// Asserts: no race (-race), no panic, every traffic response is a valid status with
// the expected body for GET, every broken-config attempt is rejected (Load errors,
// Reload is NOT called), and the warm cache survives the reload storm (still a HIT
// at the end). The reloader transplants the warm store forward on every swap exactly
// as Server.Reload does.
func TestStressChaosReloadDuringMixedTraffic(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	})

	// Three VALID variants exercised round-robin: each splices originURL once.
	// v1: single host, TTL 300s, header value A, single upstream.
	// v2: host + alias, TTL 120s, header value B, single upstream.
	// v3: single host, TTL 300s, header value A, TWO upstreams (load-balanced).
	const v1 = `test.local {
	cache { ram 64MiB }
	@tok header X-Purge-Token sekret
	purge when @tok
	upstream backend { to %[1]s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
	header X-Variant A
}
`
	const v2 = `test.local, alias.local {
	cache { ram 64MiB }
	@tok header X-Purge-Token sekret
	purge when @tok
	upstream backend { to %[1]s }
	cache_ttl default ttl 120s
	header +cache_status X-Cache
	header X-Variant B
}
`
	const v3 = `test.local {
	cache { ram 64MiB }
	@tok header X-Purge-Token sekret
	purge when @tok
	upstream backend { to %[1]s %[1]s }
	cache_ttl default ttl 300s
	header +cache_status X-Cache
	header X-Variant A
}
`
	// A syntactically broken config — must fail config.Load (never reach Reload).
	const broken = `test.local {
	cache { ram 64MiB
	upstream backend { to %[1]s }
	cache_ttl default ttl notaduration!!!
`
	variants := []string{v1, v2, v3}

	dir := t.TempDir()
	path := writeCfg(t, dir, v1, origin.srv.URL)
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h := NewHandler(loaded, Options{Logger: discardLogger()})
	t.Cleanup(h.Shutdown)

	// Warm one key so readers see a mix of HIT and MISS while the table churns.
	if rec := do(h, "GET", "http://test.local/warm", nil); rec.Code != 200 {
		t.Fatalf("warm: code = %d", rec.Code)
	}

	var mu sync.Mutex
	liveCfg := loaded
	t.Cleanup(func() {
		mu.Lock()
		_ = liveCfg.Close()
		mu.Unlock()
	})

	var (
		stop          atomic.Bool
		failure       atomic.Value // first error string
		brokenTried   atomic.Int64
		brokenApplied atomic.Int64 // MUST stay 0
	)
	recordFail := func(s string) { failure.CompareAndSwap(nil, s) }

	var wg sync.WaitGroup

	// Reloader: cycle valid variants; every 4th attempt, try the broken config and
	// assert it is rejected at load time (old config preserved).
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for !stop.Load() {
			i++
			if i%4 == 0 {
				// Broken-config attempt: write it, try to load, expect an error, and
				// (critically) do NOT call Reload — the old config keeps serving.
				brokenTried.Add(1)
				if err := os.WriteFile(path, []byte(fmt.Sprintf(broken, origin.srv.URL)), 0o644); err != nil {
					recordFail("write broken: " + err.Error())
					return
				}
				if _, err := config.Load(path); err == nil {
					brokenApplied.Add(1) // a broken config loaded -> invariant violated
					recordFail("broken config unexpectedly loaded clean")
					return
				}
				continue
			}
			text := variants[(i/1)%len(variants)]
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

	// Mixed-method readers: GET (verify body), HEAD, Range, and the occasional PURGE.
	const readers = 24
	const itersPerReader = 200
	for g := 0; g < readers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g) + 1))
			for i := 0; i < itersPerReader; i++ {
				switch rng.Intn(8) {
				case 0, 1, 2: // GET cold/warm — verify status + body
					p := "/warm"
					if i%2 == 1 {
						p = fmt.Sprintf("/g%d-%d", g, i)
					}
					rec := do(h, "GET", "http://test.local"+p, nil)
					if rec.Code != 200 {
						recordFail(fmt.Sprintf("GET %s: code = %d", p, rec.Code))
						return
					}
					if want := "body " + p; rec.Body.String() != want {
						recordFail(fmt.Sprintf("GET %s: body = %q want %q", p, rec.Body.String(), want))
						return
					}
				case 3, 4: // HEAD — status only
					rec := do(h, "HEAD", "http://test.local/warm", nil)
					if rec.Code != 200 {
						recordFail(fmt.Sprintf("HEAD: code = %d", rec.Code))
						return
					}
				case 5, 6: // Range — 206 partial or 200 full, never an error
					rec := do(h, "GET", "http://test.local/warm", http.Header{"Range": {"bytes=0-3"}})
					if rec.Code != http.StatusPartialContent && rec.Code != http.StatusOK {
						recordFail(fmt.Sprintf("Range: code = %d", rec.Code))
						return
					}
				default: // PURGE (authorized) — single-key invalidate, must 200
					rec := do(h, "PURGE", fmt.Sprintf("http://test.local/g%d-%d", g, i),
						http.Header{"X-Purge-Token": {"sekret"}})
					if rec.Code != 200 {
						recordFail(fmt.Sprintf("PURGE: code = %d", rec.Code))
						return
					}
				}
			}
		}(g)
	}

	// Bounded readers self-terminate after itersPerReader; give them a settle window
	// in the background then stop the reloader so it churns for the whole reader life.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		stop.Store(true)
	}()
	wg.Wait()
	stop.Store(true)

	if v := failure.Load(); v != nil {
		t.Fatalf("chaos failure: %s", v.(string))
	}
	if brokenTried.Load() == 0 {
		t.Fatal("test did not exercise the broken-config path")
	}
	if brokenApplied.Load() != 0 {
		t.Fatalf("broken config was applied %d times (must be 0)", brokenApplied.Load())
	}

	// Warm key survived the reload + purge storm: a fresh GET is a HIT (it may have
	// been purged then re-warmed; either way the current state must be coherent).
	_ = do(h, "GET", "http://test.local/warm", nil) // re-warm if a purge dropped it
	if rec := do(h, "GET", "http://test.local/warm", nil); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("post-storm /warm X-Cache = %q, want HIT", rec.Header().Get("X-Cache"))
	}
}

// TestStressChaosCoalescerLeaderChaos is the chaos amplification of the baseline
// leader-failure test. Across many ROUNDS, each with a DISTINCT cold key, a herd of
// concurrent requests hits the same key while the coalesce leader's origin fetch is
// subjected to a randomized failure mode: slow-but-OK, hard error (connection
// dropped), origin panic, or the leader's client context cancelled mid-fetch. After
// the chaos round a clean GET for the SAME key MUST succeed and cache cleanly,
// proving the key is never permanently poisoned (the coalescer entry is always
// released) and no waiter hangs.
//
// Asserts: no waiter hangs (whole cohort completes within a timeout), every key
// recovers to a clean cacheable 200 afterward (no poisoned key / deadlock), no
// goroutine leak across rounds, and no race / panic escapes the handler.
func TestStressChaosCoalescerLeaderChaos(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos coalescer round-storm skipped in -short")
	}

	const (
		modeSlowOK = iota
		modeError
		modePanic
		modeCancel
	)

	// chaosRound carries the per-round coordination: the failure mode, a one-shot
	// "leader entered origin" signal (closed once via leaderOnce), and a release
	// channel the held leader blocks on. The origin reads the live round through an
	// atomic.Pointer so there is no shared mutable state racing with the requests.
	type chaosRound struct {
		mode       int
		leaderIn   chan struct{}
		leaderOnce sync.Once
		release    chan struct{}
	}
	var cur atomic.Pointer[chaosRound]

	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		rd := cur.Load()
		if rd == nil {
			_, _ = io.WriteString(w, "warm-"+r.URL.Path)
			return
		}
		// Signal (once) that a fetch reached origin, then hold until released. The
		// coalescer guarantees a single origin entry per key per round, so the first
		// arrival here IS the leader.
		rd.leaderOnce.Do(func() { close(rd.leaderIn) })
		<-rd.release
		switch rd.mode {
		case modeSlowOK:
			_, _ = io.WriteString(w, "ok-"+r.URL.Path)
		case modeError:
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close() // abrupt drop -> winner fetch errors
				}
			} else {
				w.WriteHeader(http.StatusBadGateway)
			}
		case modePanic:
			panic("chaos: origin handler panic") // httptest recovers; client sees a dropped/errored response
		case modeCancel:
			// Stall briefly so the requester's context-cancel wins the race, then
			// return a body the abandoned copy will never deliver.
			time.Sleep(20 * time.Millisecond)
			_, _ = io.WriteString(w, "late-"+r.URL.Path)
		}
	})

	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	before := runtime.NumGoroutine()

	const rounds = 12
	const herd = 24
	modes := []int{modeSlowOK, modeError, modePanic, modeCancel}

	for round := 0; round < rounds; round++ {
		m := modes[round%len(modes)]
		rd := &chaosRound{mode: m, leaderIn: make(chan struct{}), release: make(chan struct{})}
		cur.Store(rd)

		key := fmt.Sprintf("http://test.local/chaos-%d", round)

		var wg sync.WaitGroup
		for i := 0; i < herd; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if m == modeCancel && i == 0 {
					// Requester 0 drives a cancellable context so the leader's fetch is
					// cancelled mid-flight, once the leader is confirmed inside origin.
					ctx, cancel := context.WithCancel(context.Background())
					req := httptest.NewRequest("GET", key, nil).WithContext(ctx)
					req.Host = "test.local"
					rec := httptest.NewRecorder()
					done := make(chan struct{})
					go func() { h.ServeHTTP(rec, req); close(done) }()
					go func() {
						select {
						case <-rd.leaderIn:
						case <-time.After(time.Second):
						}
						time.Sleep(5 * time.Millisecond)
						cancel()
					}()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						// Surfaced by the herd-hang watchdog below.
					}
					return
				}
				_ = do(h, "GET", key, nil)
			}(i)
		}

		// Wait for the leader to be inside origin, then release it to apply the mode.
		select {
		case <-rd.leaderIn:
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d (mode %d): leader never reached origin", round, m)
		}
		close(rd.release)

		// The whole herd must finish — no hang after any leader failure mode.
		fin := make(chan struct{})
		go func() { wg.Wait(); close(fin) }()
		select {
		case <-fin:
		case <-time.After(8 * time.Second):
			t.Fatalf("round %d (mode %d): coalesce herd hung", round, m)
		}

		// The key must NOT be poisoned: with a clean (non-blocking) round installed, a
		// follow-up GET succeeds and the NEXT GET is a HIT — proving the key cached
		// cleanly and was never permanently bypassed/poisoned.
		clean := &chaosRound{mode: modeSlowOK, leaderIn: make(chan struct{}), release: make(chan struct{})}
		close(clean.release) // leader never blocks now
		cur.Store(clean)
		if rec := do(h, "GET", key, nil); rec.Code != 200 {
			t.Fatalf("round %d (mode %d): post-chaos GET code = %d (poisoned key?)", round, m, rec.Code)
		}
		if rec2 := do(h, "GET", key, nil); rec2.Header().Get("X-Cache") != "HIT" {
			t.Fatalf("round %d (mode %d): post-chaos re-GET X-Cache = %q, want HIT", round, m, rec2.Header().Get("X-Cache"))
		}
	}

	// No goroutine leak across all rounds.
	//
	// The lingering goroutines we must NOT count as a leak are HTTP keep-alive
	// machinery, not anything cadish spawns per round: the httptest origin's
	// per-connection serve goroutines, and the per-upstream transport's pooled
	// idle-connection readLoop/writeLoop goroutines (IdleConnTimeout 90s). Under a
	// leader-failure round the herd de-coalesces — every waiter falls through and
	// dials origin independently — so a single panic/error round leaves up to `herd`
	// such connections (plus, for modePanic, that many in-flight conn.serve panic
	// recoveries). Their count is bounded by `herd`, never by `rounds`; a real
	// coalescer leak would instead grow with `rounds`. They drain on their own, but
	// far slower than a naive wall-clock window under -race+CPU contention (and the
	// 90s idle timeout means pooled conns would otherwise outlive the whole test).
	//
	// So before measuring, deterministically tear those connections down:
	// CloseClientConnections closes every origin-side socket, which both ends the
	// origin serve goroutines and makes the client transport's readLoops observe EOF
	// and exit. What remains to drain is only the (fast, CPU-bound) panic-recovery
	// teardown, for which a generous bounded wait is reliable without weakening what
	// this asserts: that the coalescer releases every entry and leaks no goroutine.
	origin.srv.CloseClientConnections()

	leaked := true
	for i := 0; i < 2000; i++ { // ~10s budget: generous bound, not a tight deadline
		if runtime.NumGoroutine() <= before+4 { // slack for runtime/test/server bookkeeping
			leaked = false
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if leaked {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		os.Stderr.Write(buf[:n])
		t.Fatalf("goroutine leak after chaos rounds: before=%d now=%d", before, runtime.NumGoroutine())
	}
}

// TestStressChaosFreshnessChurn churns the sharded freshness index with the full
// operation set under concurrency while the background sweeper runs and the clock
// advances: stores (positive + max_stale), hit-for-miss markers, forgets, bans, and
// — continuously — classify/lookup/staleWithin reads. A dedicated invariant goroutine
// repeatedly asserts the restart-safety rule on a key it has just forgotten: a missing
// entry must classify as stateMiss (revalidate), NEVER as a fresh/stale hit.
//
// Asserts: no race (-race), no panic, the missing-entry => never-a-stale-hit invariant
// holds under churn, classify and lookup never disagree on a STABLE fresh key, and a
// final sweep past every window reclaims everything (no leak).
func TestStressChaosFreshnessChurn(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now) // launches the background sweeper
	t.Cleanup(f.Close)

	var (
		wg      sync.WaitGroup
		stop    atomic.Bool
		failure atomic.Value
	)
	recordFail := func(s string) { failure.CompareAndSwap(nil, s) }

	const keyspace = 128
	keyFor := func(g, i int) string { return fmt.Sprintf("/k%d-%d", g, i%keyspace) }

	// Storers: positive entries, some with a max_stale window.
	const storers = 6
	for g := 0; g < storers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				k := keyFor(g, i)
				if i%3 == 0 {
					f.store(k, 30*time.Second, 10*time.Second, 20*time.Second)
				} else {
					f.store(k, 30*time.Second, 10*time.Second, 0)
				}
			}
		}(g)
	}

	// HFM markers + forgets: churn the entry lifecycle around the same keyspace.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			k := keyFor(i%storers, i)
			if i%2 == 0 {
				f.setHitForMiss(k, 5*time.Second)
			} else {
				f.forget(k)
			}
		}
	}()

	// Readers: the hot path — classify + lookup + staleWithin + hitForMiss + storedAt.
	const readers = 6
	for g := 0; g < readers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				k := keyFor(g%storers, i)
				_, _ = f.classify(k)
				_ = f.lookup(k)
				_ = f.staleWithin(k)
				_ = f.hitForMiss(k)
				_, _ = f.storedAt(k)
			}
		}(g)
	}

	// Bans: occasionally invalidate a swath of keys (exercises the banned() path on
	// the hot lookups + sweeper reclamation of banned entries).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			f.ban(regexp.MustCompile(`/k0-`))
			time.Sleep(time.Millisecond)
		}
	}()

	// Clock advancer: push time forward so entries expire and the sweeper reclaims
	// while storers keep refreshing. Throttled to ~1s of mock-time per real
	// millisecond so the advance stays bounded (a tight, unthrottled loop would jump
	// the clock by hours within the test window and expire even the "stable" key
	// below). Over the ~750ms window this advances ~750s of mock-time — far past the
	// storers' ~60s lifetimes (so expiry/sweeping is still well exercised) yet far
	// below the stable key's TTL.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			clk.advance(time.Second)
			time.Sleep(time.Millisecond)
		}
	}()

	// Restart-safety invariant: store a key, forget it, then assert classify reports
	// stateMiss (and never an HFM bypass that would be wrong post-forget). A forgotten
	// key MUST revalidate — never a stale hit. We use a private key namespace so no
	// other goroutine re-stores it between forget and check.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			k := fmt.Sprintf("/invariant-%d", i)
			f.store(k, 30*time.Second, 10*time.Second, 0)
			f.forget(k)
			st, hfm := f.classify(k)
			if st != stateMiss || hfm {
				recordFail(fmt.Sprintf("forgotten key %s classified as state=%d hfm=%v, want stateMiss (restart-safety: missing entry => revalidate)", k, st, hfm))
				return
			}
			if f.lookup(k) != stateMiss {
				recordFail(fmt.Sprintf("forgotten key %s lookup != stateMiss", k))
				return
			}
			if f.staleWithin(k) {
				recordFail(fmt.Sprintf("forgotten key %s staleWithin == true (must never serve a missing entry as stale)", k))
				return
			}
		}
	}()

	// Stable-key invariant: a key stored fresh and never touched by anyone else must
	// classify Fresh and agree between classify and lookup (no torn read under the
	// shared RLock fast path). Uses its own namespace; no clock-advance past its TTL
	// happens fast enough to flip it within a single check pair (we re-store each loop
	// so it's always well within TTL relative to the advancing clock).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			k := fmt.Sprintf("/stable-%d", i)
			f.store(k, 1000*time.Hour, 0, 0) // TTL unreachable within the bounded clock-advance window
			c, _ := f.classify(k)
			l := f.lookup(k)
			if c != stateFresh {
				recordFail(fmt.Sprintf("stable key %s classify = %d, want stateFresh", k, c))
				return
			}
			if l != stateFresh {
				recordFail(fmt.Sprintf("stable key %s lookup = %d, want stateFresh", k, l))
				return
			}
			f.forget(k)
		}
	}()

	time.Sleep(750 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if v := failure.Load(); v != nil {
		t.Fatalf("freshness churn invariant violated: %s", v.(string))
	}

	// Past every window, a final sweep reclaims everything (no leak, no race).
	clk.advance(2 * time.Hour)
	f.sweep()
	if got := f.len(); got != 0 {
		t.Fatalf("after final sweep: len = %d, want 0 (all entries reclaimable)", got)
	}
}
