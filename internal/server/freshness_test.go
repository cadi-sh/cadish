package server

import (
	"regexp"
	"sync"
	"testing"
	"time"
)

// reference reproduces the OLD serve-path pair (hitForMiss then lookup) so the test can
// assert classify is exactly equivalent. It operates on a SEPARATE freshness instance
// so its pruning side effects don't disturb the instance under test.
func reference(f *freshness, key string) (freshState, bool) {
	if f.hitForMiss(key) {
		return stateMiss, true
	}
	return f.lookup(key), false
}

// twin builds two freshness instances sharing the same fake clock and primes both with
// the same mutation, so one can be driven through classify and the other through the
// old pair and their (state, hfm) results compared.
func twin(t *testing.T, clk *fakeClock, prime func(f *freshness)) (*freshness, *freshness) {
	t.Helper()
	a := newFreshness(clk.now)
	b := newFreshness(clk.now)
	if prime != nil {
		prime(a)
		prime(b)
	}
	return a, b
}

func TestClassify_EquivalentToOldPair(t *testing.T) {
	const key = "site|GET|/page"

	cases := []struct {
		name      string
		prime     func(f *freshness)
		advance   time.Duration
		wantState freshState
		wantHFM   bool
	}{
		{"no entry", nil, 0, stateMiss, false},
		{"fresh", func(f *freshness) { f.store(key, time.Hour, time.Hour, 0) }, 0, stateFresh, false},
		{"stale in grace", func(f *freshness) { f.store(key, time.Minute, time.Hour, 0) }, 2 * time.Minute, stateStale, false},
		{"expired past grace", func(f *freshness) { f.store(key, time.Minute, time.Minute, 0) }, time.Hour, stateMiss, false},
		{"hfm active", func(f *freshness) { f.setHitForMiss(key, time.Minute) }, 0, stateMiss, true},
		{"hfm expired", func(f *freshness) { f.setHitForMiss(key, time.Minute) }, 2 * time.Minute, stateMiss, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock()
			a, b := twin(t, clk, tc.prime)
			clk.advance(tc.advance)

			gotState, gotHFM := a.classify(key)
			refState, refHFM := reference(b, key)

			if gotState != tc.wantState || gotHFM != tc.wantHFM {
				t.Errorf("classify = (%v, %v), want (%v, %v)", gotState, gotHFM, tc.wantState, tc.wantHFM)
			}
			if gotState != refState || gotHFM != refHFM {
				t.Errorf("classify = (%v, %v) but old pair = (%v, %v) — not equivalent", gotState, gotHFM, refState, refHFM)
			}
		})
	}
}

func TestClassify_BannedEntryRevalidates(t *testing.T) {
	clk := newFakeClock()
	const key = "site|GET|/banme"
	f := newFreshness(clk.now)
	f.store(key, time.Hour, time.Hour, 0) // fresh
	clk.advance(time.Second)
	f.ban(regexp.MustCompile(".*/banme$")) // ban issued AFTER store

	state, hfm := f.classify(key)
	if state != stateMiss || hfm {
		t.Fatalf("banned entry: classify = (%v, %v), want (stateMiss, false)", state, hfm)
	}
	// The banned entry must have been pruned (revalidate, never a stale hit).
	if _, ok := f.shard(key).entries[key]; ok {
		t.Fatal("banned entry should have been pruned by classify")
	}
}

func TestClassify_PrunesExpired(t *testing.T) {
	clk := newFakeClock()
	const key = "site|GET|/old"
	f := newFreshness(clk.now)
	f.store(key, time.Minute, time.Minute, 0)
	clk.advance(time.Hour) // well past grace

	if state, _ := f.classify(key); state != stateMiss {
		t.Fatalf("expired: got %v want stateMiss", state)
	}
	if _, ok := f.shard(key).entries[key]; ok {
		t.Fatal("fully-expired entry should have been pruned by classify")
	}
}

// TestClassify_ConcurrentHotKey exercises the shared RLock read path against concurrent
// writers (store) on one hot key under -race.
func TestClassify_ConcurrentHotKey(t *testing.T) {
	f := newFreshness(time.Now)
	const key = "site|GET|/hot"
	f.store(key, time.Hour, time.Hour, 0)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				_, _ = f.classify(key)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			f.store(key, time.Hour, time.Hour, 0)
		}
	}()
	wg.Wait()
}
