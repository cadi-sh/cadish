package server

import (
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Additional adversarial coverage for cache_credentialed (D101), closing the leak-relevant
// paths the original feature tests did not exercise: coalesced waiters, grace/stale
// revalidation, and HEAD. The invariant under test is the codebase-wide one — a Set-Cookie
// VALUE is NEVER written into a cached object and a HIT (fresh OR stale) never serves one —
// plus: the per-user Set-Cookie is stripped from EVERY delivery on the positive-signal store.

// credReviewCfg adds a grace window (from_header TTL + literal grace) so a stored object can
// be served STALE (within grace) on a clock advance, exercising the grace revalidation path.
const credReviewCfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl grace 1h
	cache_ttl default hit_for_miss 0s
	header +cache_status X-Cache
}
`

// TestCredentialedCoalescedWaitersGetStrippedObject: the ADR claims the coalesce LEADER stores
// the Set-Cookie-stripped shared object and WAITERS read it from cache. Drive many concurrent
// requests (different cookies) for one in-scope key whose origin emits Set-Cookie + X-Cache-Ttl;
// the origin is held so all waiters pile up behind the single leader. Every response — leader
// and waiters — must carry ZERO Set-Cookie, and origin must be hit exactly once.
func TestCredentialedCoalescedWaitersGetStrippedObject(t *testing.T) {
	release := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		<-release // hold the leader in origin so the waiters coalesce behind it
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Add("Set-Cookie", "track=for-"+r.Header.Get("Cookie")+"; Path=/")
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "shared-body")
	})
	h, _ := buildHandler(t, nil, credReviewCfg, origin.srv.URL)

	const n = 16
	var wg sync.WaitGroup
	setCookies := make([][]string, n)
	bodies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each waiter sends a DISTINCT per-user cookie — if a waiter ever saw the
			// leader's (or its own) Set-Cookie, that would be the cross-user leak.
			rec := do(h, "GET", "http://test.local/v3/readmodel/cache/home",
				http.Header{"Cookie": {"session=user" + string(rune('A'+i))}})
			setCookies[i] = rec.Header().Values("Set-Cookie")
			bodies[i] = rec.Body.String()
		}(i)
	}
	time.Sleep(100 * time.Millisecond) // let every goroutine enter the coalescer
	close(release)
	wg.Wait()

	if got := origin.hits.Load(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 (waiters coalesced behind the single leader)", got)
	}
	for i := 0; i < n; i++ {
		if len(setCookies[i]) != 0 {
			t.Fatalf("waiter %d received Set-Cookie %v — a per-user cookie leaked through the coalesced shared object", i, setCookies[i])
		}
		if bodies[i] != "shared-body" {
			t.Fatalf("waiter %d body = %q, want the shared body", i, bodies[i])
		}
	}
}

// TestCredentialedGraceStaleServesNoSetCookie: a positive-signal store with a grace window is
// served STALE after its TTL lapses (within grace). The stale serve is a cache HIT
// (serveFromCache) and must carry ZERO Set-Cookie — the stored object never held one, so no
// grace/stale path can resurrect a per-user cookie.
func TestCredentialedGraceStaleServesNoSetCookie(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Add("Set-Cookie", "track=for-alice; Path=/")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "shared")
	})
	h, _ := buildHandler(t, clk, credReviewCfg, origin.srv.URL)

	// MISS stores the stripped shared object.
	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", got)
	}
	if got := rec1.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("MISS delivered Set-Cookie %v, want none", got)
	}

	// Advance past the 60s TTL but within the 1h grace: the next request is served STALE
	// from cache (a different user's cookie), and must carry no Set-Cookie.
	clk.advance(2 * time.Minute)
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=bob"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("second X-Cache = %q, want HIT-STALE (served from grace)", got)
	}
	if got := rec2.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("stale HIT served Set-Cookie %v — a per-user cookie leaked from the stale shared object", got)
	}
	if rec2.Body.String() != "shared" {
		t.Fatalf("stale body = %q, want the shared body", rec2.Body.String())
	}
}

// TestCredentialedHeadStripsSetCookie: a HEAD request in a cache_credentialed scope whose origin
// emits Set-Cookie + X-Cache-Ttl must not deliver the Set-Cookie (the store path strips it even
// though a HEAD body is never stored). Guards the isHead branch of the store path.
func TestCredentialedHeadStripsSetCookie(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Add("Set-Cookie", "track=for-alice; Path=/")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "body")
	})
	h, _ := buildHandler(t, nil, credReviewCfg, origin.srv.URL)

	rec := do(h, "HEAD", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice"}})
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("HEAD delivered Set-Cookie %v on a positive-signal store, want none (stripped)", got)
	}
}
