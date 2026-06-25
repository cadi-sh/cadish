package server

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCoalesceDoesNotLeakSetCookie is the security guard for the coalescing + Set-Cookie
// concern: when N concurrent requests collide on one cache key and the origin returns a
// PER-USER Set-Cookie, no waiter may inherit the winner's cookie. Because a Set-Cookie
// response is not safely shareable it is never cached, so the waiters fall through to
// their OWN origin fetch and each gets its OWN cookie — there is no cross-user leak (and
// no false coalescing of a per-user response).
func TestCoalesceDoesNotLeakSetCookie(t *testing.T) {
	var ctr int64
	release := make(chan struct{})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		// Hold only the FIRST (winner) request in origin so the others pile up behind it
		// in the coalescer; once released, every request returns a UNIQUE Set-Cookie.
		first := atomic.AddInt64(&ctr, 1)
		if first == 1 {
			<-release
		}
		w.Header().Set("Set-Cookie", fmt.Sprintf("session=user-%d", first))
		_, _ = io.WriteString(w, fmt.Sprintf("body-%d", first))
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	const n = 12
	var wg sync.WaitGroup
	cookies := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := do(h, "GET", "http://test.local/hot", nil)
			cookies[i] = rec.Header().Get("Set-Cookie")
		}(i)
	}
	time.Sleep(100 * time.Millisecond) // let the waiters pile up behind the held winner
	close(release)
	wg.Wait()

	// A Set-Cookie response is not shareable → not cached → every request hit origin.
	if origin.hits.Load() != n {
		t.Errorf("origin hits = %d, want %d (a per-user Set-Cookie must NOT coalesce/cache)", origin.hits.Load(), n)
	}
	// Every client must have its OWN cookie — no two share one (no cross-user leak).
	seen := map[string]bool{}
	for i, c := range cookies {
		if c == "" {
			t.Errorf("req %d got no Set-Cookie", i)
			continue
		}
		if seen[c] {
			t.Fatalf("COALESCE LEAK: two clients received the same Set-Cookie %q", c)
		}
		seen[c] = true
	}
}
