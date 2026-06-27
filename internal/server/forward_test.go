package server

import (
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// COOKIE-NORM `forward` mode end-to-end: a `derives_from cookie NAME… forward` axis
// reads + keys the normalized token but FORWARDS the raw cookie to origin (unlike
// strip-mode, which removes it). The request still CACHES — the forward cookie is covered
// by {TOKEN} — so the origin sees the cookie (for its server-side personalization) while
// the cache collapses to the low-cardinality axis. RUN-26-JUN §A1 ADDENDUM.
const cfgForward = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@adultcookie cookie AdultContent 1
	classify {adult_php} {
		derives_from cookie AdultContent forward
		when @adultcookie -> 1
		default           -> 0
	}
	cookie_allow
	cache_key default host url {adult_php}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// fwdOrigin echoes the AdultContent cookie value it RECEIVES so the test can prove the
// raw cookie was forwarded to origin (not stripped).
func fwdOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		ac := ""
		if c, err := r.Cookie("AdultContent"); err == nil {
			ac = c.Value
		}
		_, _ = io.WriteString(w, "AdultContent="+ac)
	})
}

// TestForward_CookieReachesOriginAndCaches: the forward cookie is FORWARDED to origin AND
// the response caches (MISS then HIT) — the cookie-reading backend path is served while the
// shared cache collapses to {adult_php}.
func TestForward_CookieReachesOriginAndCaches(t *testing.T) {
	origin := fwdOrigin(t)
	h, _ := buildHandler(t, nil, cfgForward, origin.srv.URL)

	hdr := http.Header{"Cookie": {"AdultContent=1; _ga=GA1.2.3"}}
	a := do(h, "GET", "http://test.local/p", hdr)
	if a.Code != 200 {
		t.Fatalf("status = %d, want 200", a.Code)
	}
	// The origin MUST have seen the raw AdultContent cookie (forwarded, not stripped). _ga
	// is not allow-listed (cookie_allow strip-all) so it is gone — only the forward cookie remains.
	if got := a.Body.String(); got != "AdultContent=1" {
		t.Fatalf("origin saw %q, want the forwarded AdultContent=1 (cookie NOT stripped)", got)
	}
	if x := a.Header().Get("X-Cache"); x != "MISS" {
		t.Fatalf("first X-Cache = %q, want MISS", x)
	}

	// A second request with the SAME axis must HIT the shared cache (it cached — no bypass).
	b := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"AdultContent=1; _ga=GA9.9"}})
	if x := b.Header().Get("X-Cache"); x != "HIT" {
		t.Fatalf("second X-Cache = %q, want HIT (the forward response cached, axis collapsed)", x)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (request cached, second served from cache)", origin.hits.Load())
	}
}

// TestForward_BackgroundRevalidationForwardsCookie is the Finding 5 regression: when a
// forward-mode entry goes stale and is served from grace, the DETACHED background
// revalidation must STILL forward the forward-mode cookie to origin — not refresh the
// axis-keyed entry with anonymous/default content. The foreground fetch forwards the
// cookie via buildOriginHeader(r.Header, …); before the fix the background revalidation
// built origin headers from an EMPTY base (buildOriginHeader(http.Header{}, …)) and the
// forward cookie — which lives in the request header, not rd.ReqHeaderOps — was DROPPED,
// so the origin returned anonymous content stored under the personalized {TOKEN} key.
func TestForward_BackgroundRevalidationForwardsCookie(t *testing.T) {
	clk := newFakeClock()
	var mu sync.Mutex
	var seen []string
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		ac := ""
		if c, err := r.Cookie("AdultContent"); err == nil {
			ac = c.Value
		}
		mu.Lock()
		seen = append(seen, ac)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "AdultContent="+ac)
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@adultcookie cookie AdultContent 1
	classify {adult_php} {
		derives_from cookie AdultContent forward
		when @adultcookie -> 1
		default           -> 0
	}
	cookie_allow
	cache_key default host url {adult_php}
	cache_ttl default ttl 1s grace 1h
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)
	hdr := http.Header{"Cookie": {"AdultContent=1"}}

	if r := do(h, "GET", "http://test.local/p", hdr); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	// Age the entry into the grace window (ttl 1s elapsed, grace 1h remaining).
	clk.advance(2 * time.Second)

	// Stale HIT: served from grace + triggers a background revalidation.
	if r := do(h, "GET", "http://test.local/p", hdr); r.Header().Get("X-Cache") != "HIT-STALE" {
		t.Fatalf("second GET X-Cache=%q, want HIT-STALE (served from grace, bg revalidate)", r.Header().Get("X-Cache"))
	}

	// Wait for the detached background revalidation to reach the origin.
	deadline := time.Now().Add(2 * time.Second)
	for origin.hits.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("background revalidation never reached origin")
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("origin saw %d requests, want >=2", len(seen))
	}
	if seen[1] != "1" {
		t.Fatalf("background revalidation forwarded AdultContent=%q, want 1 (the forward cookie must NOT be dropped on the detached refresh)", seen[1])
	}
}

// TestForward_AxisVariesGetsDistinctEntries: two users with different AdultContent values
// get DIFFERENT cache entries (keyed by the axis), each forwarding its own cookie.
func TestForward_AxisVariesGetsDistinctEntries(t *testing.T) {
	origin := fwdOrigin(t)
	h, _ := buildHandler(t, nil, cfgForward, origin.srv.URL)

	// AdultContent=1 -> axis 1.
	r1 := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"AdultContent=1"}})
	if r1.Body.String() != "AdultContent=1" {
		t.Fatalf("origin saw %q, want AdultContent=1", r1.Body.String())
	}
	// AdultContent=0 -> default axis 0 (distinct entry → MISS, origin sees AdultContent=0).
	r2 := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"AdultContent=0"}})
	if x := r2.Header().Get("X-Cache"); x != "MISS" {
		t.Fatalf("AdultContent=0 X-Cache = %q, want MISS (distinct axis → distinct key)", x)
	}
	if r2.Body.String() != "AdultContent=0" {
		t.Fatalf("origin saw %q, want AdultContent=0 (its own cookie forwarded)", r2.Body.String())
	}
	// AdultContent=1 again: HIT (the axis-1 entry).
	r3 := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"AdultContent=1"}})
	if x := r3.Header().Get("X-Cache"); x != "HIT" {
		t.Fatalf("AdultContent=1 (repeat) X-Cache = %q, want HIT", x)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (one per distinct axis)", origin.hits.Load())
	}
}
