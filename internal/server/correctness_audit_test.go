package server

import (
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestNegativeCacheIgnoresRange is the correctness-audit regression for the
// full-body negative cache (D15) × Range (range.go) interaction.
//
// A cacheable 404/410 is now stored WITH its real error-page body (Size > 0).
// serveFromCache's Range branch fired on any cached object with Size > 0 and
// unconditionally wrote 206 Partial Content — so a Range request for a cached
// 404 produced a `206` serving a slice of the error page. A 404/410 is not a
// range-serveable representation: a HIT must serve the recorded negative status
// with the full body, ignoring Range.
func TestNegativeCacheIgnoresRange(t *testing.T) {
	const errBody = "<html>custom 404 page that is reasonably long for range slicing</html>"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, errBody)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 404 410 ttl 60s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)

	// Warm the negative entry (full body).
	if r1 := do(h, "GET", "http://test.local/missing", nil); r1.Code != http.StatusNotFound {
		t.Fatalf("warm code = %d, want 404", r1.Code)
	}

	// A Range request must NOT downgrade the cached 404 to a 206.
	r2 := do(h, "GET", "http://test.local/missing", http.Header{"Range": {"bytes=0-9"}})
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("X-Cache = %q, want HIT (served from negative cache)", got)
	}
	if r2.Code != http.StatusNotFound {
		t.Fatalf("negative HIT with Range: code = %d, want 404 (Range must not turn a 404 into 206)", r2.Code)
	}
	if r2.Body.String() != errBody {
		t.Fatalf("negative HIT with Range: body = %q, want the full %q", r2.Body.String(), errBody)
	}
	if got := r2.Header().Get("Content-Range"); got != "" {
		t.Fatalf("negative HIT with Range: Content-Range = %q, want empty (no partial content for a 404)", got)
	}
}

// TestBanInvalidatesFullBodyNegativeEntry verifies the BAN (D27) × full-body
// negative cache (D15) interaction end-to-end: a cacheable 404 stored WITH its
// body is invalidated by a regex BAN issued after it, so the next request
// re-fetches (and the negative entry is re-served fresh) rather than serving a
// banned-but-still-present negative HIT.
func TestBanInvalidatesFullBodyNegativeEntry(t *testing.T) {
	var present atomic.Bool // false => origin 404s; true => origin 200s
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if present.Load() {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "now here "+r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "<html>404 page</html>")
	})
	clk := newFakeClock()
	h, _ := buildHandler(t, clk, cfgBanNeg, origin.srv.URL)

	// Warm: the object is missing → a full-body 404 negatively cached.
	if r := do(h, "GET", "http://test.local/video/42/x.ts", nil); r.Code != http.StatusNotFound {
		t.Fatalf("warm code = %d, want 404", r.Code)
	}
	if r := do(h, "GET", "http://test.local/video/42/x.ts", nil); r.Header().Get("X-Cache") != "HIT" || r.Code != http.StatusNotFound {
		t.Fatalf("pre-ban: X-Cache=%q code=%d, want HIT 404 (negative HIT)", r.Header().Get("X-Cache"), r.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("pre-ban origin hits = %d, want 1 (negative HIT not re-fetched)", origin.hits.Load())
	}

	// The object appears at origin; issue a BAN over the path AFTER the negative
	// entry was stored. The ban must invalidate the cached 404.
	present.Store(true)
	clk.advance(time.Second)
	banHdr := http.Header{"X-Purge-Token": {"sekret"}, "X-Purge-Regex": {"/video/42/"}}
	if r := do(h, "PURGE", "http://test.local/", banHdr); r.Code != 200 {
		t.Fatalf("ban request code = %d", r.Code)
	}

	// Next request re-fetches (ban dropped the negative marker) → now a 200.
	r := do(h, "GET", "http://test.local/video/42/x.ts", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("post-ban code = %d, want 200 (banned 404 re-fetched, now present)", r.Code)
	}
	if got := r.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("post-ban X-Cache = %q, want MISS (negative entry invalidated)", got)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("post-ban origin hits = %d, want 2 (re-fetched after ban)", origin.hits.Load())
	}
}

const cfgBanNeg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@tok header X-Purge-Token sekret
	purge when @tok regex {http.X-Purge-Regex}
	cache_ttl status 404 410 ttl 60s
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
