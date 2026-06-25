package server

import (
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"
)

// TestFreshnessBanInvalidatesMatchingKeys verifies the lazy ban-lurker: a ban added
// after an object was stored makes a matching key look like a MISS (re-fetch), while
// a non-matching key stays fresh.
func TestFreshnessBanInvalidatesMatchingKeys(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)

	f.store("GET\x1fexample.com\x1f/video/42/a.ts", time.Hour, 0, 0)
	f.store("GET\x1fexample.com\x1f/video/42/b.ts", time.Hour, 0, 0)
	f.store("GET\x1fexample.com\x1f/image/7.jpg", time.Hour, 0, 0)

	for _, k := range []string{"GET\x1fexample.com\x1f/video/42/a.ts", "GET\x1fexample.com\x1f/video/42/b.ts", "GET\x1fexample.com\x1f/image/7.jpg"} {
		if f.lookup(k) != stateFresh {
			t.Fatalf("expected fresh before ban: %q", k)
		}
	}

	clk.advance(time.Second)
	f.ban(regexp.MustCompile("/video/42/"))

	if got := f.lookup("GET\x1fexample.com\x1f/video/42/a.ts"); got != stateMiss {
		t.Errorf("banned key a: got %v, want stateMiss", got)
	}
	if got := f.lookup("GET\x1fexample.com\x1f/video/42/b.ts"); got != stateMiss {
		t.Errorf("banned key b: got %v, want stateMiss", got)
	}
	if got := f.lookup("GET\x1fexample.com\x1f/image/7.jpg"); got != stateFresh {
		t.Errorf("non-matching key: got %v, want stateFresh", got)
	}
}

// TestFreshnessBanDoesNotAffectLaterStores verifies an object stored AFTER a ban is
// issued is unaffected by it (storedAt > issuedAt).
func TestFreshnessBanDoesNotAffectLaterStores(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)

	f.ban(regexp.MustCompile("/video/42/"))

	clk.advance(time.Second)
	f.store("GET\x1fexample.com\x1f/video/42/fresh.ts", time.Hour, 0, 0)

	if got := f.lookup("GET\x1fexample.com\x1f/video/42/fresh.ts"); got != stateFresh {
		t.Errorf("object stored after ban: got %v, want stateFresh (ban must not apply)", got)
	}
}

// TestFreshnessBanClearsHitForMiss verifies a ban also short-circuits a (pre-ban)
// HFM window for a matching key.
func TestFreshnessBanClearsHitForMiss(t *testing.T) {
	clk := newFakeClock()
	f := newFreshness(clk.now)

	f.setHitForMiss("GET\x1fexample.com\x1f/api/x", time.Hour)
	if !f.hitForMiss("GET\x1fexample.com\x1f/api/x") {
		t.Fatal("expected hit-for-miss window active")
	}
	clk.advance(time.Second)
	f.ban(regexp.MustCompile("/api/"))
	if f.hitForMiss("GET\x1fexample.com\x1f/api/x") {
		t.Error("ban should clear a pre-ban hit-for-miss marker for a matching key")
	}
}

// TestFreshnessNoBansZeroCost verifies the zero-bans fast path still works.
func TestFreshnessNoBansZeroCost(t *testing.T) {
	f := newFreshness(nil)
	f.store("k", time.Hour, 0, 0)
	if f.lookup("k") != stateFresh {
		t.Fatal("expected fresh with no bans")
	}
}

// cfgBan is a site that purges by token and supports a cache-wide ban regex sourced
// from the request header (bounded), plus an operator-literal ban for one path.
const cfgBan = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@tok header X-Purge-Token sekret
	purge when @tok regex {http.X-Purge-Regex}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestBanRegexInvalidatesMultipleKeysEndToEnd is the headline backlog-#22 test: an
// authorized `purge … regex EXPR` invalidates EVERY matching cached key (re-fetched
// after the ban) while a non-matching key stays a HIT.
func TestBanRegexInvalidatesMultipleKeysEndToEnd(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	})
	clk := newFakeClock()
	h, _ := buildHandler(t, clk, cfgBan, origin.srv.URL)

	// Warm three objects under /video/42/ and one unrelated image.
	warm := []string{"/video/42/a.ts", "/video/42/b.ts", "/video/42/c.ts", "/image/7.jpg"}
	for _, p := range warm {
		if rec := do(h, "GET", "http://test.local"+p, nil); rec.Code != 200 {
			t.Fatalf("warm %s: code %d", p, rec.Code)
		}
	}
	if origin.hits.Load() != 4 {
		t.Fatalf("after warm: origin hits = %d, want 4", origin.hits.Load())
	}
	// All four are now HITs.
	for _, p := range warm {
		if got := do(h, "GET", "http://test.local"+p, nil).Header().Get("X-Cache"); got != "HIT" {
			t.Fatalf("pre-ban %s X-Cache = %q, want HIT", p, got)
		}
	}
	if origin.hits.Load() != 4 {
		t.Fatalf("pre-ban HIT check hit origin: hits = %d, want 4", origin.hits.Load())
	}

	// Issue the ban one second later so it post-dates the stored objects.
	clk.advance(time.Second)
	banHdr := http.Header{"X-Purge-Token": {"sekret"}, "X-Purge-Regex": {"/video/42/"}}
	if rec := do(h, "PURGE", "http://test.local/", banHdr); rec.Code != 200 {
		t.Fatalf("ban request: code %d", rec.Code)
	}

	// The three /video/42/ keys re-fetch (MISS); the image is still a HIT.
	for _, p := range []string{"/video/42/a.ts", "/video/42/b.ts", "/video/42/c.ts"} {
		rec := do(h, "GET", "http://test.local"+p, nil)
		if got := rec.Header().Get("X-Cache"); got != "MISS" {
			t.Errorf("post-ban %s X-Cache = %q, want MISS (invalidated)", p, got)
		}
	}
	if got := do(h, "GET", "http://test.local/image/7.jpg", nil).Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("post-ban /image/7.jpg X-Cache = %q, want HIT (not matched)", got)
	}
	// Three re-fetches for the banned keys, none for the image.
	if origin.hits.Load() != 7 {
		t.Fatalf("post-ban origin hits = %d, want 7 (4 warm + 3 re-fetch)", origin.hits.Load())
	}

	// And the re-fetched objects are HITs again (the ban applied once, lazily).
	for _, p := range []string{"/video/42/a.ts", "/video/42/b.ts", "/video/42/c.ts"} {
		if got := do(h, "GET", "http://test.local"+p, nil).Header().Get("X-Cache"); got != "HIT" {
			t.Errorf("re-warmed %s X-Cache = %q, want HIT", p, got)
		}
	}
	if origin.hits.Load() != 7 {
		t.Fatalf("re-warm should not hit origin again: hits = %d, want 7", origin.hits.Load())
	}
}

// cfgBanPath uses the `regex-path` form (Varnish-compatible `^/foo`) so a
// path-anchored pattern matches the PATH component of the key, not the whole key.
const cfgBanPath = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@tok header X-Purge-Token sekret
	purge when @tok regex-path {http.X-Purge-Regex}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// TestBanRegexPathAndMatchedCount is the G1 headline test: a `regex-path ^/nocookie`
// purge (Varnish ban.sh style) actually invalidates the matching path keys (the old
// whole-key `regex ^/nocookie` could never match a key that starts with the host),
// and the response surfaces a matched count so a no-op ban is distinguishable from a
// real one.
func TestBanRegexPathAndMatchedCount(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	})
	clk := newFakeClock()
	h, _ := buildHandler(t, clk, cfgBanPath, origin.srv.URL)

	warm := []string{"/nocookie/a.ts", "/nocookie/b.ts", "/other/c.ts"}
	for _, p := range warm {
		if rec := do(h, "GET", "http://test.local"+p, nil); rec.Code != 200 {
			t.Fatalf("warm %s: code %d", p, rec.Code)
		}
	}

	// A path-anchored ban that matches two of the three keys.
	clk.advance(time.Second)
	banHdr := http.Header{"X-Purge-Token": {"sekret"}, "X-Purge-Regex": {"^/nocookie"}}
	rec := do(h, "PURGE", "http://test.local/", banHdr)
	if rec.Code != 200 {
		t.Fatalf("ban request: code %d", rec.Code)
	}
	if got := rec.Header().Get("X-Purge-Count"); got != "2" {
		t.Errorf("X-Purge-Count = %q, want 2 (two /nocookie keys matched)", got)
	}

	// The two /nocookie keys re-fetch (MISS); /other stays a HIT.
	for _, p := range []string{"/nocookie/a.ts", "/nocookie/b.ts"} {
		if got := do(h, "GET", "http://test.local"+p, nil).Header().Get("X-Cache"); got != "MISS" {
			t.Errorf("post-ban %s X-Cache = %q, want MISS (path-anchored ban hit it)", p, got)
		}
	}
	if got := do(h, "GET", "http://test.local/other/c.ts", nil).Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("post-ban /other/c.ts X-Cache = %q, want HIT (not under /nocookie)", got)
	}
}

// TestBanMatchedCountZeroOnNoMatch verifies an operator gets X-Purge-Count: 0 when a
// regex compiled but matched nothing — so a 200 does not give false confidence (G1).
func TestBanMatchedCountZeroOnNoMatch(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	})
	clk := newFakeClock()
	h, _ := buildHandler(t, clk, cfgBanPath, origin.srv.URL)

	do(h, "GET", "http://test.local/present/x", nil)

	clk.advance(time.Second)
	banHdr := http.Header{"X-Purge-Token": {"sekret"}, "X-Purge-Regex": {"^/absent"}}
	rec := do(h, "PURGE", "http://test.local/", banHdr)
	if rec.Code != 200 {
		t.Fatalf("ban request: code %d", rec.Code)
	}
	if got := rec.Header().Get("X-Purge-Count"); got != "0" {
		t.Errorf("X-Purge-Count = %q, want 0 (pattern matched nothing — no false confidence)", got)
	}
}

// TestBanRegexOverBroadRejected verifies a request-sourced over-broad ban pattern
// (match-everything) is rejected: it must NOT nuke unrelated keys — they stay HITs.
func TestBanRegexOverBroadRejected(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body "+r.URL.Path)
	})
	clk := newFakeClock()
	h, _ := buildHandler(t, clk, cfgBan, origin.srv.URL)

	for _, p := range []string{"/a", "/b", "/c"} {
		do(h, "GET", "http://test.local"+p, nil)
	}
	if origin.hits.Load() != 3 {
		t.Fatalf("warm hits = %d, want 3", origin.hits.Load())
	}

	clk.advance(time.Second)
	// ".*" matches everything → rejected by boundRequestPurgeRegex → falls back to
	// purging only the request's own key ("/"), which was never cached.
	banHdr := http.Header{"X-Purge-Token": {"sekret"}, "X-Purge-Regex": {".*"}}
	do(h, "PURGE", "http://test.local/", banHdr)

	for _, p := range []string{"/a", "/b", "/c"} {
		if got := do(h, "GET", "http://test.local"+p, nil).Header().Get("X-Cache"); got != "HIT" {
			t.Errorf("after rejected over-broad ban, %s X-Cache = %q, want HIT (no cache-nuke)", p, got)
		}
	}
	if origin.hits.Load() != 3 {
		t.Fatalf("rejected ban must not re-fetch: hits = %d, want 3", origin.hits.Load())
	}
}
