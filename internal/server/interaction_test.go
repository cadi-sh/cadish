package server

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/config"
)

// interaction_test.go — feature-INTERACTION integration tests. Each test drives a
// realistic multi-feature Cadishfile end-to-end through the real Handler and asserts
// CLIENT-VISIBLE behavior (status/headers/body) AND cache state (MISS/HIT on replay).
// These guard the subtle bugs that only surface when features COMBINE on the request
// path (e.g. encode + Vary + cache_credentialed). A green test here is a regression
// guard, not dead weight.

// bigJSON is a compressible application/json body above the 1 KiB encode floor.
var bigJSON = `{"items":[` + strings.Repeat(`{"k":"the quick brown fox jumps over the lazy dog"},`, 60) + `{"k":"end"}]}`

// ---------------------------------------------------------------------------
// #1  encode + Vary + cache_credentialed
//
// A credentialed shared-key store of a COMPRESSED variant. We assert:
//   - the stored object never carries Set-Cookie (D101 credentialed strip),
//   - a second client with a DIFFERENT Accept-Encoding gets the RIGHT variant
//     (a correct codec body, not a wrong-encoding/garbled body),
//   - the identity client gets identity,
//   - Vary advertises Accept-Encoding downstream,
//   - all served cross-user from ONE shared entry (one origin hit).
//
// ---------------------------------------------------------------------------
func TestInteractionEncodeVaryCredentialed(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("X-Cache-Ttl", "60")
		// A per-user Set-Cookie the credentialed store MUST strip (never cached,
		// never served cross-user).
		w.Header().Set("Set-Cookie", "sess="+r.Header.Get("Cookie"))
		// A KNOWN Content-Length keeps the object on the RAM tier (an unknown-length
		// chunked response routes to disk, uncached on a RAM-only cache — see router.go
		// pickTier / config cache.go: that is a separate, intended limitation).
		w.Header().Set("Content-Length", strconv.Itoa(len(bigJSON)))
		_, _ = io.WriteString(w, bigJSON)
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl
	cache_ttl default hit_for_miss 0s
	encode gzip br
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// Client A — gzip, alice. MISS, stores the SHARED identity entry.
	a := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{
		"Cookie": {"session=alice"}, "Accept-Encoding": {"gzip"}})
	if got := a.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("A X-Cache=%q want MISS", got)
	}
	if got := a.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("A Content-Encoding=%q want gzip", got)
	}
	if a.Header().Get("Set-Cookie") != "" {
		t.Fatalf("A leaked Set-Cookie %q on a credentialed store", a.Header().Get("Set-Cookie"))
	}
	if !varyHas(a.Header(), "Accept-Encoding") {
		t.Fatalf("A Vary=%q must include Accept-Encoding", a.Header().Values("Vary"))
	}
	if dec := decode(t, "gzip", a.Body.Bytes()); dec != bigJSON {
		t.Fatalf("A gzip body round-trip mismatch")
	}

	// Client B — br, bob (DIFFERENT user, DIFFERENT encoding). HIT on the shared
	// entry, must get a correct br variant (not the gzip bytes mislabeled).
	b := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{
		"Cookie": {"session=bob"}, "Accept-Encoding": {"br"}})
	if got := b.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("B X-Cache=%q want HIT", got)
	}
	if got := b.Header().Get("Content-Encoding"); got != "br" {
		t.Fatalf("B Content-Encoding=%q want br", got)
	}
	if b.Header().Get("Set-Cookie") != "" {
		t.Fatalf("B served a Set-Cookie %q from cache (must be stripped)", b.Header().Get("Set-Cookie"))
	}
	if dec := decode(t, "br", b.Body.Bytes()); dec != bigJSON {
		t.Fatalf("B br body round-trip mismatch — wrong-encoding serve")
	}

	// Client C — identity (no Accept-Encoding). HIT, identity body, no encoding.
	c := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{
		"Cookie": {"session=carol"}})
	if got := c.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("C X-Cache=%q want HIT", got)
	}
	if got := c.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("C Content-Encoding=%q want identity", got)
	}
	if c.Body.String() != bigJSON {
		t.Fatalf("C identity body mismatch")
	}

	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits=%d want 1 (one shared credentialed entry, all encodings)", n)
	}
}

// ---------------------------------------------------------------------------
// #4  Range + encode + cache
//
// A Range request against a cached COMPRESSIBLE identity object, with `encode`
// active and the client accepting gzip. The server MUST serve the IDENTITY range
// (no Content-Encoding, Content-Range total == identity size, plaintext slice) —
// never a compressed slice mislabeled as the identity range.
// ---------------------------------------------------------------------------
func TestInteractionRangeEncodeIdentitySlice(t *testing.T) {
	origin := validatorOrigin(t, "text/html", `"etag1"`, bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	// Prime: a gzip client. MISS stores the identity, serves gzip.
	prime := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if prime.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("prime not gzip")
	}

	// Range request, client ALSO accepts gzip.
	rg := do(h, "GET", "http://test.local/p", http.Header{
		"Range": {"bytes=0-99"}, "Accept-Encoding": {"gzip"}})
	if rg.Code != http.StatusPartialContent {
		t.Fatalf("range status=%d want 206", rg.Code)
	}
	if ce := rg.Header().Get("Content-Encoding"); ce != "" {
		t.Fatalf("range Content-Encoding=%q — MUST be identity (no compressed slicing)", ce)
	}
	wantCR := "bytes 0-99/" + strconv.Itoa(len(bigText))
	if cr := rg.Header().Get("Content-Range"); cr != wantCR {
		t.Fatalf("Content-Range=%q want %q (against identity size)", cr, wantCR)
	}
	if rg.Body.String() != bigText[:100] {
		t.Fatalf("range body is not the plaintext identity slice")
	}
	if cl := rg.Header().Get("Content-Length"); cl != "100" {
		t.Fatalf("Content-Length=%q want 100", cl)
	}
}

// #4b — Range against an origin-COMPRESSED stored object (origin sent
// Content-Encoding: gzip). The 206 slice is of the encoded representation and MUST
// carry Content-Encoding: gzip with a Content-Range total == the stored (compressed)
// size — consistent, never mislabeled as identity.
func TestInteractionRangeOriginCompressed(t *testing.T) {
	body := strings.Repeat("X", 5000)
	gz := gzipBytes(body)
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"z1"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(gz)))
		_, _ = w.Write(gz)
	})
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	// Prime (gzip client): stores the compressed bytes.
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})

	rg := do(h, "GET", "http://test.local/p", http.Header{
		"Range": {"bytes=0-9"}, "Accept-Encoding": {"gzip"}})
	if rg.Code != http.StatusPartialContent {
		t.Fatalf("range status=%d want 206", rg.Code)
	}
	if ce := rg.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("range Content-Encoding=%q want gzip (encoded representation)", ce)
	}
	wantCR := "bytes 0-9/" + strconv.Itoa(len(gz))
	if cr := rg.Header().Get("Content-Range"); cr != wantCR {
		t.Fatalf("Content-Range=%q want %q (against COMPRESSED size)", cr, wantCR)
	}
	if !equalBytes(rg.Body.Bytes(), gz[:10]) {
		t.Fatalf("range body is not the first 10 compressed bytes")
	}
}

// ---------------------------------------------------------------------------
// #2  cache_credentialed + cookie_allow (normalizer) + cache_key cookie: token
//
// The cache key includes `cookie:tier`. cookie_allow strips `tracking` but KEEPS
// `tier`. The key token and EvalResponse must both see the SAME (normalized) cookie:
//   - two users with the SAME tier share one entry (no per-user fragmentation),
//   - two users with DIFFERENT tier get SEPARATE entries (no cross-user leak),
//   - the ORIGINAL full cookie still reaches origin (cred forward).
//
// ---------------------------------------------------------------------------
func TestInteractionCredentialedCookieKeyToken(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{"X-Cache-Ttl": {"60"}, "Content-Type": {"application/json"}}
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cookie_allow tier
	cache_key host path cookie:tier
	cache_ttl @rm from_header X-Cache-Ttl
	cache_ttl default hit_for_miss 0s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// alice, tier=gold + a stripped tracking cookie. MISS. Origin sees the FULL cookie.
	a := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{
		"Cookie": {"tier=gold; tracking=alice"}})
	if got := a.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("alice X-Cache=%q want MISS", got)
	}
	if got := a.Body.String(); got != "cookie[tier=gold; tracking=alice]" {
		t.Fatalf("origin saw %q, want the ORIGINAL full cookie (cred forward)", got)
	}

	// bob, tier=gold + different tracking. SAME tier → SAME key → HIT (shared).
	b := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{
		"Cookie": {"tier=gold; tracking=bob"}})
	if got := b.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("bob(gold) X-Cache=%q want HIT (same tier shares the entry)", got)
	}

	// carol, tier=silver. DIFFERENT tier → DIFFERENT key → MISS (separate entry).
	c := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{
		"Cookie": {"tier=silver; tracking=carol"}})
	if got := c.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("carol(silver) X-Cache=%q want MISS (distinct tier, separate key)", got)
	}

	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits=%d want 2 (gold shared, silver separate)", n)
	}
}

// ---------------------------------------------------------------------------
// #6a  device classify + cache_key {device} + Vary: User-Agent (uncovered)
//
// A {device} key is a CLASSIFICATION of the User-Agent, not the raw header, so it
// does NOT "cover" a `Vary: User-Agent`. The shared-cache shareability gate MUST
// refuse to store such a response (otherwise one UA's body could be served to a
// different UA in the same device class). This is the fail-SAFE outcome: no
// cross-variant serve. Pin it — every request goes to origin (never a wrong-variant
// HIT).
// ---------------------------------------------------------------------------
func TestInteractionDeviceKeyUncoveredVaryRefused(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Vary", "User-Agent")
		body := "ua:" + r.Header.Get("User-Agent")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path {device}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	ua := func(s string) http.Header { return http.Header{"User-Agent": {s}} }

	// Two DIFFERENT mobile UAs (same device class). If the uncovered Vary were
	// ignored, the second would HIT and be served the FIRST UA's body — a
	// cross-variant leak. The gate must refuse to store, so both MISS with their own.
	m1 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (iPhone) Mobile/15E148"))
	if got := m1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("m1 X-Cache=%q want MISS", got)
	}
	m2 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (Linux; Android 13) Mobile"))
	if got := m2.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("m2 X-Cache=%q want MISS (uncovered Vary:User-Agent must NOT cache → no cross-UA serve)", got)
	}
	if m2.Body.String() != "ua:Mozilla/5.0 (Linux; Android 13) Mobile" {
		t.Fatalf("m2 body=%q — served a different UA's variant (cross-variant leak)", m2.Body.String())
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits=%d want 2 (uncovered Vary → never cached)", n)
	}
}

// #6b  device classify + cache_key {device} on a NON-varying origin: two UAs in the
// SAME class share one entry; a different class is a separate entry. No collision.
func TestInteractionDeviceKeyNoCollision(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		klass := "desktop-body"
		if strings.Contains(ua, "Mobile") || strings.Contains(ua, "iPhone") || strings.Contains(ua, "Android") {
			klass = "mobile-body"
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(klass)))
		_, _ = io.WriteString(w, klass)
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path {device}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	ua := func(s string) http.Header { return http.Header{"User-Agent": {s}} }

	m1 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (iPhone) Mobile/15E148"))
	if m1.Header().Get("X-Cache") != "MISS" || m1.Body.String() != "mobile-body" {
		t.Fatalf("mobile1 = %q/%q", m1.Header().Get("X-Cache"), m1.Body.String())
	}
	m2 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (Linux; Android 13) Mobile"))
	if m2.Header().Get("X-Cache") != "HIT" || m2.Body.String() != "mobile-body" {
		t.Fatalf("mobile2 = %q/%q want HIT/mobile-body", m2.Header().Get("X-Cache"), m2.Body.String())
	}
	d1 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (Windows NT 10.0) Firefox/120"))
	if d1.Header().Get("X-Cache") != "MISS" || d1.Body.String() != "desktop-body" {
		t.Fatalf("desktop1 = %q/%q want MISS/desktop-body (no cross-class collision)", d1.Header().Get("X-Cache"), d1.Body.String())
	}
	d2 := do(h, "GET", "http://test.local/p", ua("Mozilla/5.0 (Macintosh) Safari/17"))
	if d2.Header().Get("X-Cache") != "HIT" || d2.Body.String() != "desktop-body" {
		t.Fatalf("desktop2 = %q/%q want HIT/desktop-body", d2.Header().Get("X-Cache"), d2.Body.String())
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits=%d want 2 (mobile, desktop)", n)
	}
}

// ---------------------------------------------------------------------------
// #3  grace/stale-while-revalidate + encode (cached variant) + revalidation
//
// A stale COMPRESSED-variant entry is served during the grace window, then a
// background revalidation replaces the identity with NEW content (a new ETag). The
// orphaned old variant (fingerprint of the OLD identity) MUST NOT be served for the
// new entry — the self-validating variant blob (D69) detects the fingerprint
// mismatch and re-compresses. We assert: (a) the stale serve is a correct gzip of
// the OLD body (no torn/wrong-encoding serve), (b) after revalidation a gzip HIT
// decodes to the NEW body, never the stale variant.
// ---------------------------------------------------------------------------
func TestInteractionGraceEncodeVariantRevalidation(t *testing.T) {
	v1 := strings.Repeat("ALPHA-alpha-", 200) // >1KiB, compressible
	v2 := strings.Repeat("BRAVO-bravo-", 200)
	var cur atomic.Value
	cur.Store([2]string{v1, `"v1"`})
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		st := cur.Load().([2]string)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", st[1])
		w.Header().Set("Content-Length", strconv.Itoa(len(st[0])))
		_, _ = io.WriteString(w, st[0])
	})
	clk := newFakeClock()
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s grace 1h
	encode gzip
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)

	// MISS (stores v1 identity, serves gzip) then HIT (materializes the gzip variant).
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	hit := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if hit.Header().Get("X-Cache") != "HIT" || decode(t, "gzip", hit.Body.Bytes()) != v1 {
		t.Fatalf("warm HIT not gzip(v1)")
	}

	// Origin content changes; age the entry into the grace window.
	cur.Store([2]string{v2, `"v2"`})
	clk.advance(2 * time.Minute) // past 60s TTL, within 1h grace

	// Stale serve: must be a CORRECT gzip of the OLD body (v1), not torn/garbled.
	stale := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := stale.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("stale X-Cache=%q want HIT-STALE", got)
	}
	if stale.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("stale not gzip")
	}
	if dec := decode(t, "gzip", stale.Body.Bytes()); dec != v1 {
		t.Fatalf("stale gzip body decoded to %q… want v1 (no wrong-encoding/torn serve)", dec[:12])
	}

	// Wait for the background revalidation to fetch v2 and re-store.
	deadline := time.Now().Add(2 * time.Second)
	for origin.hits.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if origin.hits.Load() < 2 {
		t.Fatalf("background revalidation did not run (hits=%d)", origin.hits.Load())
	}

	// Fresh HIT for gzip after revalidation: MUST decode to v2 — the orphaned v1
	// variant (fingerprint mismatch) must NOT be served.
	fresh := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := fresh.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("post-reval X-Cache=%q want HIT", got)
	}
	if fresh.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("post-reval not gzip")
	}
	if dec := decode(t, "gzip", fresh.Body.Bytes()); dec != v2 {
		t.Fatalf("post-reval gzip decoded to OLD body — orphaned variant served! got %q want v2", dec[:12])
	}
}

// ---------------------------------------------------------------------------
// #5  strip_cookies + cache_unsafe + Set-Cookie
//
// A `strip_cookies` rule removes the origin's per-user Set-Cookie before store and
// deliver, and `cache_unsafe` lifts the private/no-store refusal. The combined
// invariant: the response IS cached (one origin hit), but NO cached/served response
// ever carries a Set-Cookie — the ironclad "Set-Cookie never cached" rule holds even
// with cache_unsafe forcing the store.
// ---------------------------------------------------------------------------
func TestInteractionStripCookiesCacheUnsafeSetCookie(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "private, no-store")
		// A per-user Set-Cookie that strip_cookies must drop before store+deliver.
		w.Header().Add("Set-Cookie", "sid=secret-"+r.Header.Get("Cookie"))
		w.Header().Set("Content-Length", "11")
		_, _ = io.WriteString(w, "shared-body")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_unsafe
	strip_cookies path /shared
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// Anonymous clients (no request Cookie): cache_unsafe + strip_cookies make the
	// private/no-store + Set-Cookie response cacheable, with Set-Cookie stripped.
	a := do(h, "GET", "http://test.local/shared", nil)
	if got := a.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("A X-Cache=%q want MISS", got)
	}
	if sc := a.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("A served Set-Cookie %q — strip_cookies must drop it", sc)
	}
	b := do(h, "GET", "http://test.local/shared", nil)
	if got := b.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("B X-Cache=%q want HIT (cache_unsafe + strip_cookies → cacheable)", got)
	}
	if sc := b.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("B served a cached Set-Cookie %q — NEVER cache Set-Cookie", sc)
	}
	if b.Body.String() != "shared-body" {
		t.Fatalf("B body=%q want shared-body", b.Body.String())
	}
	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits=%d want 1 (stored once, shared across anon clients)", n)
	}

	// REQUEST-vs-RESPONSE cookie handling: a request that CARRIES a Cookie is a
	// credentialed request — the implicit credential bypass keeps it OFF the shared
	// entry (cache_unsafe does NOT lift the request bypass), so it goes to origin and
	// can never be served another user's shared body. strip_cookies still drops the
	// per-user Set-Cookie on delivery.
	c := do(h, "GET", "http://test.local/shared", http.Header{"Cookie": {"u=carol"}})
	if got := c.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("cookie-bearing C X-Cache=HIT — a credentialed request must bypass the shared cache")
	}
	if sc := c.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("C served Set-Cookie %q — strip_cookies must drop it on deliver too", sc)
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits=%d want 2 (anon store + the bypassed cookie request)", n)
	}
}

// ---------------------------------------------------------------------------
// #8  reload-under-load: a config reload that changes the TTL while requests with
// the old config are in flight must not panic and must never serve under a
// half-applied config (each request sees one coherent live config snapshot).
// ---------------------------------------------------------------------------
func TestInteractionReloadUnderLoad(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "4")
		_, _ = io.WriteString(w, "body")
	})
	cfgA := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	encode gzip
	header +cache_status X-Cache
}
`
	cfgB := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 1s
	cache_key host path {device}
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfgA, origin.srv.URL)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Hammer the handler from several goroutines while we reload underneath it.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rec := do(h, "GET", "http://test.local/p"+strconv.Itoa(id%3),
					http.Header{"Accept-Encoding": {"gzip"}, "User-Agent": {"Mozilla Mobile"}})
				if rec.Code != http.StatusOK {
					t.Errorf("status=%d during reload", rec.Code)
					return
				}
			}
		}(i)
	}

	// Reload back and forth a number of times under the concurrent load.
	for i := 0; i < 30; i++ {
		body := cfgB
		if i%2 == 0 {
			body = cfgA
		}
		next, err := config.LoadString("<reload>", fmt.Sprintf(body, origin.srv.URL))
		if err != nil {
			t.Fatalf("reload %d load: %v", i, err)
		}
		h.Reload(next)
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// varyHas reports whether the Vary header (possibly multi-valued) lists tok.
func varyHas(hdr http.Header, tok string) bool {
	for _, v := range hdr.Values("Vary") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), tok) {
				return true
			}
		}
	}
	return false
}
