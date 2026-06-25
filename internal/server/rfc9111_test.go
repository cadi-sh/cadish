package server

import (
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// cfgCond is a basic caching site that emits an ETag + Last-Modified from origin
// so the conditional-request / Age tests have something to revalidate against.
const cfgCond = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

// originWithValidators serves a stable body plus an ETag and Last-Modified, so a
// cached HIT can be revalidated against If-None-Match / If-Modified-Since.
func originWithValidators(t *testing.T, etag, lastMod string) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		if lastMod != "" {
			w.Header().Set("Last-Modified", lastMod)
		}
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	})
}

// --- Item 1: conditional requests -> 304 from cache ---

func TestConditional_IfNoneMatch_304FromCache(t *testing.T) {
	const etag = `"v1"`
	origin := originWithValidators(t, etag, "")
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)

	// Warm the cache (MISS).
	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}

	// Matching If-None-Match on a HIT -> 304, no body.
	r := do(h, "GET", "http://test.local/p", http.Header{"If-None-Match": {etag}})
	if r.Code != http.StatusNotModified {
		t.Fatalf("matching INM: code = %d, want 304", r.Code)
	}
	if r.Body.Len() != 0 {
		t.Fatalf("matching INM: body = %q, want empty", r.Body.String())
	}
	if got := r.Header().Get("ETag"); got != etag {
		t.Fatalf("matching INM: ETag = %q, want %q", got, etag)
	}
	if got := r.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("matching INM: X-Cache = %q, want HIT", got)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1 (304 served from cache, no origin)", origin.hits.Load())
	}
}

func TestConditional_IfNoneMatch_NonMatch_200(t *testing.T) {
	const etag = `"v1"`
	origin := originWithValidators(t, etag, "")
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)
	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	r := do(h, "GET", "http://test.local/p", http.Header{"If-None-Match": {`"other"`}})
	if r.Code != http.StatusOK {
		t.Fatalf("non-matching INM: code = %d, want 200", r.Code)
	}
	if r.Body.Len() == 0 {
		t.Fatalf("non-matching INM: want full body")
	}
}

func TestConditional_IfNoneMatch_Star_304(t *testing.T) {
	origin := originWithValidators(t, `"v1"`, "")
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)
	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	r := do(h, "GET", "http://test.local/p", http.Header{"If-None-Match": {"*"}})
	if r.Code != http.StatusNotModified {
		t.Fatalf("INM *: code = %d, want 304", r.Code)
	}
}

func TestConditional_IfModifiedSince_304FromCache(t *testing.T) {
	lastMod := time.Now().UTC().Add(-2 * time.Hour).Format(http.TimeFormat)
	origin := originWithValidators(t, "", lastMod)
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)
	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	// Client's copy is newer than (or equal to) Last-Modified -> 304.
	ims := time.Now().UTC().Add(-1 * time.Hour).Format(http.TimeFormat)
	r := do(h, "GET", "http://test.local/p", http.Header{"If-Modified-Since": {ims}})
	if r.Code != http.StatusNotModified {
		t.Fatalf("IMS after Last-Modified: code = %d, want 304", r.Code)
	}
	if r.Body.Len() != 0 {
		t.Fatalf("IMS 304: body = %q, want empty", r.Body.String())
	}
}

func TestConditional_IfModifiedSince_Older_200(t *testing.T) {
	lastMod := time.Now().UTC().Add(-1 * time.Hour).Format(http.TimeFormat)
	origin := originWithValidators(t, "", lastMod)
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)
	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	// Client's copy is OLDER than Last-Modified -> full 200.
	ims := time.Now().UTC().Add(-3 * time.Hour).Format(http.TimeFormat)
	r := do(h, "GET", "http://test.local/p", http.Header{"If-Modified-Since": {ims}})
	if r.Code != http.StatusOK {
		t.Fatalf("IMS before Last-Modified: code = %d, want 200", r.Code)
	}
}

// --- Item 2: Age header ---

func TestAgeHeaderOnHit(t *testing.T) {
	clk := newFakeClock()
	origin := originWithValidators(t, `"v1"`, "")
	h, _ := buildHandler(t, clk, cfgCond, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	// Serve N seconds later.
	clk.advance(7 * time.Second)
	r := do(h, "GET", "http://test.local/p", nil)
	if r.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("expected HIT, got %q", r.Header().Get("X-Cache"))
	}
	got, err := strconv.Atoi(r.Header().Get("Age"))
	if err != nil {
		t.Fatalf("Age header = %q, not an int: %v", r.Header().Get("Age"), err)
	}
	if got != 7 {
		t.Fatalf("Age = %d, want 7", got)
	}
	if r.Header().Get("Date") == "" {
		t.Fatalf("missing Date header on cache HIT")
	}

	// Age must be monotonic: a later HIT reports a larger Age.
	clk.advance(5 * time.Second)
	r2 := do(h, "GET", "http://test.local/p", nil)
	got2, _ := strconv.Atoi(r2.Header().Get("Age"))
	if got2 < got {
		t.Fatalf("Age not monotonic: %d then %d", got, got2)
	}
}

// --- Item 3: client-forced revalidation ---

func TestClientNoCacheRevalidates(t *testing.T) {
	origin := originWithValidators(t, `"v1"`, "")
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("after warm, origin hits = %d, want 1", origin.hits.Load())
	}

	// A fresh entry + request Cache-Control: no-cache must consult origin again.
	r := do(h, "GET", "http://test.local/p", http.Header{"Cache-Control": {"no-cache"}})
	if r.Code != http.StatusOK {
		t.Fatalf("no-cache request code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("no-cache: origin hits = %d, want 2 (revalidated, not served blindly from cache)", origin.hits.Load())
	}

	// max-age=0 behaves the same.
	r2 := do(h, "GET", "http://test.local/p", http.Header{"Cache-Control": {"max-age=0"}})
	if r2.Code != http.StatusOK {
		t.Fatalf("max-age=0 request code = %d, want 200", r2.Code)
	}
	if origin.hits.Load() != 3 {
		t.Fatalf("max-age=0: origin hits = %d, want 3", origin.hits.Load())
	}

	// Pragma: no-cache (HTTP/1.0) behaves the same.
	r3 := do(h, "GET", "http://test.local/p", http.Header{"Pragma": {"no-cache"}})
	if r3.Code != http.StatusOK {
		t.Fatalf("pragma no-cache request code = %d, want 200", r3.Code)
	}
	if origin.hits.Load() != 4 {
		t.Fatalf("pragma no-cache: origin hits = %d, want 4", origin.hits.Load())
	}

	// A plain HIT (no conditional client directive) is still served from cache.
	r4 := do(h, "GET", "http://test.local/p", nil)
	if r4.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("plain request: X-Cache = %q, want HIT", r4.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != 4 {
		t.Fatalf("plain HIT: origin hits = %d, want 4 (no extra fetch)", origin.hits.Load())
	}
}

// --- Item 4: cross-method safety ---

// cfgPathKey drops `method` from the cache key, so a cached POST response COULD
// otherwise be served to a later GET at the same key.
const cfgPathKey = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key path
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

func TestUnsafeMethodNotStored(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, r.Method+" "+r.URL.Path)
	})
	h, _ := buildHandler(t, nil, cfgPathKey, origin.srv.URL)

	// A cacheable-looking POST 200 must NOT be stored.
	if r := do(h, "POST", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("POST code = %d, want 200", r.Code)
	}
	// A subsequent GET at the SAME key must MISS (origin consulted), never serve the
	// stored POST body.
	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("GET after POST: X-Cache = HIT, want MISS (POST response must not be cached/served cross-method)")
	}
	if r.Body.String() != "GET /p" {
		t.Fatalf("GET after POST: body = %q, want %q", r.Body.String(), "GET /p")
	}

	// The GET response IS cacheable: a second GET is a HIT.
	r2 := do(h, "GET", "http://test.local/p", nil)
	if got := r2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("second GET: X-Cache = %q, want HIT (GET still caches)", got)
	}
}

// TestUnsafeMethodNotServedFromCache pins the symmetric SERVE guard for the
// method-less `cache_key path`: after a GET /p caches (MISS then HIT), a POST /p
// at the same key must reach origin (its side-effect must not be silently lost)
// and must not be served the cached GET body. The store guard separately ensures
// the POST response is not cached.
func TestUnsafeMethodNotServedFromCache(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, r.Method+" "+r.URL.Path)
	})
	h, _ := buildHandler(t, nil, cfgPathKey, origin.srv.URL)

	// GET /p: MISS then HIT (the GET is cacheable under the method-less key).
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET: X-Cache = %q, want MISS", r.Header().Get("X-Cache"))
	}
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second GET: X-Cache = %q, want HIT", r.Header().Get("X-Cache"))
	}
	hitsAfterGET := origin.hits.Load()

	// POST /p at the SAME key must reach origin (not be served from the cached GET).
	r := do(h, "POST", "http://test.local/p", nil)
	if r.Code != 200 {
		t.Fatalf("POST code = %d, want 200", r.Code)
	}
	if got := r.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("POST: X-Cache = HIT, want origin fetch (unsafe method must not be served from cache)")
	}
	if r.Body.String() != "POST /p" {
		t.Fatalf("POST body = %q, want %q (must come from origin, not the cached GET)", r.Body.String(), "POST /p")
	}
	if got := origin.hits.Load(); got != hitsAfterGET+1 {
		t.Fatalf("origin hits = %d, want %d (POST must reach origin)", got, hitsAfterGET+1)
	}

	// RFC 9111 §4.4: a successful unsafe response invalidates the cached GET entry,
	// so the following GET MISSes (re-fetches) rather than serving the now-stale
	// pre-write body. (The POST response itself is never stored — that is the store
	// guard; this is the invalidation of the sibling GET.)
	r3 := do(h, "GET", "http://test.local/p", nil)
	if got := r3.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("GET after POST: X-Cache = %q, want MISS (§4.4 invalidation)", got)
	}
	if r3.Body.String() != "GET /p" {
		t.Fatalf("GET after POST: body = %q, want %q", r3.Body.String(), "GET /p")
	}
}

// --- Item 5: RFC 9111 §4.4 — invalidation of the cached entry on a successful
// unsafe-method response ---

// changingOrigin serves a body that flips from "before" to "after" once `flip` is
// set, so a test can prove the client sees the NEW body only when the cache was
// actually invalidated (a stale HIT would still return "before").
func changingOrigin(t *testing.T, before, after string, flip *atomic.Bool, postStatus int) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.Method == http.MethodPost {
			w.WriteHeader(postStatus)
			_, _ = io.WriteString(w, "post-ack")
			return
		}
		if flip.Load() {
			_, _ = io.WriteString(w, after)
			return
		}
		_, _ = io.WriteString(w, before)
	})
}

// TestUnsafeInvalidatesCachedGET (§4.4): under the method-less `cache_key path`,
// GET /p caches (HIT on the 2nd GET). A successful POST /p then invalidates that
// entry, so the NEXT GET /p MISSes and re-fetches — observing the CHANGED body.
func TestUnsafeInvalidatesCachedGET(t *testing.T) {
	var flip atomic.Bool
	origin := changingOrigin(t, "v1-body", "v2-body", &flip, http.StatusOK)
	h, _ := buildHandler(t, nil, cfgPathKey, origin.srv.URL)

	// Warm: GET /p MISS, then HIT.
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET: X-Cache = %q, want MISS", r.Header().Get("X-Cache"))
	}
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "HIT" || r.Body.String() != "v1-body" {
		t.Fatalf("second GET: X-Cache=%q body=%q, want HIT/v1-body", r.Header().Get("X-Cache"), r.Body.String())
	}

	// Origin's representation changes, then a successful POST /p arrives.
	flip.Store(true)
	if r := do(h, "POST", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("POST code = %d, want 200", r.Code)
	}

	// §4.4: the cached GET entry is invalidated — the next GET MISSes and serves the
	// NEW body (a stale HIT would still return v1-body).
	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("GET after POST: X-Cache = %q, want MISS (entry invalidated)", got)
	}
	if r.Body.String() != "v2-body" {
		t.Fatalf("GET after POST: body = %q, want %q (re-fetched after invalidation)", r.Body.String(), "v2-body")
	}
}

// cfgPathKey200 drops `method` from the key AND only caches 200s, so a failing
// (5xx) unsafe response is neither stored nor negatively cached — isolating the
// §4.4 "errors don't invalidate" assertion from negative caching.
const cfgPathKey200 = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key path
	cache_ttl status 200 ttl 60s
	header +cache_status X-Cache
}
`

// TestUnsafeErrorDoesNotInvalidate (§4.4): an UNSUCCESSFUL unsafe response (5xx)
// must NOT invalidate — RFC says only a non-error (2xx/3xx) response invalidates.
// The cached GET still HITs (with the original body) after a failed POST.
func TestUnsafeErrorDoesNotInvalidate(t *testing.T) {
	var flip atomic.Bool
	origin := changingOrigin(t, "v1-body", "v2-body", &flip, http.StatusInternalServerError)
	h, _ := buildHandler(t, nil, cfgPathKey200, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET: X-Cache = %q, want MISS", r.Header().Get("X-Cache"))
	}
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second GET: X-Cache = %q, want HIT", r.Header().Get("X-Cache"))
	}

	flip.Store(true)
	if r := do(h, "POST", "http://test.local/p", nil); r.Code != http.StatusInternalServerError {
		t.Fatalf("POST code = %d, want 500", r.Code)
	}

	// The failed POST must NOT have invalidated: the next GET still HITs the original.
	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("GET after failed POST: X-Cache = %q, want HIT (5xx must not invalidate)", got)
	}
	if r.Body.String() != "v1-body" {
		t.Fatalf("GET after failed POST: body = %q, want %q (cached entry intact)", r.Body.String(), "v1-body")
	}
}

// TestSafeMethodDoesNotInvalidate (§4.4): the invalidation path is gated on unsafe
// methods only. A GET (and HEAD) never invalidates — the cached entry survives and
// keeps HITting, proving the GET/HEAD hot path is untouched.
func TestSafeMethodDoesNotInvalidate(t *testing.T) {
	var flip atomic.Bool
	origin := changingOrigin(t, "v1-body", "v2-body", &flip, http.StatusOK)
	h, _ := buildHandler(t, nil, cfgPathKey, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first GET: X-Cache = %q, want MISS", r.Header().Get("X-Cache"))
	}
	// A HEAD at the same key must not invalidate the cached GET.
	_ = do(h, "HEAD", "http://test.local/p", nil)
	flip.Store(true) // origin body changes, but a HIT must not observe it

	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("GET after HEAD: X-Cache = %q, want HIT (safe methods never invalidate)", got)
	}
	if r.Body.String() != "v1-body" {
		t.Fatalf("GET after HEAD: body = %q, want %q (cached entry intact)", r.Body.String(), "v1-body")
	}
}
