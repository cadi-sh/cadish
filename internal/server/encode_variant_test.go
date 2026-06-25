package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// cfgVariantPurge is cfgEncode plus a token-gated regex purge so a test can
// invalidate the logical entry and re-fetch new content.
const cfgVariantPurge = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@tok header X-Purge-Token sekret
	purge when @tok regex {http.X-Purge-Regex}
	cache_ttl default ttl 60s
	encode zstd br gzip
	header +cache_status X-Cache
}
`

func purge(h *Handler, target, regex string) {
	do(h, "PURGE", target, http.Header{"X-Purge-Token": {"sekret"}, "X-Purge-Regex": {regex}})
}

// validatorOrigin serves body with a Content-Type and a strong ETag — the
// realistic shape of a cacheable text asset, which a stored compressed variant
// needs (D69: a variant is only cached when the identity carries a validator).
func validatorOrigin(t *testing.T, ct, etag, body string) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
}

// These tests cover the cached-variant optimization (D69): on a HIT, a stored
// compressed representation keyed by the negotiated content-coding is served
// directly WITHOUT re-compressing, while the cache key cardinality stays bounded
// (the identity request and a gzip request resolve to the SAME logical entry).

// TestEncodeVariantHITServesStoredBytesWithoutRecompressing is the core
// assertion: the FIRST HIT for a codec may compress-on-the-fly and store the
// variant; the SECOND HIT for the same codec must serve the STORED compressed
// bytes byte-for-byte and must NOT re-run the compressor.
func TestEncodeVariantHITServesStoredBytesWithoutRecompressing(t *testing.T) {
	origin := validatorOrigin(t, "text/html", `"etag1"`, bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	// MISS: stores the identity body; compresses on the fly for this client.
	recMiss := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if recMiss.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first request X-Cache = %q, want MISS", recMiss.Header().Get("X-Cache"))
	}
	if recMiss.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("MISS not gzip-compressed")
	}
	compAfterMiss := h.encodeCompressions.Load()
	if compAfterMiss < 1 {
		t.Fatalf("MISS did not compress (counter=%d)", compAfterMiss)
	}

	// First HIT for gzip: lazily materializes the stored variant (one compression).
	recHit1 := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if recHit1.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("recHit1 X-Cache = %q, want HIT", recHit1.Header().Get("X-Cache"))
	}
	if recHit1.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("HIT1 not gzip")
	}
	if decode(t, "gzip", recHit1.Body.Bytes()) != bigText {
		t.Fatalf("HIT1 round-trip mismatch")
	}
	compAfterHit1 := h.encodeCompressions.Load()

	// Second HIT for gzip: MUST serve the stored variant, NO new compression.
	recHit2 := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if recHit2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("recHit2 X-Cache = %q, want HIT", recHit2.Header().Get("X-Cache"))
	}
	if recHit2.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("HIT2 not gzip")
	}
	if got := h.encodeCompressions.Load(); got != compAfterHit1 {
		t.Fatalf("HIT2 re-compressed: counter went %d -> %d (want unchanged: stored variant served)", compAfterHit1, got)
	}
	// Byte-for-byte identical to the lazily-stored variant.
	if !equalBytes(recHit1.Body.Bytes(), recHit2.Body.Bytes()) {
		t.Fatalf("HIT2 bytes differ from stored variant")
	}
	if decode(t, "gzip", recHit2.Body.Bytes()) != bigText {
		t.Fatalf("HIT2 round-trip mismatch")
	}
}

// TestEncodeVariantCardinalityBounded proves the identity request and the gzip
// request resolve to the SAME logical cache entry: priming with gzip does not
// cause a second origin fetch for the identity client (one logical entry, not a
// per-Accept-Encoding key explosion). It also confirms different codecs share the
// one logical entry (still a single origin fetch).
func TestEncodeVariantCardinalityBounded(t *testing.T) {
	origin := validatorOrigin(t, "text/html", `"etag1"`, bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // MISS
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // HIT (gzip)
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"br"}})   // HIT (br variant)
	do(h, "GET", "http://test.local/p", nil)                                      // HIT (identity)

	if got := origin.hits.Load(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 (gzip/br/identity all one logical entry)", got)
	}
}

// TestEncodeVariantIdentityNotCompressed: a client that does not accept the
// coding still gets the identity body even after a variant has been stored.
func TestEncodeVariantIdentityNotCompressed(t *testing.T) {
	origin := validatorOrigin(t, "text/html", `"etag1"`, bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // prime + variant
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // store variant

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("identity client got Content-Encoding %q", rec.Header().Get("Content-Encoding"))
	}
	if rec.Body.String() != bigText {
		t.Fatalf("identity body altered")
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary missing Accept-Encoding on identity")
	}
}

// TestEncodeVariantHeadersCorrect: a stored-variant HIT carries Content-Encoding,
// Vary: Accept-Encoding, a weak ETag, and no stale identity Content-Length.
func TestEncodeVariantHeadersCorrect(t *testing.T) {
	origin := validatorOrigin(t, "text/html", `"strongtag"`, bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // MISS
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // store variant
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("variant HIT Content-Encoding = %q", rec.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("variant HIT Vary = %q, want Accept-Encoding", rec.Header().Get("Vary"))
	}
	if et := rec.Header().Get("ETag"); et != `W/"strongtag"` {
		t.Fatalf("variant HIT ETag = %q, want weak W/\"strongtag\"", et)
	}
	// Content-Length must describe the COMPRESSED bytes, never the identity size.
	if cl := rec.Header().Get("Content-Length"); cl != "" {
		if cl == itoa(len(bigText)) {
			t.Fatalf("variant HIT Content-Length = identity size %s (wrong)", cl)
		}
	}
}

// TestEncodeVariantStaleAfterRefetch: when the logical entry is invalidated and
// re-fetched with NEW content, a subsequent HIT for the codec must serve the NEW
// content, never the stale stored variant (self-validation against the identity).
func TestEncodeVariantStaleAfterRefetch(t *testing.T) {
	v1 := strings.Repeat("ALPHA alpha alpha. ", 100)
	v2 := strings.Repeat("BRAVO bravo bravo. ", 100)
	body, etag := v1, `"v1"`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", etag) // distinct validator per version (realistic)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
	clk := newFakeClock()
	h, _ := buildHandler(t, clk, cfgVariantPurge, origin.srv.URL)

	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // MISS v1
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // store v1 variant

	// Invalidate + change origin content (purge must post-date the stored object).
	clk.advance(time.Second)
	body, etag = v2, `"v2"`
	purge(h, "http://test.local/p", "/p")

	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // MISS v2 (re-store identity)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := decode(t, "gzip", rec.Body.Bytes()); got != v2 {
		t.Fatalf("served stale variant after refetch: got %.20q…, want v2 content", got)
	}
}

// TestEncodeVariantNotCachedWithoutValidator: a representation with NEITHER an
// ETag nor a Last-Modified must NOT have a compressed variant cached (we cannot
// safely detect staleness), so every HIT compresses on the fly — but always serves
// correct, fully-decodable content.
func TestEncodeVariantNotCachedWithoutValidator(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText) // sets Content-Length, NO ETag/Last-Modified
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // MISS
	do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}}) // HIT (no variant cached)
	before := h.encodeCompressions.Load()
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := h.encodeCompressions.Load(); got != before+1 {
		t.Fatalf("validator-less HIT did not recompress: counter %d -> %d (want +1)", before, got)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("validator-less HIT not gzip")
	}
	if decode(t, "gzip", rec.Body.Bytes()) != bigText {
		t.Fatalf("validator-less HIT round-trip mismatch")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
