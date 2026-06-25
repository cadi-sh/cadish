package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// --- negotiation (unit) -----------------------------------------------------

func TestNegotiateEncoding(t *testing.T) {
	enc := &pipeline.EncodeDecision{Codecs: []string{"zstd", "br", "gzip"}}
	cases := []struct {
		name, accept, want string
	}{
		{"prefers first configured the client accepts", "gzip, br, zstd", "zstd"},
		{"falls to gzip when only gzip offered", "gzip", "gzip"},
		{"picks br when zstd absent", "br, gzip", "br"},
		{"no header means identity", "", ""},
		{"identity only means identity", "identity", ""},
		{"q=0 excludes a codec", "zstd;q=0, gzip", "gzip"},
		{"all excluded means identity", "zstd;q=0, br;q=0, gzip;q=0", ""},
		{"star accepts otherwise-unnamed codec", "*", "zstd"},
		{"star q=0 excludes the rest, named wins", "*;q=0, gzip", "gzip"},
		{"unknown codec ignored", "deflate, gzip", "gzip"},
		{"whitespace and case tolerated", "  GZIP ", "gzip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := negotiateEncoding(enc, c.accept); got != c.want {
				t.Fatalf("negotiateEncoding(%q) = %q, want %q", c.accept, got, c.want)
			}
		})
	}
}

func TestNegotiateEncodingNilOrEmpty(t *testing.T) {
	if got := negotiateEncoding(nil, "gzip"); got != "" {
		t.Fatalf("nil enc = %q, want empty", got)
	}
	if got := negotiateEncoding(&pipeline.EncodeDecision{}, "gzip"); got != "" {
		t.Fatalf("no codecs = %q, want empty", got)
	}
}

func TestContentTypeIncluded(t *testing.T) {
	types := []string{"text/*", "application/json", "image/svg+xml"}
	yes := []string{"text/html", "text/html; charset=utf-8", "TEXT/CSS", "application/json", "application/json;charset=utf-8", "image/svg+xml"}
	no := []string{"", "image/png", "application/octet-stream", "video/mp4", "font/woff2"}
	for _, ct := range yes {
		if !contentTypeIncluded(ct, types) {
			t.Errorf("contentTypeIncluded(%q) = false, want true", ct)
		}
	}
	for _, ct := range no {
		if contentTypeIncluded(ct, types) {
			t.Errorf("contentTypeIncluded(%q) = true, want false", ct)
		}
	}
}

// --- header helpers (unit) --------------------------------------------------

func TestApplyEncodeHeaders(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Length", "100")
	hdr.Set("ETag", `"abc"`)
	hdr.Set("Vary", "Cookie")
	applyEncodeHeaders(hdr, "gzip")
	if got := hdr.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", got)
	}
	if hdr.Get("Content-Length") != "" {
		t.Errorf("Content-Length not dropped: %q", hdr.Get("Content-Length"))
	}
	if got := hdr.Get("ETag"); got != `W/"abc"` {
		t.Errorf("ETag = %q, want weak W/\"abc\"", got)
	}
	vary := strings.Join(hdr.Values("Vary"), ", ")
	if !strings.Contains(vary, "Cookie") || !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary = %q, want both Cookie and Accept-Encoding", vary)
	}
}

func TestAddVaryNoDuplicate(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Vary", "Accept-Encoding")
	addVaryAcceptEncoding(hdr)
	if vs := hdr.Values("Vary"); len(vs) != 1 {
		t.Fatalf("Vary duplicated: %v", vs)
	}
}

func TestWeakenETagAlreadyWeak(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("ETag", `W/"x"`)
	weakenETag(hdr)
	if got := hdr.Get("ETag"); got != `W/"x"` {
		t.Errorf("already-weak ETag changed to %q", got)
	}
}

// --- end-to-end through the handler -----------------------------------------

const cfgEncode = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	encode zstd br gzip
	header +cache_status X-Cache
}
`

// bigText is a compressible text body above the 1 KiB min_length floor.
var bigText = strings.Repeat("the quick brown fox jumps over the lazy dog. ", 100)

func textOrigin(t *testing.T, ct, body string) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		// Set Content-Length so the response has a known size (a chunked origin
		// response is a separate, pre-existing cacheability path).
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
}

func decode(t *testing.T, codec string, b []byte) string {
	t.Helper()
	var r io.Reader
	switch codec {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		r = gr
	case "br":
		r = brotli.NewReader(bytes.NewReader(b))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("zstd reader: %v", err)
		}
		r = zr.IOReadCloser()
	default:
		t.Fatalf("unknown codec %q", codec)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("%s decompress: %v", codec, err)
	}
	return string(out)
}

func TestEncodeRoundTripAllCodecs(t *testing.T) {
	for _, codec := range []string{"gzip", "br", "zstd"} {
		t.Run(codec, func(t *testing.T) {
			origin := textOrigin(t, "text/html", bigText)
			h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
			rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {codec}})
			if got := rec.Header().Get("Content-Encoding"); got != codec {
				t.Fatalf("Content-Encoding = %q, want %q", got, codec)
			}
			if rec.Header().Get("Content-Length") != "" {
				t.Fatalf("Content-Length should be dropped, got %q", rec.Header().Get("Content-Length"))
			}
			if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
				t.Fatalf("Vary missing Accept-Encoding: %q", rec.Header().Get("Vary"))
			}
			if got := decode(t, codec, rec.Body.Bytes()); got != bigText {
				t.Fatalf("round-trip mismatch (len got %d want %d)", len(got), len(bigText))
			}
			// The compressed payload must actually be smaller than the plaintext.
			if rec.Body.Len() >= len(bigText) {
				t.Fatalf("compressed size %d not smaller than %d", rec.Body.Len(), len(bigText))
			}
		})
	}
}

func TestEncodePreferenceOrder(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip, br, zstd"}})
	if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd (preferred)", got)
	}
}

func TestEncodeNoAcceptEncodingServesIdentity(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", nil)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity (no Accept-Encoding)", got)
	}
	if rec.Body.String() != bigText {
		t.Fatalf("body not served verbatim")
	}
}

// TestEncodeVaryOnIdentityCandidate locks in the downstream-shared-cache fix: a
// compressible candidate (200 + included Content-Type) served as identity (no
// Accept-Encoding) MUST still carry Vary: Accept-Encoding so a shared cache keys
// the identity and compressed representations separately.
func TestEncodeVaryOnIdentityCandidate(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", nil)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding even on identity response", rec.Header().Get("Vary"))
	}
}

// TestEncodeNoVaryForExcludedType confirms a non-candidate (excluded Content-Type)
// does NOT get a spurious Vary: Accept-Encoding.
func TestEncodeNoVaryForExcludedType(t *testing.T) {
	origin := textOrigin(t, "image/png", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want no Accept-Encoding for excluded type", rec.Header().Get("Vary"))
	}
}

func TestEncodeQ0Excludes(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"zstd;q=0, br;q=0, gzip;q=0"}})
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity (all q=0)", got)
	}
}

func TestEncodeSkipsExcludedContentType(t *testing.T) {
	origin := textOrigin(t, "image/png", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity (image/png excluded)", got)
	}
	if rec.Body.String() != bigText {
		t.Fatalf("excluded body altered")
	}
}

func TestEncodeSkipsBelowMinLength(t *testing.T) {
	small := "short body"
	origin := textOrigin(t, "text/html", small)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity (below min_length)", got)
	}
	if rec.Body.String() != small {
		t.Fatalf("small body altered")
	}
}

func TestEncodeSkipsExistingContentEncoding(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, bigText) // pretend pre-encoded
	})
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	// We must not double-encode: the upstream Content-Encoding is preserved and the
	// body is passed through verbatim.
	if rec.Body.String() != bigText {
		t.Fatalf("body re-encoded over existing Content-Encoding")
	}
	if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want the upstream gzip preserved", ce)
	}
}

func TestEncodeSkipsHead(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "HEAD", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity (HEAD)", got)
	}
}

func TestEncodeSkipsRange(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	// Prime cache so the Range request is served from the cache path.
	do(h, "GET", "http://test.local/p", nil)
	rec := do(h, "GET", "http://test.local/p", http.Header{
		"Range":           {"bytes=0-99"},
		"Accept-Encoding": {"gzip"},
	})
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity (Range)", got)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("Range code = %d, want 206", rec.Code)
	}
}

func TestEncodeHitCompressesAndCachesUncompressed(t *testing.T) {
	origin := textOrigin(t, "text/html", bigText)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)

	// MISS: compressed delivery, cache stores canonical.
	rec1 := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if rec1.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("MISS not compressed")
	}
	if decode(t, "gzip", rec1.Body.Bytes()) != bigText {
		t.Fatalf("MISS round-trip mismatch")
	}

	// HIT: still served compressed (cache holds the uncompressed representation).
	rec2 := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second request not a HIT: %q", rec2.Header().Get("X-Cache"))
	}
	if rec2.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("HIT not compressed")
	}
	if decode(t, "gzip", rec2.Body.Bytes()) != bigText {
		t.Fatalf("HIT round-trip mismatch")
	}

	// HIT without Accept-Encoding gets the canonical uncompressed body — proving the
	// cache stored the uncompressed representation.
	rec3 := do(h, "GET", "http://test.local/p", nil)
	if rec3.Header().Get("Content-Encoding") != "" {
		t.Fatalf("identity HIT was compressed")
	}
	if rec3.Body.String() != bigText {
		t.Fatalf("identity HIT body = %d bytes, want %d (uncompressed canonical)", rec3.Body.Len(), len(bigText))
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1", origin.hits.Load())
	}
}

// TestEncodeAfterReplace verifies order: `replace` runs on plaintext, then the
// substituted body is compressed and decompresses to the replaced text.
func TestEncodeAfterReplace(t *testing.T) {
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	@html content_type text/html
	replace @html FOO BAR
	encode gzip
	header +cache_status X-Cache
}
`
	body := strings.Repeat("FOO ", 400) // compressible, > min_length
	origin := textOrigin(t, "text/html", body)
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", http.Header{"Accept-Encoding": {"gzip"}})
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("not compressed")
	}
	got := decode(t, "gzip", rec.Body.Bytes())
	want := strings.Repeat("BAR ", 400)
	if got != want {
		t.Fatalf("decoded body = %.20q…, want replaced text (BAR …)", got)
	}
	if strings.Contains(got, "FOO") {
		t.Fatalf("replace did not run before encode")
	}
}

// TestEncodeLargeImageStreamsUnbuffered verifies the zero-extra-copy invariant:
// a large non-compressible (image) body is NOT buffered and NOT compressed; it
// streams through verbatim even though `encode` is configured.
func TestEncodeLargeImageStreamsUnbuffered(t *testing.T) {
	big := strings.Repeat("\x00\x01\x02\x03", maxTransformBody) // > 1 MiB binary
	origin := textOrigin(t, "image/png", big)
	h, _ := buildHandler(t, nil, cfgEncode, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/img", http.Header{"Accept-Encoding": {"gzip"}})
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("image was compressed (Content-Encoding set)")
	}
	if rec.Body.Len() != len(big) {
		t.Fatalf("image body len = %d, want %d (verbatim passthrough)", rec.Body.Len(), len(big))
	}
}
