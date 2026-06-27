package server

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

// TestRangeServeBytes is the byte-level correctness guard for a Range served FROM
// CACHE (concern: "can a Range serve wrong bytes or a wrong Content-Range?"). The
// existing TestRangeConditionals asserts only the STATUS code (206/304/200); it
// never checks that the 206 body is the requested slice nor that Content-Range /
// Content-Length describe it. This test asserts the exact bytes, the Content-Range,
// and the Content-Length for every single-range form — exercised on BOTH the RAM
// tier (bytes.Reader serve) and the DISK tier (os.File serve, where the serve path
// discards pr.start bytes with io.CopyN(io.Discard, …) before copying pr.length).
func TestRangeServeBytes(t *testing.T) {
	// 60 distinct bytes: body[i] encodes its own index so a misaligned slice is caught.
	const n = 60
	body := make([]byte, n)
	for i := range body {
		body[i] = byte('A' + (i % 26))
	}
	bodyStr := string(body)

	for _, tier := range []string{"ram", "disk"} {
		t.Run(tier, func(t *testing.T) {
			origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("ETag", `"v1"`)
				_, _ = w.Write(body)
			})
			// cache_key host path drops the method from the key, so a HEAD resolves to the
			// same entry a GET stored — exercising the HEAD-range-from-cache serve path
			// (otherwise HEAD has its own method-keyed entry and is never cached, since a
			// HEAD response is never stored).
			cfg := fmt.Sprintf(`test.local {
    cache { ram 64MiB; disk %s 64MiB }
    upstream backend { to %%s }
    storage default -> %s
    cache_key host path
    cache_ttl default ttl 60s
}
`, t.TempDir(), tier)
			h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

			// Prime the cache with a full GET (MISS → stored in the chosen tier).
			if rec := do(h, "GET", "http://test.local/blob.bin", nil); rec.Code != 200 || rec.Body.String() != bodyStr {
				t.Fatalf("prime: code=%d len=%d", rec.Code, rec.Body.Len())
			}

			cases := []struct {
				name     string
				rangeHdr string
				wantCode int
				wantBody string // for 206 / 200
				wantCR   string // expected Content-Range (206/416), "" = must be absent
				wantCLen string // expected Content-Length, "" = don't check
			}{
				{"mid range", "bytes=10-19", 206, bodyStr[10:20], "bytes 10-19/60", "10"},
				{"first byte", "bytes=0-0", 206, bodyStr[0:1], "bytes 0-0/60", "1"},
				{"last byte", "bytes=59-59", 206, bodyStr[59:60], "bytes 59-59/60", "1"},
				{"open ended", "bytes=50-", 206, bodyStr[50:], "bytes 50-59/60", "10"},
				{"suffix 5", "bytes=-5", 206, bodyStr[55:], "bytes 55-59/60", "5"},
				{"suffix over size", "bytes=-1000", 206, bodyStr, "bytes 0-59/60", "60"},
				{"whole via 0-", "bytes=0-", 206, bodyStr, "bytes 0-59/60", "60"},
				{"end past eof clamps", "bytes=55-999", 206, bodyStr[55:], "bytes 55-59/60", "5"},
				{"start past eof 416", "bytes=60-", 416, "", "bytes */60", ""},
				{"reversed 416", "bytes=20-10", 416, "", "bytes */60", ""},
				{"multi-range -> full 200", "bytes=0-1,5-6", 200, bodyStr, "", "60"},
				{"garbage -> full 200", "bytes=abc", 200, bodyStr, "", "60"},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					rec := do(h, "GET", "http://test.local/blob.bin", http.Header{"Range": {c.rangeHdr}})
					if rec.Code != c.wantCode {
						t.Fatalf("code = %d, want %d", rec.Code, c.wantCode)
					}
					if gotCR := rec.Header().Get("Content-Range"); gotCR != c.wantCR {
						t.Errorf("Content-Range = %q, want %q", gotCR, c.wantCR)
					}
					if c.wantCLen != "" {
						if gotCL := rec.Header().Get("Content-Length"); gotCL != c.wantCLen {
							t.Errorf("Content-Length = %q, want %q", gotCL, c.wantCLen)
						}
					}
					if c.wantCode == 416 {
						return // body is the 416 error page; not asserted
					}
					if got := rec.Body.String(); got != c.wantBody {
						t.Errorf("body = %q, want %q", got, c.wantBody)
					}
					// The served byte count must equal the advertised Content-Length.
					if c.wantCLen != "" {
						cl, _ := strconv.Atoi(c.wantCLen)
						if rec.Body.Len() != cl {
							t.Errorf("served %d bytes but Content-Length=%d", rec.Body.Len(), cl)
						}
					}
				})
			}

			// A HEAD with a Range must carry the 206 status + Content-Range/Content-Length
			// but NO body (RFC 9110 §9.3.2).
			t.Run("HEAD range no body", func(t *testing.T) {
				rec := do(h, "HEAD", "http://test.local/blob.bin", http.Header{"Range": {"bytes=10-19"}})
				if rec.Code != 206 {
					t.Fatalf("HEAD range code = %d, want 206", rec.Code)
				}
				if cr := rec.Header().Get("Content-Range"); cr != "bytes 10-19/60" {
					t.Errorf("HEAD Content-Range = %q", cr)
				}
				if rec.Body.Len() != 0 {
					t.Errorf("HEAD range wrote %d body bytes, want 0", rec.Body.Len())
				}
			})

			// Origin was hit exactly once (the prime); every range was served from cache.
			if origin.hits.Load() != 1 {
				t.Errorf("origin hits = %d, want 1 (ranges must serve from cache)", origin.hits.Load())
			}
		})
	}
}
