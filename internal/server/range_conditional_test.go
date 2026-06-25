package server

import (
	"io"
	"net/http"
	"testing"
)

// TestRangeConditionals is the RG1/RG2 guard (RFC 9110 §13.1 + §14.2):
//   - RG2: a precondition (If-None-Match) is evaluated BEFORE range processing, so a
//     matching If-None-Match yields 304 even when the request carries a Range.
//   - RG1: If-Range gates the Range — a matching validator serves 206, a non-matching
//     (or weak/garbled) one IGNORES the Range and serves the full 200.
func TestRangeConditionals(t *testing.T) {
	const body = "0123456789abcdefghijABCDEFGHIJ0123456789" // 40 bytes
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"etag-v1"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		_, _ = io.WriteString(w, body)
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	// Prime the cache (a plain GET → MISS, stored).
	if rec := do(h, "GET", "http://test.local/r", nil); rec.Code != 200 {
		t.Fatalf("prime: code=%d", rec.Code)
	}

	cases := []struct {
		name string
		hdr  http.Header
		want int
	}{
		{"plain Range → 206", http.Header{"Range": {"bytes=10-19"}}, http.StatusPartialContent},
		{"RG2: Range + matching If-None-Match → 304", http.Header{"Range": {"bytes=10-19"}, "If-None-Match": {`"etag-v1"`}}, http.StatusNotModified},
		{"RG1: Range + non-matching If-Range → 200 full", http.Header{"Range": {"bytes=10-19"}, "If-Range": {`"wrong-etag"`}}, http.StatusOK},
		{"RG1: Range + matching If-Range → 206", http.Header{"Range": {"bytes=10-19"}, "If-Range": {`"etag-v1"`}}, http.StatusPartialContent},
		{"RG1: Range + weak If-Range → 200 full", http.Header{"Range": {"bytes=10-19"}, "If-Range": {`W/"etag-v1"`}}, http.StatusOK},
		{"If-Range by matching Last-Modified → 206", http.Header{"Range": {"bytes=10-19"}, "If-Range": {"Mon, 02 Jan 2006 15:04:05 GMT"}}, http.StatusPartialContent},
		{"plain matching If-None-Match (no Range) → 304", http.Header{"If-None-Match": {`"etag-v1"`}}, http.StatusNotModified},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(h, "GET", "http://test.local/r", c.hdr)
			if rec.Code != c.want {
				t.Errorf("code = %d, want %d (body len %d)", rec.Code, c.want, rec.Body.Len())
			}
		})
	}
}
