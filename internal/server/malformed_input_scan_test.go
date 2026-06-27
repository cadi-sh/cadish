package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/metrics"
)

// TestMalformedInputScan drives a broad battery of malformed / adversarial but
// wire-plausible requests through the REAL handler and asserts the invariant that
// NONE of them trips a recovered panic (InternalErrors stays 0) and that a benign
// follow-up request still serves correctly (no poisoning / wedged state). It is a
// fast tripwire — specific correctness is pinned by the focused tests alongside it.
func TestMalformedInputScan(t *testing.T) {
	body := strings.Repeat("0123456789", 100) // 1000 bytes, range-serveable
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(body))
	})
	m := metrics.New()
	h, _ := buildHandler(t, nil, `test.local {
    cache { ram 64MiB }
    upstream backend { to %s }
    cache_ttl default ttl 60s
    encode gzip
}
`, origin.srv.URL)
	h.metrics = m

	// Each case is a method + target + headers. The assertion is uniform: no panic.
	type kase struct {
		name   string
		method string
		target string
		hdr    http.Header
	}
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}
	huge := strings.Repeat("A", 1<<20) // 1 MiB header value
	manyRanges := "bytes=" + strings.Repeat("0-0,", 5000) + "1-1"
	manyCookies := strings.Repeat("a=b; ", 5000)

	cases := []kase{
		// --- Range abuse ---
		{"range empty", "GET", "http://test.local/r", hdr("Range", "bytes=")},
		{"range dash", "GET", "http://test.local/r", hdr("Range", "bytes=-")},
		{"range abc", "GET", "http://test.local/r", hdr("Range", "bytes=abc")},
		{"range huge multi", "GET", "http://test.local/r", hdr("Range", manyRanges)},
		{"range overlapping", "GET", "http://test.local/r", hdr("Range", "bytes=0-100,50-150,0-999")},
		{"range giant start", "GET", "http://test.local/r", hdr("Range", "bytes=99999999999999-")},
		{"range giant suffix", "GET", "http://test.local/r", hdr("Range", "bytes=-99999999999999")},
		{"range overflow", "GET", "http://test.local/r", hdr("Range", "bytes=99999999999999999999999999-")},
		{"range neg whitespace", "GET", "http://test.local/r", hdr("Range", "bytes= - ")},
		{"range two headers", "GET", "http://test.local/r", hdr("Range", "bytes=0-0", "Range", "bytes=1-1")},
		{"range on head", "HEAD", "http://test.local/r", hdr("Range", "bytes=0-0")},
		{"range units", "GET", "http://test.local/r", hdr("Range", "items=0-0")},
		{"range plus", "GET", "http://test.local/r", hdr("Range", "bytes=+5-")},
		{"range tab", "GET", "http://test.local/r", hdr("Range", "bytes=\t0-1")},

		// --- Conflicting / duplicate / huge headers ---
		{"dup inm", "GET", "http://test.local/r", hdr("If-None-Match", `"a"`, "If-None-Match", `"b"`)},
		{"huge header", "GET", "http://test.local/r", hdr("X-Big", huge)},
		{"huge cc", "GET", "http://test.local/r", hdr("Cache-Control", strings.Repeat("no-cache,", 10000))},
		{"garbage cc", "GET", "http://test.local/r", hdr("Cache-Control", "\x00\x01max-age=\xff")},
		{"dup ae", "GET", "http://test.local/r", hdr("Accept-Encoding", "gzip", "Accept-Encoding", "br")},
		{"conflicting ae q", "GET", "http://test.local/r", hdr("Accept-Encoding", "gzip;q=0, gzip;q=1")},
		{"ae gzip q0", "GET", "http://test.local/r", hdr("Accept-Encoding", "gzip;q=0")},
		{"ae identity q0", "GET", "http://test.local/r", hdr("Accept-Encoding", "identity;q=0")},
		{"ae malformed q", "GET", "http://test.local/r", hdr("Accept-Encoding", "gzip;q=notanumber")},
		{"ae star q0", "GET", "http://test.local/r", hdr("Accept-Encoding", "*;q=0")},
		{"ae nan", "GET", "http://test.local/r", hdr("Accept-Encoding", "gzip;q=NaN")},
		{"ae inf", "GET", "http://test.local/r", hdr("Accept-Encoding", "gzip;q=Inf")},

		// --- Conditional / If-Range abuse ---
		{"if-range garbage", "GET", "http://test.local/r", hdr("Range", "bytes=0-0", "If-Range", "\x00garbage")},
		{"if-range weak", "GET", "http://test.local/r", hdr("Range", "bytes=0-0", "If-Range", `W/"v1"`)},
		{"ims garbage", "GET", "http://test.local/r", hdr("If-Modified-Since", "not a date")},
		{"inm star", "GET", "http://test.local/r", hdr("If-None-Match", "*")},

		// --- Weird methods ---
		{"lowercase get", "get", "http://test.local/r", nil},
		{"unknown method", "FROBNICATE", "http://test.local/r", nil},
		{"options star", "OPTIONS", "http://test.local/r", nil},
		{"trace", "TRACE", "http://test.local/r", nil},
		{"connect", "CONNECT", "http://test.local/r", nil},

		// --- Weird targets ---
		{"pct null", "GET", "http://test.local/%00", nil},
		{"dotdot enc", "GET", "http://test.local/%2e%2e%2f%2e%2e%2fetc/passwd", nil},
		{"enc slash", "GET", "http://test.local/a%2Fb", nil},
		{"double slash", "GET", "http://test.local//a//b", nil},
		{"long path", "GET", "http://test.local/" + strings.Repeat("a", 100000), nil},
		{"long query", "GET", "http://test.local/r?" + strings.Repeat("k=v&", 50000), nil},
		{"unicode path", "GET", "http://test.local/é中文", nil},
		{"semicolon cookie", "GET", "http://test.local/r", hdr("Cookie", manyCookies)},
		{"malformed cookie", "GET", "http://test.local/r", hdr("Cookie", "=;;==;a")},
		{"malformed auth", "GET", "http://test.local/r", hdr("Authorization", "\x00 not valid")},

		// --- Host abuse ---
		{"weird host header", "GET", "http://test.local/r", hdr("X-Forwarded-Host", "evil\r\n.com")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := m.Snapshot().InternalErrors
			req := httptest.NewRequest(c.method, c.target, nil)
			req.Host = "test.local"
			for k, vs := range c.hdr {
				for _, v := range vs {
					req.Header.Add(k, v)
				}
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if after := m.Snapshot().InternalErrors; after != before {
				t.Fatalf("input %q tripped a recovered panic (InternalErrors %d->%d), status=%d",
					c.name, before, after, rec.Code)
			}
			if rec.Code == 0 {
				t.Fatalf("input %q produced no response status", c.name)
			}
		})
	}

	// A benign request must still work after the whole battery (no wedged state).
	if got := m.Snapshot().InternalErrors; got != 0 {
		t.Fatalf("InternalErrors = %d after battery, want 0", got)
	}
	rec := do(h, "GET", "http://test.local/healthy", nil)
	if rec.Code != 200 || rec.Body.String() != body {
		t.Fatalf("post-battery benign request: code=%d len=%d", rec.Code, rec.Body.Len())
	}
}
