package server

import (
	"net/http"
	"reflect"
	"testing"
)

// TestBuildOriginHeaderIdenticalAfterR30 pins that presizing + direct-assignment (R30)
// produces byte-identical origin headers to the old CanonicalHeaderKey + Add path:
// hop-by-hop + Host + Connection-listed headers dropped, everything else forwarded with
// every value preserved, and the result independent of the client map (no aliasing).
func TestBuildOriginHeaderIdenticalAfterR30(t *testing.T) {
	client := http.Header{
		"Accept":            {"text/html"},
		"X-Multi":           {"a", "b"},
		"Cookie":            {"s=1"},
		"Host":              {"drop.me"},      // must be dropped
		"Connection":        {"X-Hop, close"}, // hop + names X-Hop
		"X-Hop":             {"secret"},       // Connection-listed → dropped
		"Keep-Alive":        {"timeout=5"},    // hop-by-hop → dropped
		"Transfer-Encoding": {"chunked"},      // hop-by-hop → dropped
	}
	out := buildOriginHeader(client, nil, nil)

	want := http.Header{
		"Accept":  {"text/html"},
		"X-Multi": {"a", "b"},
		"Cookie":  {"s=1"},
	}
	if !reflect.DeepEqual(map[string][]string(out), map[string][]string(want)) {
		t.Fatalf("origin header = %v, want %v", out, want)
	}

	// No aliasing: mutating out must not touch client's slices.
	out["X-Multi"] = append(out["X-Multi"], "c")
	if len(client["X-Multi"]) != 2 {
		t.Fatalf("client X-Multi was mutated through out: %v", client["X-Multi"])
	}
}

// TestCopyOriginHeadersIdenticalAfterR30 pins the response-side copy: hop-by-hop +
// Connection-listed dropped, all other values appended, src never aliased.
func TestCopyOriginHeadersIdenticalAfterR30(t *testing.T) {
	src := http.Header{
		"Content-Type": {"image/png"},
		"X-Multi":      {"a", "b"},
		"Connection":   {"X-Hop"},
		"X-Hop":        {"secret"},
		"Keep-Alive":   {"timeout=5"},
	}
	hdr := http.Header{}
	copyOriginHeaders(hdr, src)
	want := http.Header{
		"Content-Type": {"image/png"},
		"X-Multi":      {"a", "b"},
	}
	if !reflect.DeepEqual(map[string][]string(hdr), map[string][]string(want)) {
		t.Fatalf("copied header = %v, want %v", hdr, want)
	}
	hdr["X-Multi"] = append(hdr["X-Multi"], "c")
	if len(src["X-Multi"]) != 2 {
		t.Fatalf("src X-Multi was mutated through hdr: %v", src["X-Multi"])
	}
}

// BenchmarkBuildOriginHeader is the R30 alloc pin for the per-fetch request path.
func BenchmarkBuildOriginHeader(b *testing.B) {
	client := http.Header{
		"Accept":          {"text/html,application/xhtml+xml"},
		"Accept-Encoding": {"gzip, br"},
		"User-Agent":      {"cadish-bench/1"},
		"Cookie":          {"sid=abc; uid=42"},
		"Referer":         {"https://example.com/"},
		"X-Request-Id":    {"deadbeef"},
		"Connection":      {"keep-alive"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = buildOriginHeader(client, nil, nil)
	}
}

// BenchmarkCopyOriginHeaders is the R30 alloc pin for the per-fetch response path.
func BenchmarkCopyOriginHeaders(b *testing.B) {
	src := http.Header{
		"Content-Type":   {"application/json"},
		"Content-Length": {"1234"},
		"Etag":           {`"abc"`},
		"Cache-Control":  {"max-age=60"},
		"Date":           {"Thu, 01 Jan 1970 00:00:00 GMT"},
		"Vary":           {"Accept-Encoding"},
		"Connection":     {"keep-alive"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		copyOriginHeaders(http.Header{}, src)
	}
}
