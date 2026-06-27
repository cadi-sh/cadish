package server

import (
	"bufio"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
)

// chunkedTruncatingOrigin is a raw TCP origin that writes a chunked HTTP/1.1 response,
// emits a single data chunk, then DROPS the connection WITHOUT the terminating
// zero-length chunk. This is the dangerous truncation variant: there is no
// Content-Length for the serve-and-cache tee to compare against, so the ONLY signal
// that the body is incomplete is the copy error (ErrUnexpectedEOF) the Go client
// surfaces from Read. If any wrapper collapsed that into a clean io.EOF, the short
// body would be committed to cache as if complete (poisoning every later HIT).
func chunkedTruncatingOrigin(t *testing.T, body string) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hits := &atomic.Int64{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: max-age=60\r\nTransfer-Encoding: chunked\r\n\r\n")
				// One data chunk, then close — no terminating "0\r\n\r\n".
				fmt.Fprintf(c, "%x\r\n%s\r\n", len(body), body)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String(), hits
}

// TestTruncatedChunkedBodyNotCached pins the no-Content-Length truncation guard: a
// chunked response dropped mid-stream must abort the cache write (via the copy error),
// so the next request re-fetches (MISS) instead of serving the short body as a HIT.
func TestTruncatedChunkedBodyNotCached(t *testing.T) {
	url, hits := chunkedTruncatingOrigin(t, "PARTIAL-CHUNK-DATA")
	h, _ := buildHandler(t, nil, cfgBasic, url)

	// First request: truncated chunked stream. Client copy is errored mid-body; the
	// invariant is that nothing was committed to cache.
	_ = do(h, "GET", "http://test.local/stream", nil)

	rec2 := do(h, "GET", "http://test.local/stream", nil)
	if got := rec2.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("chunked-truncated body served X-Cache=HIT — a truncated chunked body was committed to cache (poisoning). body=%q", rec2.Body.String())
	}
	if hits.Load() < 2 {
		t.Fatalf("origin hits = %d, want >= 2 (truncated chunked entry must not be cached)", hits.Load())
	}
}
