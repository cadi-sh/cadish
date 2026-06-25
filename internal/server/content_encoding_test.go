package server

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"
)

// gzipBytes returns a valid gzip stream for s.
func gzipBytes(s string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return buf.Bytes()
}

// TestContentEncodingReplayedOnHit is the CRITICAL regression: an origin that returns a
// Content-Encoding (the client sent Accept-Encoding, Go's transport did not auto-decompress)
// is cached as the encoded bytes. On a HIT the Content-Encoding MUST be replayed, or the
// client receives an undecodable body. ObjectMeta now carries ContentEncoding for this.
func TestContentEncodingReplayedOnHit(t *testing.T) {
	gz := gzipBytes("HELLO")
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		_, _ = w.Write(gz)
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func(ae string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	a := get("gzip")
	if a.Header().Get("X-Cache") != "MISS" || a.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("MISS: X-Cache=%q CE=%q, want MISS/gzip", a.Header().Get("X-Cache"), a.Header().Get("Content-Encoding"))
	}
	b := get("gzip")
	if b.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second gzip request X-Cache=%q, want HIT (encoded blob cached with Content-Length)", b.Header().Get("X-Cache"))
	}
	if b.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("HIT dropped Content-Encoding (corrupt body): CE=%q, want gzip", b.Header().Get("Content-Encoding"))
	}
	if !bytes.Equal(b.Body.Bytes(), gz) {
		t.Errorf("HIT body is not the stored gzip bytes")
	}
}

// TestContentEncodingNotServedToNonAcceptingClient: a client that does NOT accept the stored
// encoding must never be handed the encoded blob. It falls through to a fresh origin fetch
// (which negotiates this client's Accept-Encoding), so it receives a body it can read.
func TestContentEncodingNotServedToNonAcceptingClient(t *testing.T) {
	gz := gzipBytes("HELLO")
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Compress only when the (forwarded) request accepts gzip; else identity.
		if ae := r.Header.Get("Accept-Encoding"); bytes.Contains([]byte(ae), []byte("gzip")) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			_, _ = w.Write(gz)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("HELLO"))
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	get := func(ae string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Prime the cache with the gzip variant.
	if got := get("gzip").Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("priming request CE=%q, want gzip", got)
	}
	// A client that does NOT send Accept-Encoding must not be served the gzip blob.
	c := get("")
	if c.Header().Get("Content-Encoding") == "gzip" {
		t.Fatalf("non-accepting client was served the gzip blob (undecodable): CE=gzip body magic=%x", c.Body.Bytes()[:min(2, c.Body.Len())])
	}
	if c.Body.String() != "HELLO" {
		t.Errorf("non-accepting client body=%q, want decoded identity HELLO", c.Body.String())
	}
}
