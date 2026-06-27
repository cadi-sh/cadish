package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// TestRangeMissOrigin206NotPoisoned pins that when the origin HONORS a client Range
// on a cold MISS (returns a 206 partial), cadish relays the 206 but does NOT store
// the partial bytes as the full object — a later plain GET must re-fetch and get the
// complete body, never the cached partial slice (a classic 206-as-200 poisoning).
func TestRangeMissOrigin206NotPoisoned(t *testing.T) {
	const full = "FULLBODY-0123456789-FULLBODY"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		if rng := r.Header.Get("Range"); rng != "" {
			// Honor a single open/closed range like a real 206-capable origin.
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Range", "bytes 0-3/"+strconv.Itoa(len(full)))
			w.Header().Set("Content-Length", "4")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte(full[:4]))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(full))
	})
	h, _ := buildHandler(t, nil, `test.local {
    cache { ram 16MiB }
    upstream backend { to %s }
    cache_ttl default ttl 60s
}
`, origin.srv.URL)

	// Cold MISS with a Range the origin honors -> 206, partial body relayed.
	r1 := do(h, "GET", "http://test.local/v.bin", http.Header{"Range": {"bytes=0-3"}})
	if r1.Code != http.StatusPartialContent {
		t.Fatalf("range MISS: code=%d, want 206", r1.Code)
	}
	if r1.Body.String() != full[:4] {
		t.Fatalf("range MISS body=%q, want %q", r1.Body.String(), full[:4])
	}

	// A subsequent PLAIN GET must NOT be served the cached partial. Either a fresh
	// origin fetch (full body) or a clean MISS — never the 4-byte slice.
	r2 := do(h, "GET", "http://test.local/v.bin", nil)
	if r2.Code != http.StatusOK {
		t.Fatalf("plain GET after range MISS: code=%d, want 200", r2.Code)
	}
	if r2.Body.String() != full {
		t.Fatalf("POISONED: plain GET body=%q, want full %q", r2.Body.String(), full)
	}
}

// TestGzipQ0RefusedServesIdentity pins that `Accept-Encoding: gzip;q=0` (gzip
// explicitly refused) yields an UNcompressed body — cadish must not compress when
// the only configured codec was refused with q=0.
func TestGzipQ0RefusedServesIdentity(t *testing.T) {
	body := strings.Repeat("compress me please ", 200) // well above the encode floor
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	})
	h, _ := buildHandler(t, nil, `test.local {
    cache { ram 16MiB }
    upstream backend { to %s }
    cache_ttl default ttl 60s
    encode gzip
}
`, origin.srv.URL)

	for _, ae := range []string{"gzip;q=0", "identity;q=0, gzip;q=0", "*;q=0"} {
		rec := do(h, "GET", "http://test.local/p.txt", http.Header{"Accept-Encoding": {ae}})
		if ce := rec.Header().Get("Content-Encoding"); ce != "" {
			t.Errorf("Accept-Encoding %q: Content-Encoding=%q, want identity (none)", ae, ce)
		}
		if rec.Body.String() != body {
			t.Errorf("Accept-Encoding %q: body not served verbatim (len %d, want %d)", ae, rec.Body.Len(), len(body))
		}
	}
}

// TestGiantMultiRangeFullBodyNoOOM pins that a multi-range list with thousands of
// ranges falls back to a clean full 200 (the parser refuses multi-range) — bounded
// memory, correct bytes, no 206/OOM.
func TestGiantMultiRangeFullBodyNoOOM(t *testing.T) {
	body := strings.Repeat("0123456789", 1000) // 10 KiB
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(body))
	})
	h, _ := buildHandler(t, nil, `test.local {
    cache { ram 16MiB }
    upstream backend { to %s }
    cache_ttl default ttl 60s
}
`, origin.srv.URL)
	// Prime cache.
	if rec := do(h, "GET", "http://test.local/blob", nil); rec.Code != 200 {
		t.Fatalf("prime code=%d", rec.Code)
	}
	huge := "bytes=" + strings.Repeat("0-0,", 50000) + "1-1"
	rec := do(h, "GET", "http://test.local/blob", http.Header{"Range": {huge}})
	if rec.Code != http.StatusOK {
		t.Fatalf("giant multi-range: code=%d, want 200 (full fallback)", rec.Code)
	}
	if rec.Body.String() != body {
		t.Fatalf("giant multi-range: body corrupted (len %d, want %d)", rec.Body.Len(), len(body))
	}
	if cr := rec.Header().Get("Content-Range"); cr != "" {
		t.Errorf("giant multi-range: Content-Range=%q, want none", cr)
	}
}
