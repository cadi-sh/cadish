package server

import (
	"io"
	"net/http"
	"sync"
	"testing"
)

// recordingOrigin captures the path + raw query the origin actually received.
type recordingOrigin struct {
	*countingOrigin
	mu        sync.Mutex
	lastPath  string
	lastQuery string
}

func newRecordingOrigin(t *testing.T) *recordingOrigin {
	ro := &recordingOrigin{}
	ro.countingOrigin = newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		ro.mu.Lock()
		ro.lastPath = r.URL.Path
		ro.lastQuery = r.URL.RawQuery
		ro.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	})
	return ro
}

func (ro *recordingOrigin) seen() (string, string) {
	ro.mu.Lock()
	defer ro.mu.Unlock()
	return ro.lastPath, ro.lastQuery
}

// rewrite path: the origin sees the rewritten path, the client URL is unchanged.
func TestServeRewritePath(t *testing.T) {
	ro := newRecordingOrigin(t)
	cfg := `test.local {
		cache { ram 64MiB }
		upstream backend { to %s }
		cache_ttl default ttl 60s
		rewrite path ^/old/(.*)$ /new/$1
	}
`
	h, _ := buildHandler(t, nil, cfg, ro.srv.URL)
	rec := do(h, "GET", "http://test.local/old/page", nil)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	if p, _ := ro.seen(); p != "/new/page" {
		t.Fatalf("origin path = %q, want /new/page", p)
	}
}

// rewrite strip_query: utm_* never reaches origin, but two clients differing only
// in utm share ONE cache entry (one origin hit).
func TestServeRewriteStripQuerySharesCache(t *testing.T) {
	ro := newRecordingOrigin(t)
	cfg := `test.local {
		cache { ram 64MiB }
		upstream backend { to %s }
		cache_key path query_allow genre
		cache_ttl default ttl 60s
		header +cache_status X-Cache
		rewrite strip_query utm_*
	}
`
	h, _ := buildHandler(t, nil, cfg, ro.srv.URL)

	rec1 := do(h, "GET", "http://test.local/p?genre=rock&utm_source=fb", nil)
	if rec1.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first req X-Cache = %q, want MISS", rec1.Header().Get("X-Cache"))
	}
	_, q := ro.seen()
	if q != "genre=rock" {
		t.Fatalf("origin query = %q, want genre=rock (utm stripped)", q)
	}

	// Second client: same client URL apart from a different utm value -> HIT.
	rec2 := do(h, "GET", "http://test.local/p?genre=rock&utm_source=tw", nil)
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second req X-Cache = %q, want HIT (utm must not split the key)", rec2.Header().Get("X-Cache"))
	}
	if ro.countingOrigin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1", ro.countingOrigin.hits.Load())
	}
}

// rewrite set_query reconstructs a param for the origin without poisoning the key.
func TestServeRewriteSetQuery(t *testing.T) {
	ro := newRecordingOrigin(t)
	cfg := `test.local {
		cache { ram 64MiB }
		upstream backend { to %s }
		cache_ttl default ttl 60s
		rewrite set_query publi 1
	}
`
	h, _ := buildHandler(t, nil, cfg, ro.srv.URL)
	do(h, "GET", "http://test.local/p?genre=rock", nil)
	if _, q := ro.seen(); q != "genre=rock&publi=1" {
		t.Fatalf("origin query = %q, want genre=rock&publi=1", q)
	}
}

// cache_ttl from_header: the origin's header drives the TTL end-to-end (a fresh
// HIT before expiry).
func TestServeCacheTTLFromHeader(t *testing.T) {
	clk := newFakeClock()
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Cache-Ttl", "60")
		_, _ = io.WriteString(w, "ok")
	})
	cfg := `test.local {
		cache { ram 64MiB }
		upstream backend { to %s }
		cache_ttl default from_header X-Cache-Ttl
		header +cache_status X-Cache
	}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)

	if rec := do(h, "GET", "http://test.local/p", nil); rec.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("first req = %q, want MISS", rec.Header().Get("X-Cache"))
	}
	// Within the 60s the header asked for -> HIT, no extra origin hit.
	if rec := do(h, "GET", "http://test.local/p", nil); rec.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second req = %q, want HIT (from_header TTL=60s)", rec.Header().Get("X-Cache"))
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1", origin.hits.Load())
	}
}
