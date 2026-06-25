package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// cfgReplace scopes a self-amplifying `replace a -> aa` to text/html responses.
// "a"->"aa" is chosen deliberately: if the cache stored the TRANSFORMED body, a
// second delivery would double-apply it (caat -> caaat), so an unchanged HIT body
// proves the cache holds the CANONICAL body and transforms run per-delivery.
const cfgReplace = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	@html content_type text/html
	replace @html a aa
	header +cache_status X-Cache
}
`

func htmlOrigin(t *testing.T, body string) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	})
}

func TestReplaceTransformAndCanonicalCache(t *testing.T) {
	origin := htmlOrigin(t, "cat")
	h, _ := buildHandler(t, nil, cfgReplace, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/p", nil)
	if rec1.Code != 200 || rec1.Body.String() != "caat" {
		t.Fatalf("MISS body = %q (code %d), want \"caat\"", rec1.Body.String(), rec1.Code)
	}
	if cl := rec1.Header().Get("Content-Length"); cl != "4" {
		t.Fatalf("MISS Content-Length = %q, want 4 (corrected after transform)", cl)
	}

	rec2 := do(h, "GET", "http://test.local/p", nil)
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("second request not a HIT: %q", rec2.Header().Get("X-Cache"))
	}
	// If the cache stored "caat" and re-transformed, this would be "caaat".
	if rec2.Body.String() != "caat" {
		t.Fatalf("HIT body = %q, want \"caat\" (canonical stored, transformed per-delivery)", rec2.Body.String())
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits = %d, want 1", origin.hits.Load())
	}
}

func TestReplaceContentTypeScoped(t *testing.T) {
	// Origin serves text/plain; the replace is scoped to text/html, so the body is
	// untouched.
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "cat")
	})
	h, _ := buildHandler(t, nil, cfgReplace, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Body.String() != "cat" {
		t.Fatalf("non-matching content_type body = %q, want untouched \"cat\"", rec.Body.String())
	}
}

func TestReplaceOverCapStreamsUntransformed(t *testing.T) {
	// A body larger than the transform cap streams through untransformed.
	big := strings.Repeat("z", maxTransformBody+1024) + "aMARKERa"
	origin := htmlOrigin(t, big)
	h, _ := buildHandler(t, nil, cfgReplace, origin.srv.URL)

	rec := do(h, "GET", "http://test.local/big", nil)
	if rec.Body.Len() != len(big) {
		t.Fatalf("over-cap body len = %d, want %d (untransformed passthrough)", rec.Body.Len(), len(big))
	}
	if !strings.Contains(rec.Body.String(), "aMARKERa") {
		t.Fatalf("over-cap body was transformed; marker missing")
	}
}

func TestReplaceRangeServesCanonical(t *testing.T) {
	origin := htmlOrigin(t, "cat")
	h, _ := buildHandler(t, nil, cfgReplace, origin.srv.URL)

	// Prime the cache (MISS stores canonical "cat").
	do(h, "GET", "http://test.local/p", nil)

	// A Range request is served from cache as a slice of the CANONICAL body, not
	// transformed.
	hdr := http.Header{"Range": []string{"bytes=0-2"}}
	rec := do(h, "GET", "http://test.local/p", hdr)
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("range code = %d, want 206", rec.Code)
	}
	if rec.Body.String() != "cat" {
		t.Fatalf("range body = %q, want canonical \"cat\" (transform skipped for Range)", rec.Body.String())
	}
}

func TestReplaceMultipleInOrder(t *testing.T) {
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
	@html content_type text/html
	replace @html one two
	replace @html two three
	header +cache_status X-Cache
}
`
	origin := htmlOrigin(t, "one")
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", nil)
	// one -> two -> three (applied in order).
	if rec.Body.String() != "three" {
		t.Fatalf("ordered replaces body = %q, want \"three\"", rec.Body.String())
	}
}
