package server

import (
	"io"
	"net/http"
	"testing"
)

// TestNormalizeKeyVariation: a `normalize` buckets a request header into a small
// set; two raw header values mapping to the SAME bucket share one cache entry,
// a different bucket is a separate entry — the VARY-cardinality win, end-to-end.
func TestNormalizeKeyVariation(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	const cfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	normalize plan {
		from    header X-Plan
		map     pro        -> paid
		map     enterprise -> paid
		default free
	}
	cache_key host path {plan}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	plan := func(p string) http.Header { return http.Header{"X-Plan": []string{p}} }

	// pro: MISS.
	if r := do(h, "GET", "http://test.local/p", plan("pro")); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("pro X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	// enterprise → same bucket "paid" → HIT.
	if r := do(h, "GET", "http://test.local/p", plan("enterprise")); r.Header().Get("X-Cache") != "HIT" {
		t.Errorf("enterprise X-Cache=%q, want HIT (same bucket as pro)", r.Header().Get("X-Cache"))
	}
	// free → different bucket → MISS + new origin hit.
	if r := do(h, "GET", "http://test.local/p", plan("free")); r.Header().Get("X-Cache") != "MISS" {
		t.Errorf("free X-Cache=%q, want MISS (distinct bucket)", r.Header().Get("X-Cache"))
	}
	if got := origin.hits.Load(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (buckets: paid, free)", got)
	}
}
