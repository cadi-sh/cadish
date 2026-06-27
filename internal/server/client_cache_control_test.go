package server

import (
	"net/http"
	"testing"
	"time"
)

// cfgIgnoreClientCC is cfgCond plus the per-site `client_cache_control ignore`
// opt-out: the server must NOT honor a request's client-forced revalidation
// (Cache-Control: no-cache/max-age=0, Pragma: no-cache) and instead serve the
// fresh/stale entry as normal (SPEC-IGNORE-CLIENT-CC; Varnish `unset
// req.http.Cache-Control`).
const cfgIgnoreClientCC = `test.local {
	cache { ram 64MiB }
	client_cache_control ignore
	upstream backend { to %s }
	cache_ttl default ttl 60s grace 1h
	header +cache_status X-Cache
}
`

// TestClientCacheControlIgnoreServesHit: with `client_cache_control ignore`, a
// fresh entry is served as a HIT even when the request carries the standard
// browser-hard-refresh directives — no forced MISS, no extra origin fetch.
func TestClientCacheControlIgnoreServesHit(t *testing.T) {
	origin := originWithValidators(t, `"v1"`, "")
	h, _ := buildHandler(t, nil, cfgIgnoreClientCC, origin.srv.URL)

	// Warm the cache (MISS).
	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("after warm, origin hits = %d, want 1", origin.hits.Load())
	}

	// Each of the three client-forced-revalidation forms must serve a HIT and NOT
	// reach origin again.
	cases := []struct {
		name string
		hdr  http.Header
	}{
		{"cache-control max-age=0", http.Header{"Cache-Control": {"max-age=0"}}},
		{"cache-control no-cache", http.Header{"Cache-Control": {"no-cache"}}},
		{"pragma no-cache", http.Header{"Pragma": {"no-cache"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := do(h, "GET", "http://test.local/p", tc.hdr)
			if r.Code != http.StatusOK {
				t.Fatalf("%s: code = %d, want 200", tc.name, r.Code)
			}
			if got := r.Header().Get("X-Cache"); got != "HIT" {
				t.Fatalf("%s: X-Cache = %q, want HIT (client revalidation ignored)", tc.name, got)
			}
			if origin.hits.Load() != 1 {
				t.Fatalf("%s: origin hits = %d, want 1 (no forced MISS, served from cache)", tc.name, origin.hits.Load())
			}
		})
	}
}

// TestClientCacheControlDefaultHonors: WITHOUT the flag (the default), the same
// cfg honors client-forced revalidation — each form forces a MISS / origin
// revalidation. This is the byte-for-byte-unchanged baseline the opt-out toggles.
func TestClientCacheControlDefaultHonors(t *testing.T) {
	origin := originWithValidators(t, `"v1"`, "")
	h, _ := buildHandler(t, nil, cfgCond, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("after warm, origin hits = %d, want 1", origin.hits.Load())
	}

	// Without the flag, max-age=0 forces a revalidation (origin re-consulted).
	r := do(h, "GET", "http://test.local/p", http.Header{"Cache-Control": {"max-age=0"}})
	if r.Code != http.StatusOK {
		t.Fatalf("max-age=0 code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("default: max-age=0 origin hits = %d, want 2 (honored, not served from cache)", origin.hits.Load())
	}
}

// TestClientCacheControlIgnoreStillRevalidatesPastGrace: the opt-out ONLY
// suppresses CLIENT-forced revalidation — it must NOT cause a stale-past-grace
// entry to be served. After the entry expires past its grace window a normal
// request still revalidates with origin (grace safety preserved).
func TestClientCacheControlIgnoreStillRevalidatesPastGrace(t *testing.T) {
	clk := newFakeClock()
	origin := originWithValidators(t, `"v1"`, "")
	h, _ := buildHandler(t, clk, cfgIgnoreClientCC, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Code != 200 {
		t.Fatalf("warm code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("after warm, origin hits = %d, want 1", origin.hits.Load())
	}

	// Advance well past TTL (60s) + grace (1h): the entry is EXPIRED, not servable.
	clk.advance(2 * time.Hour)

	// A plain request (no client revalidation header) must still go to origin — the
	// flag does not turn an expired entry into a stale hit.
	r := do(h, "GET", "http://test.local/p", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("post-grace code = %d, want 200", r.Code)
	}
	if origin.hits.Load() != 2 {
		t.Fatalf("post-grace: origin hits = %d, want 2 (expired entry revalidated regardless of flag)", origin.hits.Load())
	}
}
