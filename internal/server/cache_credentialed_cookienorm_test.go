package server

import (
	"net/http"
	"testing"
)

// cache_credentialed (D101) + cookie normalization parity characterization.
//
// These tests pin the SERVER's end-to-end behavior for a cache_credentialed scope combined
// with a cookie normalizer (`cookie_allow`). The companion edge behavior is pinned in
// edge/runtime/runtime.test.mjs ("cache_credentialed + cookie_allow …"). The conformance
// suite (test/conformance) cannot cover this end-to-end: it feeds BOTH runtimes the SAME
// un-normalized request through the PURE EvalRequest/EvalResponse functions, while the store
// decision lives at the HANDLER level. After the parity fix both runtimes behave identically:
// the server forwards the original cookie to origin ONLY via an origin-bound reqHeaderOp
// (handler.go, prependCookieOp) and lets EvalResponse evaluate the NORMALIZED request, exactly
// like the edge worker, which keeps the normalized cookie on ireq and forwards the original via
// reqHeaderOps (entry.js ~465). Fixtures 60 + 61 project the IR.

// TestCredentialedCookieAllowCommonCaseParity: the COMMON case — cookie_allow strips a cookie
// (`tracking`) that NEITHER the cache_credentialed scope NOR the cache_ttl signal selector
// reads (both are path-scoped). EvalResponse's outcome does not depend on the cookie value, so
// the server (original cookie restored) and the edge (normalized cookie) reach the SAME store
// decision: store under the shared key on the positive signal. This is the parity-safe case.
func TestCredentialedCookieAllowCommonCaseParity(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{"X-Cache-Ttl": {"60"}, "Content-Type": {"application/json"}}
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	cache_credentialed @rm
	cookie_allow session
	cache_key host path
	cache_ttl @rm from_header X-Cache-Ttl
	cache_ttl default hit_for_miss 0s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice; tracking=abc"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("req1 X-Cache = %q, want MISS", got)
	}
	// cache_credentialed forwards the ORIGINAL (full) cookie to origin, overriding cookie_allow.
	if got := rec1.Body.String(); got != "cookie[session=alice; tracking=abc]" {
		t.Fatalf("origin saw %q, want the ORIGINAL cookie forwarded (cred overrides cookie_allow)", got)
	}
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=bob"}})
	if got := rec2.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("req2 X-Cache = %q, want HIT (shared, signal not cookie-dependent)", got)
	}
	if n := origin.hits.Load(); n != 1 {
		t.Fatalf("origin hits = %d, want 1", n)
	}
}

// TestCredentialedCookieNormSignalParity: the COOKIE-NORM parity fix (D101 review).
//
// Here the cache_ttl SIGNAL selector `@premium cookie tier premium` reads a cookie that
// `cookie_allow session` STRIPS. The fixed server keeps the NORMALIZED cookie on preq.Header
// (the original is forwarded to origin ONLY via an origin-bound reqHeaderOp), so EvalResponse's
// @premium selector evaluates the normalized request (tier stripped), does NOT fire the positive
// signal, and NEVER stores — every request is a MISS. This now MATCHES the edge worker
// (edge/runtime/runtime.test.mjs companion), which has always evaluated evalResponse against the
// normalized cookie.
//
// Before the fix the server restored the original cookie onto preq.Header before EvalResponse, so
// @premium fired on a cookie cookie_allow stripped and a per-user (alice/premium) body was stored
// under the shared (host+path) key and served cross-user to bob — a server-only over-cache the
// edge never had. The original cookie still reaches origin (req1 below proves the forward) and
// still reaches the cluster peer + background revalidation (cache_credentialed_origin_paths_test.go).
func TestCredentialedCookieNormSignalParity(t *testing.T) {
	origin := credOrigin(t, func(string) http.Header {
		return http.Header{"X-Cache-Ttl": {"60"}, "Content-Type": {"application/json"}}
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@rm path_regex ^/v3/readmodel/cache/
	@premium cookie tier premium
	cache_credentialed @rm
	cookie_allow session
	cache_key host path
	cache_ttl @premium from_header X-Cache-Ttl
	cache_ttl default hit_for_miss 0s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	rec1 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=alice; tier=premium"}})
	if got := rec1.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("req1 X-Cache = %q, want MISS", got)
	}
	// The ORIGINAL cookie (incl. tier) is still forwarded to ORIGIN — only the DECISION phases
	// see the normalized request.
	if got := rec1.Body.String(); got != "cookie[session=alice; tier=premium]" {
		t.Fatalf("origin saw %q, want the ORIGINAL cookie (incl. tier) forwarded", got)
	}

	// req2: a DIFFERENT user with NO tier cookie. The fixed server did NOT store from req1 (the
	// @premium signal is judged against the normalized request, where tier is stripped), so req2
	// is a MISS — server == edge, no cross-user content bleed.
	rec2 := do(h, "GET", "http://test.local/v3/readmodel/cache/home", http.Header{"Cookie": {"session=bob"}})
	if got := rec2.Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("req2 X-Cache = %q, want MISS (server now matches edge: no cookie-norm over-cache)", got)
	}
	if n := origin.hits.Load(); n != 2 {
		t.Fatalf("origin hits = %d, want 2 (each request fetched origin: nothing stored under the shared key)", n)
	}
	// req2 sees its OWN response, not alice's premium body.
	if got := rec2.Body.String(); got != "cookie[session=bob]" {
		t.Fatalf("req2 body = %q, want bob's own response (no cross-user over-cache)", got)
	}
}
