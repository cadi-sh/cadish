package server

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// originWithCC serves a fixed body plus a fixed Cache-Control header, so a test can
// drive cadish's response-directive handling end-to-end through the real handler.
func originWithCC(t *testing.T, cc, body string) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		_, _ = io.WriteString(w, body)
	})
}

// TestSharedCacheRefusesResponseDirectives (CRITICAL, RFC 9111 §5.2.2): a SHARED cache
// must NOT store a response the origin marked private / no-store / no-cache (or with the
// shared-cache freshness lifetime zeroed by s-maxage=0). In cadish's DEFAULT config (no
// cache_unsafe) such a response — even though `cache_ttl default ttl 60s` matched — must
// be refused, so a SECOND request re-fetches the origin rather than being served the first
// user's confidential body from the shared cache. This is the integration-level guard for
// the pipeline-level TestSafeDefaultCacheControl: it proves nothing is actually stored.
func TestSharedCacheRefusesResponseDirectives(t *testing.T) {
	for _, cc := range []string{"private", "no-store", "no-cache", "s-maxage=0", "private, max-age=300"} {
		t.Run(cc, func(t *testing.T) {
			origin := originWithCC(t, cc, "secret-body")
			h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

			r1 := do(h, "GET", "http://test.local/p", nil)
			if r1.Code != 200 || r1.Body.String() != "secret-body" {
				t.Fatalf("first: code=%d body=%q", r1.Code, r1.Body.String())
			}
			if got := r1.Header().Get("X-Cache"); got != "MISS" {
				t.Fatalf("first X-Cache=%q, want MISS", got)
			}

			// A second request MUST also reach origin: the %q response was never stored.
			r2 := do(h, "GET", "http://test.local/p", nil)
			if got := r2.Header().Get("X-Cache"); got == "HIT" {
				t.Fatalf("Cache-Control %q: second request X-Cache=HIT — a SHARED cache stored an "+
					"unshareable response (§5.2.2 violation)", cc)
			}
			if got := origin.hits.Load(); got != 2 {
				t.Fatalf("Cache-Control %q: origin hits=%d, want 2 (response must not be cached)", cc, got)
			}
		})
	}
}

// TestMustRevalidateServedStaleUnderExplicitGrace (ADR D97 / RFC 9111 §5.2.2.1): pins the
// DOCUMENTED INTENTIONAL deviation end-to-end. cadish is operator-authoritative for
// freshness: an origin `Cache-Control: must-revalidate` does NOT forbid serving the object
// stale when the operator EXPLICITLY opted into a `grace` window. The directive does not
// block storage either. (With the default grace 0 a must-revalidate object is never served
// stale — pinned by TestMustRevalidateHonoredByDefaultGrace.)
func TestMustRevalidateServedStaleUnderExplicitGrace(t *testing.T) {
	clk := newFakeClock()
	origin := originWithCC(t, "must-revalidate", "v1-body")
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 1s grace 1h
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)

	// The must-revalidate response IS stored: MISS then HIT.
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("warm X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("must-revalidate response was not stored: X-Cache=%q, want HIT", r.Header().Get("X-Cache"))
	}

	// Age past the 1s TTL into the 1h grace window: the operator's grace serves it STALE,
	// authoritative over the origin's must-revalidate.
	clk.advance(10 * time.Second)
	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("stale X-Cache=%q, want HIT-STALE (operator grace authoritative over must-revalidate, D97)", got)
	}
	if r.Body.String() != "v1-body" {
		t.Fatalf("stale body=%q, want v1-body (served from cache)", r.Body.String())
	}
}

// TestSMaxageServedStaleUnderExplicitGrace (ADR D97 / RFC 9111 §5.2.2.10): a POSITIVE
// s-maxage carries proxy-revalidate semantics for a shared cache (MUST NOT serve stale).
// cadish DELIBERATELY subordinates this to operator config — a positive s-maxage is "a
// freshness hint the operator's cache_ttl overrides" — so with an explicit `grace` the
// object IS served stale, exactly like the must-revalidate case. This pins that documented
// deviation so a future change to honor s-maxage's stale prohibition is a conscious one.
func TestSMaxageServedStaleUnderExplicitGrace(t *testing.T) {
	clk := newFakeClock()
	origin := originWithCC(t, "s-maxage=1, public", "v1-body")
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl default ttl 1s grace 1h
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, clk, cfg, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("warm X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "HIT" {
		t.Fatalf("s-maxage response was not stored: X-Cache=%q, want HIT", r.Header().Get("X-Cache"))
	}

	clk.advance(10 * time.Second) // past cadish's 1s TTL, within 1h grace
	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got != "HIT-STALE" {
		t.Fatalf("stale X-Cache=%q, want HIT-STALE (operator grace authoritative over s-maxage proxy-revalidate, D97)", got)
	}
	if r.Body.String() != "v1-body" {
		t.Fatalf("stale body=%q, want v1-body", r.Body.String())
	}
}

// TestImmutableServedFreshWithoutRevalidation (RFC 9111 §5.2.2.6): cadish never
// revalidates a FRESH object, so an origin `immutable` is honored as a matter of course —
// repeated requests within TTL HIT the cache and never re-consult origin. (A client
// `Cache-Control: no-cache` still forces revalidation — immutable does not override the
// CLIENT directive — but that is the separate TestClientNoCacheRevalidates path.)
func TestImmutableServedFreshWithoutRevalidation(t *testing.T) {
	clk := newFakeClock()
	origin := originWithCC(t, "public, immutable", "v1-body")
	h, _ := buildHandler(t, clk, cfgBasic, origin.srv.URL)

	if r := do(h, "GET", "http://test.local/p", nil); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("warm X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	clk.advance(30 * time.Second) // within the 60s TTL
	r := do(h, "GET", "http://test.local/p", nil)
	if got := r.Header().Get("X-Cache"); got != "HIT" {
		t.Fatalf("immutable fresh X-Cache=%q, want HIT (no revalidation while fresh)", got)
	}
	if origin.hits.Load() != 1 {
		t.Fatalf("origin hits=%d, want 1 (fresh immutable object never revalidated)", origin.hits.Load())
	}
}
