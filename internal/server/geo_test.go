package server

import (
	"io"
	"net/http"
	"testing"
)

// TestGeoHeaderSpoofIgnoredFromUntrustedPeer is the security regression for the
// header-geo spoofing gap: a header-sourced geo value (CF-IPCountry) must be
// honored ONLY when the immediate socket peer is a trusted proxy — the same trust
// model as X-Forwarded-For / geo.ClientIP. From an UNTRUSTED peer (no trust_proxy,
// or peer not in the trusted set) the client-supplied CF-IPCountry must be IGNORED
// so a `deny @country RU` cannot be bypassed-into nor a geo cache bucket be chosen
// by a direct client.
func TestGeoHeaderSpoofIgnoredFromUntrustedPeer(t *testing.T) {
	const cfgNoTrust = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	geo { source header CF-IPCountry }
	@ru geo country RU
	deny @ru
	cache_ttl default ttl 60s
}
`
	const cfgTrust = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 192.0.2.0/24
	geo { source header CF-IPCountry }
	@ru geo country RU
	deny @ru
	cache_ttl default ttl 60s
}
`
	// httptest.NewRequest's RemoteAddr is 192.0.2.1:1234.

	// No trust_proxy: the direct peer is NOT trusted, so a spoofed CF-IPCountry:RU
	// is ignored → geo resolves to unknown → the RU deny does NOT fire.
	t.Run("untrusted peer: spoofed RU ignored, request allowed", func(t *testing.T) {
		origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		})
		h, _ := buildHandler(t, nil, cfgNoTrust, origin.srv.URL)
		rec := do(h, "GET", "http://test.local/", http.Header{"CF-IPCountry": {"RU"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("spoofed CF-IPCountry:RU from untrusted peer: got %d, want 200 (header geo ignored)", rec.Code)
		}
	})

	// trust_proxy covers the peer: the header IS honored, so the RU deny fires.
	t.Run("trusted peer: RU header honored, request blocked", func(t *testing.T) {
		origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		})
		h, _ := buildHandler(t, nil, cfgTrust, origin.srv.URL)
		rec := do(h, "GET", "http://test.local/", http.Header{"CF-IPCountry": {"RU"}})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("CF-IPCountry:RU from trusted peer: got %d, want 403 (header geo honored)", rec.Code)
		}
	})
}

// TestGeoHeaderBucketNotAttackerChosenFromUntrustedPeer: a direct (untrusted)
// client cannot pick its {geo} cache-key bucket via CF-IPCountry — both a US and
// an ES spoof resolve to the SAME (unknown) geo class, so they share one cache
// entry rather than each carving out an attacker-named bucket.
func TestGeoHeaderBucketNotAttackerChosenFromUntrustedPeer(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	const cfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	geo { source header CF-IPCountry }
	cache_key host path {geo}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	country := func(c string) http.Header { return http.Header{"CF-IPCountry": []string{c}} }

	if r := do(h, "GET", "http://test.local/p", country("US")); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("spoof US #1 X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	// A DIFFERENT spoofed country must HIT the same entry (both ignored → unknown).
	if r := do(h, "GET", "http://test.local/p", country("ES")); r.Header().Get("X-Cache") != "HIT" {
		t.Errorf("spoof ES X-Cache=%q, want HIT (untrusted header ignored → same bucket)", r.Header().Get("X-Cache"))
	}
	if got := origin.hits.Load(); got != 1 {
		t.Fatalf("origin hits = %d, want 1 (attacker cannot choose geo bucket from untrusted peer)", got)
	}
}

// TestGeoKeyVariation: with `cache_key … {geo}` and a header geo source, two
// requests from different countries get separate cache entries while two from
// the same country share one — the cardinality win, end-to-end through the
// server's geo pre-pass.
func TestGeoKeyVariation(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "body")
	})
	// trust_proxy covers httptest's peer (192.0.2.1) so the CF-IPCountry header is
	// honored — header-sourced geo is trusted ONLY from a trusted proxy.
	const cfg = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	trust_proxy 192.0.2.0/24
	geo { source header CF-IPCountry }
	cache_key host path {geo}
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	country := func(c string) http.Header { return http.Header{"CF-IPCountry": []string{c}} }

	// First US request: MISS.
	if r := do(h, "GET", "http://test.local/p", country("US")); r.Header().Get("X-Cache") != "MISS" {
		t.Fatalf("US #1 X-Cache=%q, want MISS", r.Header().Get("X-Cache"))
	}
	// Second US request: HIT (same geo class).
	if r := do(h, "GET", "http://test.local/p", country("US")); r.Header().Get("X-Cache") != "HIT" {
		t.Errorf("US #2 X-Cache=%q, want HIT (same country shares the entry)", r.Header().Get("X-Cache"))
	}
	// ES request: different geo class → MISS + new origin hit.
	if r := do(h, "GET", "http://test.local/p", country("ES")); r.Header().Get("X-Cache") != "MISS" {
		t.Errorf("ES X-Cache=%q, want MISS (distinct country)", r.Header().Get("X-Cache"))
	}
	if got := origin.hits.Load(); got != 2 {
		t.Fatalf("origin hits = %d, want 2 (one per country: US, ES)", got)
	}
}
