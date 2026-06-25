package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMultiValueHeaderKeyDoesNotPoison is the HIGH regression for the header dimension of the
// "gate reads differently than the origin" class: a cache_key that varies on a request header
// must capture ALL of that header's values, not just the first line. Otherwise an attacker who
// sends two X-Tenant lines (trial, acme) keys on "trial" while the origin combines/uses both →
// the attacker's response is cached under the victim tenant's key (cross-tenant poison).
func TestMultiValueHeaderKeyDoesNotPoison(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// A compliant origin combines repeated field lines (RFC 9110 §5.3).
		_, _ = io.WriteString(w, "tenant["+strings.Join(r.Header.Values("X-Tenant"), ",")+"]")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path header:X-Tenant
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	do := func(tenants ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		for _, tn := range tenants {
			req.Header.Add("X-Tenant", tn)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Attacker sends TWO tenant lines; the origin combines them and returns acme content.
	a := do("trial", "acme")
	if a.Body.String() != "tenant[trial,acme]" {
		t.Fatalf("origin should have combined both tenant lines, got %q", a.Body.String())
	}
	// A pure-trial victim must NOT be served the attacker's combined (acme-bearing) body.
	v := do("trial")
	if v.Header().Get("X-Cache") == "HIT" {
		t.Fatalf("CROSS-TENANT POISON: a single-value trial request HIT the multi-value attacker entry")
	}
	if strings.Contains(v.Body.String(), "acme") {
		t.Fatalf("CROSS-TENANT POISON: trial victim served acme content %q", v.Body.String())
	}
}
