package tlsacme

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// readyzFallback stands in for the data-plane handler on :80: it answers the reserved
// /.cadish/readyz probe with the real warm/not-warm signal (here 503 "warming" — cold),
// and everything else with a sentinel so a test can tell "served plain via the data plane"
// from "301'd to HTTPS".
func readyzFallback(warm bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyzPath {
			if warm {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("warming\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data-plane"))
	}
}

// TestReadyzNotRedirectedStandalone proves the warm-readiness gate is NOT defeated on a
// standalone (ungated) TLS server: /.cadish/readyz on :80 must reach the data plane and
// return the REAL 503 "warming" (cold) — never a 3xx redirect, which a Kubernetes httpGet
// probe (2xx AND 3xx = success) would treat as ready regardless of warm state. A normal
// path still 301s, so the fix only skips the redirect for the reserved probe.
func TestReadyzNotRedirectedStandalone(t *testing.T) {
	cert, key := genSelfSigned(t, "site.example.com")
	m, err := NewManager([]SiteConfig{{
		Hosts: []string{"site.example.com"},
		TLS:   SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key},
	}}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := m.HTTPHandler(readyzFallback(false))

	do := func(host, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+path, nil))
		return rec
	}

	// readyz on :80 → served plain by the data plane with the REAL 503, not a 301.
	if rec := do("site.example.com", readyzPath); rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "warming\n" {
		t.Errorf("readyz on :80 (standalone TLS): status = %d body = %q, want 503 %q (served plain, NOT 3xx)", rec.Code, rec.Body.String(), "warming\n")
	}
	// readyz with a query still matches on path → served plain.
	if rec := do("site.example.com", readyzPath+"?x=1"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz+query on :80: status = %d, want 503 (path-only match)", rec.Code)
	}
	// A normal path still 301s (the exemption is exact to the probe path).
	if rec := do("site.example.com", "/"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("normal path on :80: status = %d, want 301 (redirect unchanged)", rec.Code)
	}
	// A sibling path is NOT exempt → still 301 (exact match only, no prefix bypass).
	if rec := do("site.example.com", readyzPath+"/extra"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("sibling of readyz on :80: status = %d, want 301 (exact match only)", rec.Code)
	}
}

// TestReadyzNotRedirectedGatedTLSHost proves the gate is not defeated even when the probe
// carries a TLS host's name (e.g. an operator sets httpGet.host / a Host httpHeader): in
// gated (Ingress/Gateway, ForceACME) mode a TLS host normally 301s, but readyz is served
// plain with its real 200/503. The default kubelet probe uses the pod IP (no TLS) so it
// already reached the data plane; this covers the configured-Host case too. When warm the
// data plane answers 200 ok.
func TestReadyzNotRedirectedGatedTLSHost(t *testing.T) {
	cert, key := genSelfSigned(t, "tls.example.com")
	m, err := NewManager([]SiteConfig{{
		Hosts: []string{"tls.example.com"},
		TLS:   SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key},
	}}, Options{ForceACME: true, ACMEEmail: "ops@example.com", CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := m.HTTPHandler(readyzFallback(true)) // warm

	do := func(host, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+path, nil))
		return rec
	}

	// TLS host, readyz → served plain (real 200 ok), NOT 301.
	if rec := do("tls.example.com", readyzPath); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("gated TLS host, readyz: status = %d body = %q, want 200 %q (served plain)", rec.Code, rec.Body.String(), "ok\n")
	}
	// TLS host, normal path → still 301 (per-host gating unchanged).
	if rec := do("tls.example.com", "/"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("gated TLS host, normal path: status = %d, want 301", rec.Code)
	}
}
