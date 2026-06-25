package tlsacme

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRedirectGateRequiresRealCert (F11): in Ingress mode the HTTP→HTTPS redirect must
// be gated on a host having a REAL, usable certificate — a static keypair, a BYO
// dynamic cert, or an ACME cert that has actually been ISSUED (present in the cache) —
// NOT mere ACME-HostPolicy eligibility. An ACME-eligible host whose cert has not (and
// maybe cannot) issue must be served plain over :80 rather than 301'd into a dead :443.
func TestRedirectGateRequiresRealCert(t *testing.T) {
	cacheDir := t.TempDir()
	staticCert, staticKey := genSelfSigned(t, "static.example.com")
	m, err := NewManager([]SiteConfig{
		// static.example.com: a real keypair → genuinely has TLS.
		{Hosts: []string{"static.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: staticCert, KeyFile: staticKey}},
		// acme.example.com: ACME-eligible but NO cert issued yet.
		{Hosts: []string{"acme.example.com"}, TLS: SiteTLS{Mode: ModeACME}},
	}, Options{ForceACME: true, ACMEEmail: "ops@example.com", CacheDir: cacheDir})
	if err != nil {
		t.Fatal(err)
	}

	const fallbackBody = "served-plain"
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fallbackBody))
	})
	h := m.HTTPHandler(fallback)
	do := func(host string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+"/p", nil))
		return rec
	}

	// Static-keypair host → redirect (real cert exists).
	if rec := do("static.example.com"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("static-cert host: status = %d, want 301 (real cert)", rec.Code)
	}
	// ACME-eligible, NOT issued → served plain (no 301 into a dead :443).
	if rec := do("acme.example.com"); rec.Code != http.StatusOK || rec.Body.String() != fallbackBody {
		t.Errorf("ACME-not-issued host: status = %d body = %q, want 200 %q (plain)", rec.Code, rec.Body.String(), fallbackBody)
	}

	// A BYO dynamic cert (cert-manager Secret) makes the host genuinely TLS-capable.
	byoCert, byoKey := genSelfSignedPEM(t, "byo.example.com")
	if err := m.SetDynamicCerts([]DynamicCert{{Hosts: []string{"byo.example.com"}, CertPEM: byoCert, KeyPEM: byoKey}}); err != nil {
		t.Fatal(err)
	}
	if rec := do("byo.example.com"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("BYO-cert host: status = %d, want 301 (real cert)", rec.Code)
	}

	// Now simulate ACME having SUCCESSFULLY issued a cert for acme.example.com (a real
	// cert landing in the ACME cache). The host must become redirect-eligible.
	writeCachedACMECert(t, cacheDir, "acme.example.com")
	if rec := do("acme.example.com"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("ACME-issued host: status = %d, want 301 (cert now in cache)", rec.Code)
	}
}
