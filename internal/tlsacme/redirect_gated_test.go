package tlsacme

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// trustLoopback is the trust_proxy set used by the loop-guard tests: it covers the
// httptest.NewRequest default RemoteAddr (192.0.2.1:1234) so a request that arrives
// "from a trusted terminator" honors X-Forwarded-Proto (the legitimate CF deployment),
// while a request with a RemoteAddr OUTSIDE it is an untrusted/direct client.
var trustTerminator = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}

// TestGatedRedirect: in Ingress mode (ForceACME) the :80 handler redirects only hosts
// that have TLS (or a cadi.sh/ssl-redirect opt-in); a non-TLS host is served over plain
// HTTP via the fallback instead of 301'd to a dead TLS endpoint (audit 2026-06-24).
func TestGatedRedirect(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"tls.example.com"}, TLS: SiteTLS{Mode: ModeACME}},
	}, Options{ForceACME: true, ACMEEmail: "ops@example.com", CacheDir: t.TempDir()})
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

	// ACME-eligible host with NO issued cert yet → NOT redirected (F11): ACME
	// HostPolicy membership alone must not 301 into a dead :443 (the cert may never
	// issue for a non-public TLD). Served plain over :80 until a real cert exists.
	if rec := do("tls.example.com"); rec.Code != http.StatusOK || rec.Body.String() != fallbackBody {
		t.Errorf("ACME-eligible, not-yet-issued host: status = %d body = %q, want 200 %q (served plain, no 301 into dead :443)", rec.Code, rec.Body.String(), fallbackBody)
	}
	// Non-TLS host → served over plain HTTP (NOT redirected to a dead TLS endpoint).
	if rec := do("plain.example.com"); rec.Code != http.StatusOK || rec.Body.String() != fallbackBody {
		t.Errorf("non-TLS host: status = %d body = %q, want 200 %q (fallback)", rec.Code, rec.Body.String(), fallbackBody)
	}
	// Opt-in via cadi.sh/ssl-redirect (forceRedirect) → 301 even without local TLS.
	m.SetForceRedirectHosts([]string{"forced.example.com"})
	if rec := do("forced.example.com"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("forced host: status = %d, want 301", rec.Code)
	}
	// Clearing the force set returns it to fallback.
	m.SetForceRedirectHosts(nil)
	if rec := do("forced.example.com"); rec.Code != http.StatusOK {
		t.Errorf("forced host after clear: status = %d, want 200 (fallback)", rec.Code)
	}
}

// TestRedirectLoopGuardXForwardedProto: a request that already arrived over HTTPS at a
// trusted upstream (X-Forwarded-Proto: https) is NEVER redirected — it is served plain
// via the fallback. Without the guard, a `cadi.sh/ssl-redirect` host behind a TLS
// terminator would 301→https→terminator→plain HTTP→:80→301… forever (audit follow-up).
func TestRedirectLoopGuardXForwardedProto(t *testing.T) {
	// tls.example.com gets a REAL (static) keypair so it is genuinely redirect-eligible
	// (post-F11 the bare ACME HostPolicy no longer counts as "has TLS").
	cert, key := genSelfSigned(t, "tls.example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"tls.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}, TrustedProxies: trustTerminator},
	}, Options{ForceACME: true, ACMEEmail: "ops@example.com", CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetForceRedirectHosts([]string{"forced.example.com"})

	const fallbackBody = "served-plain"
	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fallbackBody))
	})
	h := m.HTTPHandler(fallback)

	do := func(host, xfproto string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/p", nil)
		if xfproto != "" {
			req.Header.Set("X-Forwarded-Proto", xfproto)
		}
		h.ServeHTTP(rec, req) // default RemoteAddr 192.0.2.1 ∈ trustTerminator
		return rec
	}
	// Same request but from an UNTRUSTED/direct peer (RemoteAddr outside trust_proxy).
	doUntrusted := func(host, xfproto string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/p", nil)
		req.RemoteAddr = "203.0.113.7:40000"
		if xfproto != "" {
			req.Header.Set("X-Forwarded-Proto", xfproto)
		}
		h.ServeHTTP(rec, req)
		return rec
	}

	// forceRedirect host WITH X-Forwarded-Proto: https → served plain (loop broken).
	if rec := do("forced.example.com", "https"); rec.Code != http.StatusOK || rec.Body.String() != fallbackBody {
		t.Errorf("forced host + XFP https: status = %d body = %q, want 200 %q (no redirect)", rec.Code, rec.Body.String(), fallbackBody)
	}
	// Same host WITHOUT the header → still 301 (the opt-in still works).
	if rec := do("forced.example.com", ""); rec.Code != http.StatusMovedPermanently {
		t.Errorf("forced host, no XFP: status = %d, want 301", rec.Code)
	}
	// X-Forwarded-Proto: http (plain at the edge) → still 301.
	if rec := do("forced.example.com", "http"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("forced host + XFP http: status = %d, want 301", rec.Code)
	}
	// TLS host WITH XFP https → served plain (guard applies to all redirect decisions).
	if rec := do("tls.example.com", "https"); rec.Code != http.StatusOK {
		t.Errorf("TLS host + XFP https: status = %d, want 200 (no redirect)", rec.Code)
	}
	// TLS host WITHOUT the header → still 301 (no regression).
	if rec := do("tls.example.com", ""); rec.Code != http.StatusMovedPermanently {
		t.Errorf("TLS host, no XFP: status = %d, want 301", rec.Code)
	}
	// Case-insensitive + comma-list (outermost proxy first).
	if rec := do("forced.example.com", "HTTPS, http"); rec.Code != http.StatusOK {
		t.Errorf("forced host + XFP 'HTTPS, http': status = %d, want 200 (no redirect)", rec.Code)
	}

	// TRUST BOUNDARY (R15): the SAME XFP:https from an UNTRUSTED/direct peer must NOT
	// suppress the redirect — otherwise a client adds the header to a plain :80 request
	// and is served in cleartext. It is 301'd exactly as if the header were absent.
	if rec := doUntrusted("forced.example.com", "https"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("forced host + XFP https from UNTRUSTED peer: status = %d, want 301 (header ignored)", rec.Code)
	}
	if rec := doUntrusted("tls.example.com", "https"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("TLS host + XFP https from UNTRUSTED peer: status = %d, want 301 (header ignored)", rec.Code)
	}
}

// TestUngatedRedirectAlways: standalone (no ForceACME) keeps the Caddy-style
// unconditional HTTP→HTTPS redirect for every host.
func TestUngatedRedirectAlways(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"a.example.com"}, TLS: SiteTLS{Mode: ModeOff}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	fallback := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	rec := httptest.NewRecorder()
	m.HTTPHandler(fallback).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://anything.example.com/", nil))
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("standalone: status = %d, want 301 (unconditional)", rec.Code)
	}
	if called {
		t.Error("standalone: fallback was called; want unconditional redirect")
	}
}

// TestStandaloneXFPNoTrustStillRedirects (R10b): standalone mode with NO trust_proxy
// configured ⇒ X-Forwarded-Proto is fully client-controlled. A plain :80 request that
// adds `X-Forwarded-Proto: https` MUST still be 301'd (the header is ignored) — never
// served in cleartext via the fallback. This is the standalone facet of R15.
func TestStandaloneXFPNoTrustStillRedirects(t *testing.T) {
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"a.example.com"}, TLS: SiteTLS{Mode: ModeOff}}, // no TrustedProxies
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	served := false
	fallback := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { served = true })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://anything.example.com/", nil)
	req.Header.Set("X-Forwarded-Proto", "https") // forged by a direct client
	m.HTTPHandler(fallback).ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("standalone + forged XFP https: status = %d, want 301 (header ignored)", rec.Code)
	}
	if served {
		t.Error("standalone + forged XFP https: served in cleartext; want 301")
	}
}
