package tlsacme

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// fallbackProbe is a stand-in for the site pipeline on :80: it answers the exempt probe
// path with 200 (the live health gate) and everything else with a sentinel so a test can
// tell "served plain via the pipeline" from "301'd to HTTPS".
func fallbackProbe(probePath, probeBody, otherBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == probePath {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(probeBody))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(otherBody))
	}
}

// TestHTTPRedirectExceptStandalone: in standalone `cadish run` with TLS configured, a path
// listed via `tls { http_redirect_except … }` answers on plain :80 via the site pipeline
// (here 200 from the fallback), while a normal path still 301s to https. This is the
// /aws-health-check case from the spec — the probe must get its real liveness signal on :80.
func TestHTTPRedirectExceptStandalone(t *testing.T) {
	cert, key := genSelfSigned(t, "site.example.com")
	m, err := NewManager([]SiteConfig{{
		Hosts: []string{"site.example.com"},
		TLS: SiteTLS{
			Mode:           ModeStatic,
			CertFile:       cert,
			KeyFile:        key,
			RedirectExcept: []string{"/aws-health-check"},
		},
	}}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const probeBody = "live-200"
	h := m.HTTPHandler(fallbackProbe("/aws-health-check", probeBody, "other"))

	do := func(target string, hdr map[string]string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		h.ServeHTTP(rec, req)
		return rec
	}

	// Exempt path on :80 → served plain (200 from the pipeline), NOT 301.
	if rec := do("http://site.example.com/aws-health-check", nil); rec.Code != http.StatusOK || rec.Body.String() != probeBody {
		t.Errorf("exempt path on :80: status = %d body = %q, want 200 %q (served plain, no 301)", rec.Code, rec.Body.String(), probeBody)
	}
	// Exempt path WITH a query string still matches on path → served plain.
	if rec := do("http://site.example.com/aws-health-check?check=1", nil); rec.Code != http.StatusOK {
		t.Errorf("exempt path + query on :80: status = %d, want 200 (path-only match)", rec.Code)
	}
	// A normal path on :80 → still 301 to https (default redirect-all unchanged).
	if rec := do("http://site.example.com/", nil); rec.Code != http.StatusMovedPermanently {
		t.Errorf("normal path on :80: status = %d, want 301 https", rec.Code)
	}
	if rec := do("http://site.example.com/", nil); rec.Header().Get("Location") != "https://site.example.com/" {
		t.Errorf("normal path Location = %q, want https://site.example.com/", rec.Header().Get("Location"))
	}
	// A non-exempt sibling path → still 301 (the exemption is exact, not a prefix).
	if rec := do("http://site.example.com/aws-health-check/extra", nil); rec.Code != http.StatusMovedPermanently {
		t.Errorf("sibling of exempt path on :80: status = %d, want 301 (exact match only)", rec.Code)
	}
}

// TestHTTPRedirectExceptLoopGuard: the X-Forwarded-Proto loop guard is intact. An exempt
// path is served plain regardless; crucially a NORMAL path arriving over https (XFP: https)
// is STILL suppressed (served plain, not 301'd) exactly as before — the exemption neither
// forces a redirect nor changes the guard.
func TestHTTPRedirectExceptLoopGuard(t *testing.T) {
	cert, key := genSelfSigned(t, "site.example.com")
	m, err := NewManager([]SiteConfig{{
		Hosts: []string{"site.example.com"},
		TLS: SiteTLS{
			Mode:           ModeStatic,
			CertFile:       cert,
			KeyFile:        key,
			RedirectExcept: []string{"/aws-health-check"},
		},
		TrustedProxies: trustTerminator, // the XFP terminator is trusted (192.0.2.0/24)
	}}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	const otherBody = "served-plain"
	h := m.HTTPHandler(fallbackProbe("/aws-health-check", "live", otherBody))

	do := func(path, xfproto string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://site.example.com"+path, nil)
		if xfproto != "" {
			req.Header.Set("X-Forwarded-Proto", xfproto)
		}
		h.ServeHTTP(rec, req)
		return rec
	}

	// Normal path WITH XFP https → still suppressed (served plain), guard intact.
	if rec := do("/", "https"); rec.Code != http.StatusOK || rec.Body.String() != otherBody {
		t.Errorf("normal path + XFP https: status = %d body = %q, want 200 %q (loop guard)", rec.Code, rec.Body.String(), otherBody)
	}
	// Normal path WITHOUT XFP → still 301 (no regression).
	if rec := do("/", ""); rec.Code != http.StatusMovedPermanently {
		t.Errorf("normal path, no XFP: status = %d, want 301", rec.Code)
	}
	// Exempt path with XFP https → served plain (200) just the same.
	if rec := do("/aws-health-check", "https"); rec.Code != http.StatusOK {
		t.Errorf("exempt path + XFP https: status = %d, want 200", rec.Code)
	}
}

// TestHTTPRedirectExceptReload: a reload that adds/removes an exempt path takes effect on
// the next :80 request (the exemption lives in the swappable host-state).
func TestHTTPRedirectExceptReload(t *testing.T) {
	cert, key := genSelfSigned(t, "site.example.com")
	base := SiteConfig{Hosts: []string{"site.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}}
	m, err := NewManager([]SiteConfig{base}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := m.HTTPHandler(fallbackProbe("/probe", "live", "other"))
	do := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://site.example.com/probe", nil))
		return rec
	}

	// Before: no exemption → /probe 301s like any path.
	if rec := do(); rec.Code != http.StatusMovedPermanently {
		t.Fatalf("before reload: status = %d, want 301", rec.Code)
	}
	// Reload adding the exemption → /probe now served plain.
	withExempt := base
	withExempt.TLS.RedirectExcept = []string{"/probe"}
	if err := m.Reload([]SiteConfig{withExempt}); err != nil {
		t.Fatal(err)
	}
	if rec := do(); rec.Code != http.StatusOK {
		t.Errorf("after reload adding exemption: status = %d, want 200 (served plain)", rec.Code)
	}
	// Reload removing it again → back to 301.
	if err := m.Reload([]SiteConfig{base}); err != nil {
		t.Fatal(err)
	}
	if rec := do(); rec.Code != http.StatusMovedPermanently {
		t.Errorf("after reload removing exemption: status = %d, want 301", rec.Code)
	}
}

// TestHTTPRedirectExceptGatedCompose: in Ingress mode (gated) the per-host gating is
// unchanged AND the path exemption composes with it — an exempt path is served plain on a
// TLS host that would otherwise 301, while a normal path on that host still 301s.
func TestHTTPRedirectExceptGatedCompose(t *testing.T) {
	cert, key := genSelfSigned(t, "tls.example.com")
	m, err := NewManager([]SiteConfig{{
		Hosts: []string{"tls.example.com"},
		TLS: SiteTLS{
			Mode:           ModeStatic,
			CertFile:       cert,
			KeyFile:        key,
			RedirectExcept: []string{"/healthz"},
		},
	}}, Options{ForceACME: true, ACMEEmail: "ops@example.com", CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	h := m.HTTPHandler(fallbackProbe("/healthz", "live", "other"))
	do := func(host, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://"+host+path, nil))
		return rec
	}

	// TLS host, exempt path → served plain (composes with the per-host gate).
	if rec := do("tls.example.com", "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("gated TLS host, exempt path: status = %d, want 200 (served plain)", rec.Code)
	}
	// TLS host, normal path → still 301 (per-host gating unchanged).
	if rec := do("tls.example.com", "/"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("gated TLS host, normal path: status = %d, want 301", rec.Code)
	}
	// Non-TLS host, normal path → served plain by the gate (unchanged) regardless of
	// the exemption, proving per-host gating still governs the default.
	if rec := do("plain.example.com", "/"); rec.Code != http.StatusOK {
		t.Errorf("gated non-TLS host: status = %d, want 200 (per-host gate, unchanged)", rec.Code)
	}
}
