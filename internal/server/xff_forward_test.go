package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// xffEchoOrigin echoes the forwarded-header family it RECEIVED so a test can prove
// cadish injected trustworthy values (R05) instead of copying the client's verbatim.
func xffEchoOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "xff=%s|xri=%s|xfp=%s|xfh=%s|fwd=%s",
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Real-IP"),
			r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("Forwarded"),
		)
	})
}

func doFromAddr(h *Handler, remoteAddr string, hdr http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://test.local/p", nil)
	req.Host = "test.local"
	req.RemoteAddr = remoteAddr
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestForward_XFF_UntrustedPeerOverwritten (R05): with NO trust_proxy, a direct client's
// forged X-Forwarded-For / X-Real-IP / Forwarded must NOT reach the origin — cadish
// overwrites X-Forwarded-For/X-Real-IP with the verified socket peer, sets
// X-Forwarded-Proto/Host from the inbound request, and drops Forwarded.
func TestForward_XFF_UntrustedPeerOverwritten(t *testing.T) {
	origin := xffEchoOrigin(t)
	const cfg = `test.local {
	cache { ram 16MiB }
	upstream backend { to %s }
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	hdr := http.Header{
		"X-Forwarded-For": {"1.2.3.4"}, // forged
		"X-Real-IP":       {"1.2.3.4"}, // forged
		"Forwarded":       {"for=1.2.3.4;proto=https"},
	}
	rec := doFromAddr(h, "203.0.113.9:51000", hdr)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := "xff=203.0.113.9|xri=203.0.113.9|xfp=http|xfh=test.local|fwd="
	if got := rec.Body.String(); got != want {
		t.Fatalf("origin saw %q\n  want %q (forged values overwritten with the verified peer)", got, want)
	}
}

// TestForward_XFF_TrustedProxyAppended (R05): behind a trusted proxy (trust_proxy), the
// vetted X-Forwarded-For chain is KEPT and the socket peer is APPENDED (standard
// reverse-proxy semantics); X-Real-IP is the trusted-proxy-resolved real client.
func TestForward_XFF_TrustedProxyAppended(t *testing.T) {
	origin := xffEchoOrigin(t)
	const cfg = `test.local {
	cache { ram 16MiB }
	upstream backend { to %s }
	trust_proxy 203.0.113.0/24
	cache_ttl default ttl 60s
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	hdr := http.Header{"X-Forwarded-For": {"1.2.3.4"}} // from the trusted proxy
	rec := doFromAddr(h, "203.0.113.9:51000", hdr)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Chain kept + socket peer appended; X-Real-IP is the real (non-trusted) client.
	want := "xff=1.2.3.4, 203.0.113.9|xri=1.2.3.4|xfp=http|xfh=test.local|fwd="
	if got := rec.Body.String(); got != want {
		t.Fatalf("origin saw %q\n  want %q (chain appended, not trusted blindly)", got, want)
	}
}
