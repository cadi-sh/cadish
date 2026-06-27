package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// DELIVER-PHASE PARITY ON FORWARDED ORIGIN ERRORS: the streamOriginError terminal
// (4a613e1 origin-error-body change) forwards a non-2xx origin body verbatim. It
// must ALSO run the response-phase deliver ops — strip_cookies, response `header`
// ops, CORS, the cache-status header — exactly as the 2xx pass path does and exactly
// as the edge worker (handleOriginResponseError → evalDeliver) does. Before the fix
// it ran only copyOriginHeaders, so an operator's explicit strip_cookies was bypassed
// on an origin-error response carrying Set-Cookie (a safety divergence vs the edge).

// TestStripCookiesAppliedToForwardedOriginError is the SAFETY assertion: a site with
// `strip_cookies` whose origin answers a bodied 403 carrying Set-Cookie must deliver
// the real body+status to the client but with NO Set-Cookie (the operator's strip
// directive is honored on the error path, matching the edge). This FAILS pre-fix.
func TestStripCookiesAppliedToForwardedOriginError(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		const errBody = `{"result":"KO","message":"DENIED"}`
		origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Add("Set-Cookie", "sessionid=leak123; HttpOnly; Path=/")
			w.WriteHeader(code)
			_, _ = io.WriteString(w, errBody)
		})
		body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
	strip_cookies path /
	header +cache_status X-Cache
}
`
		h, _ := buildHandler(t, nil, body, origin.srv.URL)
		// Request path `/` so the `strip_cookies path /` matcher (exact-path glob) fires.
		rec := do(h, "GET", "http://test.local/", nil)
		if rec.Code != code {
			t.Fatalf("%d: code = %d, want the origin status delivered verbatim", code, rec.Code)
		}
		if rec.Body.String() != errBody {
			t.Fatalf("%d: body = %q, want the origin body %q", code, rec.Body.String(), errBody)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("%d: Content-Type = %q, want application/json", code, got)
		}
		// THE SAFETY ASSERTION: strip_cookies must drop the upstream Set-Cookie on the
		// forwarded error response, just like the edge does.
		if vals := rec.Header().Values("Set-Cookie"); len(vals) != 0 {
			t.Fatalf("%d: Set-Cookie present = %v, want STRIPPED (strip_cookies must apply to the forwarded origin-error response)", code, vals)
		}
		// And the cache-status header is emitted on the error response (deliver ran).
		if got := rec.Header().Get("X-Cache"); got == "" {
			t.Fatalf("%d: X-Cache absent, want the cache-status header emitted on the forwarded error", code)
		}
	}
}

// TestRespHeaderOpAppliedToForwardedOriginError: a response-phase `header` op (set a
// header, remove the origin's Server header) is applied to the forwarded error.
func TestRespHeaderOpAppliedToForwardedOriginError(t *testing.T) {
	const errBody = "boom"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "leaky-origin/1.0")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, errBody)
	})
	// `header` ops AFTER cache_key are response-side (reference §DELIVER): set
	// X-Resp-Op, strip the origin's Server header.
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
	cache_key path
	header X-Resp-Op applied
	header -Server
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/x", nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != errBody {
		t.Fatalf("got %d %q, want 503 + origin body", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Resp-Op"); got != "applied" {
		t.Fatalf("X-Resp-Op = %q, want applied (response header op must run on the forwarded error)", got)
	}
	if got := rec.Header().Get("Server"); got != "" {
		t.Fatalf("Server = %q, want removed (header -Server must run on the forwarded error)", got)
	}
}

// TestCORSAppliedToForwardedOriginError: a CORS-configured site emits the
// Access-Control-Allow-Origin header on the forwarded error response too.
func TestCORSAppliedToForwardedOriginError(t *testing.T) {
	const errBody = "denied"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, errBody)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
	cors *
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	hdr := http.Header{"Origin": {"https://app.example"}}
	rec := do(h, "GET", "http://test.local/x", hdr)
	if rec.Code != http.StatusForbidden || rec.Body.String() != errBody {
		t.Fatalf("got %d %q, want 403 + origin body", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want * (CORS must run on the forwarded error)", got)
	}
}

// TestForwardedOriginErrorVerbatimWithoutDeliverDirectives is the regression guard:
// on a site with NO deliver-phase directives, the forwarded error is byte-identical
// to the pre-fix behavior — origin status + headers (incl. Set-Cookie, since nothing
// strips it) + body verbatim — and a large error body is still STREAMED, not buffered.
func TestForwardedOriginErrorVerbatimWithoutDeliverDirectives(t *testing.T) {
	const n = 3 << 20 // 3 MiB
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Add("Set-Cookie", "keep=me; Path=/")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.Copy(w, strings.NewReader(strings.Repeat("E", n)))
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/big-error", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
	if rec.Body.Len() != n {
		t.Fatalf("body len = %d, want %d (large error body streamed intact, not buffered/truncated)", rec.Body.Len(), n)
	}
	// No strip_cookies configured: the upstream Set-Cookie is delivered verbatim
	// (the fix changes ONLY the configured-deliver-ops behavior, not the default).
	if got := rec.Header().Get("Set-Cookie"); got != "keep=me; Path=/" {
		t.Fatalf("Set-Cookie = %q, want it delivered verbatim when no strip_cookies is configured", got)
	}
}
