package server

import (
	"io"
	"net/http"
	"testing"
)

// TestForwardedOriginErrorStripsControlHeadersOnPass pins the from_header-strip parity
// on a PASS route (cache key == ""). The 2xx pass path runs EvalResponse + StripHeaders
// unconditionally (serveOrigin), so an X-Cache-Ttl on a 200 is stripped even on a pass.
// The streamed-error terminal must do the same: a bodied origin error on a pass must
// also strip the from_header-consumed control headers. Before the fix, handleOriginError
// only computed the strip list when key != "", so the pass path leaked them on errors.
func TestForwardedOriginErrorStripsControlHeadersOnPass(t *testing.T) {
	const errBody = "passed boom"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Set("X-Cache-Grace", "5m")
		w.Header().Set("X-Keep-Me", "yes")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, errBody)
	})
	// `pass method GET` forces key == "" on the origin path; the cache_ttl from_header
	// rule still resolves StripHeaders in EvalResponse.
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	pass method GET
	cache_ttl status 503 from_header X-Cache-Ttl grace_from_header X-Cache-Grace
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/me", nil)

	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != errBody {
		t.Fatalf("got %d %q, want 503 + origin error body verbatim", rec.Code, rec.Body.String())
	}
	for _, n := range []string{"X-Cache-Ttl", "X-Cache-Grace"} {
		if got := rec.Header().Get(n); got != "" {
			t.Errorf("control header %q leaked on the PASS error path: %q (must be stripped, mirroring the 2xx pass)", n, got)
		}
	}
	if got := rec.Header().Get("X-Keep-Me"); got != "yes" {
		t.Errorf("X-Keep-Me=%q, want yes (non-control header must survive)", got)
	}
}
