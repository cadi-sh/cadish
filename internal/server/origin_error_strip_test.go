package server

import (
	"io"
	"net/http"
	"testing"
)

// TestForwardedOriginErrorStripsConsumedControlHeaders (FIX 3) pins deliver-phase parity
// for the from_header-consumed control headers on the streamed origin-error path. The 2xx
// path strips X-Cache-Ttl/X-Cache-Grace/X-Cache-Max-Stale (the internal origin↔cache
// contract a `cache_ttl … from_header …` rule consumed) before delivery; streamOriginError
// must do the same so an origin that emits them on an ERROR response cannot leak them to
// the client.
//
// To exercise the STREAMING error terminal (not the bodyless negative-cache path) while
// still populating StripHeaders, the origin marks the 503 `Cache-Control: no-store`: the
// `status 503 from_header` rule consumes the control headers (StripHeaders set) but the
// shareability downgrade makes the response non-cacheable, so the bodied error is streamed
// verbatim — and the consumed control headers must be stripped on the way out.
func TestForwardedOriginErrorStripsConsumedControlHeaders(t *testing.T) {
	const errBody = "upstream boom"
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache-Ttl", "60")
		w.Header().Set("X-Cache-Grace", "5m")
		w.Header().Set("X-Cache-Max-Stale", "30m")
		w.Header().Set("X-Keep-Me", "yes")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, errBody)
	})
	body := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_ttl status 503 from_header X-Cache-Ttl grace_from_header X-Cache-Grace max_stale_from_header X-Cache-Max-Stale
}
`
	h, _ := buildHandler(t, nil, body, origin.srv.URL)
	rec := do(h, "GET", "http://test.local/p", nil)

	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != errBody {
		t.Fatalf("got %d %q, want 503 + origin error body verbatim", rec.Code, rec.Body.String())
	}
	// THE FIX ASSERTION: the consumed control headers must NOT leak on the error path.
	for _, n := range []string{"X-Cache-Ttl", "X-Cache-Grace", "X-Cache-Max-Stale"} {
		if got := rec.Header().Get(n); got != "" {
			t.Errorf("control header %q leaked to client on the error path: %q (must be stripped, mirroring the 2xx path)", n, got)
		}
	}
	// A non-control origin header is untouched (strip is scoped to consumed headers).
	if got := rec.Header().Get("X-Keep-Me"); got != "yes" {
		t.Errorf("X-Keep-Me=%q, want yes (non-control header must survive)", got)
	}
}
