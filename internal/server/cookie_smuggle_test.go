package server

import (
	"io"
	"net/http"
	"testing"
)

// TestCookieHeaderSmugglingDoesNotLeak is a security regression for a cross-user leak in
// the DEFAULT config (no cookie_allow, default key). An attacker can split the Cookie into
// two header lines with the FIRST empty:
//
//	Cookie:\r\nCookie: session=ALICE-SECRET
//
// Go's net/http keeps these as req.Header["Cookie"] = ["", "session=ALICE-SECRET"], where
// Header.Get("Cookie") returns the FIRST value ("") — but req.Cookies() (used by the cache
// key and forwarded to the origin) sees the real session. If BypassForCredentials decides
// "has a cookie?" via Get, it concludes there is no credential, skips the bypass, and caches
// Alice's personalized response under the shared (cookie-agnostic) key — then serves it to
// everyone, including anonymous users. This test sends exactly that request and asserts the
// private response is NOT cached and NOT served to a later anonymous request.
func TestCookieHeaderSmugglingDoesNotLeak(t *testing.T) {
	// The origin reflects the session cookie it sees into the body (per-user content).
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		sess := "anon"
		if c, err := r.Cookie("session"); err == nil {
			sess = c.Value
		}
		_, _ = io.WriteString(w, "private-for:"+sess)
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	// Attacker request: a leading EMPTY Cookie line, then the real session.
	smuggled := http.Header{"Cookie": {"", "session=ALICE-SECRET"}}
	a := do(h, "GET", "http://test.local/p", smuggled)
	if a.Body.String() != "private-for:ALICE-SECRET" {
		t.Fatalf("origin saw %q, want it to receive session=ALICE-SECRET", a.Body.String())
	}

	// A later ANONYMOUS request must NOT be served Alice's private response — the load-
	// bearing assertion. A credentialed request must bypass the shared cache, so the private
	// body is never stored and B is a fresh fetch (the X-Cache header reads MISS for a bypass,
	// since the client-facing status mirrors a miss; the bypass is observable as "not stored").
	b := do(h, "GET", "http://test.local/p", nil)
	if b.Body.String() == "private-for:ALICE-SECRET" {
		t.Fatalf("CROSS-USER LEAK: anonymous request served Alice's private body %q", b.Body.String())
	}
	if b.Body.String() != "private-for:anon" {
		t.Errorf("anonymous B body = %q, want private-for:anon (fresh fetch, nothing cached)", b.Body.String())
	}
	// The smuggled request must NOT have stored its private body: the origin is hit twice
	// (A bypassed → fetched; B miss → fetched), proving A was never cached under the shared key.
	if n := origin.hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 (smuggled A bypassed + anon B miss; A never cached)", n)
	}
}
