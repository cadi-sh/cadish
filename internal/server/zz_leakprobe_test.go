package server

import (
	"io"
	"net/http"
	"testing"
)

// ZZ probe: cache_key keys by a NON-session cookie (cart_count). A logged-in user
// carries BOTH session (the real credential) and cart_count. Does the bypass treat
// the unrelated cookie token as "covering" the cookie credential and cache the
// session-private response under a key that only varies on cart_count?
func TestZZWrongCookieNameCoversCredential(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "PRIVATE-FOR["+r.Header.Get("Cookie")+"]")
	})
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path cookie:cart_count
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// User A: secret session, cart_count=3.
	a := do(h, "GET", "http://test.local/account", http.Header{"Cookie": {"session=AAA-secret; cart_count=3"}})
	t.Logf("A X-Cache=%s body=%q", a.Header().Get("X-Cache"), a.Body.String())

	// User B: DIFFERENT secret session, SAME cart_count=3.
	b := do(h, "GET", "http://test.local/account", http.Header{"Cookie": {"session=BBB-other; cart_count=3"}})
	t.Logf("B X-Cache=%s body=%q origin_hits=%d", b.Header().Get("X-Cache"), b.Body.String(), origin.hits.Load())

	if b.Body.String() == "PRIVATE-FOR[session=AAA-secret; cart_count=3]" {
		t.Fatalf("LEAK: user B received user A's private body (keyed only on cart_count)")
	}
}
