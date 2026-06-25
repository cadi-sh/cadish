package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// authReflectOrigin echoes the COMBINED Authorization field-lines (RFC 9110 §5.3) into the
// body, modeling a spec-compliant origin that sees every Authorization line cadish forwards.
func authReflectOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "auth-body:["+strings.Join(r.Header.Values("Authorization"), ",")+"]")
	})
}

// TestAuthorizationEmptyFirstLineDoesNotLeak is the Authorization twin of the Cookie smuggle:
// a leading EMPTY Authorization line then the real bearer token makes Header.Get return "",
// but the origin still receives the token. The credential bypass MUST still fire (hasAuth is
// computed over all field-lines), so the private body is never cached/served cross-user.
func TestAuthorizationEmptyFirstLineDoesNotLeak(t *testing.T) {
	origin := authReflectOrigin(t)
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)

	a := do(h, "GET", "http://test.local/p", http.Header{"Authorization": {"", "Bearer ALICE-SECRET"}})
	if !strings.Contains(a.Body.String(), "Bearer ALICE-SECRET") {
		t.Fatalf("origin should have received the smuggled token, got %q", a.Body.String())
	}
	// Anonymous follow-up must NOT be served Alice's authenticated body.
	b := do(h, "GET", "http://test.local/p", nil)
	if strings.Contains(b.Body.String(), "ALICE-SECRET") {
		t.Fatalf("CROSS-USER LEAK: anonymous request served Alice's auth body %q", b.Body.String())
	}
	if n := origin.hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 (A bypassed + B fresh; nothing cached)", n)
	}
}

// TestDuplicateAuthorizationDoesNotCollide is the Authorization twin of the duplicate
// cookie:NAME fix: with `cache_key … header:Authorization`, the key renders only the FIRST
// Authorization line while the origin sees both, so a request sending Authorization twice
// must bypass — never let a holder of only the first token be served a body minted for both.
func TestDuplicateAuthorizationDoesNotCollide(t *testing.T) {
	origin := authReflectOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path header:Authorization
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)

	// A sends TWO tokens; the elevated one is only visible to the origin (key keeps the first).
	a := do(h, "GET", "http://test.local/p", http.Header{"Authorization": {"Bearer FIRST", "Bearer ELEVATED"}})
	if !strings.Contains(a.Body.String(), "ELEVATED") {
		t.Fatalf("origin should have seen both tokens, got %q", a.Body.String())
	}
	// B holds only the FIRST token. It must NOT receive A's FIRST+ELEVATED body.
	b := do(h, "GET", "http://test.local/p", http.Header{"Authorization": {"Bearer FIRST"}})
	if strings.Contains(b.Body.String(), "ELEVATED") {
		t.Fatalf("PRIV-ESC LEAK: holder of FIRST served a body minted for FIRST+ELEVATED: %q", b.Body.String())
	}
	if n := origin.hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 (duplicate-Authorization A bypassed, B fresh)", n)
	}
}

// TestSingleAuthorizationStillKeysPerToken pins that the legit case is unaffected: a single
// Authorization line with `cache_key header:Authorization` caches per-token (same token HITs).
func TestSingleAuthorizationStillKeysPerToken(t *testing.T) {
	origin := authReflectOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cache_key host path header:Authorization
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	if got := do(h, "GET", "http://test.local/p", http.Header{"Authorization": {"Bearer T1"}}).Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("first T1 = %q, want MISS", got)
	}
	if got := do(h, "GET", "http://test.local/p", http.Header{"Authorization": {"Bearer T1"}}).Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second T1 = %q, want HIT (per-token keyed cache)", got)
	}
}
