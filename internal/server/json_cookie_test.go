package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// reflectRawCookieOrigin echoes the raw Cookie header it received into the body.
func reflectRawCookieOrigin(t *testing.T) *countingOrigin {
	return newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "body["+r.Header.Get("Cookie")+"]")
	})
}

// TestJSONCookieDoesNotEvadeCredentialGate is the blocking regression: a JSON-valued cookie
// (`sess={"uid":"alice"}`) must be SEEN by the credential gate. net/http's strict .Cookies()
// parser rejects a JSON value (0 cookies), which made hasCookie=false → no bypass → Alice's
// private body cached under the shared key and served to an anonymous user. The pipeline must
// parse cookies LENIENTLY (like the origin / the cookie_json matcher / the edge).
func TestJSONCookieDoesNotEvadeCredentialGate(t *testing.T) {
	origin := reflectRawCookieOrigin(t)
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)
	do := func(hdr http.Header) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		for k, vs := range hdr {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	a := do(http.Header{"Cookie": {`sess={"uid":"alice"}`}})
	if a.Body.String() != `body[sess={"uid":"alice"}]` {
		t.Fatalf("origin should have received the JSON cookie, got %q", a.Body.String())
	}
	b := do(nil) // anonymous
	if b.Body.String() == `body[sess={"uid":"alice"}]` {
		t.Fatalf("CROSS-USER LEAK: anonymous request served the JSON-cookie request's private body")
	}
	if n := origin.hits.Load(); n != 2 {
		t.Errorf("origin hits = %d, want 2 (JSON-cookie request bypassed; anon is a fresh miss)", n)
	}
}

// TestJSONCookieKeyedDoesNotCollapse is the second blocking case: `cache_key … cookie:NAME`
// (the documented mitigation for caching cookie traffic) must NOT collapse distinct JSON cookie
// values onto one entry. req.cookie(NAME) used net/http's strict parser → a JSON value rendered
// "" → every JSON session keyed identically → one user's body served to another.
func TestJSONCookieKeyedDoesNotCollapse(t *testing.T) {
	origin := reflectRawCookieOrigin(t)
	cfg := `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	cookie_allow sess
	cache_key host path cookie:sess
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`
	h, _ := buildHandler(t, nil, cfg, origin.srv.URL)
	do := func(sess string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://test.local/p", nil)
		req.Host = "test.local"
		req.Header.Set("Cookie", "sess="+sess)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// Alice's JSON session: MISS, cached under a key that captures her session value.
	if got := do(`{"uid":"alice"}`).Header().Get("X-Cache"); got != "MISS" {
		t.Fatalf("alice X-Cache=%q, want MISS", got)
	}
	// Bob's DIFFERENT JSON session must key distinctly → MISS, NOT a HIT of alice's entry.
	bob := do(`{"uid":"bob"}`)
	if got := bob.Header().Get("X-Cache"); got == "HIT" {
		t.Fatalf("CROSS-USER LEAK: bob's distinct JSON session collapsed onto alice's cache key (HIT)")
	}
	if bob.Body.String() == `body[sess={"uid":"alice"}]` {
		t.Fatalf("CROSS-USER LEAK: bob served alice's body %q", bob.Body.String())
	}
	// Same alice session HITs (the key does capture the value).
	if got := do(`{"uid":"alice"}`).Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("repeat alice X-Cache=%q, want HIT (same session value shares the entry)", got)
	}
}
