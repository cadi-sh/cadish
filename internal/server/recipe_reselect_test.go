package server

import (
	"io"
	"net/http"
	"testing"
)

// Finding 1 (round-3, SAFETY) end-to-end: a `cache_key` recipe whose SELECTOR reads a
// cookie that is ALSO a `derives_from` input. The key is built by the recipe selected
// PRE-strip (@premium → `host url {tier}`, which does NOT key uid). After the COOKIE-NORM
// strip removes `premium`, a naive re-selection of the recipe lands on `default`
// (`host url cookie:uid`, which DOES key uid) and would wrongly conclude the per-user
// `uid` cookie is covered — caching a private body under the uid-agnostic recipe-A key
// and serving it to the next premium user (cross-user leak). The capture-the-recipe fix
// makes both users bypass, so nothing is shared.
const cfgRecipeReselect = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@premium cookie premium 1
	classify {tier} {
		derives_from cookie premium
		when @premium -> p
		default       -> f
	}
	cookie_allow premium uid
	cache_key @premium host url {tier}
	cache_key default host url cookie:uid
	cache_ttl default ttl 60s
	header +cache_status X-Cache
}
`

func TestRecipeReselect_NoCrossUserLeak(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		uid := "anon"
		if c, err := r.Cookie("uid"); err == nil {
			uid = c.Value
		}
		_, _ = io.WriteString(w, "private:"+uid)
	})
	h, _ := buildHandler(t, nil, cfgRecipeReselect, origin.srv.URL)

	// Alice (premium=1; uid=alice): recipe A built the key (no uid) → must BYPASS, origin
	// sees uid=alice. Nothing cacheable is stored under a uid-agnostic key.
	a := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"premium=1; uid=alice"}})
	if got := a.Body.String(); got != "private:alice" {
		t.Fatalf("alice body = %q, want private:alice (uid forwarded, bypass)", got)
	}

	// Bob (premium=1; uid=bob): same {tier}=p bucket but a DIFFERENT identity cookie. If
	// the post-strip re-selection had been used he would HIT alice's cached body.
	b := do(h, "GET", "http://test.local/p", http.Header{"Cookie": {"premium=1; uid=bob"}})
	if got := b.Body.String(); got == "private:alice" {
		t.Fatal("CROSS-USER LEAK: bob (premium=1; uid=bob) served alice's private body — coverage was judged against the post-strip recipe, not the recipe that built the key")
	}
	if got := b.Body.String(); got != "private:bob" {
		t.Fatalf("bob body = %q, want private:bob (his own origin fetch)", got)
	}

	if origin.hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2 (both users bypassed; nothing cached cross-user)", origin.hits.Load())
	}
}
