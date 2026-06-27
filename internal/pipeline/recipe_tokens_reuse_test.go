package pipeline

import (
	"net/http"
	"testing"
)

// TestRecipeTokensForReqReusesCapturedSelection is the R29 pin: the credential /
// derives_from gates must reuse the recipe EvalRequest already captured (selKeySet)
// rather than recomputing routing + re-selecting the recipe. We prove "no recompute" by
// stashing a captured recipe that DIFFERS from what a fresh selection would pick for this
// request and asserting the gate returns the captured one; with selKeySet cleared it
// falls back to the fresh selection (the direct-caller path), unchanged.
func TestRecipeTokensForReqReusesCapturedSelection(t *testing.T) {
	src := `example.com {
    @vip cookie tier vip
    cache_key @vip host
    cache_key default host cookie:uid
    cache_ttl default ttl 60s
}`
	p := compileSrc(t, src)
	req := &Request{Method: "GET", Host: "example.com", Path: "/",
		Header: http.Header{"Cookie": {"uid=bob"}}}

	// No tier=vip cookie → a FRESH selection lands on the default recipe (host cookie:uid,
	// 2 tokens). selKeySet is false here, so this is the direct-caller fallback path.
	fresh := p.recipeTokensForReq(req)
	if len(fresh) != 2 {
		t.Fatalf("fresh selection = %d tokens, want 2 (default recipe host cookie:uid)", len(fresh))
	}

	// Capture the OTHER recipe (the @vip one: host only, 1 token) as if EvalRequest had
	// selected it. The gate must return THIS, not a re-selection.
	sentinel := p.keyRules[0].toks // @vip recipe (host)
	if len(sentinel) != 1 {
		t.Fatalf("sentinel recipe = %d tokens, want 1 (@vip host)", len(sentinel))
	}
	req.selKey = sentinel
	req.selKeySet = true
	got := p.recipeTokensForReq(req)
	if len(got) != 1 || &got[0] != &sentinel[0] {
		t.Fatalf("selKeySet path = %d tokens, want the captured 1-token recipe (no recompute)", len(got))
	}

	// Clearing the capture restores the direct-caller fresh selection (2 tokens).
	req.selKeySet = false
	if again := p.recipeTokensForReq(req); len(again) != 2 {
		t.Fatalf("post-clear selection = %d tokens, want 2 (re-select)", len(again))
	}
}
