package pipeline

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// classify3State is the worked 3-state example from the design doc adapted to use
// existing matchers (the design's `geo region US-UT` is a separate task), so the
// test is self-contained: a derived {age} token (ok / gate / open) keyed downstream.
const classify3State = `example.com {
    @regulated  header X-Region gated
    @verified   cookie verified_prod
    classify {age} {
        when @verified              -> ok
        when @regulated             -> gate
        default                     -> open
    }
    cache_key method host path {age}
}`

func ageOf(t *testing.T, p *Pipeline, h http.Header) string {
	t.Helper()
	key := p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/p", Header: h}).CacheKey
	// the {age} token is the last component of `method host path {age}`.
	parts := splitKey(key)
	return parts[len(parts)-1]
}

func splitKey(key string) []string {
	var out []string
	cur := ""
	for _, r := range key {
		if r == '\x1f' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

// TestClassifyFirstMatchAndDefault: the table is first-match-wins with a default
// fallthrough, and the derived value lands in the cache key.
func TestClassifyFirstMatchAndDefault(t *testing.T) {
	p := compileSrc(t, classify3State)

	verified := http.Header{}
	verified.Set("Cookie", "verified_prod=1")
	if got := ageOf(t, p, verified); got != "ok" {
		t.Errorf("verified cookie => ok, got %q", got)
	}

	regulated := http.Header{}
	regulated.Set("X-Region", "gated")
	if got := ageOf(t, p, regulated); got != "gate" {
		t.Errorf("regulated => gate, got %q", got)
	}

	// First-match: a verified user who is ALSO regulated still classifies ok
	// (the @verified row precedes @regulated).
	both := http.Header{}
	both.Set("Cookie", "verified_prod=1")
	both.Set("X-Region", "gated")
	if got := ageOf(t, p, both); got != "ok" {
		t.Errorf("verified+regulated => ok (first match wins), got %q", got)
	}

	if got := ageOf(t, p, http.Header{}); got != "open" {
		t.Errorf("neither => open (default), got %q", got)
	}
}

// TestClassifyKeyVaries: two requests that classify differently get different
// cache keys; two that classify the same share a key.
func TestClassifyKeyVaries(t *testing.T) {
	p := compileSrc(t, classify3State)
	keyFor := func(h http.Header) string {
		return p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/p", Header: h}).CacheKey
	}
	v := http.Header{}
	v.Set("Cookie", "verified_prod=1")
	g := http.Header{}
	g.Set("X-Region", "gated")
	if keyFor(v) == keyFor(g) {
		t.Error("ok vs gate must produce different cache keys")
	}
	v2 := http.Header{}
	v2.Set("Cookie", "verified_prod=1")
	if keyFor(v) != keyFor(v2) {
		t.Error("two ok requests must share a cache key")
	}
}

// TestClassifyAndSemantics: a `when @a @b` row is a CONJUNCTION — it fires only
// when ALL its matchers match, never when only one does.
func TestClassifyAndSemantics(t *testing.T) {
	src := `example.com {
    @paid   header X-Plan paid
    @beta   cookie beta
    classify {tier} {
        when @paid @beta   -> paidbeta
        when @paid         -> paid
        default            -> free
    }
    cache_key {tier}
}`
	p := compileSrc(t, src)
	tier := func(plan, cookie string) string {
		h := http.Header{}
		if plan != "" {
			h.Set("X-Plan", plan)
		}
		if cookie != "" {
			h.Set("Cookie", cookie)
		}
		return p.EvalRequest(&Request{Host: "h", Path: "/x", Header: h}).CacheKey
	}
	if got := tier("paid", "beta=1"); got != "paidbeta" {
		t.Errorf("paid AND beta => paidbeta, got %q", got)
	}
	if got := tier("paid", ""); got != "paid" {
		t.Errorf("paid only (beta absent) => paid, not paidbeta, got %q", got)
	}
	if got := tier("", "beta=1"); got != "free" {
		t.Errorf("beta only (paid absent) => free (AND row must not fire), got %q", got)
	}
}

// TestClassifyTokenInHeaderValue: the derived token is usable as a header value
// via the {tier} placeholder (dynamic header value).
func TestClassifyTokenInHeaderValue(t *testing.T) {
	src := `example.com {
    @paid   header X-Plan paid
    classify {tier} {
        when @paid   -> paid
        default      -> free
    }
    cache_key {tier}
    header X-Tier {classify.tier}
}`
	p := compileSrc(t, src)
	h := http.Header{}
	h.Set("X-Plan", "paid")
	dec := p.EvalDeliver(&Request{Host: "h", Path: "/x", Header: h}, http.Header{}, CacheStatusHit)
	var got string
	for _, op := range dec.RespHeaderOps {
		if op.Name == "X-Tier" {
			got = op.Value
		}
	}
	if got != "paid" {
		t.Errorf("header X-Tier should resolve {classify.tier} => paid, got %q", got)
	}
}

// TestClassifyTokenAsScope: `@gated classify {age}==gate` is a named matcher
// usable anywhere a matcher is (here, scoping `pass`).
func TestClassifyTokenAsScope(t *testing.T) {
	src := `example.com {
    @regulated  header X-Region gated
    @verified   cookie verified_prod
    classify {age} {
        when @verified   -> ok
        when @regulated  -> gate
        default          -> open
    }
    @gated  classify {age}==gate
    pass @gated
    cache_key method host path {age}
}`
	p := compileSrc(t, src)
	pass := func(h http.Header) bool {
		return p.EvalRequest(&Request{Method: "GET", Host: "h", Path: "/x", Header: h}).Pass
	}
	gated := http.Header{}
	gated.Set("X-Region", "gated")
	if !pass(gated) {
		t.Error("a gated request should pass (classify {age}==gate scope)")
	}
	verified := http.Header{}
	verified.Set("Cookie", "verified_prod=1")
	if pass(verified) {
		t.Error("a verified (ok) request should NOT pass the {age}==gate scope")
	}
	if pass(http.Header{}) {
		t.Error("an open request should NOT pass the {age}==gate scope")
	}
}

// TestClassifyTokenAsScopeNegate: `{age}!=open` matches the complement.
func TestClassifyTokenAsScopeNegate(t *testing.T) {
	src := `example.com {
    @verified   cookie verified_prod
    classify {age} {
        when @verified   -> ok
        default          -> open
    }
    @decided  classify {age}!=open
    pass @decided
    cache_key {age}
}`
	p := compileSrc(t, src)
	verified := http.Header{}
	verified.Set("Cookie", "verified_prod=1")
	if !p.EvalRequest(&Request{Host: "h", Path: "/x", Header: verified}).Pass {
		t.Error("ok (!= open) should pass")
	}
	if p.EvalRequest(&Request{Host: "h", Path: "/x"}).Pass {
		t.Error("open should not pass {age}!=open")
	}
}

// TestClassifyPubliFlag: the home-page `publi` boolean — an inline `query_present`
// matcher inside a classify `when` row collapses the presence of ANY ad param
// (adult_content/t/a/p/ff-*/pub-*) to a 0|1 enum used in the cache key.
func TestClassifyPubliFlag(t *testing.T) {
	src := `example.com {
    classify {publi} {
        when query_present adult_content t a p ff-* pub-*  -> 1
        default                                            -> 0
    }
    cache_key path query_allow genre age camLang {publi}
}`
	p := compileSrc(t, src)
	keyFor := func(q url.Values) string {
		return p.EvalRequest(&Request{Method: "GET", Host: "example.com", Path: "/", Query: q}).CacheKey
	}
	// An ad param present -> publi=1.
	withAd := keyFor(url.Values{"genre": {"horror"}, "pub-foo": {"1"}, "utm_source": {"g"}})
	if !strings.HasSuffix(withAd, keyTokenSep+"1") {
		t.Errorf("publi key with ad param = %q, want trailing %q1", withAd, keyTokenSep)
	}
	// No ad param -> publi=0; utm_* is stripped by query_allow.
	noAd := keyFor(url.Values{"genre": {"horror"}, "utm_source": {"g"}})
	if !strings.HasSuffix(noAd, keyTokenSep+"0") {
		t.Errorf("publi key without ad param = %q, want trailing %q0", noAd, keyTokenSep)
	}
	// The two differ only in the publi flag; the genre allowlist part matches.
	if withAd == noAd {
		t.Error("publi=1 and publi=0 must produce different cache keys")
	}
	if !strings.Contains(withAd, "genre=horror") || strings.Contains(withAd, "utm_source") {
		t.Errorf("query_allow should keep genre and drop utm_*, got %q", withAd)
	}
}

func TestClassifyCompileErrors(t *testing.T) {
	cases := map[string]string{
		"no token":          "example.com {\n classify {\n when @a -> x\n default -> y\n }\n}",
		"bad token":         "example.com {\n @a header H v\n classify age {\n when @a -> x\n default -> y\n }\n}",
		"no block":          "example.com {\n classify {age}\n}",
		"no rows":           "example.com {\n classify {age} {\n default -> y\n }\n}",
		"no default":        "example.com {\n @a header H v\n classify {age} {\n when @a -> x\n }\n}",
		"reserved name":     "example.com {\n @a header H v\n classify {device} {\n when @a -> x\n default -> y\n }\n}",
		"undefined matcher": "example.com {\n classify {age} {\n when @nope -> x\n default -> y\n }\n}",
		"when no arrow":     "example.com {\n @a header H v\n classify {age} {\n when @a x\n default -> y\n }\n}",
		"when no value":     "example.com {\n @a header H v\n classify {age} {\n when @a ->\n default -> y\n }\n}",
		"dup default":       "example.com {\n @a header H v\n classify {age} {\n when @a -> x\n default -> y\n default -> z\n }\n}",
		"unknown row":       "example.com {\n @a header H v\n classify {age} {\n when @a -> x\n frob -> z\n default -> y\n }\n}",
		"unknown key token": "example.com {\n cache_key {age}\n}",
		"dup classify":      "example.com {\n @a header H v\n classify {age} {\n when @a -> x\n default -> y\n }\n classify {age} {\n when @a -> x\n default -> y\n }\n}",
		"scope unknown tok": "example.com {\n @g classify {age}==gate\n pass @g\n}",
		"scope no op":       "example.com {\n @a header H v\n classify {age} {\n when @a -> x\n default -> y\n }\n @g classify {age}\n pass @g\n}",
		"scope empty value": "example.com {\n @a header H v\n classify {age} {\n when @a -> x\n default -> y\n }\n @g classify {age}==\n pass @g\n}",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if compileErr(t, src) == nil {
				t.Errorf("expected a compile error for %s", name)
			}
		})
	}
}

// TestClassifyResponsePhaseMatcherRejected: a classify row may not use a
// response-phase matcher (the token resolves in the request phase).
func TestClassifyResponsePhaseMatcherRejected(t *testing.T) {
	src := "example.com {\n @ct content_type text/html\n classify {age} {\n when @ct -> x\n default -> y\n }\n cache_key {age}\n}"
	if compileErr(t, src) == nil {
		t.Error("a content_type matcher in a classify row should be rejected")
	}
}
