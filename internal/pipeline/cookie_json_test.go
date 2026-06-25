package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// reqWithHeaders builds a GET request with the given headers (name -> value).
func reqWithHeaders(hdrs map[string]string) *Request {
	h := http.Header{}
	for k, v := range hdrs {
		h.Set(k, v)
	}
	return &Request{Method: "GET", Path: "/", Host: "example.com", Header: h}
}

// 1. compileMatcher parses NAME PATH [VALUE…]; rejects empty NAME/PATH.
func TestCookieJSONCompileArity(t *testing.T) {
	if compileErr(t, "example.com {\n @x cookie_json\n pass @x\n}") == nil {
		t.Error("cookie_json with no args must be a compile error")
	}
	if compileErr(t, "example.com {\n @x cookie_json nsfwCookie\n pass @x\n}") == nil {
		t.Error("cookie_json with a NAME but no PATH must be a compile error")
	}
	// A NAME + PATH (no value) is valid (presence form).
	compileSrc(t, "example.com {\n @x cookie_json nsfwCookie needVerify\n pass @x\n}")
	// header_json follows the same shape.
	if compileErr(t, "example.com {\n @x header_json X-Session\n pass @x\n}") == nil {
		t.Error("header_json with a NAME but no PATH must be a compile error")
	}
	compileSrc(t, "example.com {\n @x header_json X-Session plan.tier pro enterprise\n pass @x\n}")
}

// TestCookieJSONEmptyPathSegment: a PATH with an empty segment is rejected.
func TestCookieJSONEmptyPathSegment(t *testing.T) {
	if compileErr(t, "example.com {\n @x cookie_json c a..b\n pass @x\n}") == nil {
		t.Error("a PATH with an empty segment must be a compile error")
	}
}

// 2. Presence (no value): present non-null field -> true; missing field / missing
// cookie / null -> false.
func TestCookieJSONPresence(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json nsfwCookie needVerify\n pass @v\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }

	if !pass(`nsfwCookie={"needVerify":true}`) {
		t.Error("present non-null field should match presence")
	}
	if !pass(`nsfwCookie={"needVerify":false}`) {
		t.Error("present field with a false value still EXISTS -> presence matches")
	}
	if pass(`nsfwCookie={"other":1}`) {
		t.Error("missing field should not match presence")
	}
	if pass(`nsfwCookie={"needVerify":null}`) {
		t.Error("a null field is no usable value -> presence false")
	}
	if pass("") {
		t.Error("missing cookie should not match")
	}
	if pass(`nsfwCookie=`) {
		t.Error("present-but-empty cookie value is not valid JSON -> false")
	}
}

// TestCookieJSONMultiLineSmuggling: cookie_json reads ALL Cookie header lines, so a cookie
// split onto a second line with an empty first line (`Cookie:\r\nCookie: c={…}`) still
// matches — it cannot be hidden from a deny/respond gate while the origin still sees it.
func TestCookieJSONMultiLineSmuggling(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json nsfwCookie needVerify true\n pass @v\n}")
	// The matching cookie is on a SECOND Cookie line; the first line is empty.
	smuggled := &Request{Method: "GET", Path: "/", Header: http.Header{
		"Cookie": {"", `nsfwCookie={"needVerify":true}`},
	}}
	if !p.EvalRequest(smuggled).Pass {
		t.Error("cookie_json must see a cookie on a second Cookie header line (empty-first-line smuggling)")
	}
}

// TestHeaderJSONMultiLineSmuggling: header_json OR-matches across ALL field-lines, so a
// malicious JSON value on a second header line (behind an empty/benign first line) still
// matches a deny/respond gate — it cannot be hidden the way headerGet's first-line-only read
// allowed. (The header_json twin of TestCookieJSONMultiLineSmuggling.)
func TestHeaderJSONMultiLineSmuggling(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v header_json X-Ctx role admin\n pass @v\n}")
	smuggled := &Request{Method: "GET", Path: "/", Header: http.Header{
		"X-Ctx": {"", `{"role":"admin"}`},
	}}
	if !p.EvalRequest(smuggled).Pass {
		t.Error("header_json must see a value on a second header line (empty-first-line smuggling)")
	}
	// A genuinely absent header still fails closed (no match).
	if p.EvalRequest(&Request{Method: "GET", Path: "/", Header: http.Header{}}).Pass {
		t.Error("absent header must not match header_json")
	}
}

// TestCookiePrefixMatcherSeesJSONCookie: the `cookie NAME*` glob matcher must see a JSON-valued
// cookie (read leniently), so a deny/allow gate keyed on a cookie-name prefix cannot be evaded
// by giving the cookie a JSON value the strict net/http parser would drop.
func TestCookiePrefixMatcherSeesJSONCookie(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie admin*\n pass @v\n}")
	req := &Request{Method: "GET", Path: "/", Header: http.Header{"Cookie": {`admin={"role":"super"}`}}}
	if !p.EvalRequest(req).Pass {
		t.Error("cookie admin* must match a JSON-valued admin cookie (lenient), not be dropped by the strict parser")
	}
	// A non-matching prefix still does not match.
	req2 := &Request{Method: "GET", Path: "/", Header: http.Header{"Cookie": {`user={"id":1}`}}}
	if p.EvalRequest(req2).Pass {
		t.Error("cookie admin* must NOT match a user cookie")
	}
}

// 3. Single value equals across string/number/bool coercion.
func TestCookieJSONValueCoercion(t *testing.T) {
	boolP := compileSrc(t, "example.com {\n @v cookie_json c needVerify true\n pass @v\n}")
	if !boolP.EvalRequest(reqWithCookie(`c={"needVerify":true}`)).Pass {
		t.Error("JSON true should coerce to \"true\" and match")
	}
	if boolP.EvalRequest(reqWithCookie(`c={"needVerify":false}`)).Pass {
		t.Error("false must not match value \"true\"")
	}

	numP := compileSrc(t, "example.com {\n @v cookie_json c age 42\n pass @v\n}")
	if !numP.EvalRequest(reqWithCookie(`c={"age":42}`)).Pass {
		t.Error("JSON number 42 should coerce to \"42\" and match")
	}
	if numP.EvalRequest(reqWithCookie(`c={"age":43}`)).Pass {
		t.Error("43 must not match value 42")
	}

	strP := compileSrc(t, "example.com {\n @v cookie_json c tier pro\n pass @v\n}")
	if !strP.EvalRequest(reqWithCookie(`c={"tier":"pro"}`)).Pass {
		t.Error("string pro should match")
	}
	if strP.EvalRequest(reqWithCookie(`c={"tier":"free"}`)).Pass {
		t.Error("free must not match value pro")
	}
}

// 4. Multi-value OR.
func TestCookieJSONMultiValueOR(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json c plan pro enterprise\n pass @v\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }
	if !pass(`c={"plan":"pro"}`) {
		t.Error("pro (first OR value) should match")
	}
	if !pass(`c={"plan":"enterprise"}`) {
		t.Error("enterprise (second OR value) should match")
	}
	if pass(`c={"plan":"free"}`) {
		t.Error("free should not match")
	}
}

// 5. Fail-safe: malformed JSON, object/array leaf with a value test, deeply-nested,
// over-size all -> false.
func TestCookieJSONFailSafe(t *testing.T) {
	// Malformed JSON -> false (presence and value).
	pres := compileSrc(t, "example.com {\n @v cookie_json c needVerify\n pass @v\n}")
	if pres.EvalRequest(reqWithCookie(`c=not-json`)).Pass {
		t.Error("malformed JSON must fail closed")
	}
	if pres.EvalRequest(reqWithCookie(`c={"needVerify":tru`)).Pass {
		t.Error("truncated JSON must fail closed")
	}

	// Object/array leaf under a VALUE test -> false (value compare only fires on a scalar).
	val := compileSrc(t, "example.com {\n @v cookie_json c field x\n pass @v\n}")
	if val.EvalRequest(reqWithCookie(`c={"field":{"x":1}}`)).Pass {
		t.Error("an object leaf with a value test must be false")
	}
	if val.EvalRequest(reqWithCookie(`c={"field":[1,2]}`)).Pass {
		t.Error("an array leaf with a value test must be false")
	}
	// Object/array leaf under a PRESENCE test -> also false (not a usable scalar).
	if pres2 := compileSrc(t, "example.com {\n @v cookie_json c field\n pass @v\n}"); pres2.EvalRequest(reqWithCookie(`c={"field":{"x":1}}`)).Pass {
		t.Error("an object leaf under presence must be false (non-scalar)")
	}

	// Deeply nested beyond the cap -> false. Build depth jsonDepthCap+5 of nested arrays.
	deep := strings.Repeat("[", jsonDepthCap+5) + "1" + strings.Repeat("]", jsonDepthCap+5)
	deepP := compileSrc(t, "example.com {\n @v cookie_json c 0\n pass @v\n}")
	if deepP.EvalRequest(reqWithCookie(`c=` + deep)).Pass {
		t.Error("a document nested past the depth cap must fail closed")
	}

	// Over-size -> false. Build a valid JSON object larger than the size cap.
	big := `{"needVerify":true,"pad":"` + strings.Repeat("a", jsonValueSizeCap) + `"}`
	if len(big) <= jsonValueSizeCap {
		t.Fatal("test setup: big value should exceed the cap")
	}
	if pres.EvalRequest(reqWithCookie(`c=` + big)).Pass {
		t.Error("an over-cap value must fail closed (no parse attempted)")
	}
}

// 6. Percent-encoded value decoded once then parsed.
func TestCookieJSONPercentEncoded(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json nsfwCookie needVerify true\n pass @v\n}")
	// {"needVerify":true} percent-encoded.
	enc := "nsfwCookie=%7B%22needVerify%22%3Atrue%7D"
	if !p.EvalRequest(reqWithCookie(enc)).Pass {
		t.Error("a percent-encoded JSON cookie should decode once and match")
	}
}

// 7. Array-index path; non-numeric index on an array -> false (object key vs array).
func TestCookieJSONArrayIndex(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json c flags.0.kind gate\n pass @v\n}")
	pass := func(c string) bool { return p.EvalRequest(reqWithCookie(c)).Pass }
	if !pass(`c={"flags":[{"kind":"gate"}]}`) {
		t.Error("flags.0.kind should reach the array element field")
	}
	if pass(`c={"flags":[{"kind":"open"}]}`) {
		t.Error("a different kind should not match")
	}
	if pass(`c={"flags":[]}`) {
		t.Error("an empty array (index out of range) should be false")
	}
	// An object key where the path expects an array index -> false.
	keyOnArray := compileSrc(t, "example.com {\n @v cookie_json c flags.kind gate\n pass @v\n}")
	if keyOnArray.EvalRequest(reqWithCookie(`c={"flags":[{"kind":"gate"}]}`)).Pass {
		t.Error("an object-key segment against an array must be false")
	}
}

// 8. {$ENV} in NAME resolves to the env cookie name.
func TestCookieJSONEnvName(t *testing.T) {
	src := "example.com {\n @v cookie_json verified-{$ENV} verified true\n pass @v\n}"
	f, err := cadishfile.Parse("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cadishfile.SubstituteEnv(f, func(name string) (string, bool) {
		if name == "ENV" {
			return "prod", true
		}
		return "", false
	})
	p, err := Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The matcher must read the cookie named "verified-prod".
	if !p.EvalRequest(reqWithCookie(`verified-prod={"verified":true}`)).Pass {
		t.Error("{$ENV} in NAME should resolve to verified-prod")
	}
	if p.EvalRequest(reqWithCookie(`verified-dev={"verified":true}`)).Pass {
		t.Error("a different env cookie name should not match")
	}
}

// 9. Used in a classify `when` row, a pass/header scope, and the security gate.
func TestCookieJSONInClassifyAndScopes(t *testing.T) {
	p := compileSrc(t, `example.com {
    @nv cookie_json nsfwCookie needVerify true
    classify {needVerify} {
        when @nv -> 1
        default  -> 0
    }
    header X-Needs {classify.needVerify}
    header @nv X-NV 1
    cache_key host path {needVerify}
}`)
	dec := p.EvalRequest(reqWithCookie(`nsfwCookie={"needVerify":true}`))
	if !hasHeaderOp(dec.ReqHeaderOps, "X-Needs", "1") {
		t.Errorf("classify-derived X-Needs should be 1; got %+v", dec.ReqHeaderOps)
	}
	if !hasHeaderOp(dec.ReqHeaderOps, "X-NV", "1") {
		t.Errorf("scoped header X-NV should fire when @nv matches; got %+v", dec.ReqHeaderOps)
	}
	dec0 := p.EvalRequest(reqWithCookie(`nsfwCookie={"needVerify":false}`))
	if !hasHeaderOp(dec0.ReqHeaderOps, "X-Needs", "0") {
		t.Errorf("classify default should be 0 when needVerify=false; got %+v", dec0.ReqHeaderOps)
	}
	if hasHeaderOp(dec0.ReqHeaderOps, "X-NV", "1") {
		t.Error("scoped header X-NV must NOT fire when @nv does not match")
	}
}

// Security gate: a cookie_json deny rule blocks a matching request and lets others through.
func TestCookieJSONInSecurityGate(t *testing.T) {
	p := compileSrc(t, `example.com {
    @blocked cookie_json session banned true
    deny @blocked
    cache_ttl default ttl 60s
}`)
	reqJSON := func(cookie string) *Request {
		r := reqWithCookie(cookie)
		return r
	}
	if !p.EvalSecurity(reqJSON(`session={"banned":true}`)).Block {
		t.Error("a request whose JSON cookie field is banned=true should be blocked")
	}
	if p.EvalSecurity(reqJSON(`session={"banned":false}`)).Block {
		t.Error("banned=false must not be blocked")
	}
	if p.EvalSecurity(reqJSON("")).Block {
		t.Error("no cookie must not be blocked (fail-open to the operator default)")
	}
}

// 10. Memoization: two matchers over the same cookie parse it once per request.
func TestCookieJSONMemoization(t *testing.T) {
	// Two named matchers reading the same cookie; both referenced in one classify
	// table so they share the per-request memo. We assert correctness (the memo is
	// transparent); the parse-once property is structural (matchContext.memo).
	p := compileSrc(t, `example.com {
    @a cookie_json c needVerify true
    @b cookie_json c needVerify true
    classify {t} {
        when @a @b -> both
        default    -> none
    }
    header X-T {classify.t}
    cache_key host path {t}
}`)
	dec := p.EvalRequest(reqWithCookie(`c={"needVerify":true}`))
	if !hasHeaderOp(dec.ReqHeaderOps, "X-T", "both") {
		t.Errorf("both matchers over the same cookie should fire; got %+v", dec.ReqHeaderOps)
	}
}

// header_json: the same engine over a header value.
func TestHeaderJSONBasic(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v header_json X-Session plan.tier pro enterprise\n pass @v\n}")
	pass := func(h string) bool { return p.EvalRequest(reqWithHeaders(map[string]string{"X-Session": h})).Pass }
	if !pass(`{"plan":{"tier":"pro"}}`) {
		t.Error("header_json should reach plan.tier and match pro")
	}
	if pass(`{"plan":{"tier":"free"}}`) {
		t.Error("free should not match")
	}
	if p.EvalRequest(reqWithHeaders(nil)).Pass {
		t.Error("a missing header should not match")
	}
}

// --- Finding C: Go↔JS parity edge cases (the conformance suite proves the JS side
// decides identically; these assert the Go side's contract). ---

// Finding C #1: a numeric leaf coerces to its EXACT JSON source digits (json.Number),
// NOT a re-rendered double. 1e3 stays "1e3", 1.0 stays "1.0", 1.50 stays "1.50".
func TestCookieJSONNumberSourceCoercion(t *testing.T) {
	cases := []struct {
		raw, want string
	}{
		{`c={"n":1e3}`, "1e3"},
		{`c={"n":1.0}`, "1.0"},
		{`c={"n":1.50}`, "1.50"},
		{`c={"n":42}`, "42"},
		{`c={"n":-0}`, "-0"},
	}
	for _, tc := range cases {
		p := compileSrc(t, "example.com {\n @v cookie_json c n "+tc.want+"\n pass @v\n}")
		if !p.EvalRequest(reqWithCookie(tc.raw)).Pass {
			t.Errorf("%s: numeric leaf should coerce to exact source %q and match", tc.raw, tc.want)
		}
	}
	// A value that re-stringifies differently (1e3 -> "1000") must NOT match the
	// double form — proves we compare the source digits, not the parsed number.
	p := compileSrc(t, "example.com {\n @v cookie_json c n 1000\n pass @v\n}")
	if p.EvalRequest(reqWithCookie(`c={"n":1e3}`)).Pass {
		t.Error("1e3 must coerce to \"1e3\", not the double form \"1000\"")
	}
}

// Finding C #2: a JSON cookie value is NOT form-encoded; a literal '+' in the
// percent-decoded value is PRESERVED (PathUnescape, matching JS decodeURIComponent),
// never turned into a space.
func TestCookieJSONPercentPlusPreserved(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json c tok a+b\n pass @v\n}")
	// {"tok":"a+b"} percent-encoded (note %2B is NOT used — a raw '+' inside %-encoding).
	enc := `c=%7B%22tok%22%3A%22a+b%22%7D`
	if !p.EvalRequest(reqWithCookie(enc)).Pass {
		t.Error("a percent-encoded JSON cookie whose value contains '+' must preserve it (a+b), not decode to 'a b'")
	}
	// The space form must NOT match — confirms '+' was not turned into a space.
	pSpace := compileSrc(t, "example.com {\n @v cookie_json c tok a b\n pass @v\n}")
	if pSpace.EvalRequest(reqWithCookie(enc)).Pass {
		t.Error("'+' must not be decoded as a space")
	}
}

// Finding C #3: a duplicate object key resolves to the LAST occurrence, matching JS
// JSON.parse (last wins).
func TestCookieJSONDuplicateKeyLastWins(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json c k b\n pass @v\n}")
	if !p.EvalRequest(reqWithCookie(`c={"k":"a","k":"b"}`)).Pass {
		t.Error("duplicate key must resolve to the LAST value (b), matching JSON.parse")
	}
	pFirst := compileSrc(t, "example.com {\n @v cookie_json c k a\n pass @v\n}")
	if pFirst.EvalRequest(reqWithCookie(`c={"k":"a","k":"b"}`)).Pass {
		t.Error("the FIRST duplicate value (a) must NOT win")
	}
	// Nested duplicate at a non-leaf segment: last wins there too.
	pNest := compileSrc(t, "example.com {\n @v cookie_json c o.x 2\n pass @v\n}")
	if !pNest.EvalRequest(reqWithCookie(`c={"o":{"x":1},"o":{"x":2}}`)).Pass {
		t.Error("a duplicate non-leaf key must resolve through the LAST occurrence")
	}
}

// Finding C #4: an over-deep document is rejected UP FRONT (anywhere in the tree),
// even when the target field is shallow — mirroring the JS whole-tree depth check, so
// both runtimes fail closed identically.
func TestCookieJSONDepthCapWholeDocument(t *testing.T) {
	p := compileSrc(t, "example.com {\n @v cookie_json c shallow yes\n pass @v\n}")
	// Target "shallow" is at depth 1, but a sibling nests deeper than the cap.
	deepSibling := strings.Repeat("[", jsonDepthCap+2) + "1" + strings.Repeat("]", jsonDepthCap+2)
	raw := `c={"shallow":"yes","deep":` + deepSibling + `}`
	if p.EvalRequest(reqWithCookie(raw)).Pass {
		t.Error("a shallow target must still fail closed when a sibling exceeds the depth cap (whole-document check)")
	}
	// Sanity: the same shallow target WITHOUT an over-deep sibling still matches.
	if !p.EvalRequest(reqWithCookie(`c={"shallow":"yes","deep":[1]}`)).Pass {
		t.Error("a shallow target with shallow siblings must still match")
	}
}

// hasHeaderOp reports whether ops contains a set of NAME to VALUE.
func hasHeaderOp(ops []HeaderOp, name, value string) bool {
	for _, op := range ops {
		if http.CanonicalHeaderKey(op.Name) == http.CanonicalHeaderKey(name) && op.Value == value {
			return true
		}
	}
	return false
}
