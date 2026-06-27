package pipeline

import (
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// cookie_json / header_json — structured-value matchers (D54).
//
// A `cookie_json NAME PATH [VALUE…]` / `header_json NAME PATH [VALUE…]` matcher
// tests ONE dotted field inside a JSON cookie/header value, mirroring the `cookie`
// matcher's shape EXACTLY (name + OR-of-values + presence), just reaching one level
// into a structured value via a bounded PATH:
//
//   - no value  → the field EXISTS (present and non-null), like bare `cookie NAME`.
//   - one+ value → the field's scalar value (coerced to its JSON string form:
//                   true→"true", 42→"42", "x"→"x") EQUALS ANY listed value (OR).
//
// There is NO operator vocabulary (no eq/one_of/lt/ge) and PATH is NOT JSONPath
// (object keys + array indices only — no wildcards/filters/recursion/slices).
//
// Fail-safe: the matcher is boolean and false on ANYTHING weird (missing cookie/
// header, malformed JSON, over-size, too-deeply-nested, path missing, a non-scalar
// field under a value test, a null field). Malformed input can never flip a gate
// open — it falls through to the operator's classify `default`.
//
// Security (bound the parse): a raw value over jsonValueSizeCap is rejected before
// any parse; the decoder is depth-guarded to jsonDepthCap. The cookie/header value
// is already in hand on the request (no body buffering — the zero-copy invariant
// holds). The result is memoized per request like any matcher.

const (
	// jsonValueSizeCap is the hard cap (bytes) on the RAW cookie/header value the
	// JSON matcher will look at. Over the cap → false, no parse attempted (DoS
	// guard). 8 KiB per the spec; a crafted JSON cookie cannot blow up the parser.
	jsonValueSizeCap = 8 * 1024
	// jsonDepthCap is the hard nesting-depth cap. A document that nests deeper than
	// this anywhere along the parse is rejected (false), guarding the stack/CPU.
	jsonDepthCap = 32
)

// jsonPathSeg is one segment of a compiled PATH: either an object key or an array
// index. isIndex selects which field is meaningful.
type jsonPathSeg struct {
	key     string // object key (when !isIndex)
	index   int    // array index (when isIndex)
	isIndex bool
}

// compileJSONPath splits a dotted PATH ("user.verified", "flags.0.kind") into a
// bounded list of segments. A segment that is all ASCII digits is an array index;
// anything else is an object key. An empty PATH or an empty segment is rejected.
// The path length is bounded by jsonDepthCap so a pathological PATH can't drive an
// unbounded descent.
func compileJSONPath(path string, pos cadishfile.Pos) ([]jsonPathSeg, error) {
	if path == "" {
		return nil, &CompileError{Pos: pos, Msg: "cookie_json/header_json matcher needs a non-empty PATH (e.g. `needVerify` or `user.verified`)"}
	}
	parts := strings.Split(path, ".")
	if len(parts) > jsonDepthCap {
		return nil, &CompileError{Pos: pos, Msg: "cookie_json/header_json PATH is too deep (max " + strconv.Itoa(jsonDepthCap) + " segments)"}
	}
	segs := make([]jsonPathSeg, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, &CompileError{Pos: pos, Msg: "cookie_json/header_json PATH has an empty segment (got " + quote(path) + ")"}
		}
		if isAllASCIIDigits(p) {
			n, err := strconv.Atoi(p)
			if err != nil {
				// Unreachable for an all-digit string within int range; treat an
				// over-long numeric segment as an object key (it can never match an
				// array index, which is the safe, fail-closed behavior).
				segs = append(segs, jsonPathSeg{key: p})
				continue
			}
			segs = append(segs, jsonPathSeg{index: n, isIndex: true})
		} else {
			segs = append(segs, jsonPathSeg{key: p})
		}
	}
	return segs, nil
}

// jsonPathString reconstructs the dotted PATH source ("user.verified",
// "flags.0.kind") from compiled segments, so the edge IR can carry the faithful
// path the JS interpreter splits the same way. It round-trips a path this engine
// itself compiled.
func jsonPathString(segs []jsonPathSeg) string {
	var b strings.Builder
	for i, s := range segs {
		if i > 0 {
			b.WriteByte('.')
		}
		if s.isIndex {
			b.WriteString(strconv.Itoa(s.index))
		} else {
			b.WriteString(s.key)
		}
	}
	return b.String()
}

// isAllASCIIDigits reports whether s is a non-empty run of ASCII digits.
func isAllASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// jsonFieldResult is the outcome of resolving a PATH against a raw value.
type jsonFieldResult struct {
	// found is true when the PATH reached an existing, non-null SCALAR (a string,
	// number, or bool). value is then its coerced string form. A path that reaches
	// null, an object/array, or that does not exist at all leaves found=false.
	found bool
	value string
}

// resolveJSONField is the bounded, fail-closed engine shared by both matchers and
// the matcher's match(). raw is the (already percent-decoded) cookie/header value;
// it parses lazily along segs and returns the scalar leaf. ANY anomaly — over-size,
// malformed JSON, missing/extra structure, too-deep nesting, a non-scalar leaf, a
// null leaf — yields found=false (never an error to the caller, never a panic).
func resolveJSONField(raw string, segs []jsonPathSeg) jsonFieldResult {
	if len(raw) > jsonValueSizeCap {
		// DoS guard: refuse to even parse an over-cap value.
		return jsonFieldResult{}
	}
	if len(segs) == 0 {
		return jsonFieldResult{}
	}
	// PARITY (Finding C #4): reject an over-deep document UP FRONT — anywhere in the
	// tree, not just along the resolved path — so Go and JS fail closed on the exact
	// same inputs. The JS edge validates the whole parsed tree's depth (jsonDepthOK)
	// before resolving; mirror that here so a doc whose target is shallow but a
	// sibling nests deeper than jsonDepthCap is rejected on BOTH runtimes. (The
	// per-step depth guards below stay as defense in depth.)
	if !jsonDocDepthValid(raw) {
		return jsonFieldResult{}
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber() // keep numbers in their exact textual form (no float rounding).
	return descend(dec, segs, 0)
}

// jsonDocDepthValid streams the whole document and reports whether it parses as
// well-formed JSON whose nesting never exceeds jsonDepthCap ANYWHERE. It mirrors
// the JS edge's jsonDepthOK (which walks the entire parsed tree). A malformed
// document (or one that nests too deeply) yields false → the matcher fails closed
// identically on both runtimes. depth counts containers from the root: the
// outermost object/array is depth 1.
//
// PARITY (R18): it ALSO requires a SINGLE top-level value. json.Decoder.Token streams
// a SEQUENCE of values, so `{"a":1} true` (a complete object followed by trailing data)
// decodes without error and descend() reads only the first value — a Go MATCH where the
// JS edge's strict JSON.parse THROWS on the trailing token (no match). Rejecting any
// token after the top-level value closes (a container returning to depth 0, or a bare
// top-level scalar) makes Go fail closed on the exact inputs JSON.parse rejects, so the
// two runtimes stay in lockstep.
func jsonDocDepthValid(raw string) bool {
	dec := json.NewDecoder(strings.NewReader(raw))
	depth := 0
	complete := false // the single top-level value has finished; any further token is trailing data
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		if complete {
			// A token after the top-level value completed → trailing data (`{"a":1} true`,
			// `1 2`). Strict JSON.parse rejects this; mirror it (fail closed).
			return false
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > jsonDepthCap {
					return false
				}
			case '}', ']':
				depth--
				if depth == 0 {
					complete = true // outermost container closed
				}
			}
		} else if depth == 0 {
			// A bare top-level scalar (`true`, `42`, `"x"`) is itself the whole document.
			complete = true
		}
	}
	return true
}

// descend reads the value the decoder is positioned at and resolves segs[depth:]
// against it, returning the resolved scalar leaf (found=false on any structural
// mismatch, EOF, depth overflow, or read error). It always fully consumes the value
// it reads so the caller's scan stays balanced (required for last-wins sibling
// scanning, below).
func descend(dec *json.Decoder, segs []jsonPathSeg, depth int) jsonFieldResult {
	if depth > jsonDepthCap {
		// Drain nothing — the document depth was validated up front; this is a
		// belt-and-suspenders guard that simply fails closed.
		return jsonFieldResult{}
	}
	seg := segs[depth]
	tok, err := dec.Token()
	if err != nil {
		return jsonFieldResult{}
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// A scalar where a container was required (the PATH descends into a
		// non-container) — no such field. The scalar is one token, already consumed.
		return jsonFieldResult{}
	}
	switch delim {
	case '{':
		if seg.isIndex {
			drainContainer(dec) // an array index against an object → no match
			return jsonFieldResult{}
		}
		return descendObject(dec, segs, depth, seg.key)
	case '[':
		if !seg.isIndex {
			drainContainer(dec) // an object key against an array → no match
			return jsonFieldResult{}
		}
		return descendArray(dec, segs, depth, seg.index)
	default:
		return jsonFieldResult{}
	}
}

// descendObject scans the WHOLE open object, resolving the requested key, and on a
// duplicate key keeps the LAST occurrence — matching JS JSON.parse (and the JSON
// de-facto semantics) so Go and JS decide identically (Finding C #3). Every key's
// value is fully consumed (matched ones resolved, others skipped) so the scan
// reaches the closing '}' and the result reflects the last duplicate, not the first.
func descendObject(dec *json.Decoder, segs []jsonPathSeg, depth int, key string) jsonFieldResult {
	last := depth == len(segs)-1
	res := jsonFieldResult{}
	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return jsonFieldResult{}
		}
		k, ok := ktok.(string)
		if !ok {
			return jsonFieldResult{} // malformed: object keys are strings
		}
		if k == key {
			if last {
				res = decodeScalar(dec, depth+1) // last duplicate wins
			} else {
				res = descend(dec, segs, depth+1)
			}
			continue
		}
		// Skip this non-matching key's value (it may be a nested container).
		if !skipValue(dec, depth+1) {
			return jsonFieldResult{}
		}
	}
	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return jsonFieldResult{}
	}
	return res
}

// descendArray scans the open array to the index-th element and resolves it, then
// drains the rest of the array so the scan stays balanced (a sibling-key scan in a
// parent object relies on every value being fully consumed).
func descendArray(dec *json.Decoder, segs []jsonPathSeg, depth, index int) jsonFieldResult {
	last := depth == len(segs)-1
	res := jsonFieldResult{}
	i := 0
	for dec.More() {
		if i == index {
			if last {
				res = decodeScalar(dec, depth+1)
			} else {
				res = descend(dec, segs, depth+1)
			}
			i++
			continue
		}
		if !skipValue(dec, depth+1) {
			return jsonFieldResult{}
		}
		i++
	}
	// Consume the closing ']'.
	if _, err := dec.Token(); err != nil {
		return jsonFieldResult{}
	}
	return res
}

// drainContainer consumes the rest of the currently-open container (the decoder has
// already read its opening delimiter), so a mismatched descent leaves the parent
// scan balanced. Bounded by the up-front document depth validation.
func drainContainer(dec *json.Decoder) {
	for dec.More() {
		if !skipValue(dec, 0) {
			return
		}
	}
	_, _ = dec.Token() // closing delimiter
}

// skipValue consumes exactly one JSON value from the decoder (a scalar in one
// token, or a balanced container), bounded by jsonDepthCap so a pathological nested
// document cannot drive unbounded recursion/CPU. Returns false on EOF/read error or
// when the nesting exceeds the cap.
func skipValue(dec *json.Decoder, depth int) bool {
	if depth > jsonDepthCap {
		return false
	}
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return true // a scalar is one token; done.
	}
	if delim != '{' && delim != '[' {
		// A closing delimiter here would be malformed for a value position.
		return false
	}
	for dec.More() {
		if !skipValue(dec, depth+1) {
			return false
		}
	}
	// Consume the matching close delimiter.
	if _, err := dec.Token(); err != nil {
		return false
	}
	return true
}

// decodeScalar reads the single value the decoder is positioned at and coerces a
// scalar leaf to its string form. A null, an object/array, or a read error yields
// found=false. Coercion mirrors the JSON textual form: true→"true", a number keeps
// its exact source digits (json.Number), a string is itself.
func decodeScalar(dec *json.Decoder, depth int) jsonFieldResult {
	if depth > jsonDepthCap {
		return jsonFieldResult{}
	}
	tok, err := dec.Token()
	if err != nil {
		return jsonFieldResult{}
	}
	switch v := tok.(type) {
	case json.Delim:
		// The leaf is an object or array, not a scalar → no usable value. Drain it so
		// the parent object/array scan (last-wins) stays balanced for later siblings.
		if v == '{' || v == '[' {
			drainContainer(dec)
		}
		return jsonFieldResult{}
	case string:
		return jsonFieldResult{found: true, value: v}
	case json.Number:
		return jsonFieldResult{found: true, value: v.String()}
	case bool:
		if v {
			return jsonFieldResult{found: true, value: "true"}
		}
		return jsonFieldResult{found: true, value: "false"}
	case nil:
		// JSON null is "no usable value" (presence → false; value test → false).
		return jsonFieldResult{}
	default:
		return jsonFieldResult{}
	}
}

// decodeJSONCookieValue percent-decodes a raw cookie/header value ONCE before
// parsing: JSON cookies are commonly `%7B…`-encoded. If the value does not decode
// cleanly (no '%' escapes, or an invalid escape), it is parsed as-is — a value that
// was never percent-encoded must still parse. A value that contains '%' but is
// not valid percent-encoding falls back to the raw value (fail-open to the parser,
// which then fails closed on malformed JSON).
//
// PARITY (Finding C #2): a JSON cookie value is NOT form-encoded, so a literal '+'
// must be PRESERVED (it is a real character of a base64 token, an `x+y` string,
// etc.) — not turned into a space. We therefore use url.PathUnescape, NOT
// url.QueryUnescape. PathUnescape decodes %XX escapes exactly like the JS edge's
// decodeURIComponent and leaves '+' untouched, so Go and JS produce the identical
// decoded string (verified byte-for-byte across plain/encoded/invalid inputs).
func decodeJSONCookieValue(raw string) string {
	if !strings.ContainsRune(raw, '%') {
		return raw
	}
	if dec, err := url.PathUnescape(raw); err == nil {
		return dec
	}
	return raw
}

// jsonMatch is the shared evaluation for kindCookieJSON / kindHeaderJSON: read the
// raw value, percent-decode once, resolve the field, then apply the cookie-matcher
// semantics (presence vs OR-of-values).
func jsonMatch(raw string, present bool, segs []jsonPathSeg, values []string) bool {
	if !present {
		return false // missing cookie/header → false (same as `cookie` on absent).
	}
	res := resolveJSONField(decodeJSONCookieValue(raw), segs)
	if !res.found {
		return false
	}
	if len(values) == 0 {
		return true // presence: an existing, non-null scalar field.
	}
	for _, want := range values {
		if res.value == want {
			return true
		}
	}
	return false
}
