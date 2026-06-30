package conformance

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/cadi-sh/cadish/internal/edgeir"
)

// TestServerOnlyKindsInLockstep is the Finding 7 drift guard: the test-local
// serverOnlyMatcherKinds must EQUAL the projector's edgeir.serverOnlyEdgeKinds set. The
// two drifted once (the projector added `upstream_healthy` while this mirror still listed
// only all+query), silently weakening the coverage gate. Asserting set equality here makes
// any future divergence fail loudly instead of going unnoticed.
func TestServerOnlyKindsInLockstep(t *testing.T) {
	proj := edgeir.ServerOnlyEdgeKinds()
	for k := range proj {
		if !serverOnlyMatcherKinds[k] {
			t.Errorf("projector marks %q server-only but the coverage-gate mirror does not", k)
		}
	}
	for k := range serverOnlyMatcherKinds {
		if !proj[k] {
			t.Errorf("coverage-gate mirror lists %q but the projector does not — stale entry", k)
		}
	}
	if len(proj) != len(serverOnlyMatcherKinds) {
		t.Errorf("set sizes differ: projector=%d, mirror=%d", len(proj), len(serverOnlyMatcherKinds))
	}
}

// purgeGuardTokenFixture is the fixture whose Cadishfile carries a purge-guard secret
// (an inline `purge when header X-Purge-Token <token>`), and the literal token it must
// NEVER leak into the projected edge IR. Kept in lockstep with the fixture JSON.
const (
	purgeGuardTokenFixture = "16-purge-guard-redaction"
	purgeGuardToken        = "s3cr3t-PURGE-DO-NOT-LEAK"
)

// TestPurgeGuardTokenRedactedInIR is the cross-runtime parity for the D34 purge-token
// redaction: the generated edge IR that the JS conformance suite loads must NOT contain
// the literal purge-guard token anywhere. The projector delegates every `purge` to the
// Cadish server behind and strips the guard's inline matcher value (redactScope /
// redactMatcher in edgeir.go) so a public worker bundle never holds the secret. This
// asserts that on the SAME generated artifact the JS side consumes — closing the loop
// that the redaction holds end-to-end, not just in the Go-internal unit test.
func TestPurgeGuardTokenRedactedInIR(t *testing.T) {
	irPath := filepath.Join("generated", purgeGuardTokenFixture+".ir.json")
	data, err := os.ReadFile(irPath)
	if err != nil {
		t.Fatalf("%s missing — run `CONFORMANCE_UPDATE=1 go test ./test/conformance`: %v", irPath, err)
	}
	if bytes.Contains(data, []byte(purgeGuardToken)) {
		t.Fatalf("SECRET LEAK: purge-guard token %q is present in the projected edge IR %s — "+
			"the D34 redaction must strip it before the IR ships to the public worker", purgeGuardToken, irPath)
	}
}

// genIR is the subset of the projected EdgeIR JSON this gate inspects: the cache-key
// token kinds and delegated directive kinds present in a fixture's generated IR. It is
// intentionally a loose, forward-compatible view (extra IR fields are ignored) — the
// gate only asserts COVERAGE, not the full shape (TestConformance already pins the full
// shape byte-for-byte). Matcher kinds are gathered separately by collectKinds (a deep
// "kind" sweep) so inline/anonymous matchers nested in scopes also count.
type genIR struct {
	Key struct {
		Tokens []struct {
			Kind string `json:"kind"`
		} `json:"tokens"`
	} `json:"key"`
	Delegate []struct {
		Directive string `json:"directive"`
	} `json:"delegate"`
}

// TestEveryProjectableKindHasFixture is the META-GATE against EdgeIR projection drift:
// every meaningful kind the edgeir projector can EMIT must be exercised by at least one
// committed conformance fixture (its generated *.ir.json). When someone teaches the
// projector a new matcher kind, cache-key token, or delegated directive but does not
// add a fixture that produces it, this gate FAILS — so the Go↔JS conformance suite can
// never silently lose coverage of a newly-projected field.
//
// SCOPE (deliberately the high-value set, per the audit-followup brief):
//   - every MATCHER kind the projector emits (edgeKindName in pipeline/edgeview.go),
//     except the server-only `ip` kind, which is NEVER projected to the worker by
//     design (it would project as the sentinel "server-only-ip"); requiring a fixture
//     for it would be wrong.
//   - every cache-key TOKEN kind the projector emits (toEdgeKeyToken).
//   - every DELEGATED directive kind the projector can record (edgeir.go Delegated{}).
//
// It does NOT attempt full reflective field coverage of the EdgeIR struct (TTL/storage
// selector variants, edge-tier policies, etc.) — those are pinned by the byte-exact
// golden assertion in TestConformance. This gate guards the enumerable "kind" switches,
// which are where a new code path most easily slips in without a fixture.
func TestEveryProjectableKindHasFixture(t *testing.T) {
	// --- the sets the projector can emit (kept next to the projector's switches) ---

	// Matcher kinds: the non-sentinel results of pipeline.edgeKindName. `ip` is omitted
	// on purpose — it is server-only and never reaches the worker IR.
	wantMatcherKinds := []string{
		"path", "path_regex", "host", "host_regex", "header", "method", "upstream",
		"content_type", "resp_header", "cookie", "cookie_json", "header_json", "set_cookie",
		"classify", "geo", "query_present", "query", "all",
	}
	// Cache-key token kinds: the Kind values of pipeline.toEdgeKeyToken.
	wantTokenKinds := []string{
		"method", "host", "path", "url", "query", "query_allow", "query_strip", "header", "sticky",
		"device", "geo", "geo.continent", "geo.region", "normalize", "classify",
		"tenant", "literal",
	}
	// Delegated directive kinds the projector records in EdgeIR.Delegate (the array
	// that SHIPS in the IR). NOTE: as of D70 a scoped `cache_key` is EDGE-NATIVE (the
	// projector emits the full Key.Recipes list + selectors and the worker selects the
	// recipe first-match-wins), so `cache_key` is NOT in this list — making it
	// edge-native removed the delegation, and the meta-gate below proves the scoped
	// recipes are exercised by a fixture rather than dropped. As of D75/D76 a
	// SIZE-BOUNDED `replace` and the `respond on_error` outage path are likewise
	// edge-native (Response.Transforms / Response.OnError), so neither is in this
	// delegate list anymore; TestV4IRFieldsHaveFixtures proves they are exercised by a
	// fixture rather than dropped. (Unbounded/streaming `replace` over the cap is a
	// runtime pass-through, not a delegate entry.)
	wantDelegateKinds := []string{
		"security", "purge", "rewrite", "encode",
	}

	seenMatcher := map[string]bool{}
	seenToken := map[string]bool{}
	seenDelegate := map[string]bool{}

	files, err := filepath.Glob(filepath.Join("generated", "*.ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no generated IRs found — run `CONFORMANCE_UPDATE=1 go test ./test/conformance` first")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ir genIR
		if err := json.Unmarshal(data, &ir); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		// Named + inline matcher kinds, via a deep sweep of every "kind" field. (Token
		// kinds also surface as "kind"; they only matter to the token set, which is
		// populated from the structured decode below, so the overlap is harmless.)
		for k := range collectKinds(data) {
			seenMatcher[k] = true
		}
		for _, tk := range ir.Key.Tokens {
			seenToken[tk.Kind] = true
		}
		for _, d := range ir.Delegate {
			seenDelegate[d.Directive] = true
		}
	}

	assertCovered(t, "matcher kind", wantMatcherKinds, seenMatcher,
		"add a fixture whose Cadishfile uses this matcher, then regenerate with CONFORMANCE_UPDATE=1")
	assertCovered(t, "cache-key token kind", wantTokenKinds, seenToken,
		"add a fixture whose cache_key uses this token, then regenerate with CONFORMANCE_UPDATE=1")
	assertCovered(t, "delegated directive kind", wantDelegateKinds, seenDelegate,
		"add a fixture whose Cadishfile triggers this delegation, then regenerate with CONFORMANCE_UPDATE=1")
}

// collectKinds returns the set of every value of a "kind" JSON field anywhere in the
// IR document — a cheap deep sweep so an inline matcher nested in a scope still counts
// as covering its kind (matcher kinds and token kinds share the "kind" field name; the
// caller only uses this for the matcher-kind set, and token kinds are also matched by
// their own structured decode, so the overlap is harmless).
func collectKinds(data []byte) map[string]bool {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	out := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			if k, ok := t["kind"].(string); ok {
				out[k] = true
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(v)
	return out
}

// TestV2IRFieldsHaveFixtures guards the D70 (edge v1.1) IR fields against silently
// losing conformance coverage: a generated IR must exercise (a) a SCOPED cache_key
// recipe (key.recipes with a non-Always selector — proves the scoped projection +
// the worker's first-match selection are tested), (b) the {device} classifier block
// (ir.device — proves the edge-native UA classifier is tested), and (c) a max_stale
// window (a ttl rule with maxStale set). If a refactor drops any of these from the
// fixtures the gate fails, so the byte-exact golden assertion can never go stale on a
// field with no exercising case.
func TestV2IRFieldsHaveFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("generated", "*.ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no generated IRs found — run `CONFORMANCE_UPDATE=1 go test ./test/conformance` first")
	}
	var sawScopedRecipe, sawDevice, sawMaxStale bool
	type v2IR struct {
		Key struct {
			Recipes []struct {
				Selector struct {
					Always bool `json:"always"`
				} `json:"selector"`
			} `json:"recipes"`
		} `json:"key"`
		Device   *json.RawMessage `json:"device"`
		Response struct {
			TTL []struct {
				MaxStale string `json:"maxStale"`
			} `json:"ttl"`
		} `json:"response"`
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ir v2IR
		if err := json.Unmarshal(data, &ir); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, rc := range ir.Key.Recipes {
			if !rc.Selector.Always {
				sawScopedRecipe = true
			}
		}
		if ir.Device != nil {
			sawDevice = true
		}
		for _, r := range ir.Response.TTL {
			if r.MaxStale != "" {
				sawMaxStale = true
			}
		}
	}
	if !sawScopedRecipe {
		t.Error("no fixture produces a SCOPED cache_key recipe (key.recipes with a non-Always selector) — add one so the D70 scoped-key projection + worker selection stays covered")
	}
	if !sawDevice {
		t.Error("no fixture projects the {device} classifier (ir.device) — add a fixture whose cache_key uses {device} so the D70 edge device classifier stays covered")
	}
	if !sawMaxStale {
		t.Error("no fixture projects a max_stale window (a cache_ttl rule with maxStale) — add one so the D70 max_stale projection stays covered")
	}
}

// TestV4IRFieldsHaveFixtures guards the D75/D76 (edge v1.2) edge-native fields:
// a generated IR must exercise (a) a `replace` body transform (response.transforms
// with a non-empty rule + response.transformMaxBytes — proves the bounded edge
// transform is projected and tested, including the over-cap pass-through case its
// fixture asserts), and (b) a `respond on_error` synthetic (response.onError —
// proves the edge-native outage path is projected and tested, including precedence).
// If a refactor drops either from the fixtures the gate fails, so the byte-exact
// golden assertion can never go stale on a field with no exercising case.
func TestV4IRFieldsHaveFixtures(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("generated", "*.ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no generated IRs found — run `CONFORMANCE_UPDATE=1 go test ./test/conformance` first")
	}
	var sawTransform, sawTransformCap, sawOnError bool
	type v4IR struct {
		Response struct {
			Transforms        []json.RawMessage `json:"transforms"`
			TransformMaxBytes int64             `json:"transformMaxBytes"`
			OnError           []json.RawMessage `json:"onError"`
		} `json:"response"`
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ir v4IR
		if err := json.Unmarshal(data, &ir); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(ir.Response.Transforms) > 0 {
			sawTransform = true
		}
		if ir.Response.TransformMaxBytes > 0 {
			sawTransformCap = true
		}
		if len(ir.Response.OnError) > 0 {
			sawOnError = true
		}
	}
	if !sawTransform {
		t.Error("no fixture projects a `replace` body transform (response.transforms) — add one so the D75 bounded edge transform stays covered")
	}
	if !sawTransformCap {
		t.Error("no fixture projects response.transformMaxBytes — a `replace` fixture must carry the size cap so the over-cap pass-through path stays covered")
	}
	if !sawOnError {
		t.Error("no fixture projects a `respond on_error` synthetic (response.onError) — add one so the D76 edge-native outage path stays covered")
	}
}

// matchOneCaseRe extracts the matcher-kind switch labels from interpreter.js's
// matchOne (the `case "kind":` arms). These ARE the kinds the JS edge runtime can
// faithfully evaluate — the authoritative edge-native matcher set.
var matchOneCaseRe = regexp.MustCompile(`case "([a-z_]+)":`)

// jsEdgeNativeMatcherKinds parses edge/runtime/interpreter.js and returns the set of
// matcher kinds matchOne has a `case` for. It deliberately reads the SOURCE (not a
// hardcoded copy) so the gate tracks the real runtime: if the projector starts emitting a
// kind the JS does not handle, the IR-scan gate below catches it (the kind is neither
// edge-native nor server-only), and if someone adds a JS case the set grows automatically.
func jsEdgeNativeMatcherKinds(t *testing.T) map[string]bool {
	t.Helper()
	// interpreter.js lives at <repo>/edge/runtime/interpreter.js; this test runs from
	// <repo>/test/conformance, so walk up two dirs.
	path := filepath.Join("..", "..", "edge", "runtime", "interpreter.js")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read interpreter.js: %v", err)
	}
	// Bound the scan to the matchOne function body so unrelated `case` labels (e.g. in
	// classifyResolve / normalize) are not miscounted as matcher kinds.
	src := string(data)
	start := indexAfter(src, "function matchOne(")
	if start < 0 {
		t.Fatal("could not find matchOne in interpreter.js")
	}
	// scopeMatches immediately follows matchOne; cut there so only matchOne's cases count.
	end := indexAfter(src[start:], "function scopeMatches(")
	body := src[start:]
	if end >= 0 {
		body = src[start : start+end]
	}
	out := map[string]bool{}
	for _, m := range matchOneCaseRe.FindAllStringSubmatch(body, -1) {
		out[m[1]] = true
	}
	if len(out) == 0 {
		t.Fatal("extracted zero matcher kinds from matchOne — the parser is broken")
	}
	return out
}

func indexAfter(s, sub string) int {
	i := bytesIndex(s, sub)
	if i < 0 {
		return -1
	}
	return i
}

func bytesIndex(s, sub string) int {
	return bytes.Index([]byte(s), []byte(sub))
}

// serverOnlyMatcherKinds mirrors internal/edgeir.serverOnlyEdgeKinds: matcher kinds with
// NO edge JavaScript runtime case, which the projector marks serverOnly + delegates and the
// worker fails CLOSED on. Kept in lockstep with the projector's set (Fix #1/#4); equality is
// asserted by TestServerOnlyKindsInLockstep so this can never silently drift again. A kind
// here need not have a JS matchOne case — it must never silently match at the edge.
var serverOnlyMatcherKinds = map[string]bool{
	"upstream_healthy": true, // live lb-pool liveness probe — no edge analogue (D49)
	"ip":               true, // IP/CIDR ACL — resolves the real client IP, no edge analogue (R02)
}

// collectMatcherKinds walks a generated IR and returns the kinds of every MATCHER object:
// the entries of the `matchers` map plus every element of any `inline` array (anonymous
// scope matchers). It deliberately does NOT use the broad collectKinds sweep, because
// cache-key TOKENS also carry a `kind` field (url/literal/sticky/device/…) that is NOT a
// matcher kind and would otherwise be misclassified.
func collectMatcherKinds(data []byte) map[string]bool {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	out := map[string]bool{}
	root, _ := v.(map[string]any)
	if root != nil {
		if mm, ok := root["matchers"].(map[string]any); ok {
			for _, m := range mm {
				if mo, ok := m.(map[string]any); ok {
					if k, ok := mo["kind"].(string); ok {
						out[k] = true
					}
				}
			}
		}
	}
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			if inl, ok := t["inline"].([]any); ok {
				for _, el := range inl {
					if mo, ok := el.(map[string]any); ok {
						if k, ok := mo["kind"].(string); ok {
							out[k] = true
						}
					}
				}
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(v)
	return out
}

// TestNoUnrepresentableMatcherProjected is the DURABLE coverage gate (Fix #1): every
// matcher kind that the projector EMITS into a generated edge IR must be EITHER (a) a kind
// the JS edge runtime can faithfully evaluate (a matchOne `case`), OR (b) an explicitly
// server-only kind the projector marks serverOnly + delegates and the worker fails CLOSED
// on. A kind that is neither — most dangerously the sentinel "unknown" edgeKindName emits
// for an unmapped matcherKind — means the projector grew a new matcher the edge cannot
// represent and is silently shipping it (it would project as a kind the worker has no case
// for, defaulting to a non-match / wrong match). This is exactly the class of bug Fix #1
// fixed for `all`/`query`; this gate makes a recurrence impossible without a loud failure.
//
// It reads the JS matchOne cases from source (the live runtime contract), so it cannot
// drift from a hardcoded copy. A server-only matcher additionally MUST carry serverOnly=true
// in the IR so the worker's fail-closed branch engages.
func TestNoUnrepresentableMatcherProjected(t *testing.T) {
	edgeNative := jsEdgeNativeMatcherKinds(t)

	files, err := filepath.Glob(filepath.Join("generated", "*.ir.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no generated IRs found — run `CONFORMANCE_UPDATE=1 go test ./test/conformance` first")
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for k := range collectMatcherKinds(data) {
			if k == "unknown" {
				t.Errorf("%s projects a matcher with kind %q — edgeKindName emitted the unmapped-kind sentinel, "+
					"meaning the projector grew a matcher the edge cannot represent. Add a JS matchOne case (edge-native) "+
					"OR add it to serverOnlyEdgeKinds (delegate + fail-closed), then update the gate.", f, k)
				continue
			}
			if edgeNative[k] || serverOnlyMatcherKinds[k] {
				continue
			}
			t.Errorf("%s projects matcher kind %q which has NO JS matchOne case and is NOT in the server-only/delegated set — "+
				"the edge worker would not evaluate it faithfully (silent non-match/wrong-match). Either add a matchOne case in "+
				"edge/runtime/interpreter.js (edge-native) or mark it serverOnly in internal/edgeir (delegate + fail-closed).", f, k)
		}
	}
}

// TestServerOnlyMatcherKindsInSyncWithJS guards the inverse: a kind the JS runtime does NOT
// have a matchOne case for, yet is named in serverOnlyMatcherKinds, must genuinely be a
// fail-closed server-only kind (it has no edge case). And a kind that IS edge-native must
// NOT also be listed server-only (that would needlessly delegate a representable matcher).
// This keeps the two halves of the contract — the JS cases and the server-only set — from
// silently overlapping or contradicting.
func TestServerOnlyMatcherKindsInSyncWithJS(t *testing.T) {
	edgeNative := jsEdgeNativeMatcherKinds(t)
	for k := range serverOnlyMatcherKinds {
		if edgeNative[k] {
			t.Errorf("matcher kind %q is BOTH server-only and has a JS matchOne case — a representable matcher must not be delegated; "+
				"remove it from serverOnlyMatcherKinds (and internal/edgeir.serverOnlyEdgeKinds) or from matchOne", k)
		}
	}
}

func assertCovered(t *testing.T, label string, want []string, seen map[string]bool, hint string) {
	t.Helper()
	var missing []string
	for _, k := range want {
		if !seen[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		t.Errorf("%s %q is projectable but no conformance fixture exercises it — %s", label, k, hint)
	}
}
