// Package conformance is the cross-runtime contract test for Cadish Edge.
//
// It is the test that matters most: it proves the Go pipeline (the reference
// "brain") and the JavaScript edge interpreter decide IDENTICALLY for the same
// (IR, request). The mechanism:
//
//   - fixtures/*.json declare a Cadishfile + a list of request cases.
//   - This Go test compiles each Cadishfile, projects it to the EdgeIR (the same
//     thing `cadish edge build` ships), and evaluates every case through the
//     EvalRequest/EvalResponse/EvalDeliver pipeline, lowering the result to a
//     runtime-neutral DECISION. It writes the projected IR and the golden
//     decisions to generated/<name>.{ir,expect}.json.
//   - edge/runtime/conformance.test.mjs (plain Node, no deps) loads the SAME
//     generated IR, runs edge/runtime/interpreter.js over each case, and asserts
//     its decision equals the golden. Both green ⇒ Go and JS are synchronized by
//     construction.
//
// Run with CONFORMANCE_UPDATE=1 to (re)generate the committed IR + golden files;
// run without it (the CI default) to assert the committed files still match a
// fresh projection + evaluation (so neither the projector nor the pipeline can
// drift from the contract the JS side is pinned to).
package conformance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/edgeir"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// fixture is one conformance fixture: a Cadishfile and the request cases to run
// against it. The expected decisions are generated, not hand-authored.
type fixture struct {
	Name       string `json:"name"`
	Cadishfile string `json:"cadishfile"`
	Cases      []kase `json:"cases"`
}

// kase is one request case: the request fields plus the optional origin response
// (status + headers) and cache-lookup outcome that feed the response/deliver
// phases. Geo/device are inputs (the edge geo injection / server pre-pass
// resolved them); the interpreter only reads them.
type kase struct {
	Request     reqInput   `json:"request"`
	Origin      originResp `json:"origin"`
	CacheStatus string     `json:"cacheStatus"`

	// Body, when set, is the origin response body for the `replace` body-transform
	// probe (D75): the harness applies the deliver-phase transforms to it (Go and JS)
	// and asserts identical output, including the over-cap pass-through. IsHead/IsRange
	// flip the transform-skip gating. Empty Body => the transform decision is still
	// lowered (which rules matched) but no transformed-body bytes are produced.
	Body    string `json:"body,omitempty"`
	IsHead  bool   `json:"isHead,omitempty"`
	IsRange bool   `json:"isRange,omitempty"`

	// OriginFailed marks the outage probe (D76): the origin HARD-failed. Salvageable
	// says a stored copy is still servable within the max_stale window (it wins over
	// on_error). The harness lowers the worker's outage serving decision (stale salvage
	// vs the on_error synthetic vs bare 502) and asserts Go == JS, incl. precedence.
	OriginFailed bool `json:"originFailed,omitempty"`
	Salvageable  bool `json:"salvageable,omitempty"`

	// OutageStatus, when > 0, models the outage as the origin RETURNING this HTTP status
	// (e.g. 503 or a 404) rather than a THROWN transport failure (Fix #2). This is the
	// common flapping/maintenance shape: fetch resolves with a Response, so the worker
	// must run the SAME max_stale / negative-cache / on_error / bare-status precedence the
	// Go server's handleOriginError applies — diverging from a bare 502. When 0 the probe
	// is a thrown failure (status 0, the legacy model). The harness lowers Go and JS over
	// this and asserts they agree, including which status triggers the chain.
	OutageStatus int `json:"outageStatus,omitempty"`
}

type reqInput struct {
	Method       string              `json:"method"`
	Host         string              `json:"host"`
	Path         string              `json:"path"`
	Query        map[string][]string `json:"query"`
	Header       map[string][]string `json:"header"`
	ClientIP     string              `json:"clientIP"`
	Device       string              `json:"device"`
	Geo          string              `json:"geo"`
	GeoContinent string              `json:"geoContinent"`
	GeoRegion    string              `json:"geoRegion"`
}

type originResp struct {
	Status int                 `json:"status"`
	Header map[string][]string `json:"header"`
}

// --- the runtime-neutral decision (must match interpreter.js decide() shape) ---

type decision struct {
	Request  reqDecision  `json:"request"`
	Response respDecision `json:"response"`
	Deliver  delDecision  `json:"deliver"`
	// Outage is the outage serving decision (D76), lowered only for a case with
	// originFailed=true: what the worker serves when the origin hard-fails. nil for a
	// normal case (omitted from the golden).
	Outage *outageDecision `json:"outage,omitempty"`
}

// outageDecision is the runtime-neutral outage serving outcome (D76/Fix #2). Kind is one
// of:
//   - "stale"         — a servable cached copy within max_stale wins (any failure shape).
//   - "negativeCache" — the origin RETURNED a status that cache_ttl marks cacheable, so it
//     is stored + served (Status carries the served code). Only reachable on the
//     origin-RETURNED path (Fix #2), never on a thrown transport failure.
//   - "onError"       — the configured synthetic (Status/Body/ContentType carry it).
//   - "bareStatus"    — no copy + no matching on_error, origin RETURNED a status: forward
//     it verbatim (Status carries the returned code; Go's writeStatus(code)).
//   - "bareError"     — no copy + no matching on_error on a THROWN transport failure → 502.
type outageDecision struct {
	Kind        string `json:"kind"`
	Status      int    `json:"status,omitempty"`
	Body        string `json:"body,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

type reqDecision struct {
	Pass         bool          `json:"pass"`
	Synthetic    *synthetic    `json:"synthetic"`
	Redirect     *redirect     `json:"redirect"`
	Upstream     string        `json:"upstream"`
	CacheKey     string        `json:"cacheKey"`
	Purge        *purge        `json:"purge"`
	ReqHeaderOps []headerOpOut `json:"reqHeaderOps"`
}

type synthetic struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

type redirect struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
}

type purge struct {
	Authorized bool   `json:"authorized"`
	Regex      string `json:"regex"`
}

type respDecision struct {
	TTLNs        int64  `json:"ttlNs"`
	GraceNs      int64  `json:"graceNs"`
	MaxStaleNs   int64  `json:"maxStaleNs"`
	HitForMissNs int64  `json:"hitForMissNs"`
	StoreTier    string `json:"storeTier"`
	Cacheable    bool   `json:"cacheable"`
}

type delDecision struct {
	RespHeaderOps     []headerOpOut `json:"respHeaderOps"`
	StripCookies      bool          `json:"stripCookies"`
	CORS              *corsOut      `json:"cors"`
	CacheStatusHeader string        `json:"cacheStatusHeader"`
	// CacheKeyHeader/CacheKeyRaw mirror the `header +cache_key` directive; CacheKeyValue
	// is the EMITTED header value (12-hex sha256 prefix of the cache key, or the raw key
	// under `raw`). It is the Go↔JS hash-parity probe: the JS interpreter computes the
	// SAME value over the key it builds, so a matching golden proves identical hashing.
	CacheKeyHeader string `json:"cacheKeyHeader"`
	CacheKeyRaw    bool   `json:"cacheKeyRaw"`
	CacheKeyValue  string `json:"cacheKeyValue"`

	// Transforms is the ordered list of `replace` rules whose scope matched this
	// response (the deliver-phase body-substitution decision, D75). BodyTransformed +
	// TransformedBody are produced only when the case carries a Body: they are the
	// result of applying the transforms with the size cap + skip gating, the Go↔JS
	// byte-identity probe (including over-cap pass-through, where BodyTransformed is
	// false and TransformedBody == the original body).
	Transforms      []replacementOut `json:"transforms"`
	BodyTransformed bool             `json:"bodyTransformed"`
	TransformedBody string           `json:"transformedBody"`
}

type replacementOut struct {
	Old string `json:"old"`
	New string `json:"new"`
}

type headerOpOut struct {
	Op    string `json:"op"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type corsOut struct {
	AllowAllOrigins bool     `json:"allowAllOrigins"`
	Origins         []string `json:"origins"`
	Methods         []string `json:"methods"`
	Headers         []string `json:"headers"`
}

// buildRequest turns the fixture request input into the pipeline's Request.
func buildRequest(in reqInput) *pipeline.Request {
	h := http.Header{}
	for k, vs := range in.Header {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	q := url.Values{}
	for k, vs := range in.Query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return &pipeline.Request{
		Method:       in.Method,
		Host:         in.Host,
		Path:         in.Path,
		Query:        q,
		Header:       h,
		ClientIP:     in.ClientIP,
		Device:       in.Device,
		Geo:          in.Geo,
		GeoContinent: in.GeoContinent,
		GeoRegion:    in.GeoRegion,
	}
}

// userAgentOf returns the first User-Agent value from a fixture request's headers
// (case-insensitive lookup), or "" — the input the {device} classifier reads.
func userAgentOf(in reqInput) string {
	for k, vs := range in.Header {
		if strings.EqualFold(k, "User-Agent") && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func cacheStatusFromToken(tok string) pipeline.CacheStatus {
	switch tok {
	case "HIT":
		return pipeline.CacheStatusHit
	case "HIT-STALE":
		return pipeline.CacheStatusHitStale
	default:
		return pipeline.CacheStatusMiss
	}
}

// evalCase runs the three phases and lowers the result to the neutral decision.
func evalCase(p *pipeline.Pipeline, c kase) decision {
	req := buildRequest(c.Request)

	// {device} pre-pass parity (D70): the server resolves req.Device from the
	// User-Agent via the site's classifier before EvalRequest. Mirror that here when the
	// fixture does not pre-set a device and the site keys on {device}, so the Go golden
	// reflects the SAME classification the edge worker performs natively from the IR
	// device ruleset — the conformance probe that the two classifiers agree.
	if req.Device == "" && p.UsesDeviceToken() {
		req.Device = p.DeviceClassifier().Classify(userAgentOf(c.Request))
	}

	rq := p.EvalRequest(req)
	rd := reqDecision{
		Pass:         rq.Pass,
		Upstream:     rq.Upstream,
		CacheKey:     rq.CacheKey,
		ReqHeaderOps: lowerOps(rq.ReqHeaderOps),
	}
	if rq.Synthetic != nil {
		rd.Synthetic = &synthetic{Status: rq.Synthetic.Status, Body: rq.Synthetic.Body}
	}
	if rq.Redirect != nil {
		rd.Redirect = &redirect{Status: rq.Redirect.Status, Location: rq.Redirect.Location}
	}
	if rq.Purge != nil {
		rd.Purge = &purge{Authorized: rq.Purge.Authorized, Regex: rq.Purge.Regex}
	}

	var origHeader http.Header
	if c.Origin.Header != nil {
		origHeader = http.Header{}
		for k, vs := range c.Origin.Header {
			for _, v := range vs {
				origHeader.Add(k, v)
			}
		}
	}
	rs := p.EvalResponse(req, c.Origin.Status, origHeader)
	respDec := respDecision{
		TTLNs:        int64(rs.TTL),
		GraceNs:      int64(rs.Grace),
		MaxStaleNs:   int64(rs.MaxStale),
		HitForMissNs: int64(rs.HitForMiss),
		StoreTier:    rs.StoreTier,
		Cacheable:    rs.Cacheable,
	}

	dl := p.EvalDeliver(req, origHeader, cacheStatusFromToken(c.CacheStatus))
	delDec := delDecision{
		RespHeaderOps:     lowerOps(dl.RespHeaderOps),
		StripCookies:      dl.StripCookies,
		CacheStatusHeader: dl.CacheStatusHeader,
		CacheKeyHeader:    dl.CacheKeyHeader,
		CacheKeyRaw:       dl.CacheKeyRaw,
		Transforms:        lowerReplacements(dl.Transforms),
	}
	// `replace` body transform (D75): apply the matched transforms to the case body,
	// mirroring the server's deliver-phase gating (internal/server/transform.go):
	// skip Range/HEAD/already-encoded, apply only within the size cap, pass an over-cap
	// body through untransformed. The result is the Go↔JS byte-identity probe.
	delDec.TransformedBody, delDec.BodyTransformed = applyTransformsRef(c.Body, dl.Transforms, origHeader, c.IsRange, c.IsHead)
	// The emitted cache-key value is materialized only when a `header +cache_key`
	// directive targets a header (CacheKeyHeader set) — exactly the seam the server's
	// deliver path uses. The cache key is the RECV-held key (rq.CacheKey); empty for a
	// synthetic/redirect (no key) → "". This is the Go↔JS hash-parity probe.
	if dl.CacheKeyHeader != "" {
		delDec.CacheKeyValue = pipeline.CacheKeyHeaderValue(rq.CacheKey, dl.CacheKeyRaw)
	}
	if dl.CORS != nil {
		delDec.CORS = &corsOut{
			AllowAllOrigins: dl.CORS.AllowAllOrigins,
			Origins:         orEmpty(dl.CORS.Origins),
			Methods:         orEmpty(dl.CORS.Methods),
			Headers:         orEmpty(dl.CORS.Headers),
		}
	}

	dec := decision{Request: rd, Response: respDec, Deliver: delDec}
	// Outage serving decision (D76/Fix #2): only for an origin hard-failure case. Mirrors
	// the server precedence in handleOriginError: serve-stale-within-max_stale wins; else
	// (for a RETURNED status) the negative cache when cache_ttl marks it cacheable; else the
	// FIRST matching `respond on_error` synthetic; else the bare returned status (a thrown
	// transport failure has no status → 502).
	if c.OriginFailed {
		dec.Outage = outageRef(p, req, origHeader, c.Salvageable, c.OutageStatus)
	}
	return dec
}

// maxTransformBodyRef mirrors internal/server/transform.go's maxTransformBody (1 MiB)
// and pipeline.EdgeTransformMaxBytes: the edge transform size ceiling. Kept here so the
// conformance reference applies the SAME cap the projected IR carries to the JS worker.
const maxTransformBodyRef = 1 << 20

// applyTransformsRef mirrors the server's deliver-phase `replace` application
// (internal/server/transform.go transformsApply + applyReplacements + the size-cap
// gating in handler.go): transforms are skipped for Range/HEAD/already-encoded
// responses; a body within the cap is substituted (literal ReplaceAll, in order); an
// over-cap body passes through untransformed. Returns the output body and whether it was
// transformed. With no Body the function is a no-op ("", false).
func applyTransformsRef(body string, repls []pipeline.Replacement, hdr http.Header, isRange, isHead bool) (string, bool) {
	if body == "" {
		return "", false
	}
	encoded := hdr != nil && hdr.Get("Content-Encoding") != ""
	if len(repls) == 0 || isRange || isHead || encoded {
		return body, false
	}
	if len(body) > maxTransformBodyRef {
		return body, false // over-cap: pass through untransformed (server streams it)
	}
	s := body
	for _, r := range repls {
		if r.Old == "" {
			continue
		}
		s = strings.ReplaceAll(s, r.Old, r.New)
	}
	return s, true
}

// outageRef lowers the server's origin-error precedence (handleOriginError) to the
// neutral outage decision (D76/Fix #2). outageStatus is the status the origin RETURNED
// (0 ⇒ a thrown transport failure). Precedence, exactly mirroring handleOriginError:
//  1. serve-stale-within-max_stale (salvageable) — wins on EVERY failure shape.
//  2. negative cache — ONLY for a returned status that EvalResponse marks cacheable
//     (a transport failure has no status to negatively cache); store+serve it.
//  3. the first matching `respond on_error` synthetic.
//  4. the bare outcome: the returned status (writeStatus(code)) for a returned failure,
//     or 502 (bareError) for a thrown transport failure.
func outageRef(p *pipeline.Pipeline, req *pipeline.Request, origHeader http.Header, salvageable bool, outageStatus int) *outageDecision {
	if salvageable {
		return &outageDecision{Kind: "stale"}
	}
	// The status the error chain consults: the returned status, or 502 for a thrown
	// transport failure (mirrors handler.go's `code` default of StatusBadGateway when
	// origin.StatusOf == 0).
	code := outageStatus
	if code == 0 {
		code = http.StatusBadGateway
	}
	// Negative caching is only reachable when the origin RETURNED a status (a thrown
	// transport failure carries none). On the returned path the Go server passes the
	// response headers to EvalResponse; mirror that here.
	if outageStatus > 0 {
		rs := p.EvalResponse(req, outageStatus, origHeader)
		if rs.Cacheable {
			return &outageDecision{Kind: "negativeCache", Status: outageStatus}
		}
	}
	// on_error fires only on the HARD-failure path: a THROWN transport failure (status 0)
	// or a RETURNED status mapped to a *StatusError. httporigin maps to *StatusError ANY
	// non-success status EXCEPT 404/410 (negativeStatus is ONLY 404||410): so every
	// returned status >= 400 that is NOT 404/410 (403, 405, 429, 5xx, …) takes
	// handleOriginError's hard-failure chain, where on_error fires. A returned 404/410 is
	// a Negative *Response the server serves directly — it NEVER consults on_error
	// (handler.go: the 404/410 path delivers the negative response, the on_error block
	// lives only in handleOriginError). So skip on_error ONLY for a returned 404/410.
	if outageStatus == 0 || (outageStatus >= 400 && outageStatus != 404 && outageStatus != 410) {
		if p.HasOnError() {
			if oe := p.EvalOnError(req, code); oe != nil {
				return &outageDecision{Kind: "onError", Status: oe.Status, Body: string(oe.Body), ContentType: oe.ContentType}
			}
		}
	}
	if outageStatus > 0 {
		return &outageDecision{Kind: "bareStatus", Status: outageStatus}
	}
	return &outageDecision{Kind: "bareError"}
}

func lowerReplacements(repls []pipeline.Replacement) []replacementOut {
	out := make([]replacementOut, 0, len(repls))
	for _, r := range repls {
		out = append(out, replacementOut{Old: r.Old, New: r.New})
	}
	return out
}

func lowerOps(ops []pipeline.HeaderOp) []headerOpOut {
	out := make([]headerOpOut, 0, len(ops))
	for _, op := range ops {
		out = append(out, headerOpOut{Op: op.Op.String(), Name: op.Name, Value: op.Value})
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func compilePipeline(t *testing.T, src string) *pipeline.Pipeline {
	t.Helper()
	f, err := cadishfile.Parse("fixture.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("fixture must define exactly 1 site, got %d", len(f.Sites))
	}
	p, err := pipeline.Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func marshalIndent(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(b, '\n')
}

// TestConformance projects each fixture's IR and evaluates each case to a golden
// decision, generating (CONFORMANCE_UPDATE=1) or asserting the committed
// generated/ files. The JS side (conformance.test.mjs) is pinned to the same
// generated IR + golden.
func TestConformance(t *testing.T) {
	update := os.Getenv("CONFORMANCE_UPDATE") != ""
	genDir := "generated"
	if update {
		if err := os.MkdirAll(genDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	files, err := filepath.Glob(filepath.Join("fixtures", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no fixtures found under fixtures/*.json")
	}
	sort.Strings(files)

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var fx fixture
		if err := json.Unmarshal(data, &fx); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		t.Run(fx.Name, func(t *testing.T) {
			p := compilePipeline(t, fx.Cadishfile)

			ir, _, err := edgeir.Project(p)
			if err != nil {
				t.Fatalf("project: %v", err)
			}
			irBytes := marshalIndent(t, ir)

			decisions := make([]decision, 0, len(fx.Cases))
			for _, c := range fx.Cases {
				decisions = append(decisions, evalCase(p, c))
			}
			expectBytes := marshalIndent(t, decisions)

			irPath := filepath.Join(genDir, fx.Name+".ir.json")
			expectPath := filepath.Join(genDir, fx.Name+".expect.json")

			if update {
				if err := os.WriteFile(irPath, irBytes, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(expectPath, expectBytes, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			assertFileEquals(t, irPath, irBytes)
			assertFileEquals(t, expectPath, expectBytes)
		})
	}
}

func assertFileEquals(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s missing — run `CONFORMANCE_UPDATE=1 go test ./test/conformance` to generate it: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale (projection/evaluation drifted from the committed contract).\n"+
			"Run `CONFORMANCE_UPDATE=1 go test ./test/conformance` to regenerate, then re-run the JS conformance test.", path)
	}
}
