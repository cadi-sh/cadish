package conformance

// Generative Go==JS edge-parity check.
//
// The committed conformance fixtures (fixtures/*.json) pin ~65 hand-authored
// (config, request) cases byte-for-byte across the Go pipeline and the JS edge
// interpreter. This file ADDS a GENERATOR: it synthesizes thousands of varied but
// valid Cadishfile configs + requests over the directives/matchers most likely to
// diverge (cache_ttl/cache_key tokens, cookie/cookie_json/header_json matchers,
// query/query_allow/query_strip/query_present, host/host_regex, geo, {device},
// cache_unsafe/cache_credentialed/cookie_allow, multi-line headers, percent/astral
// values), and asserts the SAME property the fixtures do: for every FULLY
// edge-native config (projector ForcedPass==0 AND nothing delegated), the Go
// decision (evalCase — the exact reference the committed suite uses) MUST equal the
// JS interpreter's decide(). A config that delegates or is forced-pass is SKIPPED:
// the edge legitimately coarsens it (fail-closed/server-behind), so its decision is
// allowed to differ — that is the safe direction, not a parity violation.
//
// The Go↔JS bridge reuses the conformance design: Go computes the golden, the JS
// half (parity_driver.mjs) loads the SAME projected IR + input and runs decide(),
// and the two are compared after canonical JSON ordering. The whole generated batch
// is evaluated in ONE node process for speed.
//
// CI determinism: TestEdgeParityGenerative iterates a FIXED seed range (size
// PARITY_GEN_N, default kept small so `go test ./...` stays fast) — same seeds every
// run, so it never flakes. FuzzEdgeParity wraps the same generator for on-demand
// `go test -fuzz`; its seed corpus runs as ordinary (deterministic) subtests. Both
// SKIP when `node` is not on PATH, so a node-less Go-only CI still passes (the JS
// half is also gated behind node in npm test).

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/edgeir"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// ---------------------------------------------------------------------------
// batch payload exchanged with parity_driver.mjs
// ---------------------------------------------------------------------------

type genBatch struct {
	Batches []genBatchItem `json:"batches"`
}

type genBatchItem struct {
	Name  string         `json:"name"`
	IR    edgeir.EdgeIR  `json:"ir"`
	Cases []genBatchCase `json:"cases"`
}

type genBatchCase struct {
	Input jsInput         `json:"input"`
	Want  json.RawMessage `json:"want"`
}

// jsInput is the input shape interpreter.js decide() consumes — the request fields
// flattened (embedded reqInput) plus the case-level origin/cacheStatus/outage probes,
// exactly the object conformance.test.mjs builds from a fixture case.
type jsInput struct {
	reqInput
	Origin       originResp `json:"origin"`
	CacheStatus  string     `json:"cacheStatus"`
	Body         string     `json:"body,omitempty"`
	IsHead       bool       `json:"isHead,omitempty"`
	IsRange      bool       `json:"isRange,omitempty"`
	OriginFailed bool       `json:"originFailed,omitempty"`
	Salvageable  bool       `json:"salvageable,omitempty"`
	OutageStatus int        `json:"outageStatus,omitempty"`
}

type driverResult struct {
	Total      int `json:"total"`
	Mismatches []struct {
		Name      string `json:"name"`
		CaseIndex int    `json:"caseIndex"`
		WantS     string `json:"wantS"`
		GotS      string `json:"gotS"`
	} `json:"mismatches"`
	Threw []struct {
		Name      string `json:"name"`
		CaseIndex int    `json:"caseIndex"`
		Error     string `json:"error"`
	} `json:"threw"`
}

// ---------------------------------------------------------------------------
// compile + golden helpers (skip-on-error variants of compilePipeline/evalCase)
// ---------------------------------------------------------------------------

func tryCompile(src string) (*pipeline.Pipeline, error) {
	f, err := cadishfile.Parse("gen.cadish", []byte(src))
	if err != nil {
		return nil, err
	}
	if len(f.Sites) != 1 {
		return nil, fmt.Errorf("want exactly 1 site, got %d", len(f.Sites))
	}
	return pipeline.Compile(f.Sites[0])
}

// safeEval runs evalCase but recovers a panic into an error, so one pathological
// generated case cannot abort the whole sweep (a panic is itself reported, as it
// would be a real pipeline bug).
func safeEval(p *pipeline.Pipeline, c kase) (dec decision, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("evalCase panic: %v", r)
		}
	}()
	return evalCase(p, c), nil
}

// ---------------------------------------------------------------------------
// generator
// ---------------------------------------------------------------------------

type jsonRef struct {
	header bool // true: header_json; false: cookie_json
	name   string
	field  string
	val    string // a value the matcher accepts (so a request can be built to match)
}

// genHint records what a generated config referenced, so the request generator can
// build requests that actually exercise the matchers/tokens, and so the sweep can
// report coverage.
type genHint struct {
	hosts         []string
	cookieNames   []string
	headerNames   []string
	jsonRefs      []jsonRef
	queryKeys     []string
	fromHeaders   []string
	respHeader    string
	respHeaderVal string

	usesDevice bool
	usesGeo    bool
	usesGeoC   bool
	usesGeoR   bool
	hasOnError bool

	directives map[string]bool
}

func (h *genHint) dir(d string) { h.directives[d] = true }

var (
	genUAs = []string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"curl/8.4.0",
		"",
	}
	genQVals = []string{
		"red", "a b", "a+b", "x%2Fy", "val;semi", "ünïcode", "𝔘astral", "UPPER",
		"with=eq", "", "1e3", "1.0", "café",
	}
	genCookieVals = []string{
		"secret", "1", "registered", "usd", "true", "a+b", "\"quoted\"", "a%20b", "ünï",
	}
	genGeoCountries  = []string{"US", "DE", "FR", "GB", "JP"}
	genGeoContinents = []string{"EU", "NA", "AS", "OC"}
	genGeoRegions    = []string{"US-TX", "US-UT", "US-CA", "DE-BE"}
	genMethods       = []string{"GET", "GET", "GET", "POST", "HEAD", "PUT"}
)

func pick[T any](rng *rand.Rand, xs []T) T { return xs[rng.Intn(len(xs))] }

func chance(rng *rand.Rand, p float64) bool { return rng.Float64() < p }

// genConfig synthesizes one valid Cadishfile + the hint describing it.
func genConfig(rng *rand.Rand) (string, genHint) {
	h := genHint{directives: map[string]bool{}}
	var b strings.Builder

	// --- site hosts ---
	hosts := []string{"example.com"}
	siteLabel := "example.com"
	if chance(rng, 0.4) {
		siteLabel = "example.com, *.example.com"
		hosts = append(hosts, "shop.example.com", "www.example.com")
	}
	if chance(rng, 0.25) {
		// a dedicated apex some host matchers key on
		hosts = append(hosts, "adult.example.com")
	}
	h.hosts = hosts
	b.WriteString(siteLabel + " {\n")

	// --- named matchers ---
	type named struct {
		name     string
		kind     string
		reqPhase bool // matches in the REQUEST phase (can scope pass/redirect/cache_key/classify)
	}
	var matchers []named
	nm := rng.Intn(4)
	for i := 0; i < nm; i++ {
		name := fmt.Sprintf("@m%d", i)
		switch rng.Intn(12) {
		case 0:
			hn := fmt.Sprintf("X-H%d", i)
			fmt.Fprintf(&b, "    %s header %s val%d\n", name, hn, i)
			h.headerNames = append(h.headerNames, hn)
			matchers = append(matchers, named{name, "header", true})
		case 1:
			hn := fmt.Sprintf("X-P%d", i)
			fmt.Fprintf(&b, "    %s header_present %s\n", name, hn)
			h.headerNames = append(h.headerNames, hn)
			matchers = append(matchers, named{name, "header_present", true})
		case 2:
			fmt.Fprintf(&b, "    %s path /seg%d/*\n", name, i)
			matchers = append(matchers, named{name, "path", true})
		case 3:
			fmt.Fprintf(&b, "    %s path_regex ^/re%d/\n", name, i)
			matchers = append(matchers, named{name, "path_regex", true})
		case 4:
			fmt.Fprintf(&b, "    %s host adult.example.com\n", name)
			matchers = append(matchers, named{name, "host", true})
		case 5:
			fmt.Fprintf(&b, "    %s host_regex ^shop\\.\n", name)
			matchers = append(matchers, named{name, "host_regex", true})
		case 6:
			fmt.Fprintf(&b, "    %s content_type text/html\n", name)
			matchers = append(matchers, named{name, "content_type", false})
		case 7:
			fmt.Fprintf(&b, "    %s set_cookie\n", name)
			matchers = append(matchers, named{name, "set_cookie", false})
		case 8:
			cn := fmt.Sprintf("c%d", i)
			if chance(rng, 0.5) {
				fmt.Fprintf(&b, "    %s cookie %s\n", name, cn)
			} else {
				fmt.Fprintf(&b, "    %s cookie %s val%d\n", name, cn, i)
			}
			h.cookieNames = append(h.cookieNames, cn)
			matchers = append(matchers, named{name, "cookie", true})
		case 9:
			cn := fmt.Sprintf("jc%d", i)
			field := pick(rng, []string{"role", "tier", "flags.0.kind", "a.b"})
			val := pick(rng, []string{"admin", "pro", "gate", "yes"})
			fmt.Fprintf(&b, "    %s cookie_json %s %s %s\n", name, cn, field, val)
			h.cookieNames = append(h.cookieNames, cn)
			h.jsonRefs = append(h.jsonRefs, jsonRef{false, cn, field, val})
			matchers = append(matchers, named{name, "cookie_json", true})
		case 10:
			hn := fmt.Sprintf("X-J%d", i)
			field := pick(rng, []string{"role", "plan.tier", "a.b"})
			val := pick(rng, []string{"admin", "pro", "enterprise"})
			fmt.Fprintf(&b, "    %s header_json %s %s %s\n", name, hn, field, val)
			h.headerNames = append(h.headerNames, hn)
			h.jsonRefs = append(h.jsonRefs, jsonRef{true, hn, field, val})
			matchers = append(matchers, named{name, "header_json", true})
		case 11:
			if chance(rng, 0.5) {
				fmt.Fprintf(&b, "    %s geo continent EU\n", name)
				h.usesGeo = true
			} else {
				fmt.Fprintf(&b, "    %s geo region US-TX US-UT\n", name)
				h.usesGeo = true
			}
			matchers = append(matchers, named{name, "geo", true})
		}
	}
	pickMatcher := func() (string, bool) {
		if len(matchers) == 0 {
			return "", false
		}
		return matchers[rng.Intn(len(matchers))].name, true
	}
	// pickReqMatcher returns a REQUEST-phase matcher (the only kind that may scope
	// pass/redirect/cache_key/classify/cache_credentialed — response-phase matchers
	// like content_type/set_cookie are rejected there by the compiler).
	pickReqMatcher := func() (string, bool) {
		var req []string
		for _, m := range matchers {
			if m.reqPhase {
				req = append(req, m.name)
			}
		}
		if len(req) == 0 {
			return "", false
		}
		return req[rng.Intn(len(req))], true
	}

	// --- query_present matcher (its own line; consumes the rest as globs) ---
	if chance(rng, 0.3) {
		qk := fmt.Sprintf("qp%d", rng.Intn(3))
		fmt.Fprintf(&b, "    @qp query_present %s t ff-*\n", qk)
		h.queryKeys = append(h.queryKeys, qk, "ff-x")
		matchers = append(matchers, named{"@qp", "query_present", true})
	}

	// --- classify block ---
	var classifyTok string
	derivesActive := false
	if chance(rng, 0.35) {
		classifyTok = "age"
		b.WriteString("    classify {age} {\n")
		// derives_from cookie axes — the COOKIE-NORM strip/forward seam (the credential/
		// forward gate, Findings 1/2; where real Go≠JS divergences lived). A `forward`
		// axis is KEPT to origin; a bare axis is STRIPPED post-key.
		if chance(rng, 0.5) {
			derivesActive = true
			sc := fmt.Sprintf("Strip%d", rng.Intn(3))
			b.WriteString("        derives_from cookie " + sc + "\n")
			h.cookieNames = append(h.cookieNames, sc)
			h.dir("derives_from")
		}
		if chance(rng, 0.4) {
			derivesActive = true
			fc := fmt.Sprintf("Keep%d", rng.Intn(3))
			b.WriteString("        derives_from cookie " + fc + " forward\n")
			h.cookieNames = append(h.cookieNames, fc)
			h.dir("derives_from_forward")
		}
		if mn, ok := pickReqMatcher(); ok {
			fmt.Fprintf(&b, "        when %s -> gate\n", mn)
		} else {
			b.WriteString("        when cookie verified -> gate\n")
			h.cookieNames = append(h.cookieNames, "verified")
		}
		b.WriteString("        default -> open\n    }\n")
		h.dir("classify")
	}

	// --- normalize block ---
	var normTok string
	if chance(rng, 0.3) {
		normTok = "curr"
		src := pick(rng, []string{"cookie currency", "header X-Curr", "query cur"})
		fmt.Fprintf(&b, "    normalize curr {\n        from %s\n        map USD,usd -> usd\n        map EUR -> eur\n        default usd\n    }\n", src)
		switch {
		case strings.HasPrefix(src, "cookie"):
			h.cookieNames = append(h.cookieNames, "currency")
		case strings.HasPrefix(src, "header"):
			h.headerNames = append(h.headerNames, "X-Curr")
		default:
			h.queryKeys = append(h.queryKeys, "cur")
		}
		h.dir("normalize")
	}

	// --- tenant block ---
	usesTenant := false
	if chance(rng, 0.25) {
		b.WriteString("    tenant {\n        from host\n        map *.example.com -> main\n        default other\n    }\n")
		usesTenant = true
		h.dir("tenant")
	}

	// --- respond / on_error ---
	if chance(rng, 0.25) {
		b.WriteString("    respond /health-check 200 \"OK\"\n")
		h.dir("respond")
	}
	if chance(rng, 0.3) {
		b.WriteString("    respond on_error 503 \"origin down\"\n")
		h.hasOnError = true
		h.dir("respond_on_error")
	}

	// --- redirect ---
	if chance(rng, 0.3) {
		if chance(rng, 0.5) {
			b.WriteString("    redirect ^/old/(.*)$ 301 https://{host}/new/$1\n")
		} else if mn, ok := pickReqMatcher(); ok {
			fmt.Fprintf(&b, "    redirect %s 302 https://verify.{host}/\n", mn)
		} else {
			b.WriteString("    redirect ^/x/(.*)$ 302 https://{host}/y/$1\n")
		}
		h.dir("redirect")
	}

	// --- pass ---
	if chance(rng, 0.4) {
		if mn, ok := pickReqMatcher(); ok && chance(rng, 0.6) {
			fmt.Fprintf(&b, "    pass %s\n", mn)
		} else {
			b.WriteString("    pass method POST\n")
		}
		h.dir("pass")
	}

	// --- cache_key (always) ---
	// Build a token list; the GREEDY query_allow/query_strip token (consumes trailing
	// bare globs) goes LAST. Scoped recipes sometimes precede the default recipe.
	buildKey := func() string {
		var toks []string
		// A greedy trailing query selector (query_allow/query_strip) cannot combine with a
		// full-query token (`query` or `url`) — decide it first so the base excludes those.
		greedy := chance(rng, 0.3)
		base := []string{"method", "host", "path", "url", "query"}
		if greedy {
			base = []string{"method", "host", "path"}
		}
		// always include at least host+path or url
		if greedy || chance(rng, 0.5) {
			toks = append(toks, "host", "path")
		} else {
			toks = append(toks, "url")
		}
		for _, t := range base {
			if chance(rng, 0.25) {
				toks = append(toks, t)
			}
		}
		if len(h.headerNames) > 0 && chance(rng, 0.4) {
			toks = append(toks, "header:"+pick(rng, h.headerNames))
		}
		if len(h.cookieNames) > 0 && chance(rng, 0.4) {
			toks = append(toks, "cookie:"+pick(rng, h.cookieNames))
		}
		if chance(rng, 0.3) {
			toks = append(toks, "{device}")
			h.usesDevice = true
		}
		if chance(rng, 0.25) {
			toks = append(toks, "{geo}")
			h.usesGeo = true
		}
		if chance(rng, 0.2) {
			toks = append(toks, "{geo.continent}")
			h.usesGeoC = true
		}
		if chance(rng, 0.2) {
			toks = append(toks, "{geo.region}")
			h.usesGeoR = true
		}
		if classifyTok != "" && (derivesActive || chance(rng, 0.6)) {
			// when derives_from is active the recipe MUST reference {age} for the strip/
			// forward seam to engage, so force it in then.
			toks = append(toks, "{"+classifyTok+"}")
		}
		if normTok != "" && chance(rng, 0.6) {
			toks = append(toks, "{"+normTok+"}")
		}
		if usesTenant && chance(rng, 0.6) {
			toks = append(toks, "{tenant}")
		}
		// greedy trailing token (at most one; decided above, excludes url/query)
		if greedy {
			qk := fmt.Sprintf("qk%d", rng.Intn(3))
			h.queryKeys = append(h.queryKeys, qk, "ff-y")
			if chance(rng, 0.5) {
				toks = append(toks, "query_allow", qk, "ff-*")
			} else {
				toks = append(toks, "query_strip", qk, "utm_*")
			}
		}
		return strings.Join(toks, " ")
	}
	// Request-phase header (BEFORE cache_key → forwarded to origin) reflecting a class
	// token, to fuzz the request-phase class-token neutralization (maskedValueContext /
	// maskedValueRequest, F-A1/ISO): when the SELECTED recipe does not key on the class,
	// both engines must blank the forwarded value identically. Emitted before the cache_key
	// block so it lands in reqHeaderRules (pastKey false).
	if chance(rng, 0.35) {
		classTok := pick(rng, []string{"{device}", "{geo}", "{geo.continent}", "{geo.region}"})
		fmt.Fprintf(&b, "    header X-Req-Class %s\n", classTok)
		h.dir("header")
	}
	scoped := false
	if mn, ok := pickReqMatcher(); ok && chance(rng, 0.3) {
		fmt.Fprintf(&b, "    cache_key %s %s\n", mn, buildKey())
		scoped = true
	}
	fmt.Fprintf(&b, "    cache_key default %s\n", buildKey())
	_ = scoped
	h.dir("cache_key")

	// --- cache_ttl (always default + extras) ---
	if chance(rng, 0.3) {
		b.WriteString("    cache_ttl status 404 410 ttl 60s grace 1h\n")
	}
	if chance(rng, 0.25) {
		b.WriteString("    cache_ttl status not 200 hit_for_miss 5s\n")
	}
	if chance(rng, 0.25) {
		b.WriteString("    cache_ttl resp_header X-Powered-By Express ttl 1m grace 24h\n")
		h.respHeader, h.respHeaderVal = "X-Powered-By", "Express"
	}
	if chance(rng, 0.3) {
		hn := "X-Cache-Ttl"
		if mn, ok := pickMatcher(); ok {
			fmt.Fprintf(&b, "    cache_ttl %s from_header %s grace 30s\n", mn, hn)
			h.fromHeaders = append(h.fromHeaders, hn)
		}
	}
	// max_stale + grace variety on default. The compiler requires max_stale >= grace,
	// so derive max_stale from the grace seconds when both are present.
	def := "    cache_ttl default ttl " + strconv.Itoa(1+rng.Intn(120)) + "s"
	graceSec := 0
	if chance(rng, 0.5) {
		graceSec = 1 + rng.Intn(600)
		def += " grace " + strconv.Itoa(graceSec) + "s"
	}
	if chance(rng, 0.4) {
		def += " max_stale " + strconv.Itoa(graceSec+1+rng.Intn(120)) + "s"
	}
	b.WriteString(def + "\n")
	h.dir("cache_ttl")

	// --- storage ---
	if chance(rng, 0.3) {
		tier := pick(rng, []string{"ram", "disk"})
		if mn, ok := pickMatcher(); ok && chance(rng, 0.5) {
			fmt.Fprintf(&b, "    storage %s -> %s\n", mn, tier)
		}
		fmt.Fprintf(&b, "    storage default -> %s\n", pick(rng, []string{"ram", "disk"}))
		h.dir("storage")
	}

	// --- strip_cookies ---
	if chance(rng, 0.25) {
		if mn, ok := pickMatcher(); ok && chance(rng, 0.5) {
			fmt.Fprintf(&b, "    strip_cookies %s\n", mn)
		} else {
			b.WriteString("    strip_cookies path_regex \\.(css|js|png)$\n")
		}
		h.dir("strip_cookies")
	}

	// --- cors ---
	if chance(rng, 0.2) {
		b.WriteString("    cors https://app.example.com methods GET POST OPTIONS headers Content-Type X-Token\n")
		h.dir("cors")
	}

	// --- cache_unsafe ---
	if chance(rng, 0.15) {
		b.WriteString("    cache_unsafe\n")
		h.dir("cache_unsafe")
	}

	// --- cache_credentialed ---
	if mn, ok := pickReqMatcher(); ok && chance(rng, 0.2) {
		fmt.Fprintf(&b, "    cache_credentialed %s\n", mn)
		h.dir("cache_credentialed")
	}

	// --- cookie_allow ---
	if chance(rng, 0.2) {
		if chance(rng, 0.5) {
			b.WriteString("    cookie_allow lang darkMode wp_logged_in_*\n")
			h.cookieNames = append(h.cookieNames, "lang", "darkMode")
		} else {
			b.WriteString("    cookie_allow\n")
		}
		h.dir("cookie_allow")
	}

	// --- encode (DELEGATED on purpose: exercises the skip path) ---
	if chance(rng, 0.08) {
		b.WriteString("    encode gzip\n")
		h.dir("encode")
	}

	// --- header directives ---
	b.WriteString("    header +cache_status X-Cache\n")
	if chance(rng, 0.6) {
		if chance(rng, 0.5) {
			b.WriteString("    header +cache_key X-Key raw\n")
		} else {
			b.WriteString("    header +cache_key X-Cache-Key\n")
		}
	}
	if chance(rng, 0.3) {
		b.WriteString("    header -Server\n")
	}
	if h.usesGeo && chance(rng, 0.4) {
		b.WriteString("    header X-Geo {geo}\n")
	}
	if chance(rng, 0.2) {
		b.WriteString("    header X-Client {client_ip}\n")
	}
	if chance(rng, 0.2) {
		b.WriteString("    header Access-Control-Allow-Origin {http.Origin}\n")
	}
	if mn, ok := pickMatcher(); ok && chance(rng, 0.3) {
		fmt.Fprintf(&b, "    header %s X-Flag 1\n", mn)
	}

	b.WriteString("}\n")
	return b.String(), h
}

// genCases builds a handful of varied requests for a config.
func genCases(rng *rand.Rand, h genHint) []kase {
	n := 1 + rng.Intn(3)
	out := make([]kase, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, genCase(rng, h))
	}
	return out
}

func genCase(rng *rand.Rand, h genHint) kase {
	req := reqInput{
		Method: pick(rng, genMethods),
		Host:   pick(rng, h.hosts),
		Header: map[string][]string{},
		Query:  map[string][]string{},
		TLS:    chance(rng, 0.5),
	}

	// path: sometimes match a path/path_regex matcher
	switch rng.Intn(6) {
	case 0:
		req.Path = "/seg0/item"
	case 1:
		req.Path = "/re0/x"
	case 2:
		req.Path = "/old/page"
	case 3:
		req.Path = "/health-check"
	case 4:
		req.Path = "/panel/settings"
	default:
		req.Path = "/p/" + pick(rng, []string{"a", "b", "café", "x y"})
	}

	// query: referenced keys + noise, multi-value + special values
	addQ := func(k string) {
		nv := 1 + rng.Intn(2)
		for j := 0; j < nv; j++ {
			req.Query[k] = append(req.Query[k], pick(rng, genQVals))
		}
	}
	for _, qk := range h.queryKeys {
		if chance(rng, 0.6) {
			addQ(qk)
		}
	}
	if chance(rng, 0.5) {
		addQ("utm_source")
	}
	if chance(rng, 0.5) {
		addQ(pick(rng, []string{"color", "size", "q", "ff-x"}))
	}

	// cookies: single line vs multi-line; referenced names + noise
	var cookiePairs []string
	cookiePairs = append(cookiePairs, "a=1")
	for _, cn := range h.cookieNames {
		if chance(rng, 0.6) {
			// is this a json cookie?
			isJSON := false
			for _, jr := range h.jsonRefs {
				if !jr.header && jr.name == cn {
					isJSON = true
					if chance(rng, 0.6) {
						cookiePairs = append(cookiePairs, cn+"="+jsonObjFor(jr))
					} else {
						cookiePairs = append(cookiePairs, cn+"={}")
					}
					break
				}
			}
			if !isJSON {
				cookiePairs = append(cookiePairs, cn+"="+pick(rng, genCookieVals))
			}
		}
	}
	if len(cookiePairs) > 0 {
		if chance(rng, 0.45) {
			// multi-line Cookie (the class that surfaced the 62 divergence)
			for _, p := range cookiePairs {
				req.Header["Cookie"] = append(req.Header["Cookie"], p)
			}
		} else {
			req.Header["Cookie"] = []string{strings.Join(cookiePairs, "; ")}
		}
	}

	// header_json + plain header matchers
	for _, hn := range h.headerNames {
		if !chance(rng, 0.6) {
			continue
		}
		var jr *jsonRef
		for k := range h.jsonRefs {
			if h.jsonRefs[k].header && h.jsonRefs[k].name == hn {
				jr = &h.jsonRefs[k]
				break
			}
		}
		// case-vary the header NAME sometimes
		name := hn
		if chance(rng, 0.3) {
			name = strings.ToLower(hn)
		}
		if jr != nil {
			if chance(rng, 0.4) {
				// multi-line header_json (the class that surfaced the 63 divergence)
				req.Header[name] = append(req.Header[name], "{}", jsonObjFor(*jr))
			} else {
				req.Header[name] = append(req.Header[name], jsonObjFor(*jr))
			}
		} else {
			val := "val0"
			if chance(rng, 0.3) {
				// multi-value plain header
				req.Header[name] = append(req.Header[name], "x", val)
			} else {
				req.Header[name] = append(req.Header[name], val)
			}
		}
	}
	// from_header control headers
	for _, fh := range h.fromHeaders {
		if chance(rng, 0.6) {
			req.Header[fh] = []string{pick(rng, []string{"30s", "1m", "0s", "bogus"})}
		}
	}
	if h.respHeaderVal != "" {
		// X-Curr / currency etc. handled above; nothing here
	}
	// User-Agent (device classification)
	if h.usesDevice || chance(rng, 0.3) {
		if ua := pick(rng, genUAs); ua != "" {
			req.Header["User-Agent"] = []string{ua}
		}
	}
	// Origin header for CORS dynamic
	if chance(rng, 0.3) {
		req.Header["Origin"] = []string{"https://app.example.com"}
	}
	// client IP
	if chance(rng, 0.6) {
		req.ClientIP = pick(rng, []string{"203.0.113.7", "198.51.100.9", "2001:db8::1"})
	}
	// geo inputs
	if h.usesGeo || chance(rng, 0.3) {
		req.Geo = pick(rng, genGeoCountries)
	}
	if h.usesGeoC || chance(rng, 0.3) {
		req.GeoContinent = pick(rng, genGeoContinents)
	}
	if h.usesGeoR || chance(rng, 0.3) {
		req.GeoRegion = pick(rng, genGeoRegions)
	}
	// explicit device sometimes (overrides UA classification)
	if chance(rng, 0.2) {
		req.Device = pick(rng, []string{"mobile", "desktop", "tablet", "bot"})
	}

	// origin response
	origin := originResp{
		Status: pick(rng, []int{200, 200, 200, 404, 410, 500, 503, 302}),
		Header: map[string][]string{},
	}
	origin.Header["Content-Type"] = []string{pick(rng, []string{"text/html", "text/css", "application/json"})}
	if chance(rng, 0.3) {
		origin.Header["Set-Cookie"] = []string{"sid=abc; Path=/"}
	}
	if h.respHeader != "" && chance(rng, 0.6) {
		origin.Header[h.respHeader] = []string{h.respHeaderVal}
	}

	c := kase{
		Request:     req,
		Origin:      origin,
		CacheStatus: pick(rng, []string{"MISS", "MISS", "HIT", "HIT-STALE"}),
	}

	// outage probe (only meaningful when on_error / negative cache may fire)
	if chance(rng, 0.2) {
		c.OriginFailed = true
		c.Salvageable = chance(rng, 0.3)
		if chance(rng, 0.6) {
			c.OutageStatus = pick(rng, []int{500, 503, 404, 410, 403, 429})
		}
	}
	return c
}

// jsonObjFor builds a JSON value a cookie_json/header_json matcher with the given
// field/val accepts (supports a dotted field path and array index).
func jsonObjFor(jr jsonRef) string {
	parts := strings.Split(jr.field, ".")
	// build from the inside out
	var val string
	// leaf value: quote unless it looks numeric
	if _, err := strconv.ParseFloat(jr.val, 64); err == nil {
		val = jr.val
	} else {
		val = strconv.Quote(jr.val)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if idx, err := strconv.Atoi(p); err == nil {
			// array index: build an array of idx+1 elements with the value at idx
			elems := make([]string, idx+1)
			for k := range elems {
				elems[k] = "null"
			}
			elems[idx] = val
			val = "[" + strings.Join(elems, ",") + "]"
		} else {
			val = "{" + strconv.Quote(p) + ":" + val + "}"
		}
	}
	return val
}

// ---------------------------------------------------------------------------
// the sweep
// ---------------------------------------------------------------------------

// sweepStats records what the generative run actually exercised.
type sweepStats struct {
	generated     int
	compileErrors int
	forcedPass    int
	delegated     int
	asserted      int // configs that reached the Go==JS assertion
	cases         int
	matcherKinds  map[string]bool
	tokenKinds    map[string]bool
	directives    map[string]bool
}

func newSweepStats() *sweepStats {
	return &sweepStats{
		matcherKinds: map[string]bool{},
		tokenKinds:   map[string]bool{},
		directives:   map[string]bool{},
	}
}

// keyTokenKinds decodes the cache-key token kinds present in a projected IR.
func keyTokenKinds(irJSON []byte) map[string]bool {
	var v struct {
		Key struct {
			Tokens []struct {
				Kind string `json:"kind"`
			} `json:"tokens"`
			Recipes []struct {
				Tokens []struct {
					Kind string `json:"kind"`
				} `json:"tokens"`
			} `json:"recipes"`
		} `json:"key"`
	}
	out := map[string]bool{}
	if err := json.Unmarshal(irJSON, &v); err != nil {
		return out
	}
	for _, t := range v.Key.Tokens {
		out[t.Kind] = true
	}
	for _, r := range v.Key.Recipes {
		for _, t := range r.Tokens {
			out[t.Kind] = true
		}
	}
	return out
}

// buildBatch generates `count` configs from the seed, compiles+projects each, and for
// every FULLY edge-native one (ForcedPass==0 && Delegated==0) computes the Go golden
// and appends it to the batch. It returns the batch, a name->config map (for reporting
// a failure), and the coverage/skip stats.
func buildBatch(seedBase int64, count int, st *sweepStats) (genBatch, map[string]string) {
	var batch genBatch
	configs := map[string]string{}
	for i := 0; i < count; i++ {
		rng := rand.New(rand.NewSource(seedBase + int64(i)))
		src, hint := genConfig(rng)
		cases := genCases(rng, hint)
		st.generated++

		p, err := tryCompile(src)
		if err != nil {
			st.compileErrors++
			continue
		}
		ir, rep, err := edgeir.Project(p)
		if err != nil {
			st.compileErrors++
			continue
		}
		if rep.ForcedPass > 0 {
			st.forcedPass++
			continue
		}
		if rep.Delegated > 0 {
			st.delegated++
			continue
		}

		// coverage: matcher kinds + token kinds from the IR, directives from the hint
		irJSON, _ := json.Marshal(ir)
		for k := range collectMatcherKinds(irJSON) {
			st.matcherKinds[k] = true
		}
		for k := range keyTokenKinds(irJSON) {
			st.tokenKinds[k] = true
		}
		for d := range hint.directives {
			st.directives[d] = true
		}

		name := fmt.Sprintf("gen-%d", seedBase+int64(i))
		item := genBatchItem{Name: name, IR: ir}
		bad := false
		for _, c := range cases {
			dec, err := safeEval(p, c)
			if err != nil {
				// a Go-side panic is a real bug; surface it loudly via a sentinel batch.
				configs[name] = src + "\n// PANIC: " + err.Error()
				bad = true
				break
			}
			wantJSON, _ := json.Marshal(dec)
			item.Cases = append(item.Cases, genBatchCase{Input: toJSInput(c), Want: wantJSON})
		}
		if bad {
			// still record the config so the failure is reportable; skip JS (no golden)
			continue
		}
		configs[name] = src
		batch.Batches = append(batch.Batches, item)
		st.asserted++
		st.cases += len(item.Cases)
	}
	return batch, configs
}

func toJSInput(c kase) jsInput {
	return jsInput{
		reqInput:     c.Request,
		Origin:       c.Origin,
		CacheStatus:  c.CacheStatus,
		Body:         c.Body,
		IsHead:       c.IsHead,
		IsRange:      c.IsRange,
		OriginFailed: c.OriginFailed,
		Salvageable:  c.Salvageable,
		OutageStatus: c.OutageStatus,
	}
}

// runDriver writes the batch to a temp file and runs parity_driver.mjs over it,
// returning the parsed result. Skips (via t.Skip) when node is unavailable.
func runDriver(t *testing.T, batch genBatch) driverResult {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH — skipping generative Go==JS parity (the JS half also runs under npm test)")
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "batch.json")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	driver := "parity_driver.mjs"
	cmd := exec.Command(node, driver, tmp)
	out, runErr := cmd.Output()
	var res driverResult
	if len(out) > 0 {
		if jerr := json.Unmarshal(out, &res); jerr != nil {
			t.Fatalf("driver output not JSON (%v): %s", jerr, string(out))
		}
	} else if runErr != nil {
		t.Fatalf("driver failed with no output: %v", runErr)
	}
	return res
}

// reportFailures fails the test with the minimized (config, case index, want/got) for
// each divergence — the CRITICAL Go≠JS-not-failed-closed signal.
func reportFailures(t *testing.T, res driverResult, configs map[string]string) {
	for _, m := range res.Threw {
		t.Errorf("JS interpreter THREW on a fully edge-native config (Go produced a golden, JS crashed) — %s case %d:\n%s\nCONFIG:\n%s",
			m.Name, m.CaseIndex, m.Error, configs[m.Name])
	}
	for _, m := range res.Mismatches {
		t.Errorf("CRITICAL Go≠JS divergence (fully edge-native, NOT fail-closed) — %s case %d\n  GoWant: %s\n  JSGot:  %s\nCONFIG:\n%s",
			m.Name, m.CaseIndex, m.WantS, m.GotS, configs[m.Name])
	}
}

// TestEdgeParityGenerative is the deterministic generative parity guard. It sweeps a
// FIXED seed range (size PARITY_GEN_N, default 200 — kept small so `go test ./...`
// stays fast), asserting Go==JS for every fully edge-native generated config. Same
// seeds every run ⇒ never flaky. Set PARITY_GEN_N higher (e.g. 5000) for deep local
// exploration. PARITY_GEN_SEED shifts the base seed to explore a different slice.
func TestEdgeParityGenerative(t *testing.T) {
	n := 200
	if v := os.Getenv("PARITY_GEN_N"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	base := int64(1)
	if v := os.Getenv("PARITY_GEN_SEED"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			base = parsed
		}
	}

	st := newSweepStats()
	batch, configs := buildBatch(base, n, st)
	res := runDriver(t, batch)
	reportFailures(t, res, configs)

	t.Logf("generative sweep: generated=%d compileErr=%d forcedPass=%d delegated=%d asserted=%d cases=%d",
		st.generated, st.compileErrors, st.forcedPass, st.delegated, st.asserted, st.cases)
	t.Logf("coverage matcherKinds=%s", sortedKeys(st.matcherKinds))
	t.Logf("coverage tokenKinds=%s", sortedKeys(st.tokenKinds))
	t.Logf("coverage directives=%s", sortedKeys(st.directives))
	if st.asserted == 0 {
		t.Fatal("no fully edge-native configs were asserted — the generator or skip gate is broken")
	}
}

func sortedKeys(m map[string]bool) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	// simple insertion sort to avoid importing sort twice (sort is already imported elsewhere in pkg)
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return strings.Join(ks, ",")
}

// FuzzEdgeParity is the on-demand deep explorer: `go test -fuzz=FuzzEdgeParity
// -fuzztime=2m`. Each fuzz input deterministically seeds the SAME generator; the seed
// corpus (f.Add below) runs as ordinary subtests under `go test`, giving a small fixed
// set of generated configs that are checked Go==JS every CI run. Native coverage-guided
// fuzzing then expands the space on demand. Skips when node is unavailable.
func FuzzEdgeParity(f *testing.F) {
	for _, s := range [][]byte{
		[]byte("seed-a"), []byte("seed-b"), []byte("seed-c"),
		[]byte("cookie-multiline"), []byte("header-json"),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		hsh := fnv.New64a()
		_, _ = hsh.Write(data)
		seed := int64(hsh.Sum64() & 0x7fffffffffffffff)

		st := newSweepStats()
		// one config per fuzz input (a few requests each); single node call.
		batch, configs := buildBatch(seed, 1, st)
		if len(batch.Batches) == 0 {
			return // generated a non-edge-native/uncompilable config; nothing to assert
		}
		res := runDriver(t, batch)
		reportFailures(t, res, configs)
	})
}
