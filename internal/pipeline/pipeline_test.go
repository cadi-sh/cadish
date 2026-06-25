package pipeline

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// compileSrc parses a single-site config string and compiles it, failing the test
// on any parse/compile error.
func compileSrc(t *testing.T, src string) *Pipeline {
	t.Helper()
	f, err := cadishfile.Parse("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("want exactly 1 site, got %d", len(f.Sites))
	}
	p, err := Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// compileErr expects compilation to fail and returns the *CompileError.
func compileErr(t *testing.T, src string) *CompileError {
	t.Helper()
	f, err := cadishfile.Parse("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(f.Sites))
	}
	_, err = Compile(f.Sites[0])
	if err == nil {
		t.Fatal("want compile error, got nil")
	}
	ce, ok := err.(*CompileError)
	if !ok {
		t.Fatalf("want *CompileError, got %T: %v", err, err)
	}
	return ce
}

func TestEvalRequestPassFirstMatch(t *testing.T) {
	p := compileSrc(t, `x {
		@ajax header X-Requested-With XMLHttpRequest
		@nocache path /panel/*
		pass @ajax
		pass method POST
		pass @nocache
	}
`)
	tests := []struct {
		name string
		req  *Request
		want bool
	}{
		{"ajax", &Request{Method: "GET", Path: "/", Header: http.Header{"X-Requested-With": {"XMLHttpRequest"}}}, true},
		{"post", &Request{Method: "POST", Path: "/"}, true},
		{"nocache-path", &Request{Method: "GET", Path: "/panel/settings"}, true},
		{"plain", &Request{Method: "GET", Path: "/home"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.EvalRequest(tt.req).Pass; got != tt.want {
				t.Errorf("Pass = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvalRequestRespond(t *testing.T) {
	p := compileSrc(t, "x {\n respond /health-check 200 \"OK\"\n}\n")
	dec := p.EvalRequest(&Request{Method: "GET", Path: "/health-check"})
	if dec.Synthetic == nil || dec.Synthetic.Status != 200 || dec.Synthetic.Body != "OK" {
		t.Fatalf("respond synthetic = %+v, want {200 OK}", dec.Synthetic)
	}
	dec2 := p.EvalRequest(&Request{Method: "GET", Path: "/other"})
	if dec2.Synthetic != nil {
		t.Errorf("non-matching path should not be synthetic, got %+v", dec2.Synthetic)
	}
}

// TestEvalRequestRespondScoped exercises the scoped `respond @scope STATUS BODY`
// form (the terminal no-match 404 the ingress translator emits). The scope is a
// conjunction of (optionally `!`-negated) matcher refs, identical to the security
// gate's grammar; here `respond !@a !@b 404` means "404 every path that matches
// NEITHER @a NOR @b" — i.e. the unmatched-path set, regardless of ordering.
func TestEvalRequestRespondScoped(t *testing.T) {
	p := compileSrc(t, `x {
		@exact path /exact
		@api path /api /api/*
		respond !@exact !@api 404
	}
`)
	// A covered path is NOT 404'd (scope conjunction has a non-negated miss).
	for _, covered := range []string{"/exact", "/api", "/api/sub"} {
		if dec := p.EvalRequest(&Request{Method: "GET", Path: covered}); dec.Synthetic != nil {
			t.Errorf("covered path %q should not be synthetic, got %+v", covered, dec.Synthetic)
		}
	}
	// Element-wise Prefix: /apiother must NOT be covered by @api, so it 404s.
	for _, unmatched := range []string{"/exact/sub", "/notexist", "/apiother", "/"} {
		dec := p.EvalRequest(&Request{Method: "GET", Path: unmatched})
		if dec.Synthetic == nil || dec.Synthetic.Status != 404 {
			t.Errorf("unmatched path %q should 404, got %+v", unmatched, dec.Synthetic)
		}
	}
}

func TestEvalRequestRoute(t *testing.T) {
	p := compileSrc(t, `x {
		upstream images { to https://s3 }
		@static host_regex ^static
		route @static -> images
	}
`)
	if up := p.EvalRequest(&Request{Host: "static.example.com", Path: "/i.jpg"}).Upstream; up != "images" {
		t.Errorf("Upstream = %q, want images", up)
	}
	if up := p.EvalRequest(&Request{Host: "www.example.com", Path: "/"}).Upstream; up != "" {
		t.Errorf("Upstream = %q, want empty", up)
	}
}

func TestEvalRequestPurge(t *testing.T) {
	p := compileSrc(t, `x {
		purge when header X-Purge-Token secret regex {http.X-Purge-Regex}
	}
`)
	dec := p.EvalRequest(&Request{
		Method: "PURGE", Path: "/",
		Header: http.Header{"X-Purge-Token": {"secret"}, "X-Purge-Regex": {`^/list/`}},
	})
	if dec.Purge == nil || !dec.Purge.Authorized {
		t.Fatalf("purge decision = %+v, want authorized", dec.Purge)
	}
	if dec.Purge.Regex != `^/list/` {
		t.Errorf("purge regex = %q, want ^/list/", dec.Purge.Regex)
	}
	// Wrong token -> no purge.
	dec2 := p.EvalRequest(&Request{Method: "PURGE", Path: "/", Header: http.Header{"X-Purge-Token": {"wrong"}}})
	if dec2.Purge != nil {
		t.Errorf("wrong token should not authorize purge, got %+v", dec2.Purge)
	}
}

func TestEvalResponseTTLFirstMatch(t *testing.T) {
	p := compileSrc(t, `x {
		upstream images { to https://s3 }
		@images upstream images
		route @images -> images
		cache_ttl status 404 410 ttl 60s grace 1h
		cache_ttl status not 200 hit_for_miss 5s
		cache_ttl @images ttl 24h grace 365d
		cache_ttl default ttl 2s grace 24h
	}
`)
	imgReq := &Request{Host: "x", Path: "/i.jpg", Query: url.Values{}}
	// Note: @images requires routed upstream. route @images -> images is circular
	// (route condition can't depend on upstream), so for the image case we route by
	// a separate path. Use host-based routing instead in this sub-test:
	_ = imgReq

	tests := []struct {
		name    string
		status  int
		req     *Request
		ttl     time.Duration
		grace   time.Duration
		hfm     time.Duration
		cacheok bool
	}{
		{"404", 404, &Request{Path: "/x"}, 60 * time.Second, time.Hour, 0, true},
		{"410", 410, &Request{Path: "/x"}, 60 * time.Second, time.Hour, 0, true},
		{"503-hfm", 503, &Request{Path: "/x"}, 0, 0, 5 * time.Second, false},
		{"200-default", 200, &Request{Path: "/x"}, 2 * time.Second, 24 * time.Hour, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := p.EvalResponse(tt.req, tt.status, nil)
			if d.TTL != tt.ttl || d.Grace != tt.grace || d.HitForMiss != tt.hfm || d.Cacheable != tt.cacheok {
				t.Errorf("EvalResponse(%d) = {ttl %v grace %v hfm %v cacheable %v}, want {ttl %v grace %v hfm %v cacheable %v}",
					tt.status, d.TTL, d.Grace, d.HitForMiss, d.Cacheable, tt.ttl, tt.grace, tt.hfm, tt.cacheok)
			}
		})
	}
}

func TestEvalResponseStorageTier(t *testing.T) {
	p := compileSrc(t, `x {
		upstream images { to https://s3 }
		@static host_regex ^static
		@images upstream images
		route @static -> images
		storage @images -> disk
		storage default -> ram
	}
`)
	// Routed to images (host static*) -> @images matches -> disk.
	if tier := p.EvalResponse(&Request{Host: "static.x.com", Path: "/i.jpg"}, 200, nil).StoreTier; tier != "disk" {
		t.Errorf("image StoreTier = %q, want disk", tier)
	}
	// Other host -> default ram.
	if tier := p.EvalResponse(&Request{Host: "www.x.com", Path: "/page"}, 200, nil).StoreTier; tier != "ram" {
		t.Errorf("default StoreTier = %q, want ram", tier)
	}
}

func TestEvalDeliverHeaderOps(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path
		header -Server -X-Powered-By
		header X-Frame-Options SAMEORIGIN
		header +cache_status X-Cache
	}
`)
	dec := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusHit)
	wantOps := []HeaderOp{
		{Op: OpRemove, Name: "Server"},
		{Op: OpRemove, Name: "X-Powered-By"},
		{Op: OpSet, Name: "X-Frame-Options", Value: "SAMEORIGIN"},
		{Op: OpSet, Name: "X-Cache", Value: "HIT"},
	}
	if len(dec.RespHeaderOps) != len(wantOps) {
		t.Fatalf("got %d ops, want %d: %+v", len(dec.RespHeaderOps), len(wantOps), dec.RespHeaderOps)
	}
	for i, w := range wantOps {
		if dec.RespHeaderOps[i] != w {
			t.Errorf("op[%d] = %+v, want %+v", i, dec.RespHeaderOps[i], w)
		}
	}
	if dec.CacheStatusHeader != "X-Cache" {
		t.Errorf("CacheStatusHeader = %q, want X-Cache", dec.CacheStatusHeader)
	}
	// MISS token.
	if got := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss).RespHeaderOps[3].Value; got != "MISS" {
		t.Errorf("cache_status MISS op value = %q, want MISS", got)
	}
}

// TestCacheKeyHash covers the pure hash helper: a 12-hex sha256 prefix, stable for
// a given key, distinct for distinct keys, empty for an empty key (no header).
func TestCacheKeyHash(t *testing.T) {
	const k1 = "GET\x1fexample.com\x1f/page"
	h1 := CacheKeyHash(k1)
	if len(h1) != 12 {
		t.Fatalf("hash len = %d, want 12 (%q)", len(h1), h1)
	}
	for _, c := range h1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("hash %q is not lower-hex", h1)
		}
	}
	if h1 != CacheKeyHash(k1) {
		t.Error("hash is not stable for the same key")
	}
	if CacheKeyHash("GET\x1fexample.com\x1f/other") == h1 {
		t.Error("distinct keys hashed to the same value")
	}
	if CacheKeyHash("") != "" {
		t.Error("empty key must hash to empty (header omitted)")
	}
	// Pin the exact prefix so a future change to the algorithm/format is caught and so
	// the value is verifiable against `printf … | shasum -a 256` (Go↔shell↔JS parity).
	if got := CacheKeyHash("hello"); got != "2cf24dba5fb0" {
		t.Errorf("CacheKeyHash(hello) = %q, want 2cf24dba5fb0", got)
	}
}

// TestCacheKeyHeaderValue covers the hash-default / raw-opt-in / no-key resolution.
func TestCacheKeyHeaderValue(t *testing.T) {
	const k = "GET\x1fexample.com\x1f/page"
	if got, want := CacheKeyHeaderValue(k, false), CacheKeyHash(k); got != want {
		t.Errorf("hash form = %q, want %q", got, want)
	}
	if got := CacheKeyHeaderValue(k, true); got != k {
		t.Errorf("raw form = %q, want the raw key %q", got, k)
	}
	if got := CacheKeyHeaderValue("", false); got != "" {
		t.Errorf("no key (hash) = %q, want empty", got)
	}
	if got := CacheKeyHeaderValue("", true); got != "" {
		t.Errorf("no key (raw) = %q, want empty", got)
	}
}

// TestEvalDeliverCacheKeyHeader covers the deliver-decision seam: the directive
// surfaces the target name + raw flag; it is NOT materialized into a RespHeaderOp
// (the key is server-held), and absent by default.
func TestEvalDeliverCacheKeyHeader(t *testing.T) {
	// Default (hash) form.
	p := compileSrc(t, `x {
		cache_key path
		header +cache_key X-Cache-Key
	}
`)
	dec := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if dec.CacheKeyHeader != "X-Cache-Key" {
		t.Errorf("CacheKeyHeader = %q, want X-Cache-Key", dec.CacheKeyHeader)
	}
	if dec.CacheKeyRaw {
		t.Error("CacheKeyRaw should be false for the hash form")
	}
	// The cache_key op must NOT appear as a materialized response header op (no key
	// available in the deliver match context — the server resolves it).
	for _, op := range dec.RespHeaderOps {
		if op.Name == "X-Cache-Key" {
			t.Errorf("cache_key op leaked into RespHeaderOps: %+v", op)
		}
	}

	// raw form.
	praw := compileSrc(t, `x {
		cache_key path
		header +cache_key X-Cache-Key raw
	}
`)
	rd := praw.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if rd.CacheKeyHeader != "X-Cache-Key" || !rd.CacheKeyRaw {
		t.Errorf("raw form: header=%q raw=%v, want X-Cache-Key true", rd.CacheKeyHeader, rd.CacheKeyRaw)
	}

	// Absent by default.
	pnone := compileSrc(t, `x {
		cache_key path
		header +cache_status X-Cache
	}
`)
	nd := pnone.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if nd.CacheKeyHeader != "" {
		t.Errorf("CacheKeyHeader = %q, want empty when no directive", nd.CacheKeyHeader)
	}
}

// TestEvalDeliverCacheKeyScoped covers scoped emission: the directive surfaces the
// header only when its @scope matches.
func TestEvalDeliverCacheKeyScoped(t *testing.T) {
	p := compileSrc(t, `x {
		@debug header X-Debug 1
		cache_key path
		header @debug +cache_key X-Cache-Key raw
	}
`)
	matched := p.EvalDeliver(&Request{Path: "/", Header: http.Header{"X-Debug": {"1"}}}, nil, CacheStatusMiss)
	if matched.CacheKeyHeader != "X-Cache-Key" || !matched.CacheKeyRaw {
		t.Errorf("scope matched: header=%q raw=%v, want X-Cache-Key true", matched.CacheKeyHeader, matched.CacheKeyRaw)
	}
	unmatched := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if unmatched.CacheKeyHeader != "" {
		t.Errorf("scope unmatched: CacheKeyHeader = %q, want empty", unmatched.CacheKeyHeader)
	}
}

// TestCacheKeyHeaderCompileErrors covers the check/compile rules: a missing target
// name is an error, and any trailing modifier other than `raw` is an error.
func TestCacheKeyHeaderCompileErrors(t *testing.T) {
	missing := compileErr(t, `x {
		header +cache_key
	}
`)
	if missing.Msg == "" {
		t.Error("missing target name should be a compile error with a message")
	}
	unknown := compileErr(t, `x {
		header +cache_key X-Cache-Key rawx
	}
`)
	if unknown.Msg == "" {
		t.Error("unknown modifier should be a compile error with a message")
	}
}

func TestEvalDeliverScopedHeader(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path
		header path_regex \.css$ Cache-Control "public, max-age=31536000"
	}
`)
	hit := p.EvalDeliver(&Request{Path: "/a.css"}, nil, CacheStatusMiss)
	if len(hit.RespHeaderOps) != 1 || hit.RespHeaderOps[0].Name != "Cache-Control" {
		t.Errorf("css request should get Cache-Control op, got %+v", hit.RespHeaderOps)
	}
	miss := p.EvalDeliver(&Request{Path: "/a.html"}, nil, CacheStatusMiss)
	if len(miss.RespHeaderOps) != 0 {
		t.Errorf("html request should get no scoped op, got %+v", miss.RespHeaderOps)
	}
}

// TestEvalDeliverDynamicHeaderValues covers #17: a response `header` value that
// interpolates request-derived tokens is resolved per-request, while static
// values are unchanged.
func TestEvalDeliverDynamicHeaderValues(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path
		header Access-Control-Allow-Origin {http.Origin}
		header X-Real-IP {client_ip}
		header X-Static plain-value
	}
`)
	// Request that carries an Origin header and a client IP.
	req := &Request{
		Path:     "/",
		ClientIP: "198.51.100.9",
		Header:   http.Header{"Origin": {"https://app.example.com"}},
	}
	dec := p.EvalDeliver(req, nil, CacheStatusHit)
	if !hasSetOp(dec.RespHeaderOps, "Access-Control-Allow-Origin", "https://app.example.com") {
		t.Errorf("ACAO should reflect Origin, got %+v", dec.RespHeaderOps)
	}
	if !hasSetOp(dec.RespHeaderOps, "X-Real-IP", "198.51.100.9") {
		t.Errorf("X-Real-IP should be the client IP, got %+v", dec.RespHeaderOps)
	}
	if !hasSetOp(dec.RespHeaderOps, "X-Static", "plain-value") {
		t.Errorf("static header value should be unchanged, got %+v", dec.RespHeaderOps)
	}

	// A second request with a DIFFERENT Origin must resolve to that Origin: the
	// template is resolved per-request, not baked at compile time.
	req2 := &Request{Path: "/", ClientIP: "10.0.0.1", Header: http.Header{"Origin": {"https://other.example.org"}}}
	dec2 := p.EvalDeliver(req2, nil, CacheStatusHit)
	if !hasSetOp(dec2.RespHeaderOps, "Access-Control-Allow-Origin", "https://other.example.org") {
		t.Errorf("ACAO should reflect the second request's Origin, got %+v", dec2.RespHeaderOps)
	}

	// An absent Origin header resolves to an empty value (no panic, no leftover token).
	req3 := &Request{Path: "/", ClientIP: "10.0.0.2"}
	dec3 := p.EvalDeliver(req3, nil, CacheStatusHit)
	if !hasSetOp(dec3.RespHeaderOps, "Access-Control-Allow-Origin", "") {
		t.Errorf("absent Origin should resolve to empty, got %+v", dec3.RespHeaderOps)
	}
}

// TestEvalRequestDynamicHeaderValues covers a request-phase `header` (before
// cache_key) interpolating {client_ip} — e.g. setting X-Real-IP for the origin.
func TestEvalRequestDynamicHeaderValues(t *testing.T) {
	p := compileSrc(t, `x {
		header X-Real-IP {client_ip}
		cache_key path
	}
`)
	req := &Request{Path: "/", ClientIP: "203.0.113.5"}
	dec := p.EvalRequest(req)
	if !hasSetOp(dec.ReqHeaderOps, "X-Real-IP", "203.0.113.5") {
		t.Errorf("X-Real-IP req op should be the client IP, got %+v", dec.ReqHeaderOps)
	}
}

// TestEvalDeliverUnknownHTTPToken: an unknown {http.X} (absent header) resolves
// to empty, and an unknown {name} that is not a request token is kept verbatim.
func TestEvalDeliverUnknownHTTPToken(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path
		header X-Echo {http.X-Absent}
		header X-Keep {nope}
	}
`)
	req := &Request{Path: "/"}
	dec := p.EvalDeliver(req, nil, CacheStatusHit)
	if !hasSetOp(dec.RespHeaderOps, "X-Echo", "") {
		t.Errorf("absent {http.X-Absent} should resolve to empty, got %+v", dec.RespHeaderOps)
	}
	if !hasSetOp(dec.RespHeaderOps, "X-Keep", "{nope}") {
		t.Errorf("unknown {nope} should be kept verbatim, got %+v", dec.RespHeaderOps)
	}
}

func TestEvalDeliverStripAndCORS(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path
		strip_cookies path_regex \.(css|js)$
		cors * methods GET POST headers X-Foo
	}
`)
	d := p.EvalDeliver(&Request{Path: "/a.css"}, nil, CacheStatusHit)
	if !d.StripCookies {
		t.Error("css should strip cookies")
	}
	if d.CORS == nil || !d.CORS.AllowAllOrigins {
		t.Fatalf("want CORS allow-all, got %+v", d.CORS)
	}
	if len(d.CORS.Methods) != 2 || len(d.CORS.Headers) != 1 {
		t.Errorf("CORS methods/headers = %+v", d.CORS)
	}
	d2 := p.EvalDeliver(&Request{Path: "/page"}, nil, CacheStatusHit)
	if d2.StripCookies {
		t.Error("non-css should not strip cookies")
	}
}

func TestConcurrentEval(t *testing.T) {
	// A compiled Pipeline must be safe for concurrent use: each Eval builds its own
	// match context, sharing only immutable compiled state.
	p := compileSrc(t, `x {
		upstream images { to https://s3 }
		@ajax header X-Requested-With XMLHttpRequest
		@static host_regex ^static
		@images upstream images
		route @static -> images
		pass @ajax
		cache_key url host
		cache_ttl status 404 ttl 60s grace 1h
		cache_ttl @images ttl 24h grace 365d
		cache_ttl default ttl 2s grace 24h
		storage @images -> disk
		storage default -> ram
		header +cache_status X-Cache
	}
`)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := &Request{
				Method: "GET", Host: "static.example.com", Path: "/img.jpg",
				Query:  url.Values{"v": {"1"}},
				Header: http.Header{"X-Requested-With": {"XMLHttpRequest"}},
			}
			_ = p.EvalRequest(req)
			_ = p.EvalResponse(req, 200, nil)
			_ = p.EvalDeliver(req, nil, CacheStatusHit)
		}(i)
	}
	wg.Wait()
}

func TestRequestHeaderPhase(t *testing.T) {
	// A header directive BEFORE cache_key is a request-phase edit.
	p := compileSrc(t, `x {
		header +X-Forwarded-Proto https
		cache_key path
		header -Server
	}
`)
	reqOps := p.EvalRequest(&Request{Path: "/"}).ReqHeaderOps
	if len(reqOps) != 1 || reqOps[0].Name != "X-Forwarded-Proto" {
		t.Errorf("req header ops = %+v, want one X-Forwarded-Proto", reqOps)
	}
	respOps := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss).RespHeaderOps
	if len(respOps) != 1 || respOps[0].Name != "Server" {
		t.Errorf("resp header ops = %+v, want one Server remove", respOps)
	}
}
