package vcladapt

import (
	"fmt"
	"sort"
	"strings"
)

// Result is the outcome of adapting a VCL source.
type Result struct {
	// Cadishfile is the generated skeleton.
	Cadishfile string
	// Mapped is the count of idioms confidently converted.
	Mapped int
	// TODOs is the count of constructs left for human review.
	TODOs int
}

// Adapt converts VCL source into a best-effort Cadishfile skeleton. filename is
// used only in the generated header comment.
func Adapt(filename, src string) *Result {
	f := parse(src)
	b := &builder{}
	b.run(f)
	return b.render(filename)
}

type builder struct {
	upstreams    []string
	reqHeaders   []string
	passMethods  []string
	nocacheGlobs []string
	passInline   []string // pass path_regex / pass header … lines
	routes       []string
	matchers     []string // @name … lines for routes
	responds     []string
	cacheKey     []string
	cacheKeyNote string
	ttlLines     []string
	respHeaders  []string
	stripCookies bool
	todos        []string
	mapped       int
	hostCounter  int
}

func (b *builder) todo(reason, snippet string) {
	if snippet != "" {
		b.todos = append(b.todos, fmt.Sprintf("# TODO(adapt): %s\n#   %s", reason, snippet))
	} else {
		b.todos = append(b.todos, fmt.Sprintf("# TODO(adapt): %s", reason))
	}
}

func (b *builder) run(f *vclFile) {
	for _, be := range f.backends {
		b.backend(be)
	}
	// Map the subs cadish understands; TODO the rest.
	for _, name := range f.subOrder {
		switch name {
		case "vcl_recv":
			b.recv(f.subs[name])
		case "vcl_backend_response", "vcl_fetch":
			b.backendResponse(f.subs[name])
		case "vcl_hash":
			b.hash(f.subs[name])
		case "vcl_deliver", "vcl_synth":
			b.deliver(f.subs[name])
		case "vcl_init", "vcl_backend_fetch", "vcl_hit", "vcl_miss", "vcl_pass", "vcl_pipe", "vcl_backend_error", "vcl_purge":
			b.todo("sub "+name+" not auto-mapped — port its logic by hand", "")
		default:
			b.todo("sub "+name+" not recognized", "")
		}
	}
	for _, a := range f.acls {
		b.todo("acl "+a+" — IP allow/deny lists aren't a cadish v1 primitive", "")
	}
	for _, im := range f.imports {
		b.todo("import "+im+" — vmod; reimplement as config or a module", "")
	}
	for _, inc := range f.includes {
		b.todo("include \""+inc+"\" — adapt the included file separately (cadish `import`)", "")
	}
	for _, o := range f.others {
		b.todo("top-level `"+o+"` not recognized", "")
	}
}

// backend → upstream.
func (b *builder) backend(be *backend) {
	if be.host == "" {
		b.todo("backend "+be.name+" has no .host — fill in `to`", "")
		return
	}
	var sb strings.Builder
	note := ""
	if templated(be.host) || templated(be.port) {
		note = "    # TODO(adapt): templated host/port — substitute a real value\n"
	}
	port := be.port
	to := "http://" + be.host
	if port != "" {
		to += ":" + port
	}
	fmt.Fprintf(&sb, "upstream %s {\n%s    to %s\n", sanitizeName(be.name), note, to)
	if be.probe != nil {
		method := orDefault(be.probe.method, "GET")
		url := orDefault(be.probe.url, "/")
		expect := orDefault(be.probe.expect, "200")
		line := fmt.Sprintf("    health %s %s expect %s", method, url, expect)
		if be.probe.interval != "" {
			line += " interval " + be.probe.interval
		}
		if be.probe.window != "" {
			line += " window " + be.probe.window
		}
		if be.probe.threshold != "" {
			line += " threshold " + be.probe.threshold
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteString("}")
	b.upstreams = append(b.upstreams, sb.String())
	b.mapped++
}

// vcl_recv mapping.
func (b *builder) recv(stmts []stmt) {
	for _, s := range stmts {
		if !s.isIf {
			b.recvSimple(s)
			continue
		}
		// Only single-clause ifs (no else) are mechanically mappable.
		if len(s.clauses) != 1 || s.els != nil {
			b.todo("conditional in vcl_recv with else/elif branches", snippet(s))
			continue
		}
		c := s.clauses[0]
		// A compound `&&` or negated (`!`/`!~`/`!=`) condition can't be decomposed into
		// cadish's positive, OR-combined matchers without silently widening or inverting
		// the rule (see condHasUntranslatableLogic). Flag it loudly rather than emit a
		// mistranslation — this guards pass, route, and synth alike.
		if condHasUntranslatableLogic(c.cond) {
			b.todo("vcl_recv conditional uses `&&`/negation cadish can't decompose mechanically (would widen or invert the rule) — translate by hand", snippet(s))
			continue
		}
		switch {
		case bodyReturnsPass(c.body):
			b.recvPass(c.cond, s)
		case hasSynth(c.body):
			b.recvSynth(c.cond, c.body, s)
		case backendHint(c.body) != "":
			b.recvRoute(c.cond, backendHint(c.body), s)
		default:
			b.todo("vcl_recv conditional not mechanical", snippet(s))
		}
	}
}

func (b *builder) recvPass(cond []token, s stmt) {
	urls := extractMatches(cond, "req.url")
	method := extractEq(cond, "req.method")
	headers := headerRefs(cond)
	mappedAny := false
	for _, u := range urls {
		if u == "" {
			continue
		}
		mappedAny = true
		if !looksRegexy(u) && strings.HasPrefix(u, "/") {
			b.nocacheGlobs = append(b.nocacheGlobs, pathGlob(u))
			b.mapped++
			continue
		}
		// cadish's path_regex compiles under RE2; a PCRE-only VCL pattern would emit
		// output `cadish check` rejects (or a different meaning). Flag it, don't emit it.
		if reason, bad := re2Reject(u); bad {
			b.todo("vcl_recv return(pass) regex isn't valid RE2 (cadish uses RE2, not PCRE): "+reason+" — rewrite the pattern for RE2 by hand", "req.url ~ "+quote(u))
			continue
		}
		b.passInline = append(b.passInline, "pass path_regex "+quote(u)+
			"   # VCL `~` is a substring match — verify")
		b.mapped++
	}
	if method != "" {
		if strings.EqualFold(method, "PURGE") {
			b.todo("vcl_recv handles PURGE — wire `purge when …` with your token guard", snippet(s))
		} else {
			b.passMethods = appendUnique(b.passMethods, strings.ToUpper(method))
			b.mapped++
		}
		mappedAny = true
	}
	for _, h := range headers {
		if h.filter == "" {
			// Bare presence check → cadish's presence-only `pass header NAME`.
			b.passInline = append(b.passInline, "pass header "+h.name)
			b.mapped++
		} else {
			// Value filter (e.g. `~ "(?i)Prerender"`) has no cadish equivalent: collapsing it
			// to `pass header NAME` would pass EVERY request carrying that header (A2). Flag it,
			// and surface the dropped filter inline so a human sees what was lost (A-P2).
			b.todo(fmt.Sprintf("vcl_recv passes on a %s VALUE filter `%s %s` — cadish `pass header` matches presence only; gate it by hand (e.g. a @matcher)", h.name, h.name, h.filter), snippet(s))
		}
		mappedAny = true
	}
	if !mappedAny {
		b.todo("vcl_recv return(pass) on a non-mechanical condition", snippet(s))
	}
}

func (b *builder) recvSynth(cond []token, body []stmt, s stmt) {
	status, msg, ok := synthOf(body)
	if !ok {
		b.todo("vcl_recv synthetic response not a simple synth(CODE, \"MSG\")", snippet(s))
		return
	}
	if status >= 300 && status < 400 {
		b.todo("vcl_recv redirect via synth — express as a route/respond by hand", snippet(s))
		return
	}
	path := firstMatch(cond, "req.url")
	if path == "" || looksRegexy(path) {
		b.todo("vcl_recv synth not guarded by a literal path", snippet(s))
		return
	}
	b.responds = append(b.responds, fmt.Sprintf("respond %s %d %s", path, status, quote(msg)))
	b.mapped++
}

func (b *builder) recvRoute(cond []token, upstream string, s stmt) {
	// An OR-alternative host condition (`req.http.host ~ "a" || req.http.host ~ "b"`) is a
	// union: BOTH hosts must route to the backend. The &&/negation guard in recv() already
	// rejected any condition with `&&`/`!`, so anything reaching here is a pure positive
	// chain — extractMatches yields every host atom, and emitting a matcher+route per atom
	// reproduces the union faithfully. (firstMatch routed only the first and silently
	// dropped the rest.)
	hosts := extractMatches(cond, "req.http.host")
	if len(hosts) == 0 {
		b.todo("vcl_recv sets backend by a non-host condition", snippet(s))
		return
	}
	mappedAny := false
	for _, host := range hosts {
		if host == "" {
			continue
		}
		// host_regex compiles under RE2; a PCRE-only host pattern would fail `cadish check`.
		// Reject just the offending alternative loudly and keep mapping the rest, naming the
		// dropped pattern so the operator can rewrite it.
		if reason, bad := re2Reject(host); bad {
			b.todo("vcl_recv routes by a host regex that isn't valid RE2 (cadish uses RE2, not PCRE): "+reason+" — rewrite for RE2 by hand", "req.http.host ~ "+quote(host))
			continue
		}
		b.hostCounter++
		name := fmt.Sprintf("host%d", b.hostCounter)
		b.matchers = append(b.matchers, fmt.Sprintf("@%s host_regex %s", name, quote(host)))
		b.routes = append(b.routes, fmt.Sprintf("route @%s -> %s", name, sanitizeName(upstream)))
		b.mapped++
		mappedAny = true
	}
	if !mappedAny {
		b.todo("vcl_recv sets backend by a non-host condition", snippet(s))
	}
}

func (b *builder) recvSimple(s stmt) {
	if name, val, ok := setHeader(s.simple, "req.http"); ok {
		if val == "" || hasCall(s.simple) {
			b.todo("vcl_recv sets a request header with a function/expression", snippet(s))
			return
		}
		b.reqHeaders = append(b.reqHeaders, fmt.Sprintf("header %s %s", name, quote(val)))
		b.mapped++
		return
	}
	if name, ok := unsetHeader(s.simple, "req.http"); ok {
		b.reqHeaders = append(b.reqHeaders, "header -"+name)
		b.mapped++
		return
	}
	if isReturn(s.simple, "pass") {
		b.passInline = append(b.passInline, "pass   # TODO(adapt): VCL unconditional return(pass)")
		return
	}
	if head(s.simple) == "set" || head(s.simple) == "unset" || head(s.simple) == "return" {
		b.todo("vcl_recv statement not mechanical", snippet(s))
	}
}

// vcl_backend_response mapping.
func (b *builder) backendResponse(stmts []stmt) {
	for _, s := range stmts {
		if s.isIf {
			b.berespIf(s)
			continue
		}
		if isUnsetCookie(s.simple) {
			b.stripCookies = true
			b.mapped++
			continue
		}
		if name, val, ok := setHeader(s.simple, "beresp.http"); ok && val != "" && !hasCall(s.simple) {
			b.respHeaders = append(b.respHeaders, fmt.Sprintf("header %s %s", name, quote(val)))
			b.mapped++
			continue
		}
		if name, ok := unsetHeader(s.simple, "beresp.http"); ok {
			if !strings.EqualFold(name, "set-cookie") && !strings.EqualFold(name, "cookie") {
				b.respHeaders = append(b.respHeaders, "header -"+name)
				b.mapped++
			}
			continue
		}
	}
	// Top-level default ttl/grace (statements not inside an if).
	t, g, expr := topLevelTTL(stmts)
	if t != "" {
		line := "cache_ttl default ttl " + t
		if g != "" {
			line += " grace " + g
		}
		b.ttlLines = append(b.ttlLines, line)
		b.mapped++
	} else if expr {
		// A vmod-driven ttl (e.g. std.duration(beresp.http.X-TTL, 60s)) is non-mechanical:
		// emit the original line as a TODO, never a bogus literal token (A1).
		b.todo("vcl_backend_response sets beresp.ttl from a vmod/expression — set a literal `cache_ttl` by hand", ttlExprSnippet(stmts))
	}
}

func (b *builder) berespIf(s stmt) {
	if len(s.clauses) == 0 {
		return
	}
	for _, c := range s.clauses {
		codes, neg, note, ok := statusCodes(c.cond)
		t, g, hfm, expr := ttlOfBody(c.body)
		if expr {
			// A vmod/expression-driven beresp.ttl can't become a literal cadish duration (A1).
			b.todo("vcl_backend_response sets beresp.ttl from a vmod/expression — set a literal `cache_ttl` by hand", ttlExprSnippet(c.body))
			continue
		}
		if !ok || (t == "" && !hfm) {
			b.todo("vcl_backend_response conditional not a simple status→ttl", snippetStmts(c.body))
			continue
		}
		sel := "status " + strings.Join(codes, " ")
		if neg {
			sel = "status not " + strings.Join(codes, " ")
		}
		var line string
		if hfm {
			line = "cache_ttl " + sel + " hit_for_miss " + orDefault(t, "5s")
		} else {
			line = "cache_ttl " + sel + " ttl " + t
			if g != "" {
				line += " grace " + g
			}
		}
		line += note
		b.ttlLines = append(b.ttlLines, line)
		b.mapped++
		// Strip-cookie inside the same arm.
		for _, st := range c.body {
			if isUnsetCookie(st.simple) {
				b.stripCookies = true
			}
		}
	}
}

// vcl_hash mapping.
func (b *builder) hash(stmts []stmt) {
	for _, s := range stmts {
		if s.isIf {
			b.todo("vcl_hash conditional (conditional VARY) — model with a {device}/{geo} normalizer or header: token", snippetStmts(s.clauses[0].body))
			continue
		}
		expr, ok := hashData(s.simple)
		if !ok {
			continue
		}
		switch {
		case expr == "req.url":
			b.cacheKey = appendUnique(b.cacheKey, "url")
			b.mapped++
		case expr == "req.http.host":
			b.cacheKey = appendUnique(b.cacheKey, "host")
			b.mapped++
		case strings.HasPrefix(expr, "req.http."):
			b.cacheKey = appendUnique(b.cacheKey, "header:"+strings.TrimPrefix(expr, "req.http."))
			b.mapped++
		default:
			b.todo("vcl_hash hash_data("+expr+") not a plain url/host/header", "")
		}
	}
	// Varnish's BUILT-IN vcl_hash always appends hash_data(req.url) and
	// hash_data(req.http.host) AFTER the custom sub (only a rare `return(lookup)` in the
	// custom sub bypasses it), so a custom vcl_hash that omits them — the common
	// `hash_data(req.http.X-Currency)` shape in real configs — STILL keys on url+host.
	// cadish's cache_key is the WHOLE key with no implicit base (an empty cache_key uses
	// `method host path`, but a non-empty one is taken verbatim), so emitting only the
	// custom terms would silently DROP url+host and collide every URL/host into one cache
	// bucket — catastrophic cross-content/cross-host mixing. Seed the builtin base.
	if len(b.cacheKey) > 0 {
		seeded := false
		for _, base := range []string{"host", "url"} {
			if !containsStr(b.cacheKey, base) {
				b.cacheKey = append([]string{base}, b.cacheKey...)
				seeded = true
			}
		}
		if seeded {
			b.cacheKeyNote = "   # url+host added to match Varnish's built-in vcl_hash (always hashed after a custom sub); drop only if your VCL did return(lookup)"
		}
	}
}

// vcl_deliver / vcl_synth mapping.
func (b *builder) deliver(stmts []stmt) {
	for _, s := range stmts {
		if s.isIf {
			b.todo("vcl_deliver conditional not mechanical", snippet(s))
			continue
		}
		if name, val, ok := setHeader(s.simple, "resp.http"); ok && val != "" && !hasCall(s.simple) {
			b.respHeaders = append(b.respHeaders, fmt.Sprintf("header %s %s", name, quote(val)))
			b.mapped++
			continue
		}
		if name, ok := unsetHeader(s.simple, "resp.http"); ok {
			b.respHeaders = append(b.respHeaders, "header -"+name)
			b.mapped++
			continue
		}
		if head(s.simple) == "set" || head(s.simple) == "unset" {
			b.todo("vcl_deliver statement not mechanical", snippet(s))
		}
	}
}

// render assembles the Cadishfile.
func (b *builder) render(filename string) *Result {
	b.TODOsort()
	var out strings.Builder
	fmt.Fprintf(&out, "# Generated by `cadish adapt` from %s — a best-effort skeleton.\n", filename)
	fmt.Fprintf(&out, "# %d idiom(s) mapped, %d need review (search for TODO(adapt)).\n", b.mapped, len(b.todos))
	out.WriteString("# Review every TODO, set the real site host(s), and run `cadish check`.\n\n")

	out.WriteString("example.com {   # TODO(adapt): set your real site address(es)\n")
	out.WriteString("    tls { acme you@example.com }   # TODO(adapt): confirm TLS\n\n")

	section := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&out, "    # ---- %s ----\n", title)
		for _, l := range lines {
			for _, sub := range strings.Split(l, "\n") {
				out.WriteString("    " + sub + "\n")
			}
		}
		out.WriteString("\n")
	}

	section("upstreams", b.upstreams)
	section("matchers / routing", append(append([]string{}, b.matchers...), b.routes...))

	var nocache []string
	if len(b.nocacheGlobs) > 0 {
		nocache = append(nocache, "@nocache path "+strings.Join(dedupe(b.nocacheGlobs), " "))
		// These globs are PREFIX matches, but the VCL they came from used `~` (an
		// unanchored substring match) or `==` (an exact match) — neither is exactly a
		// prefix. Surface the reduction so a migrator verifies it (mirrors the inline note
		// on the `pass path_regex` branch); cadish `path /x*` is prefix, `path /x` is exact.
		nocache = append(nocache, "pass @nocache   # globs are PREFIX matches — VCL `~` is substring / `==` is exact; verify each path")
	}
	for _, m := range b.passMethods {
		nocache = append(nocache, "pass method "+m)
	}
	nocache = append(nocache, b.passInline...)
	section("no-cache (pass)", nocache)

	section("synthetic responses", b.responds)
	section("request headers", b.reqHeaders)
	if len(b.cacheKey) > 0 {
		section("cache key", []string{"cache_key " + strings.Join(b.cacheKey, " ") + b.cacheKeyNote})
	}
	section("ttl / grace", b.ttlLines)

	resp := append([]string{}, b.respHeaders...)
	if b.stripCookies {
		resp = append([]string{"strip_cookies"}, resp...)
	}
	section("response headers / cookies", resp)

	if len(b.todos) > 0 {
		out.WriteString("    # ==== NEEDS REVIEW ====\n")
		for _, t := range b.todos {
			for _, sub := range strings.Split(t, "\n") {
				out.WriteString("    " + sub + "\n")
			}
		}
	}
	out.WriteString("}\n")

	return &Result{Cadishfile: out.String(), Mapped: b.mapped, TODOs: len(b.todos)}
}

func (b *builder) TODOsort() { sort.Stable(sort.StringSlice(b.todos)) }
