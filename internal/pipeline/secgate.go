package pipeline

import (
	"net/netip"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// The SECURITY GATE is the first thing evaluated in the RECV phase — before the
// cache key is computed, before the cache is consulted, and before the origin is
// dialed. A blocked request therefore touches NEITHER the cache NOR the origin
// (design §1): the server calls EvalSecurity first and, on a Deny, writes the 403
// and returns without ever reaching LOOKUP/ORIGIN.
//
// The engine is a `classify`-style first-match decision table (D26): each rule is
// a CONJUNCTION of matchers (AND within a rule, with `!` negation per term),
// rules are tried in order (OR across rules), and the first match wins — but
// instead of yielding a token VALUE it yields a SECURITY ACTION. The internal
// order is `allow` (short-circuit/bypass) → `deny`/`block` (403); rate_limit /
// OWASP / challenge are later slices that slot in after deny.
//
// This is SERVER-ONLY (design §2.15): the gate never runs at Cadish Edge and the
// security rules are NEVER projected into the worker IR — they are simply absent
// there (Cloudflare provides the edge's own security layer). The IR projector
// (edgeview.go) does not read p.allowRules / p.denyRules, so nothing leaks.

// secAction is the security action a matched gate rule yields.
type secAction int

const (
	secAllow secAction = iota // short-circuit: bypass the rest of the gate
	secDeny                   // 403, before cache + origin
)

// secTerm is one matcher in a security rule's conjunction, with optional `!`
// negation (`deny @admin !@office` — admin paths, but not from the office). A term
// matches when its matcher matches XOR its negate flag.
type secTerm struct {
	m      *matcher
	negate bool
}

// secRule is one compiled `allow`/`deny`/`block` rule: a conjunction of terms
// (AND, first-match-wins across the rule list) yielding an action. monitor marks a
// per-rule monitor override (a deny in monitor logs "would-deny" and PASSES).
type secRule struct {
	action  secAction
	terms   []secTerm
	monitor bool // per-rule monitor override (deny only; allow never disrupts)
	pos     cadishfile.Pos
	name    string // a representative matcher name for metrics/audit ("" if inline)
}

// matches reports whether EVERY term in the rule's conjunction matches (AND, with
// per-term negation). An empty conjunction never reaches here (compile rejects it).
func (r *secRule) matches(c *matchContext) bool {
	return respondTermsMatch(c, r.terms)
}

// respondTermsMatch reports whether EVERY term in a conjunction matches (AND, with
// per-term negation). Shared by the security gate (secRule.matches) and the scoped
// `respond @scope` form so the two cannot drift. An empty conjunction matches
// unconditionally (the caller's compile guards against an empty scoped respond).
func respondTermsMatch(c *matchContext, terms []secTerm) bool {
	for _, t := range terms {
		got := c.matches(t.m)
		if got == t.negate {
			return false
		}
	}
	return true
}

// SecurityDecision is the outcome of the security gate (EvalSecurity). The server
// applies it FIRST, before computing the cache key or consulting cache/origin.
//
// Block is true when a `deny`/`block` rule fired and the rule was NOT in monitor
// mode: the server must return Status (403) immediately, touching neither cache
// nor origin. When Block is false the request proceeds normally through the rest
// of the lifecycle.
//
// Monitor records that a `deny` rule WOULD have blocked but did not (global or
// per-rule monitor mode, decision #19): the server logs/counts a "would-block" and
// lets the request pass. Allow records that an `allow` rule short-circuited the
// gate (an office/monitoring IP that is never blocked). Rule is a representative
// name for metrics/audit.
type SecurityDecision struct {
	Block   bool   // a deny fired and was enforced -> server returns Status now
	Monitor bool   // a deny fired but monitor mode suppressed it -> would-block, passes
	Allow   bool   // an allow short-circuited the gate
	Status  int    // the block status (403) when Block is true
	Rule    string // representative matcher name of the rule that fired ("" if none/inline)
	// RateLimit is set (non-nil) when a `rate_limit` rule applies to this request
	// (WAF v1b): the PURE gate identifies the rule and computes the bucket KEY here,
	// WITHOUT counting. The server consults its in-memory token bucket with this and
	// returns 429 + Retry-After (or, in monitor mode, logs would-429 and passes). It
	// is nil when no rate_limit rule applies, or when an allow/deny short-circuited
	// the gate first (gate order: allow -> deny -> rate_limit).
	RateLimit *RateLimitHit
}

// hasSecurityGate reports whether the site configured any security rule. When
// false the server skips the gate entirely (one cheap branch) — zero cost when no
// security is configured (design §2).
func (p *Pipeline) hasSecurityGate() bool {
	return len(p.allowRules) > 0 || len(p.denyRules) > 0 || p.hasRateLimit()
}

// UsesSecurityGate reports whether the server must run the security gate for this
// site (and therefore resolve the real client IP for the `ip` matcher). It is
// false for any site with no allow/deny rules, so a non-security site pays nothing.
func (p *Pipeline) UsesSecurityGate() bool { return p.hasSecurityGate() }

// UsesRateLimit reports whether the site configured any `rate_limit` rule, so the
// server can construct the in-memory token-bucket limiter ONLY when needed (zero
// cost — and no goroutine — on a site with no rate limiting).
func (p *Pipeline) UsesRateLimit() bool { return p.hasRateLimit() }

// EvalSecurity evaluates the security gate (the first step of RECV) and returns
// the decision. It is a pure function, safe for concurrent use, and is called by
// the server BEFORE the cache key / cache lookup / origin — so an enforced deny
// touches neither cache nor origin.
//
// Order (design §3/§6): allow first (an allowlist bypasses everything — office /
// monitoring IPs are never blocked), then deny (403). The `monitor` toggle (global
// or per-rule) turns an enforced deny into a recorded "would-block" that passes.
func (p *Pipeline) EvalSecurity(req *Request) SecurityDecision {
	if !p.hasSecurityGate() {
		return SecurityDecision{}
	}
	var stack [memoStack]int8
	ctx := &matchContext{req: req, upstream: "", memo: newMemo(stack[:], p.numMatchers)}

	// allow: a matching allowlist rule short-circuits the gate (no deny runs).
	for _, r := range p.allowRules {
		if r.matches(ctx) {
			return SecurityDecision{Allow: true, Rule: r.name}
		}
	}
	// deny/block: first matching rule wins. monitor mode (global or per-rule)
	// records a would-block and passes instead of enforcing the 403.
	for _, r := range p.denyRules {
		if r.matches(ctx) {
			if p.securityMonitor || r.monitor {
				return SecurityDecision{Monitor: true, Status: securityBlockStatus, Rule: r.name}
			}
			return SecurityDecision{Block: true, Status: securityBlockStatus, Rule: r.name}
		}
	}
	// rate_limit: AFTER deny (don't spend a counter on an already-forbidden request).
	// The PURE gate identifies the applicable rule and computes the bucket key; the
	// server's token bucket does the counting and the 429 + Retry-After (or, in
	// monitor mode, the would-429-and-pass). Reuses ctx so a matcher shared with a
	// deny rule is evaluated once.
	if p.hasRateLimit() {
		if hit := p.evalRateLimit(ctx); hit != nil {
			return SecurityDecision{RateLimit: hit}
		}
	}
	return SecurityDecision{}
}

// securityBlockStatus is the default block response status for `deny`/`block`
// (design §2.13). A future `respond` customization is a later slice; 403 now.
const securityBlockStatus = 403

// compileIP builds an `ip` matcher: a set of IP/CIDR prefixes (v4 + v6). A bare IP
// is treated as a host route (/32 for v4, /128 for v6). It matches against the
// trusted-proxy-resolved REAL client IP (req.RealClientIP), the SAME resolution
// {geo} uses (decision #16) — never the immediate peer.
func compileIP(name string, args []string, pos cadishfile.Pos) (*matcher, error) {
	if len(args) == 0 {
		return nil, &CompileError{Pos: pos, Msg: "ip matcher needs at least one IP or CIDR (e.g. `ip 203.0.113.43/32 10.0.0.0/8 ::1`)"}
	}
	prefixes := make([]netip.Prefix, 0, len(args))
	for _, a := range args {
		p, err := parseIPOrCIDR(a)
		if err != nil {
			return nil, &CompileError{Pos: pos, Msg: "ip matcher: bad IP/CIDR " + quote(a) + ": " + err.Error()}
		}
		prefixes = append(prefixes, p)
	}
	return &matcher{name: name, kind: kindIP, pos: pos, idx: -1, ipPrefixes: prefixes}, nil
}

// parseIPOrCIDR parses either a CIDR ("10.0.0.0/8") or a bare IP ("203.0.113.43",
// "::1") into a masked netip.Prefix (bare IP => host route /32 or /128). The result
// is Unmap'd so a 4-in-6 entry compares against the Unmap'd resolved client IP.
func parseIPOrCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// compileSecurityRule compiles an `allow`/`deny`/`block` directive into a secRule.
// The grammar is `ACTION <terms> [monitor]`, where <terms> is a CONJUNCTION:
//
//	allow @office                    # OR-of-refs is also a conjunction of one ref
//	deny  @ru_cn                     # single ref
//	deny  @admin !@office            # AND + per-term `!` negation
//	deny  @scanners monitor          # per-rule monitor: would-block, passes
//	allow ip 10.0.0.0/8              # one inline matcher (no @ref)
//
// allow rules ignore a trailing `monitor` (an allow never disrupts; decision #19).
func compileSecurityRule(d *cadishfile.Directive, action secAction, matchers map[string]*matcher) (secRule, error) {
	r := secRule{action: action, pos: d.Pos}
	args := d.Args
	// A trailing `monitor` keyword marks a per-rule monitor override.
	if n := len(args); n > 0 && args[n-1].Raw == "monitor" {
		r.monitor = true
		args = args[:n-1]
	}
	if len(args) == 0 {
		return secRule{}, &CompileError{Pos: d.Pos, Msg: d.Name + " needs a matcher or condition (e.g. `" + d.Name + " @office`)"}
	}
	// Two shapes: a conjunction of (optionally negated) @matcher refs, or exactly
	// one inline `TYPE arg…` matcher. Mirrors classify's compileConjunction but adds
	// `!` negation per term (the WAF gate's distinguishing feature).
	if isSecRefArg(args[0]) {
		for _, a := range args {
			if a.Raw == "and" || a.Raw == "AND" {
				continue // optional readability connector
			}
			name, negate, ok := parseSecRef(a)
			if !ok {
				return secRule{}, &CompileError{Pos: a.Pos, Msg: d.Name + ": expected a @matcher reference (optionally !-negated), got " + quote(a.Raw)}
			}
			m, ok := matchers[name]
			if !ok {
				return secRule{}, &CompileError{Pos: a.Pos, Msg: "undefined matcher @" + name}
			}
			if isResponsePhaseKind(m.kind) {
				return secRule{}, &CompileError{Pos: a.Pos, Msg: d.Name + " cannot use a response-phase matcher (" + matcherKindName(m.kind) + "); the security gate runs in RECV before the origin response exists"}
			}
			r.terms = append(r.terms, secTerm{m: m, negate: negate})
			if r.name == "" && !negate {
				r.name = name
			}
		}
		if len(r.terms) == 0 {
			return secRule{}, &CompileError{Pos: d.Pos, Msg: d.Name + " needs at least one matcher"}
		}
		return r, nil
	}
	if isMatcherType(args[0].Raw) {
		m, err := compileMatcher("", args[0].Raw, rawArgs(args[1:]), d.Pos)
		if err != nil {
			return secRule{}, err
		}
		if isResponsePhaseKind(m.kind) {
			return secRule{}, &CompileError{Pos: d.Pos, Msg: d.Name + " cannot use a response-phase matcher (" + matcherKindName(m.kind) + "); the security gate runs in RECV before the origin response exists"}
		}
		r.terms = append(r.terms, secTerm{m: m})
		return r, nil
	}
	return secRule{}, &CompileError{Pos: d.Pos, Msg: d.Name + " expects @matcher refs (optionally !-negated) or one inline matcher, got " + quote(args[0].Raw)}
}

// isSecRefArg reports whether arg is a (possibly `!`-negated) @matcher reference.
// A plain `@x` arrives as ArgMatcherRef; a negated `!@x` arrives as an ArgLiteral
// whose text starts with `!@`, so it must be recognized here too.
func isSecRefArg(a cadishfile.Arg) bool {
	if a.Kind == cadishfile.ArgMatcherRef {
		return true
	}
	return strings.HasPrefix(a.Raw, "!@")
}

// parseSecRef splits a (possibly negated) matcher-ref token into its name and
// negate flag: `@office` -> ("office", false), `!@office` -> ("office", true).
func parseSecRef(a cadishfile.Arg) (name string, negate bool, ok bool) {
	raw := a.Raw
	if strings.HasPrefix(raw, "!@") {
		return raw[2:], true, true
	}
	if strings.HasPrefix(raw, "@") {
		return raw[1:], false, true
	}
	return "", false, false
}

// compileMonitorToggle parses the global `monitor` directive: a bare `monitor`
// (or `monitor on`) turns the whole security gate to monitor mode (deny rules log
// "would-block" and pass); `monitor off` is the explicit no-op default.
func compileMonitorToggle(d *cadishfile.Directive) (bool, error) {
	switch len(d.Args) {
	case 0:
		return true, nil
	case 1:
		switch d.Args[0].Raw {
		case "on":
			return true, nil
		case "off":
			return false, nil
		default:
			return false, &CompileError{Pos: d.Args[0].Pos, Msg: "monitor takes `on` or `off` (or nothing for on), got " + quote(d.Args[0].Raw)}
		}
	default:
		return false, &CompileError{Pos: d.Pos, Msg: "monitor takes at most one arg (`on`/`off`)"}
	}
}
