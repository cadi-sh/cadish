package pipeline

import (
	"strconv"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// rate_limit is the stateful native security primitive (WAF v1b / D51). It is the
// THIRD step of the security gate, after `allow` and `deny` (spec §3/§6: don't
// spend a counter on an already-allowed or already-forbidden request).
//
// The split (D51): this PURE pipeline identifies the applicable rule for a request
// and computes the bucket KEY — the resolved real client IP, a header value, or a
// whole-site constant — and returns it on the SecurityDecision as a RateLimitHit.
// It does NO counting. The server's in-memory sharded token-bucket
// (internal/ratelimit) owns the mutable state: it consults Allow(key, rule) in the
// gate seam and returns 429 + Retry-After (or, in monitor mode, logs would-429 and
// passes). Per-node only — no distributed counters (cluster caveat: effective limit
// ≈ N× with N nodes; mitigate with limit = target/N).
//
// SERVER-ONLY (spec §2.15): like allow/deny, rate_limit is never projected into the
// edge IR — there is no Edge accessor for it, so it is absent there by construction.

// rlKeyKind selects what a rate_limit bucket is keyed on.
type rlKeyKind int

const (
	rlKeyIP     rlKeyKind = iota // key ip (default): the resolved real client IP
	rlKeyHeader                  // key header NAME: a request header value
	rlKeyGlobal                  // key global: one whole-site bucket
)

// rateLimitRule is one compiled `rate_limit` directive. scope (nil = unconditional)
// gates applicability to matching requests; ratePerSec + burst define the bucket;
// keyKind/keyHeader select the bucket key; monitor records a per-rule would-429.
// id is a stable per-rule identifier folded into the bucket key so two distinct
// rate_limit rules on the same site never share a bucket.
type rateLimitRule struct {
	id         int
	scope      *scope
	ratePerSec float64
	burst      int
	keyKind    rlKeyKind
	keyHeader  string // kindHeader: the header name to key on
	monitor    bool
	name       string // representative matcher name for metrics/audit ("" if inline/unscoped)
}

// RateLimitHit is what the pure gate returns when a rate_limit rule applies to a
// request: the identified rule's parameters plus the computed bucket KEY. The
// server feeds {Key, Limit/RatePerSec, Burst} to its token-bucket limiter; it does
// the stateful counting, not the pipeline. Monitor mode (per-rule or global) means
// the server records a would-429 and PASSES instead of throttling (decision #19).
type RateLimitHit struct {
	Key        string  // the bucket key (rule id + the resolved IP / header / global tag)
	RatePerSec float64 // steady refill rate (tokens/second)
	Burst      int     // extra capacity above one token
	Monitor    bool    // would-429 only: record + pass, do not throttle
	Rule       string  // representative matcher name for metrics/audit
}

// hasRateLimit reports whether the site configured any rate_limit rule.
func (p *Pipeline) hasRateLimit() bool { return len(p.rateLimitRules) > 0 }

// evalRateLimit runs the rate_limit rules (first-match-wins) for a request whose
// scope matches, returning the identified hit or nil. It is called by EvalSecurity
// AFTER allow/deny short-circuits, sharing the caller's match context (so a matcher
// shared with a deny rule is evaluated once). Pure: it computes the key, no counting.
func (p *Pipeline) evalRateLimit(ctx *matchContext) *RateLimitHit {
	for i := range p.rateLimitRules {
		r := &p.rateLimitRules[i]
		if !ctx.scopeMatches(r.scope) {
			continue
		}
		return &RateLimitHit{
			Key:        r.bucketKey(ctx.req),
			RatePerSec: r.ratePerSec,
			Burst:      r.burst,
			Monitor:    r.monitor || p.securityMonitor,
			Rule:       r.name,
		}
	}
	return nil
}

// bucketKey computes the per-request bucket key: a per-rule id prefix (so distinct
// rules never collide) plus the keyed dimension. For key ip the dimension is the
// resolved real client IP (decision #16, never the peer); for key header it is the
// header value; for key global it is a constant (one site-wide bucket). An empty
// dimension (missing header, unresolved IP) still produces a stable key so such
// requests share one bucket rather than escaping the limit.
func (r *rateLimitRule) bucketKey(req *Request) string {
	var dim string
	switch r.keyKind {
	case rlKeyIP:
		if req.RealClientIP.IsValid() {
			dim = req.RealClientIP.String()
		} else {
			dim = "noip"
		}
	case rlKeyHeader:
		// Combined (all field-lines), matching the rest of cadish's header reading, so a
		// split header can't fork (or pin a victim's) throttle bucket.
		dim = req.headerCombined(r.keyHeader)
		if dim == "" {
			dim = "noheader"
		}
	case rlKeyGlobal:
		dim = "global"
	}
	// "id|dimension" — id namespaces the bucket per rule; a NUL would also work but a
	// printable separator keeps logs readable and the id is a small integer.
	return strconv.Itoa(r.id) + "|" + dim
}

// compileRateLimit parses a `rate_limit` directive:
//
//	rate_limit [@scope… | INLINE-MATCHER] RATE [burst N] [key ip|header NAME|global] [monitor]
//
// RATE is `Nr/s`, `Nr/m`, or `Nr/h` (requests per second/minute/hour, N may be a
// decimal). Examples:
//
//	rate_limit @api 100r/s burst 50 key ip
//	rate_limit 5r/s                          # unscoped, default key ip, no burst
//	rate_limit 100r/s key header X-Api-Key monitor
//	rate_limit @login 10r/m key global
//
// Default action is 429 (the only action in v1; an explicit `-> block` is accepted
// for symmetry with the spec's illustrative grammar but is the default).
func compileRateLimit(d *cadishfile.Directive, id int, matchers map[string]*matcher) (rateLimitRule, error) {
	r := rateLimitRule{id: id, keyKind: rlKeyIP}
	args := d.Args

	// Trailing `monitor` flag.
	if n := len(args); n > 0 && args[n-1].Raw == "monitor" {
		r.monitor = true
		args = args[:n-1]
	}
	// Optional trailing `-> block` (the default action; accepted for grammar symmetry).
	if n := len(args); n >= 2 && args[n-2].Raw == "->" {
		if args[n-1].Raw != "block" {
			return rateLimitRule{}, &CompileError{Pos: args[n-1].Pos, Msg: "rate_limit action must be `block` (the default), got " + quote(args[n-1].Raw)}
		}
		args = args[:n-2]
	}

	// Optional leading @matcher-ref scope, or one inline matcher.
	sc, rest, err := leadingRefScope(args, matchers)
	if err != nil {
		return rateLimitRule{}, err
	}
	if sc == nil && len(rest) > 0 && isMatcherType(rest[0].Raw) && !isRateSpec(rest[0].Raw) {
		// Inline single-arg matcher scope: `rate_limit path /api/* 100r/s …`.
		if len(rest) < 2 {
			return rateLimitRule{}, &CompileError{Pos: d.Pos, Msg: "rate_limit inline matcher needs an argument"}
		}
		m, merr := compileMatcher("", rest[0].Raw, []string{rest[1].Raw}, d.Pos)
		if merr != nil {
			return rateLimitRule{}, merr
		}
		if isResponsePhaseKind(m.kind) {
			return rateLimitRule{}, &CompileError{Pos: d.Pos, Msg: "rate_limit cannot use a response-phase matcher (" + matcherKindName(m.kind) + "); the security gate runs in RECV"}
		}
		sc = &scope{matchers: []*matcher{m}}
		rest = rest[2:]
	}
	if sc != nil {
		for _, m := range sc.matchers {
			if isResponsePhaseKind(m.kind) {
				return rateLimitRule{}, &CompileError{Pos: d.Pos, Msg: "rate_limit cannot use a response-phase matcher (" + matcherKindName(m.kind) + "); the security gate runs in RECV"}
			}
			if r.name == "" && m.name != "" {
				r.name = m.name
			}
		}
	}
	r.scope = sc

	// RATE (required).
	if len(rest) == 0 {
		return rateLimitRule{}, &CompileError{Pos: d.Pos, Msg: "rate_limit needs a rate (e.g. `rate_limit 100r/s` or `rate_limit @api 100r/s burst 50 key ip`)"}
	}
	rate, err := parseRateSpec(rest[0].Raw)
	if err != nil {
		return rateLimitRule{}, &CompileError{Pos: rest[0].Pos, Msg: "rate_limit: " + err.Error()}
	}
	r.ratePerSec = rate
	rest = rest[1:]

	// Optional `burst N` and `key …`, in any order.
	for len(rest) > 0 {
		switch rest[0].Raw {
		case "burst":
			if len(rest) < 2 {
				return rateLimitRule{}, &CompileError{Pos: rest[0].Pos, Msg: "rate_limit: `burst` needs a count (e.g. `burst 50`)"}
			}
			n, perr := strconv.Atoi(rest[1].Raw)
			if perr != nil || n < 0 {
				return rateLimitRule{}, &CompileError{Pos: rest[1].Pos, Msg: "rate_limit: burst must be a non-negative integer, got " + quote(rest[1].Raw)}
			}
			r.burst = n
			rest = rest[2:]
		case "key":
			if len(rest) < 2 {
				return rateLimitRule{}, &CompileError{Pos: rest[0].Pos, Msg: "rate_limit: `key` needs `ip`, `header NAME`, or `global`"}
			}
			switch rest[1].Raw {
			case "ip":
				r.keyKind = rlKeyIP
				rest = rest[2:]
			case "global":
				r.keyKind = rlKeyGlobal
				rest = rest[2:]
			case "header":
				if len(rest) < 3 || rest[2].Raw == "" {
					return rateLimitRule{}, &CompileError{Pos: rest[1].Pos, Msg: "rate_limit: `key header` needs a header name (e.g. `key header X-Api-Key`)"}
				}
				r.keyKind = rlKeyHeader
				r.keyHeader = rest[2].Raw
				rest = rest[3:]
			default:
				return rateLimitRule{}, &CompileError{Pos: rest[1].Pos, Msg: "rate_limit: key must be `ip`, `header NAME`, or `global`, got " + quote(rest[1].Raw)}
			}
		default:
			return rateLimitRule{}, &CompileError{Pos: rest[0].Pos, Msg: "rate_limit: unexpected token " + quote(rest[0].Raw) + " (want `burst N`, `key …`, `monitor`)"}
		}
	}
	return r, nil
}

// isRateSpec reports whether a token looks like a rate spec (`100r/s`), so the
// inline-matcher detection does not mistake the rate for a matcher type. A matcher
// type never contains `r/`.
func isRateSpec(s string) bool { return strings.Contains(s, "r/") }

// parseRateSpec parses a `Nr/s` / `Nr/m` / `Nr/h` rate into tokens-per-second. N
// may be a decimal. A non-positive rate is rejected (a zero rate would deny every
// request; use `deny` for that).
func parseRateSpec(s string) (float64, error) {
	slash := strings.IndexByte(s, '/')
	if slash < 0 || !strings.HasSuffix(s[:slash], "r") {
		return 0, &rateSpecError{s}
	}
	numStr := s[:slash-1] // drop the trailing 'r'
	unit := s[slash+1:]
	n, err := strconv.ParseFloat(numStr, 64)
	if err != nil || n <= 0 {
		return 0, &rateSpecError{s}
	}
	switch unit {
	case "s":
		return n, nil
	case "m":
		return n / 60, nil
	case "h":
		return n / 3600, nil
	default:
		return 0, &rateSpecError{s}
	}
}

type rateSpecError struct{ s string }

func (e *rateSpecError) Error() string {
	return "bad rate " + quote(e.s) + " (want `Nr/s`, `Nr/m`, or `Nr/h`, e.g. `100r/s`)"
}
