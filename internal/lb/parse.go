package lb

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/pipeline"
)

// ParseUpstream builds a Config from an `upstream NAME { ... }` directive block.
// It validates structure and values, returning a positioned *cadishfile.ParseError
// on the first problem. Recognized inner directives:
//
//	to URL...                                     (repeatable; ≥1 required)
//	policy round_robin|least_conn|sticky|shard    (or: lb POLICY)
//	sticky by cookie NAME [else client_ip]        (⇒ Policy sticky)
//	sticky by client_ip                           (⇒ Policy sticky)
//	shard_by url|key                              (⇒ Policy shard)
//	health METHOD PATH expect CODE interval D window N threshold T
//	timeout [connect D] [first_byte D] [between_bytes D]
//	max_conns N
//	replicas N                                    (consistent-hash vnodes; tests)
//
// Policy defaults to round_robin, or is inferred from a sticky/shard_by line
// when no explicit policy/lb directive is present.
func ParseUpstream(d *cadishfile.Directive) (Config, error) {
	return parsePool("upstream", d)
}

// ParseCluster builds a Config from a `cluster NAME { ... }` directive block. A
// cluster is a peer pool — semantically the cache-sharding case — and accepts
// exactly the same inner directives as ParseUpstream. (It does not force a shard
// policy; configure `shard_by url` explicitly, as the canonical example does.)
func ParseCluster(d *cadishfile.Directive) (Config, error) {
	return parsePool("cluster", d)
}

func parsePool(kind string, d *cadishfile.Directive) (Config, error) {
	if d.Name != kind {
		return Config{}, posErrf(d.Pos, "expected %q directive, got %q", kind, d.Name)
	}
	if len(d.Args) != 1 {
		return Config{}, posErrf(d.Pos, "%s requires exactly one name argument", kind)
	}
	cfg := Config{
		Name: d.Args[0].Raw,
		Kind: kind,
		Pos:  d.Pos,
	}
	if !d.HasBlock {
		return Config{}, posErrf(d.Pos, "%s %q requires a { } block", kind, cfg.Name)
	}

	explicitPolicy := false
	sawSticky := false
	sawShard := false

	for _, n := range d.Block {
		sub, ok := n.(*cadishfile.Directive)
		if !ok {
			return Config{}, posErrf(n.Position(), "%s %q: unexpected statement", kind, cfg.Name)
		}
		switch sub.Name {
		case "to":
			if len(sub.Args) == 0 {
				return Config{}, posErrf(sub.Pos, "`to` needs at least one backend URL")
			}
			for _, a := range sub.Args {
				t, err := parseTarget(a.Raw, a.Pos)
				if err != nil {
					return Config{}, err
				}
				cfg.Backends = append(cfg.Backends, t)
			}
		case "policy", "lb":
			p, err := parsePolicyArg(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Policy = p
			explicitPolicy = true
		case "sticky":
			sp, err := parseSticky(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Sticky = sp
			sawSticky = true
		case "shard_by":
			sk, err := parseShardBy(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Shard = sk
			sawShard = true
		case "health":
			h, err := parseHealth(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Health = h
		case "timeout":
			to, err := parseTimeouts(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Timeouts = to
		case "max_conns":
			n, err := parseSingleInt(sub, "max_conns")
			if err != nil {
				return Config{}, err
			}
			if n < 0 {
				return Config{}, posErrf(sub.Pos, "max_conns must be >= 0")
			}
			cfg.MaxConns = n
		case "replicas":
			n, err := parseSingleInt(sub, "replicas")
			if err != nil {
				return Config{}, err
			}
			if n <= 0 {
				return Config{}, posErrf(sub.Pos, "replicas must be > 0")
			}
			if n > maxReplicas {
				// A ring places `replicas` virtual nodes PER backend; an absurd
				// count (e.g. a stray "replicas 2000000000") would allocate
				// gigabytes and stall startup building the ring. Reject loudly
				// rather than OOM. maxReplicas is far above any real tuning need.
				return Config{}, posErrf(sub.Pos, "replicas %d is too large (max %d)", n, maxReplicas)
			}
			cfg.Replicas = n
		case "sni":
			name, err := ParseSNIArg(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.SNI = name
		case "http_reuse":
			if err := ParseHTTPReuseArg(sub); err != nil {
				return Config{}, err
			}
			cfg.DisableReuse = true
		default:
			return Config{}, posErrf(sub.Pos, "%s %q: unknown directive %q", kind, cfg.Name, sub.Name)
		}
	}

	if sawSticky && sawShard {
		return Config{}, posErrf(d.Pos, "%s %q: `sticky` and `shard_by` are mutually exclusive", kind, cfg.Name)
	}
	if !explicitPolicy {
		switch {
		case sawSticky:
			cfg.Policy = Sticky
		case sawShard:
			cfg.Policy = Shard
		default:
			cfg.Policy = RoundRobin
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ParseSNIArg parses an `sni <server-name>` directive into its single hostname
// argument (gap H6). It takes exactly one non-empty host token; an accidental
// matcher ref (`@name`) is rejected so a typo doesn't silently advertise a bogus
// SNI. The validity check mirrors a fixed `host_header VALUE`.
func ParseSNIArg(d *cadishfile.Directive) (string, error) {
	if len(d.Args) != 1 {
		return "", posErrf(d.Pos, "sni takes exactly one argument: a server name (e.g. `sni www.example.com`)")
	}
	v := d.Args[0].Raw
	if v == "" || strings.HasPrefix(v, "@") {
		return "", posErrf(d.Args[0].Pos, "sni: invalid server name %q", v)
	}
	return v, nil
}

// ParseHTTPReuseArg parses an `http_reuse never` directive (gap H6). ONLY `never`
// is accepted (owner decision 2026-06-24 — keep the surface minimal; the implicit
// default is connection reuse). Any other keyword — including HAProxy's
// safe/aggressive/always — is a positioned error naming the supported set. It
// returns nil on the valid `never` form; the caller sets DisableReuse.
func ParseHTTPReuseArg(d *cadishfile.Directive) error {
	if len(d.Args) != 1 {
		return posErrf(d.Pos, "http_reuse takes exactly one keyword: `never` (the only supported value)")
	}
	if d.Args[0].Raw != "never" {
		return posErrf(d.Args[0].Pos, "http_reuse: unsupported value %q (only `never` is supported; reuse is the default)", d.Args[0].Raw)
	}
	return nil
}

func parsePolicyArg(d *cadishfile.Directive) (Policy, error) {
	if len(d.Args) != 1 {
		return 0, posErrf(d.Pos, "%s needs exactly one policy keyword", d.Name)
	}
	switch d.Args[0].Raw {
	case "round_robin":
		return RoundRobin, nil
	case "least_conn":
		return LeastConn, nil
	case "sticky":
		return Sticky, nil
	case "shard":
		return Shard, nil
	default:
		return 0, posErrf(d.Args[0].Pos, "unknown policy %q (want round_robin, least_conn, sticky, shard)", d.Args[0].Raw)
	}
}

// parseSticky parses `sticky by cookie NAME [else SRC]` or `sticky by client_ip`.
func parseSticky(d *cadishfile.Directive) (*StickySpec, error) {
	args := d.Args
	if len(args) >= 1 && args[0].Raw == "by" {
		args = args[1:]
	}
	if len(args) == 0 {
		return nil, posErrf(d.Pos, "sticky needs a source (cookie NAME | client_ip)")
	}
	sp := &StickySpec{}
	rest, err := parseStickySource(d, args, &sp.Source, &sp.Cookie)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return sp, nil
	}
	if rest[0].Raw != "else" {
		return nil, posErrf(rest[0].Pos, "sticky: expected `else`, got %q", rest[0].Raw)
	}
	rest = rest[1:]
	if len(rest) == 0 {
		return nil, posErrf(d.Pos, "sticky: `else` needs a fallback source")
	}
	tail, err := parseStickySource(d, rest, &sp.Fallback, &sp.FallbackCookie)
	if err != nil {
		return nil, err
	}
	if len(tail) != 0 {
		return nil, posErrf(tail[0].Pos, "sticky: unexpected token %q", tail[0].Raw)
	}
	return sp, nil
}

// parseStickySource consumes a source clause ("cookie NAME" or "client_ip") from
// the front of args, writing into src/cookie, and returns the remaining args.
func parseStickySource(d *cadishfile.Directive, args []cadishfile.Arg, src, cookie *string) ([]cadishfile.Arg, error) {
	switch args[0].Raw {
	case "cookie":
		if len(args) < 2 {
			return nil, posErrf(args[0].Pos, "sticky: `cookie` needs a name")
		}
		*src = "cookie"
		*cookie = args[1].Raw
		return args[2:], nil
	case "client_ip":
		*src = "client_ip"
		return args[1:], nil
	default:
		return nil, posErrf(args[0].Pos, "sticky: unknown source %q (want cookie NAME | client_ip)", args[0].Raw)
	}
}

func parseShardBy(d *cadishfile.Directive) (ShardKey, error) {
	if len(d.Args) != 1 {
		return ShardNone, posErrf(d.Pos, "shard_by needs exactly one argument (url | key)")
	}
	switch d.Args[0].Raw {
	case "url":
		return ShardURL, nil
	case "key":
		return ShardKeyVal, nil
	default:
		return ShardNone, posErrf(d.Args[0].Pos, "shard_by: want `url` or `key`, got %q", d.Args[0].Raw)
	}
}

// parseHealth parses
// `health METHOD PATH expect CODE interval D window N threshold T`.
func parseHealth(d *cadishfile.Directive) (*HealthSpec, error) {
	if len(d.Args) < 2 {
		return nil, posErrf(d.Pos, "health: want METHOD PATH expect CODE interval D window N threshold T")
	}
	h := &HealthSpec{Method: strings.ToUpper(d.Args[0].Raw), Path: d.Args[1].Raw}
	rest := d.Args[2:]
	for len(rest) > 0 {
		kw := rest[0]
		// `expect` is variadic: it consumes one OR MORE acceptance tokens (exact
		// codes `200`, `301` and/or class forms `2xx`, `3xx`) up to the next known
		// keyword or end of args. Single-int (`expect 301`) keeps back-compat.
		if kw.Raw == "expect" {
			vals := rest[1:]
			n := 0
			for n < len(vals) && !healthKeyword(vals[n].Raw) {
				n++
			}
			if n == 0 {
				return nil, posErrf(kw.Pos, "health: expect wants at least one status code or class (e.g. 200, 301, 2xx)")
			}
			for _, v := range vals[:n] {
				code, cls, err := parseExpectToken(v.Raw)
				if err != nil {
					return nil, posErrf(v.Pos, "health: expect wants a status code or class (e.g. 200, 2xx), got %q", v.Raw)
				}
				switch {
				case cls != 0:
					h.ExpectClasses = append(h.ExpectClasses, cls)
				case n == 1:
					// Single exact code → the back-compat ExpectCode field.
					h.ExpectCode = code
				default:
					h.ExpectCodes = append(h.ExpectCodes, code)
				}
			}
			rest = vals[n:]
			continue
		}
		if len(rest) < 2 {
			return nil, posErrf(kw.Pos, "health: %q needs a value", kw.Raw)
		}
		val := rest[1]
		switch kw.Raw {
		case "interval":
			dur, err := pipeline.ParseDuration(val.Raw)
			if err != nil {
				return nil, posErrf(val.Pos, "health: bad interval %q: %v", val.Raw, err)
			}
			h.Interval = dur
		case "window":
			n, err := strconv.Atoi(val.Raw)
			if err != nil {
				return nil, posErrf(val.Pos, "health: window wants an integer, got %q", val.Raw)
			}
			if n > maxWindow {
				// A window is the last N probe outcomes; an absurd N drives a
				// `make([]bool, N)` ~2GB-per-backend allocation at pool construction.
				// Reject loudly rather than OOM. maxWindow is far above any real need.
				return nil, posErrf(val.Pos, "health: window %d is too large (max %d)", n, maxWindow)
			}
			h.Window = n
		case "threshold":
			n, err := strconv.Atoi(val.Raw)
			if err != nil {
				return nil, posErrf(val.Pos, "health: threshold wants an integer, got %q", val.Raw)
			}
			h.Threshold = n
		default:
			return nil, posErrf(kw.Pos, "health: unknown key %q", kw.Raw)
		}
		rest = rest[2:]
	}
	if !h.hasExpect() {
		return nil, posErrf(d.Pos, "health: missing `expect CODE`")
	}
	if h.Interval == 0 {
		h.Interval = 5 * time.Second
	}
	if h.Window == 0 {
		h.Window = 3
	}
	if h.Threshold == 0 {
		h.Threshold = h.Window
	}
	return h, nil
}

// healthKeyword reports whether a token is a `health` sub-key (so the variadic
// `expect` list knows where to stop).
func healthKeyword(s string) bool {
	switch s {
	case "expect", "interval", "window", "threshold":
		return true
	}
	return false
}

// HealthKeyword reports whether a token is a `health` sub-key. Exported so the
// `cadish check` linter can find where a variadic `expect` list ends and validate
// exactly the tokens the runtime parser consumes (check≡run).
func HealthKeyword(s string) bool { return healthKeyword(s) }

// MaxWindow is the largest accepted health `window N` sample count. Exported so the
// `cadish check` linter rejects an absurd window at lint time with the SAME bound the
// runtime parser enforces in parseHealth (check≡run) — otherwise check passes a config
// that would drive a ~2GB-per-backend allocation and fail at `cadish run`.
func MaxWindow() int { return maxWindow }

// ValidateExpectToken reports whether s is a valid `health … expect` acceptance —
// an exact status code (100–599) or a status class `Nxx` (1≤N≤5). It is the same
// predicate the runtime parser enforces via parseExpectToken, exported so the
// `cadish check` linter rejects a malformed `expect` token (e.g. `6xx`, `999`,
// `foo`) at lint time instead of only at load (check≡run).
func ValidateExpectToken(s string) bool {
	_, _, err := parseExpectToken(s)
	return err == nil
}

// parseExpectToken parses one `expect` acceptance: an exact status code (returns
// code>0, cls==0) or a status class `Nxx` (returns cls = leading digit, code==0).
func parseExpectToken(s string) (code, cls int, err error) {
	if len(s) == 3 && (s[1] == 'x' || s[1] == 'X') && (s[2] == 'x' || s[2] == 'X') && s[0] >= '1' && s[0] <= '5' {
		return 0, int(s[0] - '0'), nil
	}
	code, err = strconv.Atoi(s)
	if err != nil || code < 100 || code > 599 {
		return 0, 0, fmt.Errorf("not a status code or class")
	}
	return code, 0, nil
}

// parseTimeouts parses `timeout [connect D] [first_byte D] [between_bytes D]`.
func parseTimeouts(d *cadishfile.Directive) (Timeouts, error) {
	var to Timeouts
	rest := d.Args
	if len(rest) == 0 {
		return to, posErrf(d.Pos, "timeout: needs at least one of connect/first_byte/between_bytes")
	}
	for len(rest) > 0 {
		kw := rest[0]
		if len(rest) < 2 {
			return to, posErrf(kw.Pos, "timeout: %q needs a duration", kw.Raw)
		}
		dur, err := pipeline.ParseDuration(rest[1].Raw)
		if err != nil {
			return to, posErrf(rest[1].Pos, "timeout: bad duration %q: %v", rest[1].Raw, err)
		}
		switch kw.Raw {
		case "connect":
			to.Connect = dur
		case "first_byte":
			to.FirstByte = dur
		case "between_bytes":
			to.BetweenBytes = dur
		default:
			return to, posErrf(kw.Pos, "timeout: unknown key %q (want connect/first_byte/between_bytes)", kw.Raw)
		}
		rest = rest[2:]
	}
	return to, nil
}

func parseSingleInt(d *cadishfile.Directive, name string) (int, error) {
	if len(d.Args) != 1 {
		return 0, posErrf(d.Pos, "%s needs exactly one integer argument", name)
	}
	n, err := strconv.Atoi(d.Args[0].Raw)
	if err != nil {
		return 0, posErrf(d.Args[0].Pos, "%s wants an integer, got %q", name, d.Args[0].Raw)
	}
	return n, nil
}
