package pipeline

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// defaultKVMaxBytes is the default `kv_max_bytes` guardrail: objects larger than
// this are written to L1 only, never replicated through KV (design §"Size bound").
const defaultKVMaxBytes int64 = 1 << 20 // 1 MiB

// edgeConfig is the compiled `edge { … }` block. It carries two distinct things:
//
//   - Cloudflare DEPLOY IDENTITY (account / zone / worker / routes / kv namespace)
//     — consumed only by the management plane (`cadish edge deploy/enable/disable`);
//     NEVER projected into the public worker IR.
//   - edge CACHE-TIER POLICIES (per-scope local | distribute | skip, + a default)
//     — projected into the worker IR so the runtime stores each object in the right
//     tier (L1 only, L1+L2 KV, or not at all).
//
// KV (distribute) is opt-in: with no `distribute` policy and no explicit default
// of "distribute", no namespace is needed (design §7).
type edgeConfig struct {
	account     string
	zone        string
	worker      string
	routes      []string
	kvNamespace string

	defaultTier string // local|distribute|skip ("" normalized to "local")
	policies    []edgeTierRule

	// kvTTL caps KV retention (the KV `expirationTtl`) independently of the object's
	// ttl+grace. Zero => unset (use the object's ttl+grace, today's behavior).
	kvTTL time.Duration
	// kvMaxBytes is the hard size bound for the KV (L2) tier: a response body larger
	// than this is written to L1 only, never KV. Defaults to defaultKVMaxBytes (1 MiB).
	kvMaxBytes int64
}

// edgeTierRule is one per-scope edge cache-tier policy.
type edgeTierRule struct {
	scope *scope
	tier  string // local|distribute|skip
}

// validEdgeTier reports whether t is a recognized edge cache tier.
func validEdgeTier(t string) bool {
	return t == "local" || t == "distribute" || t == "skip"
}

// compileEdgeBlock parses an `edge { … }` directive into an edgeConfig. Matcher
// refs in tier policies resolve against the site's named matchers.
func compileEdgeBlock(d *cadishfile.Directive, matchers map[string]*matcher) (*edgeConfig, error) {
	if !d.HasBlock {
		return nil, &CompileError{Pos: d.Pos, Msg: "edge needs a `{ … }` block (account/zone/worker/route/kv/default/distribute)"}
	}
	ec := &edgeConfig{}
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "account":
			v, err := edgeOneArg(bd, "account")
			if err != nil {
				return nil, err
			}
			ec.account = v
		case "zone":
			v, err := edgeOneArg(bd, "zone")
			if err != nil {
				return nil, err
			}
			ec.zone = v
		case "worker":
			v, err := edgeOneArg(bd, "worker")
			if err != nil {
				return nil, err
			}
			ec.worker = v
		case "kv":
			v, err := edgeOneArg(bd, "kv")
			if err != nil {
				return nil, err
			}
			ec.kvNamespace = v
		case "route":
			if len(bd.Args) == 0 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge: `route PATTERN…` needs at least one route pattern"}
			}
			for _, a := range bd.Args {
				ec.routes = append(ec.routes, a.Raw)
			}
		case "default":
			v, err := edgeOneArg(bd, "default")
			if err != nil {
				return nil, err
			}
			if !validEdgeTier(v) {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge default tier must be local, distribute, or skip, got " + quote(v)}
			}
			ec.defaultTier = v
		case "kv_ttl":
			v, err := edgeOneArg(bd, "kv_ttl")
			if err != nil {
				return nil, err
			}
			d, err := parseDuration(v)
			if err != nil {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge: kv_ttl is not a valid duration: " + err.Error()}
			}
			if d <= 0 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge: kv_ttl must be positive, got " + quote(v)}
			}
			ec.kvTTL = d
		case "kv_max_bytes":
			v, err := edgeOneArg(bd, "kv_max_bytes")
			if err != nil {
				return nil, err
			}
			n, err := parseSize(v)
			if err != nil {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge: kv_max_bytes is not a valid size: " + err.Error()}
			}
			if n <= 0 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge: kv_max_bytes must be positive, got " + quote(v)}
			}
			ec.kvMaxBytes = n
		case "distribute", "local", "skip":
			sc, err := parseScopeAll(bd.Args, matchers, bd.Pos)
			if err != nil {
				return nil, err
			}
			if sc == nil {
				return nil, &CompileError{Pos: bd.Pos, Msg: "edge " + bd.Name + " needs a @matcher scope (e.g. `" + bd.Name + " @html`)"}
			}
			ec.policies = append(ec.policies, edgeTierRule{scope: sc, tier: bd.Name})
		default:
			return nil, &CompileError{Pos: bd.Pos, Msg: "edge: unknown setting " + quote(bd.Name) + " (want account/zone/worker/route/kv/default/distribute/local/skip/kv_ttl/kv_max_bytes)"}
		}
	}
	if ec.defaultTier == "" {
		ec.defaultTier = "local"
	}
	if ec.kvMaxBytes == 0 {
		ec.kvMaxBytes = defaultKVMaxBytes
	}
	return ec, nil
}

// parseSize parses a byte-size literal (e.g. "1MB", "512KiB", "1048576") for the
// edge `kv_max_bytes` setting. It mirrors config.ParseSize's grammar — binary
// (KiB/MiB/GiB/TiB/PiB, ×1024) or decimal (KB/MB/GB/TB/PB, ×1000) suffixes, a bare
// "B" or no suffix for bytes, fractions allowed, case-insensitive — but lives here
// to avoid a pipeline→config import cycle.
func parseSize(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("empty size")
	}
	lower := strings.ToLower(raw)
	units := []struct {
		suffix string
		mult   float64
	}{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40}, {"pib", 1 << 50},
		{"kb", 1e3}, {"mb", 1e6}, {"gb", 1e9}, {"tb", 1e12}, {"pb", 1e15},
		{"b", 1},
	}
	mult := 1.0
	numPart := lower
	for _, u := range units {
		if strings.HasSuffix(lower, u.suffix) {
			mult = u.mult
			numPart = strings.TrimSpace(lower[:len(lower)-len(u.suffix)])
			break
		}
	}
	if numPart == "" {
		return 0, fmt.Errorf("size %q has no numeric part", raw)
	}
	n, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %v", raw, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("size %q must not be negative", raw)
	}
	return int64(n * mult), nil
}

func edgeOneArg(d *cadishfile.Directive, name string) (string, error) {
	if len(d.Args) != 1 {
		return "", &CompileError{Pos: d.Pos, Msg: "edge: `" + name + "` needs exactly one value"}
	}
	return d.Args[0].Raw, nil
}

// --- neutral accessors for the edge projector / management plane ----------------

// EdgeDeploy is the neutral view of the `edge {}` block's Cloudflare deploy
// identity. HasKV reports whether an L2 KV namespace is configured (or implied by
// a distribute policy / default).
type EdgeDeploy struct {
	Account     string
	Zone        string
	Worker      string
	Routes      []string
	KVNamespace string
	Configured  bool // true iff the site declared an `edge {}` block
}

// EdgeDeployConfig returns the site's Cloudflare deploy identity. Configured is
// false when there is no `edge {}` block (deploy then needs flags/env).
func (p *Pipeline) EdgeDeployConfig() EdgeDeploy {
	if p.edge == nil {
		return EdgeDeploy{}
	}
	return EdgeDeploy{
		Account:     p.edge.account,
		Zone:        p.edge.zone,
		Worker:      p.edge.worker,
		Routes:      append([]string(nil), p.edge.routes...),
		KVNamespace: p.edge.kvNamespace,
		Configured:  true,
	}
}

// EdgeDefaultTier returns the default edge cache tier ("local" when no edge block).
func (p *Pipeline) EdgeDefaultTier() string {
	if p.edge == nil || p.edge.defaultTier == "" {
		return "local"
	}
	return p.edge.defaultTier
}

// EdgeKVTTL returns the configured `kv_ttl` cap on KV retention and whether it was
// set. Zero/false => no cap (KV retention defaults to the object's ttl+grace).
func (p *Pipeline) EdgeKVTTL() (time.Duration, bool) {
	if p.edge == nil || p.edge.kvTTL <= 0 {
		return 0, false
	}
	return p.edge.kvTTL, true
}

// EdgeKVMaxBytes returns the `kv_max_bytes` size bound for the KV (L2) tier. A
// response body larger than this is written to L1 only, never KV. Defaults to
// defaultKVMaxBytes (1 MiB) when no edge block sets it.
func (p *Pipeline) EdgeKVMaxBytes() int64 {
	if p.edge == nil || p.edge.kvMaxBytes <= 0 {
		return defaultKVMaxBytes
	}
	return p.edge.kvMaxBytes
}

// EdgeTierPolicy is the neutral view of one per-scope edge cache-tier policy.
type EdgeTierPolicy struct {
	Scope EdgeScope
	Tier  string
}

// EdgeTierPolicies returns the per-scope edge cache-tier policies, in order.
func (p *Pipeline) EdgeTierPolicies() []EdgeTierPolicy {
	if p.edge == nil {
		return nil
	}
	out := make([]EdgeTierPolicy, 0, len(p.edge.policies))
	for _, r := range p.edge.policies {
		out = append(out, EdgeTierPolicy{Scope: scopeView(r.scope), Tier: r.tier})
	}
	return out
}

// EdgeUsesKV reports whether the edge cache needs an L2 KV namespace: an explicit
// `kv NAME`, a `distribute` policy, or a default tier of "distribute".
func (p *Pipeline) EdgeUsesKV() bool {
	if p.edge == nil {
		return false
	}
	if p.edge.kvNamespace != "" || p.edge.defaultTier == "distribute" {
		return true
	}
	for _, r := range p.edge.policies {
		if r.tier == "distribute" {
			return true
		}
	}
	return false
}
