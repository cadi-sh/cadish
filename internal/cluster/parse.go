package cluster

import (
	"fmt"
	"strconv"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/lb"
)

// Parse builds a Config from a `cluster { … }` membership directive. The block
// has NO name argument (that form is the lb pool) and accepts:
//
//	self    URL                                              (this node; ∈ peers)
//	peers   URL...                                           (repeatable; ≥1)
//	region  NAME
//	mode    read_through | owner                             (default read_through)
//	fallback strict | degraded                               (default degraded)
//	health  METHOD PATH expect CODE interval D window N threshold T
//	replicas N                                               (ring vnodes; tests)
//
// Errors are positioned *cadishfile.ParseError (file:line:col: message).
func Parse(d *cadishfile.Directive) (Config, error) {
	if d.Name != "cluster" {
		return Config{}, posErrf(d.Pos, "expected `cluster` directive, got %q", d.Name)
	}
	if len(d.Args) != 0 {
		return Config{}, posErrf(d.Pos, "cluster membership block takes no name (write `cluster { peers … }`); a named `cluster NAME { to … }` is an upstream pool")
	}
	if !d.HasBlock {
		return Config{}, posErrf(d.Pos, "cluster requires a { } block")
	}
	cfg := Config{Pos: d.Pos}

	for _, n := range d.Block {
		sub, ok := n.(*cadishfile.Directive)
		if !ok {
			return Config{}, posErrf(n.Position(), "cluster: unexpected statement")
		}
		switch sub.Name {
		case "self":
			if len(sub.Args) != 1 {
				return Config{}, posErrf(sub.Pos, "self needs exactly one URL")
			}
			cfg.Self = sub.Args[0].Raw
		case "peers":
			if len(sub.Args) == 0 {
				return Config{}, posErrf(sub.Pos, "peers needs at least one peer URL")
			}
			for _, a := range sub.Args {
				t, err := lb.ParseTarget(a.Raw, a.Pos)
				if err != nil {
					return Config{}, err
				}
				cfg.Peers = append(cfg.Peers, t)
			}
		case "region":
			if len(sub.Args) != 1 {
				return Config{}, posErrf(sub.Pos, "region needs exactly one name")
			}
			cfg.Region = sub.Args[0].Raw
		case "mode":
			m, err := parseMode(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Mode = m
		case "fallback":
			f, err := parseFallback(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Fallback = f
		case "health":
			h, err := lb.ParseHealthSpec(sub)
			if err != nil {
				return Config{}, err
			}
			cfg.Health = h
		case "replicas":
			if len(sub.Args) != 1 {
				return Config{}, posErrf(sub.Pos, "replicas needs exactly one integer")
			}
			n, err := strconv.Atoi(sub.Args[0].Raw)
			if err != nil || n <= 0 {
				return Config{}, posErrf(sub.Args[0].Pos, "replicas must be a positive integer, got %q", sub.Args[0].Raw)
			}
			cfg.Replicas = n
		default:
			return Config{}, posErrf(sub.Pos, "cluster: unknown directive %q", sub.Name)
		}
	}

	return cfg, validate(&cfg)
}

func validate(cfg *Config) error {
	if cfg.Region == "" {
		return posErrf(cfg.Pos, "cluster: `region` is required")
	}
	if len(cfg.Peers) == 0 {
		return posErrf(cfg.Pos, "cluster: at least one `peers` URL is required")
	}
	if cfg.Self == "" {
		return posErrf(cfg.Pos, "cluster: `self` is required (this node's peer URL)")
	}
	// Self must be one of the configured peers, normalized through the same target
	// parser so http://h:80 and h:80 compare equal.
	selfT, err := lb.ParseTarget(cfg.Self, cfg.Pos)
	if err != nil {
		return err
	}
	// With dynamic discovery (dns://, k8s://) the peer set is resolved at runtime
	// and won't textually list `self`, so we only enforce membership when EVERY
	// peer is a static URL (the case where the set is fully known at parse time).
	allStatic := true
	found := false
	for _, p := range cfg.Peers {
		if p.Scheme != lb.SchemeStatic {
			allStatic = false
		}
		if p.Raw == selfT.Raw {
			found = true
		}
	}
	if allStatic && !found {
		return posErrf(cfg.Pos, "cluster: `self` %q must be one of the `peers`", cfg.Self)
	}
	cfg.Self = selfT.Raw // store the normalized form so PeerID(self) matches
	return nil
}

func parseMode(d *cadishfile.Directive) (Mode, error) {
	if len(d.Args) != 1 {
		return 0, posErrf(d.Pos, "mode needs exactly one keyword (read_through | owner)")
	}
	switch d.Args[0].Raw {
	case "read_through":
		return ModeReadThrough, nil
	case "owner":
		return ModeOwner, nil
	default:
		return 0, posErrf(d.Args[0].Pos, "unknown cluster mode %q (want read_through | owner)", d.Args[0].Raw)
	}
}

func parseFallback(d *cadishfile.Directive) (Fallback, error) {
	if len(d.Args) != 1 {
		return 0, posErrf(d.Pos, "fallback needs exactly one keyword (strict | degraded)")
	}
	switch d.Args[0].Raw {
	case "strict":
		return FallbackStrict, nil
	case "degraded":
		return FallbackDegraded, nil
	default:
		return 0, posErrf(d.Args[0].Pos, "unknown cluster fallback %q (want strict | degraded)", d.Args[0].Raw)
	}
}

func posErrf(p cadishfile.Pos, format string, args ...any) error {
	return &cadishfile.ParseError{File: p.File, Line: p.Line, Col: p.Col, Msg: fmt.Sprintf(format, args...)}
}
