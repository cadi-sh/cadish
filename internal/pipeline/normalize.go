package pipeline

import (
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// normSourceKind is where a normalizer reads its input value.
type normSourceKind int

const (
	normHeader normSourceKind = iota
	normCookie
	normQuery
)

// normalizer is a compiled `normalize NAME { from … ; map V -> B … ; default B }`
// directive: read a request value (a header, cookie, or query param), map it
// (exact match) to one of a small, bounded set of buckets, else the default
// bucket. It is the v2c generalization of {device}/{geo} to arbitrary request
// inputs — and unlike them it resolves ENTIRELY from the Request, so the {NAME}
// cache-key token is pure and needs no server pre-pass.
type normalizer struct {
	name       string
	source     normSourceKind
	sourceName string
	mapping    map[string]string // raw value -> bucket
	def        string            // default bucket ("" if unset)
}

// sourceValue reads the normalizer's input from the request.
func (n *normalizer) sourceValue(req *Request) string {
	switch n.source {
	case normHeader:
		return req.headerCombined(n.sourceName)
	case normCookie:
		return req.cookie(n.sourceName)
	case normQuery:
		if req.Query == nil {
			return ""
		}
		return req.Query.Get(n.sourceName)
	}
	return ""
}

// resolve maps the request's source value to a bucket (exact match), or the
// default bucket when there is no mapping.
func (n *normalizer) resolve(req *Request) string {
	if b, ok := n.mapping[n.sourceValue(req)]; ok {
		return b
	}
	return n.def
}

// buckets returns the bounded set of buckets this normalizer can emit (map
// targets plus the default), so tooling can confirm {NAME} is low-cardinality.
func (n *normalizer) buckets() []string {
	seen := make(map[string]bool, len(n.mapping)+1)
	out := make([]string, 0, len(n.mapping)+1)
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, b := range n.mapping {
		add(b)
	}
	add(n.def)
	return out
}

// reservedNormalizerNames are the built-in normalizer token names a user-defined
// `normalize` may not shadow (they have dedicated cache-key tokens).
var reservedNormalizerNames = map[string]bool{"sticky": true, "device": true, "geo": true, "tenant": true}

// compileNormalize parses a `normalize NAME { … }` directive into a normalizer.
func compileNormalize(d *cadishfile.Directive) (*normalizer, error) {
	if len(d.Args) != 1 {
		return nil, &CompileError{Pos: d.Pos, Msg: "normalize needs a name: `normalize NAME { … }`"}
	}
	name := d.Args[0].Raw
	if reservedNormalizerNames[name] {
		return nil, &CompileError{Pos: d.Pos, Msg: "normalize name " + quote(name) + " is reserved (built-in {" + name + "} token)"}
	}
	if !d.HasBlock {
		return nil, &CompileError{Pos: d.Pos, Msg: "normalize " + quote(name) + " needs a { } block"}
	}
	n := &normalizer{name: name, mapping: map[string]string{}}
	haveSource := false
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "from":
			if haveSource {
				return nil, &CompileError{Pos: bd.Pos, Msg: "normalize " + quote(name) + ": duplicate `from`"}
			}
			if len(bd.Args) != 2 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "normalize: `from header|cookie|query NAME`"}
			}
			switch bd.Args[0].Raw {
			case "header":
				n.source = normHeader
			case "cookie":
				n.source = normCookie
			case "query":
				n.source = normQuery
			default:
				return nil, &CompileError{Pos: bd.Args[0].Pos, Msg: "normalize: `from` source must be header, cookie, or query, got " + quote(bd.Args[0].Raw)}
			}
			n.sourceName = bd.Args[1].Raw
			haveSource = true
		case "map":
			// map VALUE[,VALUE…] -> BUCKET   (one comma-list token, or several
			// whitespace-separated value tokens, before the arrow).
			arrow := -1
			for i, a := range bd.Args {
				if a.Raw == "->" {
					arrow = i
					break
				}
			}
			if arrow < 1 || arrow != len(bd.Args)-2 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "normalize: `map VALUE[,VALUE…] -> BUCKET`"}
			}
			bucket := bd.Args[arrow+1].Raw
			added := false
			for _, a := range bd.Args[:arrow] {
				for _, v := range strings.Split(a.Raw, ",") {
					if v = strings.TrimSpace(v); v != "" {
						n.mapping[v] = bucket
						added = true
					}
				}
			}
			if !added {
				return nil, &CompileError{Pos: bd.Pos, Msg: "normalize: `map` needs at least one value before `->`"}
			}
		case "default":
			if len(bd.Args) != 1 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "normalize: `default BUCKET`"}
			}
			n.def = bd.Args[0].Raw
		default:
			return nil, &CompileError{Pos: bd.Pos, Msg: "normalize " + quote(name) + ": unknown setting " + quote(bd.Name) + " (want from/map/default)"}
		}
	}
	if !haveSource {
		return nil, &CompileError{Pos: d.Pos, Msg: "normalize " + quote(name) + " needs a `from` source"}
	}
	if len(n.mapping) == 0 && n.def == "" {
		return nil, &CompileError{Pos: d.Pos, Msg: "normalize " + quote(name) + " needs at least one `map` or a `default`"}
	}
	return n, nil
}
