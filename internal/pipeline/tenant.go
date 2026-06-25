package pipeline

import (
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// tenantResolver maps a request to a bounded tenant id for the {tenant} cache-key
// token. It is the REQUEST-DERIVED form of {tenant} (`tenant { from … ; map … ;
// default … }`): read the Host (default) or a header, match it against an ordered
// pattern list (exact, or a `*.suffix` host wildcard), and emit the tenant name,
// else the default. Pure — resolved entirely from the Request, like `normalize`,
// so it needs no server pre-pass.
//
// The other form of {tenant} is the per-site CONSTANT set by a bare `tenant NAME`
// directive (used by site-group expansion); that path bakes the name into the
// token and never builds a resolver.
type tenantResolver struct {
	fromHeader string // "" => derive from Host; else the header name
	rules      []tenantRule
	def        string
}

type tenantRule struct {
	pattern string
	name    string
}

func (r tenantRule) match(v string) bool {
	if strings.HasPrefix(r.pattern, "*.") {
		// *.example.com matches example.com and any sub.example.com.
		suffix := r.pattern[1:] // ".example.com"
		return v == r.pattern[2:] || strings.HasSuffix(v, suffix)
	}
	return v == r.pattern
}

func (tr *tenantResolver) resolve(req *Request) string {
	var v string
	if tr.fromHeader != "" {
		v = strings.ToLower(req.headerCombined(tr.fromHeader))
	} else {
		v = req.normHost() // lower-cased, port-stripped
	}
	for _, r := range tr.rules {
		if r.match(v) {
			return r.name
		}
	}
	return tr.def
}

// tenants returns the bounded set of tenant ids this resolver can emit (rule
// targets + default), so `cadish check` can report the count.
func (tr *tenantResolver) tenants() []string {
	seen := make(map[string]bool, len(tr.rules)+1)
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range tr.rules {
		add(r.name)
	}
	add(tr.def)
	return out
}

// compileTenantBlock parses the request-derived `tenant { from … ; map … ;
// default … }` directive.
func compileTenantBlock(d *cadishfile.Directive) (*tenantResolver, error) {
	tr := &tenantResolver{}
	haveFrom := false
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "from":
			if haveFrom {
				return nil, &CompileError{Pos: bd.Pos, Msg: "tenant: duplicate `from`"}
			}
			switch {
			case len(bd.Args) == 1 && bd.Args[0].Raw == "host":
				tr.fromHeader = ""
			case len(bd.Args) == 2 && bd.Args[0].Raw == "header":
				tr.fromHeader = bd.Args[1].Raw
			default:
				return nil, &CompileError{Pos: bd.Pos, Msg: "tenant: `from host` or `from header NAME`"}
			}
			haveFrom = true
		case "map":
			if len(bd.Args) != 3 || bd.Args[1].Raw != "->" {
				return nil, &CompileError{Pos: bd.Pos, Msg: "tenant: `map PATTERN -> NAME`"}
			}
			tr.rules = append(tr.rules, tenantRule{pattern: strings.ToLower(bd.Args[0].Raw), name: bd.Args[2].Raw})
		case "default":
			if len(bd.Args) != 1 {
				return nil, &CompileError{Pos: bd.Pos, Msg: "tenant: `default NAME`"}
			}
			tr.def = bd.Args[0].Raw
		default:
			return nil, &CompileError{Pos: bd.Pos, Msg: "tenant: unknown setting " + quote(bd.Name) + " (want from/map/default)"}
		}
	}
	if !haveFrom {
		return nil, &CompileError{Pos: d.Pos, Msg: "tenant needs a `from host` or `from header NAME`"}
	}
	if len(tr.rules) == 0 && tr.def == "" {
		return nil, &CompileError{Pos: d.Pos, Msg: "tenant needs at least one `map` or a `default`"}
	}
	return tr, nil
}
