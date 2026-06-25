package cadishfile

// Site-group expansion: the V2d multi-tenant mechanism. A `group { … }` block
// holds shared BASE directives plus one `tenant NAME { host H…; <overrides> }`
// block per brand/host. ExpandGroups rewrites each group into one ordinary Site
// per tenant — addresses = the tenant's hosts, body = the tenant's overrides
// followed by the inherited base (so a tenant's rule takes priority and the base
// is the fallback), tagged with an injected `tenant NAME` directive that drives
// the `{tenant}` cache-key token. This is a pure AST macro expansion (like
// SubstituteEnv) — it interprets only the group/tenant/host keywords, not any
// directive semantics.

// groupAddress marks a site block as a group (rather than a host-addressed site).
const groupAddress = "group"

// singletonGroupDirectives are directives a tenant override REPLACES wholesale:
// the base's copy is dropped when the tenant supplies one (these are last-wins or
// at-most-one-per-site, so leaving the base copy would shadow the override).
var singletonGroupDirectives = map[string]bool{
	"cache":         true,
	"cache_key":     true,
	"tls":           true,
	"cors":          true,
	"device_detect": true,
	"geo":           true,
	"tenant":        true,
}

// namedGroupDirectives are directives keyed by their first argument (a tenant
// override of the same name replaces the base's, to avoid duplicate-name errors).
var namedGroupDirectives = map[string]bool{
	"upstream":  true,
	"cluster":   true,
	"normalize": true,
}

// IsGroup reports whether a site is a `group { … }` block.
func IsGroup(s *Site) bool {
	return s != nil && len(s.Addresses) == 1 && s.Addresses[0] == groupAddress
}

// ExpandGroups replaces every `group` site in sites with one ordinary site per
// tenant (base ⊕ tenant overrides). Non-group sites pass through unchanged. It
// returns a *GroupError on a malformed group.
func ExpandGroups(sites []*Site) ([]*Site, error) {
	out := make([]*Site, 0, len(sites))
	for _, s := range sites {
		if !IsGroup(s) {
			out = append(out, s)
			continue
		}
		expanded, err := expandGroup(s)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded...)
	}
	return out, nil
}

// GroupError is a positioned error from group expansion.
type GroupError struct {
	Pos Pos
	Msg string
}

func (e *GroupError) Error() string { return e.Pos.String() + ": " + e.Msg }

func expandGroup(g *Site) ([]*Site, error) {
	// Partition the group body into shared base nodes and per-tenant blocks.
	var base []Node
	var tenants []*Directive
	for _, n := range g.Body {
		if d, ok := n.(*Directive); ok && d.Name == "tenant" {
			tenants = append(tenants, d)
			continue
		}
		base = append(base, n)
	}
	if len(tenants) == 0 {
		return nil, &GroupError{Pos: g.Pos, Msg: "group needs at least one `tenant NAME { … }` block"}
	}

	var out []*Site
	seenName := map[string]bool{}
	for _, td := range tenants {
		if len(td.Args) != 1 {
			return nil, &GroupError{Pos: td.Pos, Msg: "tenant needs exactly one name: `tenant NAME { … }`"}
		}
		name := td.Args[0].Raw
		if seenName[name] {
			return nil, &GroupError{Pos: td.Pos, Msg: "duplicate tenant " + name + " in group"}
		}
		seenName[name] = true
		if !td.HasBlock {
			return nil, &GroupError{Pos: td.Pos, Msg: "tenant " + name + " needs a { } block"}
		}

		hosts, overrides, err := splitTenantBlock(td)
		if err != nil {
			return nil, err
		}
		body := mergeBaseTenant(base, overrides, name, td.Pos)
		out = append(out, &Site{Addresses: hosts, Body: body, Pos: td.Pos})
	}
	return out, nil
}

// splitTenantBlock pulls the `host …` line (the tenant's addresses) out of a
// tenant block and returns the remaining override nodes.
func splitTenantBlock(td *Directive) (hosts []string, overrides []Node, err error) {
	for _, n := range td.Block {
		if d, ok := n.(*Directive); ok && d.Name == "host" {
			for _, a := range d.Args {
				hosts = append(hosts, a.Raw)
			}
			continue
		}
		overrides = append(overrides, n)
	}
	if len(hosts) == 0 {
		return nil, nil, &GroupError{Pos: td.Pos, Msg: "tenant " + td.Args[0].Raw + " needs a `host HOST…` line"}
	}
	return hosts, overrides, nil
}

// mergeBaseTenant builds the expanded site body: an injected `tenant NAME`
// directive, then the tenant's overrides (first, so first-match-wins rules take
// priority), then the base directives that the tenant did not override.
func mergeBaseTenant(base, overrides []Node, name string, pos Pos) []Node {
	// Identify what the tenant overrides.
	overSingleton := map[string]bool{}
	overNamed := map[string]bool{} // "kind\x00name"
	overMatcher := map[string]bool{}
	for _, n := range overrides {
		switch d := n.(type) {
		case *Directive:
			if singletonGroupDirectives[d.Name] {
				overSingleton[d.Name] = true
			}
			if namedGroupDirectives[d.Name] && len(d.Args) >= 1 {
				overNamed[d.Name+"\x00"+d.Args[0].Raw] = true
			}
		case *MatcherDef:
			overMatcher[d.Name] = true
		}
	}

	out := make([]Node, 0, len(overrides)+len(base)+1)
	// Inject `tenant NAME` so Compile resolves {tenant}.
	out = append(out, &Directive{Name: "tenant", Args: []Arg{{Raw: name, Pos: pos}}, Pos: pos})
	out = append(out, overrides...)
	for _, n := range base {
		switch d := n.(type) {
		case *Directive:
			if singletonGroupDirectives[d.Name] && overSingleton[d.Name] {
				continue
			}
			if namedGroupDirectives[d.Name] && len(d.Args) >= 1 && overNamed[d.Name+"\x00"+d.Args[0].Raw] {
				continue
			}
		case *MatcherDef:
			if overMatcher[d.Name] {
				continue
			}
		}
		out = append(out, n)
	}
	return out
}
