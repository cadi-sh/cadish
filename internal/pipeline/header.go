package pipeline

import "github.com/cadi-sh/cadish/internal/cadishfile"

// HeaderOpKind is the kind of a header edit.
type HeaderOpKind int

const (
	// OpSet replaces (sets) the header to Value: `header NAME VALUE`.
	OpSet HeaderOpKind = iota
	// OpAppend adds a value without removing existing ones: `header +NAME VALUE`.
	OpAppend
	// OpRemove deletes the header: `header -NAME`.
	OpRemove
	// OpCacheStatus is the `header +cache_status NAME` special: at delivery the
	// engine materializes it into an OpSet writing the cache-status token (HIT /
	// MISS / HIT-STALE) into the header named by Name. It never appears in a
	// DeliverDecision (it is resolved away); it exists only in the compiled rules.
	OpCacheStatus
	// OpCacheKey is the `header +cache_key NAME [raw]` special: a delivery-only
	// debug header that emits the request's computed cache key into the header named
	// by Name — the 12-hex sha256 prefix by default, or the raw key string when
	// Value == "raw". Like OpCacheStatus the cache key is NOT in the deliver-phase
	// matchContext (it is the server-held key), so this op is NOT materialized into
	// an OpSet by applyHeaderRules; instead EvalDeliver surfaces the target name +
	// raw flag on the DeliverDecision (CacheKeyHeader/CacheKeyRaw) and the server
	// sets the header from the key it already holds. Value carries "raw" for the raw
	// form and is empty for the hash form.
	OpCacheKey
)

// String renders the op kind (for debugging/tests).
func (k HeaderOpKind) String() string {
	switch k {
	case OpSet:
		return "set"
	case OpAppend:
		return "append"
	case OpRemove:
		return "remove"
	case OpCacheStatus:
		return "cache_status"
	case OpCacheKey:
		return "cache_key"
	default:
		return "unknown"
	}
}

// HeaderOp is a single header edit to apply to a request or response.
type HeaderOp struct {
	Op    HeaderOpKind
	Name  string
	Value string
	// ValueTpl is set at compile time when Value contains a template placeholder
	// ({http.NAME} / {client_ip} / {host} / …) and so must be expanded against the
	// request before the op is emitted (dynamic header values, #17). It is false for
	// a plain literal value, which is emitted verbatim with zero per-request work.
	// The pipeline resolves the template (in applyHeaderRules); a HeaderOp surfaced
	// in a decision always carries a fully-resolved Value, so the server applies it
	// uniformly and never sees the template.
	ValueTpl bool
}

// headerRule is a compiled `header` directive: an optional scope plus one or more
// ops (a single directive may carry several, e.g. `header -A -B -C`). All ops fire
// together when the scope matches.
type headerRule struct {
	scope *scope
	ops   []HeaderOp
}

// parseHeaderOps parses the op portion of a `header` directive (after any scope).
// It supports multiple ops in one directive:
//
//	-NAME              remove
//	+NAME VALUE        append
//	+cache_status N    cache-status special (Name = N)
//	+cache_key N [raw] cache-key debug special (Name = N; Value="raw" for the raw form)
//	NAME VALUE         set
//
// Set/append consume the following token as the value; a quoted empty value is
// allowed, but a missing value for set/append is an error.
func parseHeaderOps(args []cadishfile.Arg, pos cadishfile.Pos) ([]HeaderOp, error) {
	if len(args) == 0 {
		return nil, &CompileError{Pos: pos, Msg: "header directive needs at least one operation"}
	}
	var ops []HeaderOp
	i := 0
	for i < len(args) {
		tok := args[i].Raw
		switch {
		case len(tok) > 1 && tok[0] == '-':
			ops = append(ops, HeaderOp{Op: OpRemove, Name: tok[1:]})
			i++
		case len(tok) > 1 && tok[0] == '+':
			name := tok[1:]
			if name == "cache_status" {
				if i+1 >= len(args) {
					return nil, &CompileError{Pos: pos, Msg: "header +cache_status needs a target header name"}
				}
				ops = append(ops, HeaderOp{Op: OpCacheStatus, Name: args[i+1].Raw})
				i += 2
				continue
			}
			if name == "cache_key" {
				if i+1 >= len(args) {
					return nil, &CompileError{Pos: pos, Msg: "header +cache_key needs a target header name"}
				}
				op := HeaderOp{Op: OpCacheKey, Name: args[i+1].Raw}
				i += 2
				// The only allowed trailing modifier is `raw` (emit the raw key string
				// instead of its hash). Anything else is a compile error so a typo never
				// silently becomes a second header op.
				if i < len(args) {
					mod := args[i].Raw
					if mod != "raw" {
						return nil, &CompileError{Pos: pos, Msg: "header +cache_key " + op.Name + ": unknown modifier " + quote(mod) + " (the only allowed modifier is `raw`)"}
					}
					op.Value = "raw"
					i++
				}
				ops = append(ops, op)
				continue
			}
			if i+1 >= len(args) {
				return nil, &CompileError{Pos: pos, Msg: "header +" + name + " needs a value"}
			}
			val := args[i+1].Raw
			ops = append(ops, HeaderOp{Op: OpAppend, Name: name, Value: val, ValueTpl: hasPlaceholder(val)})
			i += 2
		default:
			if i+1 >= len(args) {
				return nil, &CompileError{Pos: pos, Msg: "header " + tok + " needs a value"}
			}
			val := args[i+1].Raw
			ops = append(ops, HeaderOp{Op: OpSet, Name: tok, Value: val, ValueTpl: hasPlaceholder(val)})
			i += 2
		}
	}
	return ops, nil
}
