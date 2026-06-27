package cadishfile

import "strings"

// SubstituteEnv expands environment-variable placeholders of the form "{$VAR}"
// in every argument of the AST, in place, using the provided lookup function.
//
// This is a separate, opt-in pass rather than something baked into the lexer or
// parser: `cadish check` and `cadish fmt` must be able to operate on a config
// without a populated environment (and without leaking host environment values
// into formatted output). Pass os.LookupEnv (wrapped) for the real environment,
// or a test stub.
//
// Only "{$VAR}" spans are substituted. Generic placeholders like "{device}" or
// "{http.X-Foo}" are left untouched — those are runtime placeholders resolved by
// the pipeline, not environment variables. If a referenced variable is not found
// by lookup, the placeholder is replaced with the empty string (matching Caddy's
// behavior). After substitution an argument's Kind is recomputed: a token that no
// longer contains any "{" placeholder is reclassified from ArgPlaceholder to
// ArgLiteral (or ArgMatcherRef if it begins with "@").
//
// lookup receives the bare variable name (without "$" or braces) and returns its
// value and whether it was set.
func SubstituteEnv(f *File, lookup func(name string) (string, bool)) {
	if f == nil {
		return
	}
	if f.Global != nil {
		substituteNodes(f.Global.Body, lookup)
	}
	substituteNodes(f.Body, lookup)
	for _, s := range f.Sites {
		substituteNodes(s.Body, lookup)
	}
}

// ContainsEnvPlaceholder reports whether s contains an UNESCAPED "{$" env-expansion
// span — the trigger for SubstituteEnv (including the R07 quoted-literal expansion). A
// backslash-escaped "\{" is not a placeholder and is skipped. It is the canonical guard
// for any externally-influenced value (k8s Ingress/Gateway tenant match names, header/
// query values, methods, paths) concatenated into GENERATED Cadishfile text: such a
// value must never be allowed to expand against the controller pod's environment when the
// combined config is loaded (config.loadFromSource -> SubstituteEnv(os.LookupEnv)), which
// would leak the admin token / any secret. QuoteArg quotes but does not neutralize "{$"
// (and there is no value-preserving escape — "\{$" survives lexing as a literal backslash),
// so generation code must REJECT a tenant token for which this returns true rather than
// emit it.
func ContainsEnvPlaceholder(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\\' { // skip the escaped character
			i++
			continue
		}
		if s[i] == '{' && s[i+1] == '$' {
			return true
		}
	}
	return false
}

// substituteNodes applies env substitution to a list of nodes recursively.
func substituteNodes(nodes []Node, lookup func(string) (string, bool)) {
	for _, n := range nodes {
		switch v := n.(type) {
		case *MatcherDef:
			for i := range v.Args {
				substituteArg(&v.Args[i], lookup)
			}
		case *Directive:
			for i := range v.Args {
				substituteArg(&v.Args[i], lookup)
			}
			substituteNodes(v.Block, lookup)
		}
	}
}

// substituteArg expands env placeholders within a single argument and updates
// its Kind to reflect the post-substitution text.
//
// An UNQUOTED env span is ArgPlaceholder, expanded and reclassified below. A QUOTED
// string is ArgLiteral (classifyArg treats every quoted token as a literal so a quoted
// "@x"/"{device}" is inert), which would otherwise leave a quoted env span "{$VAR}"
// UNSUBSTITUTED — loading the literal text. For a secret-bearing directive
// (`auth_token "{$ADMIN_TOKEN}"`, `purge`) that meant a fully PREDICTABLE bearer token,
// silently and fail-OPEN (the unquoted form fails closed to empty when unset) — R07.
// So a quoted literal that carries an env span "{$…}" is expanded too (Caddy parity),
// but kept ArgLiteral: quoting still suppresses RUNTIME placeholders ({device}, {http.*})
// — only `{$ENV}` spans expand inside quotes. A backslash-escaped "\{$VAR}" passes
// through (expandEnv honors the escape), so the rare literal-text case stays expressible.
func substituteArg(a *Arg, lookup func(string) (string, bool)) {
	if a.Kind == ArgPlaceholder {
		a.Raw = expandEnv(a.Raw, lookup)
		a.Kind = classifyArg(a.Raw, a.Quoted)
		return
	}
	if a.Quoted && strings.Contains(a.Raw, "{$") {
		a.Raw = expandEnv(a.Raw, lookup) // stays ArgLiteral: runtime placeholders remain inert
	}
}

// expandEnv replaces every "{$VAR}" span in s with its looked-up value (empty
// string when unset). The Caddy-style default form "{$VAR:default}" expands to the
// variable's value when set, otherwise to everything after the FIRST ':' (so a
// default may itself contain ':' / a URL, e.g. "{$ADDR:http://localhost:8080}").
// "{$VAR:}" yields an empty default. A SET variable always wins, even when its
// value is the empty string. Generic "{...}" spans that do not start with "$" are
// left intact. Escaped braces ("\{") are passed through literally.
func expandEnv(s string, lookup func(string) (string, bool)) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			b.WriteByte(c)
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if c == '{' {
			// Find the matching close brace (no nesting expected for env vars).
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				b.WriteString(s[i:])
				break
			}
			end += i
			inner := s[i+1 : end]
			if strings.HasPrefix(inner, "$") {
				spec := inner[1:]
				// "{$VAR:default}" — split on the FIRST ':' into name + default. A
				// default may itself contain ':' (e.g. a URL). No ':' => no default.
				name, def, hasDefault := spec, "", false
				if colon := strings.IndexByte(spec, ':'); colon >= 0 {
					name, def, hasDefault = spec[:colon], spec[colon+1:], true
				}
				if val, ok := lookup(name); ok {
					// A set variable always wins, even if its value is empty.
					b.WriteString(val)
				} else if hasDefault {
					b.WriteString(def)
				}
				// unset with no default => empty string
				i = end
				continue
			}
			// Not an env placeholder: emit verbatim and continue past it.
			b.WriteString(s[i : end+1])
			i = end
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
