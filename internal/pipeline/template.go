package pipeline

import (
	"net/http"
	"strings"
)

// TemplateEnv carries the request-derived values a target/header template can
// interpolate. Capture is the regex submatch slice (Capture[0] is the whole
// match, Capture[1] is $1, …) from the matcher that selected the directive, or
// nil when no regex capture is in scope.
//
// This is the shared substitution primitive behind the computed `redirect`
// directive (target templates) and dynamic header values (#17). It is a pure,
// allocation-light string expander — no regex compilation, no I/O.
//
// Header and ClientIP are the request-scoped sources for the `{http.NAME}` and
// `{client_ip}` placeholders (dynamic header values, #17). They are left zero by
// the redirect path, which uses only the scalar/capture placeholders.
type TemplateEnv struct {
	Host     string
	Path     string
	Query    string // raw, canonically-ordered query string without the leading '?'
	Capture  []string
	Header   http.Header // request headers, for {http.NAME}; may be nil
	ClientIP string      // resolved client IP (no port), for {client_ip}

	// Geo / GeoContinent / GeoRegion are the server-resolved geo classes, for the
	// {geo} / {geo.continent} / {geo.region} placeholders. Left zero on the redirect
	// path (no geo in scope there).
	Geo          string
	GeoContinent string
	GeoRegion    string
}

// classifyResolver resolves {classify.NAME} placeholders against a request's
// matchContext. It is passed to expandTemplate BY VALUE as a separate argument (never
// stored on TemplateEnv) and is itself a small value type, not a ctx-capturing
// closure: the per-request *matchContext it carries is copied through the call and
// never stored into a heap-reachable location, so the dynamic-header path keeps the
// match context on the stack and the no-feature request stays alloc-free
// (zero-cost-when-unused). Its zero value (nil classifiers) resolves nothing — the
// redirect path and sites with no classifiers leave {classify.NAME} verbatim.
type classifyResolver struct {
	ctx         *matchContext
	classifiers map[string]*classifier
}

// resolve returns the classify token NAME's derived value, or ok=false for an unknown
// token (the placeholder is then kept verbatim). The zero resolver resolves nothing.
func (r classifyResolver) resolve(name string) (string, bool) {
	if r.classifiers == nil || r.ctx == nil {
		return "", false
	}
	cl, ok := r.classifiers[name]
	if !ok {
		return "", false
	}
	return cl.resolve(r.ctx), true
}

// uri returns Path with the query appended (?q=…) when a query is present. It is
// the convenience {uri} placeholder = {path} + optional ?{query}.
func (e *TemplateEnv) uri() string {
	if e.Query == "" {
		return e.Path
	}
	return e.Path + "?" + e.Query
}

// expandTemplate substitutes placeholders in tmpl against env and returns the
// result. Two placeholder families are supported:
//
//   - Named braces: {host} {path} {query} {uri} — request-derived scalars. An
//     unknown {name} is left verbatim (so a literal "{x}" in a URL survives).
//   - Numbered captures: $1 … $9 (and $0 for the whole match) — regex submatches
//     from the selecting path_regex matcher. A "$$" is a literal '$'. A "$N" with
//     no corresponding capture expands to "" (out-of-range groups vanish, matching
//     Go's regexp.Expand semantics for absent groups).
//
// The scan is single-pass and never panics on a trailing '{' or '$'.
//
// cr resolves {classify.NAME} placeholders. It is taken by value (its zero value
// resolves nothing) and kept OUT of TemplateEnv so the per-request matchContext it
// carries is never stored — that is what keeps the dynamic-header path off the heap.
func expandTemplate(tmpl string, env *TemplateEnv, cr classifyResolver) string {
	if tmpl == "" {
		return ""
	}
	// Fast path: no metacharacters at all.
	if !strings.ContainsAny(tmpl, "{$") {
		return tmpl
	}
	var b strings.Builder
	b.Grow(len(tmpl) + 16)
	for i := 0; i < len(tmpl); {
		c := tmpl[i]
		switch c {
		case '{':
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				// Unterminated '{': emit the rest verbatim.
				b.WriteString(tmpl[i:])
				i = len(tmpl)
				continue
			}
			name := tmpl[i+1 : i+end]
			if v, ok := env.named(name, cr); ok {
				b.WriteString(v)
			} else {
				b.WriteString(tmpl[i : i+end+1]) // unknown: keep "{name}" literally
			}
			i += end + 1
		case '$':
			if i+1 >= len(tmpl) {
				b.WriteByte('$')
				i++
				continue
			}
			n := tmpl[i+1]
			if n == '$' {
				b.WriteByte('$')
				i += 2
				continue
			}
			if n >= '0' && n <= '9' {
				idx := int(n - '0')
				if idx < len(env.Capture) {
					b.WriteString(env.Capture[idx])
				}
				// out-of-range -> expands to nothing
				i += 2
				continue
			}
			// A '$' not followed by a digit or '$' is a literal dollar.
			b.WriteByte('$')
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// named resolves a {name} placeholder to its value; ok is false for an unknown
// name (the caller keeps it verbatim).
//
// Beyond the scalar request fields, two request-scoped families are resolved
// (dynamic header values, #17):
//
//   - {client_ip} — the resolved client IP (TemplateEnv.ClientIP).
//   - {http.NAME} — request header NAME (canonicalized by http.Header.Get); an
//     ABSENT header resolves to "" with ok=true (the placeholder is consumed, not
//     left verbatim) — this matches the operator's intent to emit a possibly-empty
//     reflected value. A bare "{http.}" (no header name) is treated as unknown and
//     kept verbatim.
func (e *TemplateEnv) named(name string, cr classifyResolver) (string, bool) {
	switch name {
	case "host":
		return e.Host, true
	case "path":
		return e.Path, true
	case "query":
		return e.Query, true
	case "uri":
		return e.uri(), true
	case "client_ip":
		return e.ClientIP, true
	case "geo":
		return e.Geo, true
	case "geo.continent":
		return e.GeoContinent, true
	case "geo.region":
		return e.GeoRegion, true
	}
	if hn, ok := strings.CutPrefix(name, "http."); ok && hn != "" {
		if e.Header == nil {
			return "", true
		}
		return e.Header.Get(hn), true
	}
	if cn, ok := strings.CutPrefix(name, "classify."); ok && cn != "" {
		return cr.resolve(cn)
	}
	return "", false
}

// hasPlaceholder reports whether s contains a template placeholder that
// expandTemplate could substitute (a '{' or '$'). It is the compile-time gate
// used to decide whether a header value needs per-request expansion: a value with
// no placeholder is emitted verbatim with zero per-request work. It is a
// conservative over-approximation (a literal "{x}" or "$" sets the flag), which is
// safe — expandTemplate is a no-op identity for non-placeholder braces/dollars.
func hasPlaceholder(s string) bool {
	return strings.ContainsAny(s, "{$")
}
