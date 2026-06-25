package pipeline

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// rewriteOpKind classifies a `rewrite` sub-operation.
type rewriteOpKind int

const (
	// rwPath: regex-replace the path sent to origin (HAProxy `replace-path`).
	rwPath rewriteOpKind = iota
	// rwStripQuery: drop the named query params (globs ok) before forwarding (e.g.
	// `utm_*`).
	rwStripQuery
	// rwSetQuery: add or override one query param before forwarding (e.g. the SSR
	// `publi` reconstruction). The value may interpolate {http.NAME} and {query}.
	rwSetQuery
)

// rewriteRule is one compiled `rewrite` directive: an optional matcher scope that
// gates applicability, plus exactly one rewrite operation. Rules are applied in
// source order; each operates on the result of the previous one, so a `path`
// replace and a `strip_query` compose deterministically.
type rewriteRule struct {
	scope *scope
	kind  rewriteOpKind

	// rwPath
	re   *regexp.Regexp // path pattern (always anchored as written by the operator)
	repl string         // replacement template ($1.. capture refs, Go regexp syntax)

	// rwStripQuery
	names *nameGlobSet // param-name patterns to drop

	// rwSetQuery
	name     string // param name to set
	valueTpl string // value template ({http.NAME}/{query}/{host}/{path} or a literal)
}

// compileRewrite parses a `rewrite [@scope] OP …` directive:
//
//	rewrite [@scope] path PATTERN REPLACEMENT   # regex replace on the origin path
//	rewrite [@scope] strip_query NAME…          # drop query params (globs ok)
//	rewrite [@scope] set_query NAME VALUE        # add/override one query param
//
// The optional leading @matcher scope makes the rewrite conditional (reusing the
// shared matcher machinery). A `rewrite` is a RECV-phase directive, so its scope
// may not use a response-phase matcher.
func compileRewrite(d *cadishfile.Directive, matchers map[string]*matcher) (rewriteRule, error) {
	sc, args, err := leadingRefScope(d.Args, matchers)
	if err != nil {
		return rewriteRule{}, err
	}
	if err := ensureNotResponsePhase(sc, "rewrite", d.Pos); err != nil {
		return rewriteRule{}, err
	}
	if len(args) == 0 {
		return rewriteRule{}, &CompileError{Pos: d.Pos, Msg: "rewrite needs an operation: `path PATTERN REPL`, `strip_query NAME…`, or `set_query NAME VALUE`"}
	}
	r := rewriteRule{scope: sc}
	switch args[0].Raw {
	case "path":
		if len(args) != 3 {
			return rewriteRule{}, &CompileError{Pos: d.Pos, Msg: "rewrite path needs `PATTERN REPLACEMENT`"}
		}
		re, cerr := regexp.Compile(args[1].Raw)
		if cerr != nil {
			return rewriteRule{}, &CompileError{Pos: args[1].Pos, Msg: "rewrite path: invalid regex " + quote(args[1].Raw) + ": " + cerr.Error()}
		}
		r.kind = rwPath
		r.re = re
		r.repl = args[2].Raw
	case "strip_query":
		if len(args) < 2 {
			return rewriteRule{}, &CompileError{Pos: d.Pos, Msg: "rewrite strip_query needs at least one param name (e.g. `strip_query utm_*`)"}
		}
		names := make([]string, 0, len(args)-1)
		for _, a := range args[1:] {
			names = append(names, a.Raw)
		}
		r.kind = rwStripQuery
		r.names = newNameGlobSet(names)
	case "set_query":
		if len(args) != 3 {
			return rewriteRule{}, &CompileError{Pos: d.Pos, Msg: "rewrite set_query needs `NAME VALUE`"}
		}
		if args[1].Raw == "" {
			return rewriteRule{}, &CompileError{Pos: args[1].Pos, Msg: "rewrite set_query: NAME must be non-empty"}
		}
		r.kind = rwSetQuery
		r.name = args[1].Raw
		r.valueTpl = args[2].Raw
	default:
		return rewriteRule{}, &CompileError{Pos: args[0].Pos, Msg: "unknown rewrite operation " + quote(args[0].Raw) + " (want `path`, `strip_query`, or `set_query`)"}
	}
	return r, nil
}

// evalRewrite applies the matching rewrite rules in order and returns the resolved
// origin path + raw query, or nil when no rule matched (the server then forwards
// the client path/query unchanged — zero extra work on the common path). It never
// touches the cache key. ctx is the request-phase match context (memoized).
func (p *Pipeline) evalRewrite(ctx *matchContext) *RewriteDecision {
	if len(p.rewriteRules) == 0 {
		return nil
	}
	req := ctx.req
	path := req.Path
	// Lazily materialize a mutable copy of the query only when a query op fires, so
	// a pure path rewrite (or no match) does not allocate a url.Values.
	var q url.Values
	qCopied := false
	copyQuery := func() {
		if qCopied {
			return
		}
		q = make(url.Values, len(req.Query))
		for k, vs := range req.Query {
			q[k] = append([]string(nil), vs...)
		}
		qCopied = true
	}
	matched := false
	for i := range p.rewriteRules {
		r := &p.rewriteRules[i]
		if !ctx.scopeMatches(r.scope) {
			continue
		}
		switch r.kind {
		case rwPath:
			if loc := r.re.FindStringSubmatchIndex(path); loc != nil {
				path = string(r.re.ExpandString(nil, r.repl, path, loc))
				matched = true
			}
		case rwStripQuery:
			copyQuery()
			for name := range q {
				if r.names.match(name) {
					delete(q, name)
				}
			}
			matched = true
		case rwSetQuery:
			copyQuery()
			q.Set(r.name, p.resolveRewriteValue(r.valueTpl, ctx))
			matched = true
		}
	}
	if !matched {
		return nil
	}
	out := &RewriteDecision{Path: path}
	if qCopied {
		out.RawQuery = encodeQuerySorted(q)
	} else {
		// A path-only rewrite forwards the original query verbatim.
		out.RawQuery = rawQueryOf(req)
	}
	return out
}

// resolveRewriteValue expands a `set_query` value template against the request. It
// supports {http.NAME}, {host}, {path}, {query}, and literals; an unknown token is
// left verbatim (the redirect/header template engine is reused for consistency).
func (p *Pipeline) resolveRewriteValue(tpl string, ctx *matchContext) string {
	if !strings.Contains(tpl, "{") {
		return tpl // fast path: a literal value (the common case)
	}
	req := ctx.req
	env := &TemplateEnv{
		Host:   req.normHost(),
		Path:   req.Path,
		Query:  canonicalQuery(req),
		Header: req.Header,
	}
	return expandTemplate(tpl, env, classifyResolver{})
}

// encodeQuerySorted renders url.Values as an already-encoded query string with keys
// (and each key's values) sorted, so the output is deterministic. Empty values
// yield "" so a fully-stripped query forwards no '?'.
func encodeQuerySorted(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	first := true
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		ek := url.QueryEscape(k)
		for _, v := range vals {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(ek)
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// rawQueryOf returns a canonical raw query string for the request (no leading
// '?'), used when a path-only rewrite forwards the query unchanged. It is rendered
// from the parsed Query so it matches encodeQuerySorted's shape.
func rawQueryOf(req *Request) string {
	return encodeQuerySorted(req.Query)
}
