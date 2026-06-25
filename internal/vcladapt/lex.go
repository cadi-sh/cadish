// Package vcladapt is a best-effort Varnish VCL → Cadishfile converter (the
// `cadish adapt` command). It is explicitly a SKELETON GENERATOR, not a compiler:
// it maps the mechanical, high-confidence idioms (backends, pass rules, ttl/grace,
// hash, header edits, synthetic health responses) and emits `# TODO(adapt): …` —
// with the original snippet — for anything non-mechanical (ACLs, vmods, regsub,
// device detect, ESI, inline-C, templating), plus a mapped-vs-needs-review count.
//
// The goal is an ~80%-there Cadishfile a human finishes, not a runnable config.
package vcladapt

import "strings"

// tokKind classifies a VCL token.
type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tStr   // a quoted string; Text is the contents without quotes
	tNum   // a number or duration token (e.g. "200", "60s", "1h")
	tPunct // an operator/punctuation token (e.g. "{", "==", "~", "||")
)

// token is one lexed VCL token.
type token struct {
	kind tokKind
	text string
	line int
}

// lex tokenizes VCL source, dropping comments (#…, //…, /* … */). It is permissive
// — it never errors — because adapt is best-effort over possibly-templated input.
func lex(src string) []token {
	var toks []token
	line := 1
	i := 0
	n := len(src)
	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '/':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && src[i+1] == '*':
			i += 2
			for i+1 < n && !(src[i] == '*' && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			i += 2
		case c == '"':
			start := i + 1
			i++
			for i < n && src[i] != '"' && src[i] != '\n' {
				i++
			}
			toks = append(toks, token{tStr, src[start:i], line})
			if i < n && src[i] == '"' {
				i++
			}
		case c == '{' && i+1 < n && src[i+1] == '"':
			// VCL long string {" … "}.
			start := i + 2
			i += 2
			for i+1 < n && !(src[i] == '"' && src[i+1] == '}') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			toks = append(toks, token{tStr, src[start:i], line})
			i += 2
		case isIdentStart(c) || (c == '.' && i+1 < n && isLetter(src[i+1])):
			// A leading '.' starts an identifier only for VCL backend/probe fields
			// (.host, .port, .url, …); elsewhere '.' is an interior identifier char.
			start := i
			i++
			for i < n && isIdentChar(src[i]) {
				i++
			}
			toks = append(toks, token{tIdent, src[start:i], line})
		case c >= '0' && c <= '9':
			start := i
			for i < n && (isDigit(src[i]) || isLetter(src[i]) || src[i] == '.') {
				i++
			}
			toks = append(toks, token{tNum, src[start:i], line})
		default:
			// Operators: try the two-char forms first.
			if i+1 < n {
				two := src[i : i+2]
				switch two {
				case "==", "!=", "!~", ">=", "<=", "&&", "||", "->":
					toks = append(toks, token{tPunct, two, line})
					i += 2
					continue
				}
			}
			toks = append(toks, token{tPunct, string(c), line})
			i++
		}
	}
	toks = append(toks, token{tEOF, "", line})
	return toks
}

func isIdentStart(c byte) bool { return isLetter(c) || c == '_' }

// isIdentChar includes '.' and '-' so VCL identifiers like req.http.X-Requested-With
// lex as a single token.
func isIdentChar(c byte) bool {
	return isLetter(c) || isDigit(c) || c == '_' || c == '.' || c == '-'
}

func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool  { return c >= '0' && c <= '9' }

// looksRegexy reports whether s contains regex metacharacters (so a VCL `~ "s"`
// can't be reduced to a literal path glob).
func looksRegexy(s string) bool {
	return strings.ContainsAny(s, "^$()[]{}|+*?\\")
}
