package cadishfile

import "strings"

// Pos is a source position attached to AST nodes for error reporting and
// tooling. It is 1-based; a zero Pos means "unknown / synthesized".
type Pos struct {
	File string
	Line int
	Col  int
}

// String renders the position as "file:line:col" (the conventional compiler
// format). A missing file is rendered as "<input>".
func (p Pos) String() string {
	file := p.File
	if file == "" {
		file = "<input>"
	}
	return sprintFileLineCol(file, p.Line, p.Col)
}

// File is the root of a parsed Cadishfile. It is a sequence of site blocks,
// optionally preceded by a single global options block.
//
// The parser is semantics-free: Sites and their bodies are represented
// faithfully but never interpreted. Comments are not part of the AST (they are
// preserved by the token-level formatter, not here).
type File struct {
	// Global is the optional leading global-options block ("{ ... }" at the very
	// top of the file). It is nil when absent. It is intentionally a thin stub:
	// this milestone does not interpret global options, it only records that one
	// was present and keeps its raw statements.
	Global *Options
	// Sites is the ordered list of site blocks in the file.
	Sites []*Site
	// Body holds top-level statements that are not wrapped in a site block.
	// A complete config is normally all Sites, but an importable sub-config
	// (e.g. nocache.cadish, brought in via `import`) is a bare list of matcher
	// definitions and directives with no site wrapper; those land here. Body and
	// Sites may both be populated, though mixing them in one file is unusual.
	Body []Node
}

// Options is the global options block. It is a stub for this milestone: the body
// is parsed as an ordinary statement list (the same Node types as a site body)
// but no global-specific semantics are applied. Later milestones may replace
// Body with structured fields.
type Options struct {
	Body []Node
	Pos  Pos
}

// Site is one site block: one or more comma-separated address tokens followed by
// a "{ ... }" body of statements.
//
// Addresses are kept as raw token strings and are NOT validated or normalized
// (e.g. "example.com", "*.example.com"); semantic interpretation of
// addresses belongs to a later milestone.
type Site struct {
	// Addresses are the site header tokens, in source order, with any
	// separating commas removed (a trailing comma on a token is stripped).
	Addresses []string
	// Body is the ordered statement list: MatcherDef and Directive nodes.
	Body []Node
	Pos  Pos
}

// Node is a single statement inside a site body or a nested directive block.
// It is implemented by *MatcherDef and *Directive. The unexported node() method
// keeps the interface closed to this package's types.
type Node interface {
	// Position returns the node's source position (the first token).
	Position() Pos
	node()
}

// ArgKind classifies an argument token by the structural shape of its text.
// This is a syntactic classification only; it does not imply the reference or
// placeholder actually resolves to anything.
type ArgKind int

const (
	// ArgLiteral is a plain literal argument: a bare word or quoted string that
	// is neither a matcher reference nor a placeholder.
	ArgLiteral ArgKind = iota
	// ArgMatcherRef is an argument that references a named matcher: an unquoted
	// token beginning with "@" (e.g. "@images"). A quoted "@x" is ArgLiteral.
	ArgMatcherRef
	// ArgPlaceholder is an argument that contains a placeholder, i.e. a "{...}"
	// span — either an environment placeholder "{$VAR}" or a generic
	// placeholder such as "{device}" or "{http.X-Foo}". The whole token is
	// classified as a placeholder if it contains any unescaped "{".
	ArgPlaceholder
)

// String returns a human-readable name for the argument kind.
func (k ArgKind) String() string {
	switch k {
	case ArgLiteral:
		return "literal"
	case ArgMatcherRef:
		return "matcher-ref"
	case ArgPlaceholder:
		return "placeholder"
	default:
		return "unknown"
	}
}

// Arg is a single argument token of a matcher definition or directive. It
// carries the raw (unquoted) token text, whether it was quoted in source, its
// syntactic Kind, and its source position.
//
// Raw is the token text as the lexer produced it: for a quoted argument the
// surrounding quotes are stripped and escapes resolved, but for a placeholder
// the "{...}" is preserved verbatim so it can be substituted later (see
// SubstituteEnv). Env substitution is deliberately NOT applied at parse time.
type Arg struct {
	Raw    string
	Quoted bool
	Kind   ArgKind
	Pos    Pos
}

// String returns the argument's raw text (useful in tests and debugging).
func (a Arg) String() string { return a.Raw }

// MatcherDef is a matcher definition statement: "@name type arg...".
//
// Example: "@nocache path /a/* /b/*" parses to
// MatcherDef{Name:"nocache", Type:"path", Args:[/a/*, /b/*]}.
//
// The leading "@" is stripped from Name. Type is the matcher type keyword (e.g.
// "path", "host_regex", "header"); it is NOT validated. A matcher definition has
// no nested block.
type MatcherDef struct {
	Name string
	Type string
	Args []Arg
	Pos  Pos
}

func (*MatcherDef) node()           {}
func (m *MatcherDef) Position() Pos { return m.Pos }

// Directive is a directive statement: "name arg..." optionally followed by a
// nested "{ ... }" block of further statements.
//
// Examples:
//
//	tls { acme x }            => Directive{Name:"tls", Block:[Directive{acme x}]}
//	cache_key url host        => Directive{Name:"cache_key", Args:[url, host]}
//	pass @ajax                => Directive{Name:"pass", Args:[@ajax (matcher-ref)]}
//
// Name is the directive keyword (not validated). Args are its arguments. Block
// is the nested statement list; it is nil when the directive has no block. Note
// that an empty but present block ("name { }") yields a non-nil, zero-length
// Block, distinguishing it from no block at all.
type Directive struct {
	Name     string
	Args     []Arg
	Block    []Node
	HasBlock bool
	Pos      Pos
}

func (*Directive) node()           {}
func (d *Directive) Position() Pos { return d.Pos }

// classifyArg determines the ArgKind for a token based on its text and whether
// it was quoted. Quoted tokens are always literals. An unquoted token starting
// with "@" is a matcher reference. An unquoted token containing an unescaped
// "{" (a placeholder span) is a placeholder. Otherwise it is a literal.
func classifyArg(text string, quoted bool) ArgKind {
	if quoted {
		return ArgLiteral
	}
	if strings.HasPrefix(text, "@") && len(text) > 1 {
		return ArgMatcherRef
	}
	if containsPlaceholder(text) {
		return ArgPlaceholder
	}
	return ArgLiteral
}

// containsPlaceholder reports whether text contains an unescaped "{" introducing
// a placeholder span.
func containsPlaceholder(text string) bool {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++ // skip escaped char
		case '{':
			return true
		}
	}
	return false
}
