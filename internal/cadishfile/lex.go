// Package cadishfile implements a lexer, parser, AST, and formatter for the
// Cadishfile: cadish's flat, Caddy-style configuration format.
//
// The package is purely STRUCTURAL. It faithfully represents a Cadishfile as an
// abstract syntax tree (AST) but knows nothing about the semantics of individual
// directives or matchers — that validation belongs to later milestones (the
// pipeline compiler and `cadish check`). Concretely, the parser will happily
// accept a directive named "frobnicate" with arbitrary arguments; it is not this
// package's job to decide whether that directive exists or what it means.
//
// The grammar implemented here is "form A" from the cadish design document: a
// sequence of site blocks, each holding a flat list of matcher definitions
// (@name ...) and directives (name ... { ... }). See docs/cadishfile-grammar.md
// for the full grammar and the directive/matcher catalog.
//
// The package is stdlib-only (zero external dependencies).
package cadishfile

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// TokenKind classifies a lexical token.
type TokenKind int

const (
	// TokenWord is a bare word, quoted string, placeholder, or matcher
	// reference — anything that is a single "argument-like" unit. The lexer
	// does not distinguish placeholders or matcher refs from plain words; that
	// classification happens in the parser (see Arg.Kind), because it is a
	// structural property of the token text, not of how it was lexed.
	TokenWord TokenKind = iota
	// TokenOpenBrace is "{" used to open a block. Note: a "{" that is the start
	// of a placeholder such as "{$VAR}" or "{device}" is NOT this kind; the
	// lexer keeps placeholders together as a single TokenWord.
	TokenOpenBrace
	// TokenCloseBrace is "}" used to close a block.
	TokenCloseBrace
	// TokenSemicolon is ";", an explicit statement separator.
	TokenSemicolon
	// TokenNewline marks the end of a logical line. Consecutive newlines are
	// coalesced into a single TokenNewline by the lexer, but the original blank
	// lines are preserved via the BlankBefore count so the formatter can keep
	// (normalized) paragraph spacing.
	TokenNewline
	// TokenComment is a "# ..." comment running to end of line. Comments are
	// emitted as tokens (rather than discarded) so the formatter can preserve
	// them. The parser ignores them for AST construction.
	TokenComment
	// TokenEOF marks end of input.
	TokenEOF
)

// String returns a human-readable name for the token kind, used in error
// messages and tests.
func (k TokenKind) String() string {
	switch k {
	case TokenWord:
		return "word"
	case TokenOpenBrace:
		return "'{'"
	case TokenCloseBrace:
		return "'}'"
	case TokenSemicolon:
		return "';'"
	case TokenNewline:
		return "newline"
	case TokenComment:
		return "comment"
	case TokenEOF:
		return "EOF"
	default:
		return fmt.Sprintf("TokenKind(%d)", int(k))
	}
}

// Token is a single lexical unit carrying its source position. Positions are
// 1-based; Col is a rune (not byte) column so multi-byte UTF-8 input reports
// sensible columns.
type Token struct {
	Kind TokenKind
	// Text is the token's value. For TokenWord it is the unquoted text (the
	// enclosing double quotes, if any, are stripped and escapes resolved). For
	// TokenComment it is the comment text including the leading '#'. For
	// punctuation and newline/EOF it is the literal symbol or empty.
	Text string
	File string
	Line int
	Col  int

	// Quoted reports whether a TokenWord was written as a double-quoted string
	// in the source. The formatter uses this (and whether the text needs
	// quoting) to decide how to re-emit the token; the parser uses it so that a
	// quoted "@x" is treated as a literal, not a matcher reference.
	Quoted bool

	// BlankBefore is the number of blank source lines immediately preceding
	// this token's line. It is only meaningful on the first token of a line.
	// The formatter clamps it to at most one blank line.
	BlankBefore int
}

// String renders a token compactly for debugging and test output.
func (t Token) String() string {
	switch t.Kind {
	case TokenWord:
		if t.Quoted {
			return fmt.Sprintf("%s(%q,quoted)@%d:%d", t.Kind, t.Text, t.Line, t.Col)
		}
		return fmt.Sprintf("%s(%q)@%d:%d", t.Kind, t.Text, t.Line, t.Col)
	case TokenComment:
		return fmt.Sprintf("%s(%q)@%d:%d", t.Kind, t.Text, t.Line, t.Col)
	default:
		return fmt.Sprintf("%s@%d:%d", t.Kind, t.Line, t.Col)
	}
}

// lexer scans Cadishfile source into tokens. It operates on the whole input at
// once (configs are small) and tracks line/column positions.
type lexer struct {
	src  string
	file string
	pos  int // byte offset into src
	line int
	col  int

	// pendingBlank counts blank lines seen since the last emitted non-newline
	// token, to populate Token.BlankBefore.
	pendingBlank int
	// atLineStart is true when no significant token has been emitted on the
	// current line yet (used to attach BlankBefore and to know where comments
	// begin).
	atLineStart bool
}

// newLexer constructs a lexer over src with the given filename (used only for
// position reporting).
func newLexer(file string, src []byte) *lexer {
	s := string(src)
	// Discard a leading UTF-8 byte order mark if present.
	s = strings.TrimPrefix(s, "\uFEFF")
	return &lexer{src: s, file: file, line: 1, col: 1, atLineStart: true}
}

// tokenize lexes the entire input into a slice of tokens terminated by a single
// TokenEOF. It returns a *ParseError on a lexical error (currently only an
// unterminated quoted string).
func tokenize(file string, src []byte) ([]Token, error) {
	l := newLexer(file, src)
	var toks []Token
	for {
		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		toks = append(toks, tok)
		if tok.Kind == TokenEOF {
			return toks, nil
		}
	}
}

// peekRune returns the rune at the current position and its byte width without
// advancing.
func (l *lexer) peekRune() (rune, int) {
	if l.pos >= len(l.src) {
		return 0, 0
	}
	return utf8.DecodeRuneInString(l.src[l.pos:])
}

// advance consumes one rune, updating line/column counters. Newlines are handled
// by the caller (which emits a TokenNewline); advance still updates counters so
// positions stay correct when called on a '\n'.
func (l *lexer) advance() rune {
	r, w := l.peekRune()
	if w == 0 {
		return 0
	}
	l.pos += w
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

// isDisallowedControl reports whether r is a control character that must never
// appear inside a Cadishfile token. The lexer handles '\t', '\n' and '\r'
// structurally (as whitespace / line breaks); every other C0 control character
// and DEL is rejected so that, e.g., a NUL cannot be smuggled into a site address
// or hostname (which would otherwise register the wrong host). This mirrors the
// syntactic strictness the parser already applies (unterminated strings/blocks).
func isDisallowedControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return r < 0x20 || r == 0x7f
}

// controlError builds a *ParseError for a disallowed control character at the
// current lexer position, naming the byte in a stable, readable form ("NUL" for
// 0x00, "0xNN" otherwise) so check and compile-error output render it the same way.
func (l *lexer) controlError(r rune) error {
	name := fmt.Sprintf("0x%02x", r)
	if r == 0 {
		name = "NUL"
	}
	return &ParseError{File: l.file, Line: l.line, Col: l.col, Msg: fmt.Sprintf("disallowed control character %s in input", name)}
}

// next returns the next token. Whitespace separates tokens; '\n' produces a
// TokenNewline (with blank-line bookkeeping); '\' at end of line is a line
// continuation that is consumed silently.
func (l *lexer) next() (Token, error) {
	for {
		r, w := l.peekRune()
		if w == 0 {
			return l.mk(TokenEOF, ""), nil
		}
		if isDisallowedControl(r) {
			return Token{}, l.controlError(r)
		}

		switch {
		case r == '\n':
			line, col := l.line, l.col
			l.advance()
			if l.atLineStart {
				// A newline while already at line start means the previous
				// line was blank.
				l.pendingBlank++
				continue
			}
			l.atLineStart = true
			return Token{Kind: TokenNewline, File: l.file, Line: line, Col: col}, nil

		case r == '\r':
			// Ignore carriage returns; we only care about '\n'.
			l.advance()
			continue

		case r == ' ' || r == '\t':
			l.advance()
			continue

		case r == '\\':
			// Line continuation: a backslash followed (possibly after spaces is
			// NOT allowed — must be immediately) by a newline. Otherwise the
			// backslash is an ordinary word character.
			if l.isLineContinuation() {
				l.advance() // consume '\'
				// consume the newline without emitting a token or counting it
				if r2, _ := l.peekRune(); r2 == '\r' {
					l.advance()
				}
				l.advance() // consume '\n'
				continue
			}
			return l.lexWord(), nil

		case r == '#':
			return l.lexComment(), nil

		case r == '{':
			// A "{" can either open a block or begin a placeholder token such as
			// "{$VAR}" or "{device}". Distinguish by peeking: a placeholder is a
			// brace-balanced run with no interior whitespace (lexWord handles the
			// scan). A bare "{" that opens a block is followed by whitespace, a
			// newline, or nothing meaningful.
			if l.looksLikePlaceholder() {
				return l.lexWord(), nil
			}
			line, col, blank := l.line, l.col, l.takeBlank()
			l.advance()
			l.atLineStart = false
			return Token{Kind: TokenOpenBrace, Text: "{", File: l.file, Line: line, Col: col, BlankBefore: blank}, nil

		case r == '}':
			line, col, blank := l.line, l.col, l.takeBlank()
			l.advance()
			l.atLineStart = false
			return Token{Kind: TokenCloseBrace, Text: "}", File: l.file, Line: line, Col: col, BlankBefore: blank}, nil

		case r == ';':
			line, col := l.line, l.col
			l.advance()
			l.atLineStart = false
			return Token{Kind: TokenSemicolon, Text: ";", File: l.file, Line: line, Col: col}, nil

		case r == '"':
			return l.lexQuoted()

		default:
			return l.lexWord(), nil
		}
	}
}

// looksLikePlaceholder reports whether the "{" at the current position begins a
// placeholder token (a brace-balanced run with no interior whitespace), as
// opposed to a block-opening brace. It does not consume input.
func (l *lexer) looksLikePlaceholder() bool {
	depth := 0
	for i := l.pos; i < len(l.src); {
		r, w := utf8.DecodeRuneInString(l.src[i:])
		i += w
		if isDisallowedControl(r) {
			return false // control char before close => not a placeholder
		}
		switch r {
		case ' ', '\t', '\n', '\r':
			return false // whitespace before close => block brace
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return true
			}
		}
	}
	return false // never closed => treat as block brace
}

// isLineContinuation reports whether the backslash at the current position is
// immediately followed by an optional '\r' and then '\n'.
func (l *lexer) isLineContinuation() bool {
	rest := l.src[l.pos+1:] // skip the '\'
	rest = strings.TrimPrefix(rest, "\r")
	return strings.HasPrefix(rest, "\n")
}

// takeBlank returns and resets the pending blank-line count, but only when at
// the start of a line (blank spacing only applies to a line's first token).
func (l *lexer) takeBlank() int {
	if !l.atLineStart {
		return 0
	}
	b := l.pendingBlank
	l.pendingBlank = 0
	return b
}

// mk builds a positionless-ish token at the current position for EOF.
func (l *lexer) mk(kind TokenKind, text string) Token {
	return Token{Kind: kind, Text: text, File: l.file, Line: l.line, Col: l.col, BlankBefore: l.takeBlank()}
}

// lexComment reads a '#' comment to the end of the line (not including the
// newline). The returned token's Text includes the leading '#'.
func (l *lexer) lexComment() Token {
	line, col, blank := l.line, l.col, l.takeBlank()
	start := l.pos
	for {
		r, w := l.peekRune()
		if w == 0 || r == '\n' {
			break
		}
		if isDisallowedControl(r) {
			// Terminate the comment here; next() rejects the control character.
			break
		}
		l.advance()
	}
	text := strings.TrimRight(l.src[start:l.pos], " \t\r")
	l.atLineStart = false
	return Token{Kind: TokenComment, Text: text, File: l.file, Line: line, Col: col, BlankBefore: blank}
}

// lexWord reads a bare (unquoted) word. A word runs until whitespace, a
// structural character ('{', '}', ';', '#' at a boundary), or EOF. A '{' inside
// a word is kept as part of the word when it begins a placeholder ("{$VAR}",
// "{device}", "{http.X-Foo}"); a balanced run of braces is consumed so the
// placeholder stays a single token. A standalone '{' that opens a block is
// handled by next() before we ever get here.
//
// Backslashes inside a bare word are kept LITERALLY: the Cadishfile is full of
// regexes (e.g. "\.(css|js)$") where backslashes are significant, so the lexer
// must not consume them as escapes. The single exception is a backslash that is
// immediately followed by a newline, which is a line continuation and ends the
// current word run (the newline is then consumed by next()).
func (l *lexer) lexWord() Token {
	line, col, blank := l.line, l.col, l.takeBlank()
	var b strings.Builder
	for {
		r, w := l.peekRune()
		if w == 0 {
			break
		}
		if r == '\\' {
			// A backslash immediately before a newline is a line continuation:
			// it terminates the word (the continuation itself is handled by
			// next()). Any other backslash is a literal word character.
			if l.isLineContinuation() {
				break
			}
			b.WriteRune(l.advance())
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			break
		}
		if isDisallowedControl(r) {
			// Terminate the word here; next() will re-see the control character
			// and return the disallowed-control error with its position.
			break
		}
		if r == ';' || r == '}' {
			break
		}
		if r == '{' {
			// Could be a placeholder embedded in the word. Consume a balanced
			// brace run and keep it as part of the token.
			ph, ok := l.scanPlaceholder()
			if ok {
				b.WriteString(ph)
				continue
			}
			// Not a placeholder (e.g. a stray '{'): it terminates the word so
			// it can be lexed as a block opener.
			break
		}
		if r == '#' {
			// '#' only starts a comment at a token boundary; mid-word it is a
			// literal character (e.g. an anchor or fragment).
			b.WriteRune(l.advance())
			continue
		}
		if r == '"' {
			// A quote mid-word is treated literally; full quoted strings are
			// only recognized at a token boundary by next().
			b.WriteRune(l.advance())
			continue
		}
		b.WriteRune(l.advance())
	}
	l.atLineStart = false
	return Token{Kind: TokenWord, Text: b.String(), File: l.file, Line: line, Col: col, BlankBefore: blank}
}

// scanPlaceholder consumes a brace-balanced run starting at the current '{' and
// returns its literal text (including the braces). It returns ok=false if the
// run does not look like a placeholder — specifically if it contains whitespace
// or is never closed, in which case nothing is consumed. This keeps "{$VAR}",
// "{device}", and "{http.X-Foo}" as single word tokens while leaving a real
// block-opening "{" to next().
func (l *lexer) scanPlaceholder() (string, bool) {
	// Save state so we can roll back if this is not a placeholder.
	savePos, saveLine, saveCol := l.pos, l.line, l.col
	var b strings.Builder
	depth := 0
	for {
		r, w := l.peekRune()
		if w == 0 {
			// unterminated: not a placeholder, roll back
			l.pos, l.line, l.col = savePos, saveLine, saveCol
			return "", false
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || isDisallowedControl(r) {
			// whitespace or a disallowed control char inside braces => not a
			// placeholder, roll back (a control char is then rejected by next()).
			l.pos, l.line, l.col = savePos, saveLine, saveCol
			return "", false
		}
		b.WriteRune(l.advance())
		if r == '{' {
			depth++
		} else if r == '}' {
			depth--
			if depth == 0 {
				return b.String(), true
			}
		}
	}
}

// lexQuoted reads a double-quoted string. Inner spaces are preserved; "\"" is an
// escaped quote and "\\" an escaped backslash; any other "\x" keeps both
// characters literally (matching Caddy's permissive behavior). A newline inside
// the string is allowed and preserved. An unterminated string is an error.
func (l *lexer) lexQuoted() (Token, error) {
	line, col, blank := l.line, l.col, l.takeBlank()
	l.advance() // consume opening quote
	var b strings.Builder
	for {
		r, w := l.peekRune()
		if w == 0 {
			return Token{}, &ParseError{File: l.file, Line: line, Col: col, Msg: "unterminated quoted string"}
		}
		if isDisallowedControl(r) {
			return Token{}, l.controlError(r)
		}
		if r == '\\' {
			l.advance()
			esc, ew := l.peekRune()
			switch {
			case ew == 0:
				return Token{}, &ParseError{File: l.file, Line: line, Col: col, Msg: "unterminated quoted string"}
			case isDisallowedControl(esc):
				// A disallowed control character must be rejected even when it
				// follows a backslash. Accepting it here let a NUL/0x05/etc. be
				// smuggled into a quoted token; the formatter then doubles the
				// backslash, unescaping the control char, and re-parsing rejects it
				// — a round-trip the formatter must never be able to break (caught
				// by FuzzParse on "\"\\\x05\"").
				return Token{}, l.controlError(esc)
			case esc == '"' || esc == '\\':
				b.WriteRune(l.advance())
			default:
				b.WriteByte('\\')
				b.WriteRune(l.advance())
			}
			continue
		}
		if r == '"' {
			l.advance() // consume closing quote
			l.atLineStart = false
			return Token{Kind: TokenWord, Text: b.String(), File: l.file, Line: line, Col: col, Quoted: true, BlankBefore: blank}, nil
		}
		b.WriteRune(l.advance())
	}
}
