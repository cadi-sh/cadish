package cadishfile

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ParseError is the error type returned by all parsing and lexing failures. It
// formats as "file:line:col: message", the conventional compiler diagnostic
// shape, so callers (e.g. `cadish fmt`) can print actionable errors.
type ParseError struct {
	File string
	Line int
	Col  int
	Msg  string
}

// Error implements the error interface, rendering "file:line:col: message".
func (e *ParseError) Error() string {
	return sprintFileLineCol(e.fileOrDefault(), e.Line, e.Col) + ": " + e.Msg
}

func (e *ParseError) fileOrDefault() string {
	if e.File == "" {
		return "<input>"
	}
	return e.File
}

// sprintFileLineCol renders "file:line:col"; line/col are omitted when zero so a
// position-less error still reads cleanly.
func sprintFileLineCol(file string, line, col int) string {
	switch {
	case line > 0 && col > 0:
		return file + ":" + strconv.Itoa(line) + ":" + strconv.Itoa(col)
	case line > 0:
		return file + ":" + strconv.Itoa(line)
	default:
		return file
	}
}

// Parse parses src (the contents of a Cadishfile) and returns its AST. The
// filename is used only for position reporting in errors and AST positions; it
// need not exist on disk. On a lexical or syntax error it returns a *ParseError.
//
// Parse does NOT perform environment-variable substitution; call SubstituteEnv
// on the result if you want "{$VAR}" placeholders expanded. This separation lets
// `cadish check` and `cadish fmt` operate without a populated environment.
func Parse(filename string, src []byte) (*File, error) {
	toks, err := tokenize(filename, src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, file: filename}
	return p.parseFile()
}

// ParseFile reads the file at path and parses it. The path is used as the
// filename for positions.
func ParseFile(path string) (*File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, src)
}

// maxBlockDepth bounds how deeply blocks may nest. The parser is recursive
// (parseBlockBody -> parseStatement -> parseDirective -> parseBlockBody), so an
// adversarial config of the form "x {{{{...}}}}" would otherwise grow the
// goroutine stack until the runtime aborts with a fatal "goroutine stack
// exceeds" error — which recover() cannot catch. Real configs nest only a
// handful of levels (cache { ram ... }, lb { ... }); a cap well above any
// legitimate use turns the attack into a clean *ParseError while staying
// zero-cost on the normal path.
const maxBlockDepth = 1000

// parser is a single-pass recursive-descent parser over the token stream
// produced by tokenize. Newlines and semicolons are statement separators;
// comments are skipped (they are not represented in the AST).
type parser struct {
	toks  []Token
	pos   int
	file  string
	depth int // current block-nesting depth (guards against stack overflow)
}

// cur returns the current token without consuming it.
func (p *parser) cur() Token { return p.toks[p.pos] }

// next consumes and returns the current token, advancing the cursor. It never
// advances past EOF.
func (p *parser) next() Token {
	t := p.toks[p.pos]
	if t.Kind != TokenEOF {
		p.pos++
	}
	return t
}

// errf builds a *ParseError at the given token's position.
func (p *parser) errf(t Token, format string, args ...any) error {
	return &ParseError{File: p.file, Line: t.Line, Col: t.Col, Msg: fmt.Sprintf(format, args...)}
}

// skipTrivia advances past newline and comment tokens. Comments carry no AST
// meaning; newlines between statements are separators consumed here.
func (p *parser) skipTrivia() {
	for {
		switch p.cur().Kind {
		case TokenNewline, TokenComment:
			p.next()
		default:
			return
		}
	}
}

// skipSeparators advances past statement separators: newlines, semicolons, and
// comments. Used between statements where one or more separators are allowed.
func (p *parser) skipSeparators() {
	for {
		switch p.cur().Kind {
		case TokenNewline, TokenSemicolon, TokenComment:
			p.next()
		default:
			return
		}
	}
}

// parseFile parses the whole token stream into a *File.
func (p *parser) parseFile() (*File, error) {
	f := &File{}
	p.skipSeparators()

	// Optional leading global options block: a "{" appearing before any site
	// header tokens. We only treat a "{" as the global block when it is the very
	// first significant token of the file.
	if p.cur().Kind == TokenOpenBrace {
		opts, err := p.parseGlobalOptions()
		if err != nil {
			return nil, err
		}
		f.Global = opts
		p.skipSeparators()
	}

	for p.cur().Kind != TokenEOF {
		if p.cur().Kind == TokenCloseBrace {
			return nil, p.errf(p.cur(), "unexpected '}' at top level")
		}
		// Disambiguate between a site block ("addrs... { body }") and a
		// top-level statement (a matcher def or directive). Sub-configs meant to
		// be `import`ed are bare statement lists with no site wrapper (e.g.
		// nocache.cadish). We look ahead: if the leading run of words is closed
		// by a "{", it is a site block; otherwise it is a top-level statement.
		if p.startsSiteBlock() {
			site, err := p.parseSite()
			if err != nil {
				return nil, err
			}
			f.Sites = append(f.Sites, site)
		} else {
			stmt, err := p.parseStatement()
			if err != nil {
				return nil, err
			}
			f.Body = append(f.Body, stmt)
		}
		p.skipSeparators()
	}
	return f, nil
}

// startsSiteBlock looks ahead from the current position (assumed to be the first
// token of a top-level construct) to decide whether it begins a site block. A
// site block is a run of address words — optionally spanning lines and separated
// by commas — terminated by "{". A top-level statement (matcher def or directive)
// is terminated by a newline, ";", "}", comment, or EOF before any "{". A token
// beginning with "@" (a matcher reference/definition) is never a site address, so
// it is always a statement.
func (p *parser) startsSiteBlock() bool {
	first := p.cur()
	if first.Kind == TokenWord && !first.Quoted && strings.HasPrefix(first.Text, "@") {
		return false
	}
	for i := p.pos; i < len(p.toks); i++ {
		switch p.toks[i].Kind {
		case TokenOpenBrace:
			return true
		case TokenWord, TokenComment:
			continue
		case TokenNewline, TokenSemicolon, TokenCloseBrace, TokenEOF:
			return false
		}
	}
	return false
}

// parseGlobalOptions parses the leading "{ ... }" block. The opening brace is the
// current token.
func (p *parser) parseGlobalOptions() (*Options, error) {
	open := p.next() // consume '{'
	body, err := p.parseBlockBody(open)
	if err != nil {
		return nil, err
	}
	return &Options{Body: body, Pos: tokPos(p.file, open)}, nil
}

// parseSite parses one site block: address tokens up to "{", then the body.
func (p *parser) parseSite() (*Site, error) {
	first := p.cur()
	site := &Site{Pos: tokPos(p.file, first)}

	// Collect address tokens until the opening brace. Addresses may be
	// separated by commas (either as their own pseudo-tokens "," or as a
	// trailing "," on an address word). We accept words only here.
	for {
		t := p.cur()
		switch t.Kind {
		case TokenOpenBrace:
			if len(site.Addresses) == 0 {
				return nil, p.errf(t, "site block has no address before '{'")
			}
			open := p.next() // consume '{'
			body, err := p.parseBlockBody(open)
			if err != nil {
				return nil, err
			}
			site.Body = body
			return site, nil
		case TokenWord:
			p.next()
			addrs := splitAddressToken(t.Text)
			site.Addresses = append(site.Addresses, addrs...)
		case TokenNewline, TokenComment:
			// Addresses may span multiple lines (rare) — but a newline before
			// any "{" most commonly means the user forgot the brace. We allow
			// continuation only while we have not yet seen a brace; skip the
			// trivia and keep collecting.
			p.next()
		case TokenEOF:
			return nil, p.errf(t, "unexpected EOF: expected '{' to open site block for %s", strings.Join(site.Addresses, ", "))
		case TokenCloseBrace:
			return nil, p.errf(t, "unexpected '}': expected '{' to open site block")
		case TokenSemicolon:
			return nil, p.errf(t, "unexpected ';' in site address")
		default:
			return nil, p.errf(t, "unexpected %s in site address", t.Kind)
		}
	}
}

// parseBlockBody parses statements until a matching "}". The caller has already
// consumed the opening "{" (passed as open for error context). It returns the
// statement list (possibly empty but non-nil) on success.
func (p *parser) parseBlockBody(open Token) ([]Node, error) {
	p.depth++
	if p.depth > maxBlockDepth {
		p.depth--
		return nil, p.errf(open, "block nesting too deep (exceeds %d levels)", maxBlockDepth)
	}
	defer func() { p.depth-- }()

	body := []Node{}
	for {
		p.skipSeparators()
		t := p.cur()
		switch t.Kind {
		case TokenCloseBrace:
			p.next() // consume '}'
			return body, nil
		case TokenEOF:
			return nil, p.errf(open, "unterminated block: missing '}' (opened here)")
		default:
			stmt, err := p.parseStatement()
			if err != nil {
				return nil, err
			}
			body = append(body, stmt)
		}
	}
}

// parseStatement parses a single statement: a matcher definition (first token
// begins with "@") or a directive (optionally with a nested block). The current
// token is the statement's first token and is not a separator or brace.
func (p *parser) parseStatement() (Node, error) {
	first := p.cur()
	if first.Kind != TokenWord {
		return nil, p.errf(first, "expected a directive or matcher name, got %s", first.Kind)
	}
	if !first.Quoted && strings.HasPrefix(first.Text, "@") {
		return p.parseMatcherDef()
	}
	return p.parseDirective()
}

// parseMatcherDef parses "@name type arg...". The current token is the "@name"
// token.
func (p *parser) parseMatcherDef() (Node, error) {
	nameTok := p.next()
	name := strings.TrimPrefix(nameTok.Text, "@")
	if name == "" {
		return nil, p.errf(nameTok, "matcher definition has empty name after '@'")
	}
	m := &MatcherDef{Name: name, Pos: tokPos(p.file, nameTok)}

	// The matcher type is the next word on the line.
	tt := p.cur()
	if !isArgToken(tt) {
		return nil, p.errf(nameTok, "matcher @%s is missing a type (e.g. path, header, host_regex)", name)
	}
	// A matcher type must be a clean bare identifier. Besides the obvious
	// rejections (a quoted token, an "@ref", a placeholder), it must also not
	// contain any character that would force the formatter to re-quote it
	// (needsQuoting): otherwise `cadish fmt` would emit a quoted type that this
	// very check then rejects on re-parse — a round-trip the formatter must never
	// be able to break (caught by FuzzParse on "@0 0\"").
	if tt.Quoted || strings.HasPrefix(tt.Text, "@") || containsPlaceholder(tt.Text) || needsQuoting(tt.Text) {
		return nil, p.errf(tt, "matcher @%s type must be a bare word, got %q", name, tt.Text)
	}
	p.next()
	m.Type = tt.Text

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}
	m.Args = args

	// A matcher definition must not be followed by a block on the same logical
	// statement.
	if p.cur().Kind == TokenOpenBrace {
		return nil, p.errf(p.cur(), "matcher @%s cannot have a block", name)
	}
	if err := p.expectStatementEnd(); err != nil {
		return nil, err
	}
	return m, nil
}

// parseDirective parses "name arg..." with an optional trailing "{ ... }" block.
// The current token is the directive name.
func (p *parser) parseDirective() (Node, error) {
	nameTok := p.next()
	d := &Directive{Name: nameTok.Text, Pos: tokPos(p.file, nameTok)}

	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}
	d.Args = args

	if p.cur().Kind == TokenOpenBrace {
		open := p.next()
		block, err := p.parseBlockBody(open)
		if err != nil {
			return nil, err
		}
		d.Block = block
		d.HasBlock = true
		// After a block, the statement is complete; a separator (or EOF/'}') is
		// expected next, but we tolerate trailing content on the same line being
		// the next statement only via separators.
		if err := p.expectStatementEnd(); err != nil {
			return nil, err
		}
		return d, nil
	}

	if err := p.expectStatementEnd(); err != nil {
		return nil, err
	}
	return d, nil
}

// parseArgs consumes argument tokens until a statement boundary: a newline,
// semicolon, "{", "}", or EOF. Comments end the line too. Each consumed word
// becomes an Arg with its syntactic kind.
func (p *parser) parseArgs() ([]Arg, error) {
	var args []Arg
	for {
		t := p.cur()
		switch t.Kind {
		case TokenWord:
			p.next()
			args = append(args, Arg{
				Raw:    t.Text,
				Quoted: t.Quoted,
				Kind:   classifyArg(t.Text, t.Quoted),
				Pos:    tokPos(p.file, t),
			})
		case TokenNewline, TokenSemicolon, TokenOpenBrace, TokenCloseBrace, TokenComment, TokenEOF:
			return args, nil
		default:
			return nil, p.errf(t, "unexpected %s in arguments", t.Kind)
		}
	}
}

// expectStatementEnd consumes the separator that ends a statement. A statement
// must be terminated by a newline, a semicolon, a "}" (end of block, which is
// NOT consumed here), or EOF. Comments also terminate a line. Anything else is a
// syntax error.
func (p *parser) expectStatementEnd() error {
	t := p.cur()
	switch t.Kind {
	case TokenNewline, TokenSemicolon:
		p.next()
		return nil
	case TokenComment:
		p.next()
		return nil
	case TokenCloseBrace, TokenEOF:
		// End of enclosing block or file: do not consume; caller handles it.
		return nil
	default:
		return p.errf(t, "unexpected %s after statement; expected newline, ';', or '}'", t.Kind)
	}
}

// isArgToken reports whether t can serve as an argument/word token.
func isArgToken(t Token) bool { return t.Kind == TokenWord }

// tokPos converts a token to an AST Pos.
func tokPos(file string, t Token) Pos {
	return Pos{File: file, Line: t.Line, Col: t.Col}
}

// splitAddressToken splits a site-header address token on commas, dropping empty
// parts. This handles both "a.com," (trailing comma fused to the word) and the
// case where a user writes "a.com,b.com" with no surrounding spaces.
func splitAddressToken(text string) []string {
	if !strings.Contains(text, ",") {
		return []string{text}
	}
	var out []string
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
