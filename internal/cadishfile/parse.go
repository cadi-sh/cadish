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

// ParseFragment parses src as an imported fragment body: the SAME grammar as a
// site body — a flat list of statements where each statement is a matcher
// definition ("@name type arg…") or a directive that MAY carry a trailing
// "{ … }" block. It returns the statement nodes, ready to be spliced in place of
// an `import` directive at its site-body position.
//
// Unlike Parse — which at the top level reads "addrs… { … }" as a SITE block
// (addresses + body) — ParseFragment routes the whole token stream through the
// block-body grammar. A brace-bodied directive in a fragment (classify {…},
// upstream {…}, tls {…}, cache {…}, geo {…}, device_detect {…}, …) therefore
// associates its body into a Directive.Block exactly as it would inline at the
// splice point, instead of being mis-read as a site header and flattened into
// orphaned top-level statements. A malformed/unclosed block, or a stray "}", is a
// positioned *ParseError. The filename is used only for error/AST positions; the
// AST stays semantics-free (no directive is interpreted).
func ParseFragment(filename string, src []byte) ([]Node, error) {
	toks, err := tokenize(filename, src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, file: filename}
	return p.parseFragmentBody()
}

// ParseFragmentFile reads the file at path and parses it as an imported fragment
// body (see ParseFragment). The path is used as the filename for positions.
func ParseFragmentFile(path string) ([]Node, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseFragment(path, src)
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
		} else if tok, bad := p.unseparatedAddrWrap(); bad {
			// A site-address list that spans multiple lines without comma-separating
			// EVERY wrapped element (a comma-LESS wrap, or a space-separated wrapped
			// line where only the last token carries a ",") would otherwise silently
			// drop the earlier address(es) as no-op top-level statements — the
			// production-525 shape. Refuse loudly with a positioned, actionable error.
			return nil, p.errf(tok, "site address list spans multiple lines — comma-separate every wrapped address (put ',' after each, or place them all on one line)")
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
//
// Multi-line address lists: a site header's addresses may wrap across newlines
// (the failing live config listed 40 addresses over 19 lines). We continue the
// look-ahead across a newline ONLY when the preceding word ended with a trailing
// "," — the explicit address-list continuation signal (Caddy/cadish separate
// addresses with commas or whitespace; a wrapped line always carries the comma).
// Requiring the trailing comma keeps a genuine top-level statement — which ends
// at its newline with no continuation — from being absorbed into a following
// site header (SPEC-MULTILINE-ADDR). Before this fix the look-ahead bailed on the
// first newline, so only the last address line before "{" became the site and the
// earlier lines were silently mis-parsed as top-level statements — registering
// the static TLS cert for too few domains and causing a production 525.
func (p *parser) startsSiteBlock() bool {
	first := p.cur()
	if first.Kind == TokenWord && !first.Quoted && strings.HasPrefix(first.Text, "@") {
		return false
	}
	// A wrapped address list may cross a newline ONLY when the header seen so far is a
	// pure comma-separated address list: EVERY word is an unquoted, address-shaped
	// token that ALSO carries a trailing "," (the explicit list-continuation signal).
	// This is what distinguishes a genuine address list from a comma-ending directive
	// (Finding 2) WITHOUT rejecting valid single-label hosts (Finding 1):
	//
	//   - An address list comma-separates every element, so when the line continues to
	//     the next line every element — including the last word before the newline —
	//     ends in ",":  `a.example.com, *.a.example.com,` / `intranet,`.
	//   - A directive line has space-separated leading words that do NOT end in "," —
	//     `header_down` / `X-Foo` in `header_down X-Foo bar,` — and only the final word
	//     carries a stray comma. A quoted arg (`respond "hi,"`) is quoted. Either flips
	//     addrList false, so the newline is NOT crossed and the statement stays top-level.
	//
	// Because the rule keys on comma-termination (not on label count), a bare
	// single-label host (`intranet`, `db`, `cache`) — a documented-valid cadish
	// site/listen address (config/addr.go) — continues a wrapped list correctly instead
	// of being silently dropped (the re-introduced 525 regression this replaces).
	addrList := true
	for i := p.pos; i < len(p.toks); i++ {
		switch p.toks[i].Kind {
		case TokenOpenBrace:
			return true
		case TokenWord:
			t := p.toks[i]
			// A word keeps the run a pure comma-list only if it is an unquoted,
			// address-shaped token ending in ",". The FINAL word before "{" need not
			// end in "," — but that word is followed by "{" (handled above), never a
			// newline, so addrList only gates newline crossings.
			if t.Quoted || !isAddressToken(t.Text) || !strings.HasSuffix(t.Text, ",") {
				addrList = false
			}
		case TokenComment:
			// Comments are trivia: they neither continue nor end the address run.
		case TokenNewline:
			// Cross a newline ONLY while the header so far is a comma-separated
			// address list (every word an address token ending in ",").
			if addrList {
				continue
			}
			return false
		case TokenSemicolon, TokenCloseBrace, TokenEOF:
			return false
		}
	}
	return false
}

// isAddressToken reports whether a bare (unquoted) word is SHAPED like a site
// address rather than being obviously non-address syntax. It recognizes a dotted
// host, a "*." wildcard, an IP literal, a "scheme://host" form, a leading ":port"
// listen form, and any bare hostname label — including a SINGLE label like
// `intranet`, `db`, `cache`, or `localhost`, which config/addr.go accepts as a
// valid site/listen address (an exact Host routing / TLS-cert key). It mirrors
// addr.go's rule: any token built solely from hostname characters is address-shaped;
// only a token carrying a character no hostname/IP/port can hold (a space, a quote,
// a placeholder brace, etc.) is rejected.
//
// Because a single-label host is now address-shaped, a single-label DIRECTIVE token
// (`header_down`, `bar`) is ALSO address-shaped. Disambiguation between a wrapped
// address list and a comma-ending directive is therefore NOT done here (it must not
// rely on rejecting single labels — doing so silently dropped valid hosts, the 525
// regression); the caller (startsSiteBlock) keys on comma-termination of EVERY word
// instead.
func isAddressToken(text string) bool {
	text = strings.TrimSuffix(text, ",")
	if text == "" {
		return true // a bare "," separator: neutral, neither address nor directive arg
	}
	// Caddy-style ":port" / "host:port" listen address with no host: ":8080".
	if strings.HasPrefix(text, ":") {
		rest := text[1:]
		if rest == "" {
			return false
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	// scheme://host
	if i := strings.Index(text, "://"); i >= 0 {
		text = text[i+len("://"):]
	}
	// Drop any path/query that might trail an address token.
	if i := strings.IndexAny(text, "/?#"); i >= 0 {
		text = text[:i]
	}
	text = strings.TrimPrefix(text, "*.")
	if text == "" {
		return false
	}
	// Bracketed IPv6 literal "[::1]".
	if strings.HasPrefix(text, "[") {
		return strings.Contains(text, "]")
	}
	// Strip a trailing ":port".
	if i := strings.LastIndexByte(text, ':'); i >= 0 {
		text = text[:i]
	}
	if text == "" {
		return false
	}
	for _, r := range text {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	// Anything left is built solely from hostname characters: a dotted host, an IP, OR
	// a bare single label (`intranet`, `db`, `localhost`) — all valid cadish addresses
	// per config/addr.go. It is address-SHAPED. (The caller disambiguates a single-label
	// directive token from a real address via comma-termination, not here.)
	return true
}

// unseparatedAddrWrap reports a site-address list that wraps across statement
// separator(s) WITHOUT comma-separating every element — the silent-525 outage shape.
// It fires when, from the current token through the opening "{" of a following site
// header, EVERY word is an unquoted address-shaped token, the run crosses at least one
// statement separator (a newline OR a ";" — Finding 5), and the run contains TWO OR
// MORE clearly hostname-shaped addresses. Concrete shapes that fire:
//
//   - the comma-LESS wrap: `a.example.com\nb.example.com {` (no trailing commas);
//   - the space-separated wrap: `example.com www.example.com,\napi.example.com {`,
//     where the wrapped line has 2+ whitespace-separated addresses but only the
//     LAST carries a ",". The conservative continuation rule in startsSiteBlock
//     (comma after EVERY element) correctly refuses to claim either as a site, so
//     without this they would silently drop the earlier address(es) into top-level
//     Body and register the static TLS cert for too few domains.
//
// It returns the offending FIRST token so the caller can emit a positioned error.
//
// Two properties keep it both correct and round-trip-stable:
//
//   - It must NOT fire on a genuine top-level statement. The first word must be
//     clearly hostname-shaped — a dotted host, "localhost", a ":port"/"[ipv6]"/"host:port"
//     form — so any directive (whose name is a bare dot-less label, even one with an
//     underscore such as `header_down`, or whose later args happen to be dotted like
//     `tls cert.example.com key.pem`) is excluded up front.
//
//   - It must require 2+ CLEARLY hostname-shaped addresses, and must treat ";" and
//     newline identically. A SINGLE lone leading token followed by a site header that
//     is merely address-TOKEN-shaped but not clearly an address — a bare digit/label
//     such as `0` — falls through to a no-op top-level Body directive that `cadish check`
//     flags (noop-top-level-statement), instead of hard-erroring. Without this, Parse
//     accepted `.;;0{ }` (`.` a Body directive, `0 { }` a site) yet its own Format output
//     `.\n0 {` re-parsed as a comma-less wrap and ERRORED — an internal Parse/Format
//     asymmetry surfaced by FuzzParse. Because Format normalizes separators to newlines,
//     scanning ";" and newline the same way (and counting clearly-shaped words the same
//     way regardless of which separator the writer used) means no input can sit on one
//     side of the fire/no-fire boundary while its formatted form sits on the other.
//
// A legitimate comma-after-every-element wrap is already claimed as a site by
// startsSiteBlock before this is consulted, so it never reaches here.
func (p *parser) unseparatedAddrWrap() (Token, bool) {
	first := p.cur()
	if first.Kind != TokenWord || first.Quoted || strings.HasPrefix(first.Text, "@") {
		return first, false
	}
	// A BARE single-label first word (`intranet`, `db`) is excluded because a dot-less
	// label is shape-INDISTINGUISHABLE from a directive name: `intranet`\n`api.internal {`
	// (a forgotten-comma address drop) and `metrics`\n`api.internal {` (a real directive
	// before a site) are the SAME token shape, so a hard parse error cannot tell them
	// apart without false-firing. That residual single-label silent-drop (Finding R12) is
	// closed one layer up, by a `cadish check` warning on no-op top-level body statements
	// (detectNoOpTopLevelBody), NOT by the semantics-free parser.
	if !clearlyHostnameShaped(first.Text) {
		return first, false
	}
	// Uniform scan from the first token to the opening brace of a following site header.
	// EVERY word must be an unquoted address-shaped token; a quoted/placeholder/non-address
	// word (`{host}`, `"hi,"`) means this is a real statement, not a mis-wrapped address
	// list — bail to the safe directive path. Newlines and ";" both count as a separator
	// crossing (they are interchangeable, and Format emits newlines). We fire only when a
	// "{" terminates the run AFTER at least one separator crossing AND 2+ clearly
	// hostname-shaped addresses were seen (the first word guarantees one).
	clearCount := 0
	sawSep := false
	for i := p.pos; i < len(p.toks); i++ {
		t := p.toks[i]
		switch t.Kind {
		case TokenWord:
			if t.Quoted || !isAddressToken(t.Text) {
				return first, false
			}
			if clearlyHostnameShaped(t.Text) {
				clearCount++
			}
		case TokenNewline, TokenSemicolon:
			sawSep = true
		case TokenComment:
			// trivia: neither continues nor ends the run.
		case TokenOpenBrace:
			return first, sawSep && clearCount >= 2
		default: // TokenCloseBrace, TokenEOF, or any other token: an ordinary statement.
			return first, false
		}
	}
	return first, false
}

// clearlyHostnameShaped reports whether a bare (unquoted) word is UNAMBIGUOUSLY a
// site address rather than possibly a directive name. Two disjoint cases qualify:
//
//   - it is address-shaped AND carries a dot (a dotted host, wildcard, or IP) or is
//     exactly "localhost"; OR
//   - it has a shape NO directive name can EVER take (Finding 2): it begins with ":"
//     and is a valid `:port` listen form (`:8080`), begins with "[" (a bracketed IPv6
//     literal such as `[::1]:8080`), or contains "://" (a `scheme://host` form). A
//     cadish/Caddy directive name is always a bare label, so keying the loud
//     unseparated-wrap error on these shapes is false-positive-safe.
//
// A dot-less single label (`tls`, `intranet`, `db`) is still deliberately excluded
// because it is indistinguishable from a directive name; the address-list continuation
// for those relies on explicit trailing commas (claimed as a site by startsSiteBlock)
// instead.
func clearlyHostnameShaped(text string) bool {
	text = strings.TrimSuffix(text, ",")
	if neverDirectiveShaped(text) {
		return true
	}
	// Finding 4: a dot-less `host:port` first token (`cache:6081`, `localhost:8080`) is
	// also unambiguously an address — a directive NAME can never contain a ":" (it is
	// always a bare hostname-character label), and isAddressToken already validates the
	// `:port`. Without this, a comma-less wrap whose first line is a dot-less `host:port`
	// abstained from the loud error and silently DROPPED the address (the 525-outage shape).
	// False-positive-safe: the ":" alone disqualifies the token from being a directive name.
	return isAddressToken(text) && (strings.Contains(text, ".") || text == "localhost" || strings.ContainsRune(text, ':'))
}

// neverDirectiveShaped reports whether a bare (unquoted) token has a shape that a
// directive NAME can never take, so it can only be a site address: a `:port` listen
// form (`:8080`), a bracketed IPv6 literal (`[::1]:8080`), or a `scheme://host` form.
// A directive name is always a bare hostname-character label, so none of these shapes
// is ambiguous — using them to trigger the loud comma-less-wrap error cannot false-fire
// on a real directive (Finding 2). A leading ":" must still parse as a valid `:port`
// (digits only) so a stray `:foo` is not misread as an address.
func neverDirectiveShaped(text string) bool {
	if strings.Contains(text, "://") {
		return true
	}
	if strings.HasPrefix(text, "[") {
		return true
	}
	if strings.HasPrefix(text, ":") {
		rest := text[1:]
		if rest == "" {
			return false
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
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

// parseFragmentBody parses an imported fragment as a flat statement list using
// the SAME grammar as a site body: it loops parseStatement (matcher defs +
// directives-with-optional-blocks) until EOF. It is parseBlockBody's twin,
// terminated by EOF rather than a matching "}". A stray "}" — a fragment whose
// braces are unbalanced from the top — is a positioned error rather than a silent
// truncation; an unterminated inner block surfaces from parseBlockBody as its own
// positioned "unterminated block" error.
func (p *parser) parseFragmentBody() ([]Node, error) {
	body := []Node{}
	for {
		p.skipSeparators()
		t := p.cur()
		switch t.Kind {
		case TokenEOF:
			return body, nil
		case TokenCloseBrace:
			return nil, p.errf(t, "unexpected '}' in imported fragment")
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
