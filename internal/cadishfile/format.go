package cadishfile

import (
	"strings"
)

// indentUnit is one level of indentation in formatted output: 4 spaces.
const indentUnit = "    "

// Format rewrites a Cadishfile into canonical form: the Cadishfile equivalent of
// gofmt. It guarantees:
//
//   - 4-space indentation, one level per nested block;
//   - exactly one statement per line (statements separated by ";" in the input
//     are split onto their own lines);
//   - opening braces stay on the statement line ("name {"), closing braces on
//     their own line at the parent indentation;
//   - line-continuation backslashes are removed (continued arguments are joined
//     onto one line);
//   - runs of blank lines are collapsed to at most one;
//   - comments are preserved: a full-line comment stays on its own line at the
//     current indentation, and a trailing comment ("...  # note") stays at the
//     end of its statement line;
//   - the output ends with exactly one trailing newline.
//
// Format requires the input to PARSE: it lexes and parses the source first (so it
// reports the same lexical AND syntactic errors as the parser, e.g. an
// unterminated quoted string or an unterminated block) and refuses to emit a
// partial/truncated result for a config that does not parse. This prevents
// `cadish fmt -w` from corrupting a file by writing an unclosed block. Once the
// input is known to parse, Format does its work at the token level (so comments
// and blank-line spacing are preserved verbatim).
//
// Format is idempotent: Format(Format(x)) == Format(x).
func Format(src []byte) ([]byte, error) {
	toks, err := tokenize("", src)
	if err != nil {
		return nil, err
	}
	// Refuse to format input that does not parse: formatting at the token level
	// would otherwise silently emit a truncated result for, e.g., an unterminated
	// block (missing '}'), corrupting the file under `fmt -w`.
	if _, perr := Parse("", src); perr != nil {
		return nil, perr
	}

	var b strings.Builder
	depth := 0
	// atLineStart is true when nothing has been written on the current output
	// line yet.
	atLineStart := true
	// wroteAny is true once we have emitted the first real token, used to gate
	// leading blank lines.
	wroteAny := false
	// pendingBlank requests a single blank line before the next emitted line.
	pendingBlank := false
	// suppressBlank is set right after an opening brace so a blank line at the
	// very top of a block body is dropped (blocks should not start with a blank
	// line).
	suppressBlank := false

	indent := func() {
		for i := 0; i < depth; i++ {
			b.WriteString(indentUnit)
		}
	}

	// newlineIfNeeded terminates the current output line if something is on it.
	newlineIfNeeded := func() {
		if !atLineStart {
			b.WriteByte('\n')
			atLineStart = true
		}
	}

	// startLine begins a fresh output line, honoring a pending blank line and
	// applying indentation. It must be called when atLineStart is true.
	startLine := func() {
		if pendingBlank && wroteAny {
			b.WriteByte('\n')
		}
		pendingBlank = false
		indent()
		atLineStart = false
		wroteAny = true
	}

	// writeWord appends a word token to the current line, inserting a single
	// separating space when the line already has content.
	writeWord := func(text string) {
		if atLineStart {
			startLine()
		} else {
			b.WriteByte(' ')
		}
		b.WriteString(text)
	}

	for i := 0; i < len(toks); i++ {
		t := toks[i]

		// Honor a normalized blank line before a line's first token, unless we
		// just opened a block (no blank line at the top of a body).
		if t.BlankBefore > 0 && atLineStart && !suppressBlank {
			pendingBlank = true
		}
		// suppressBlank only guards the first line-start token after a brace.
		if t.Kind != TokenNewline {
			suppressBlank = false
		}

		switch t.Kind {
		case TokenEOF:
			// done

		case TokenNewline:
			newlineIfNeeded()

		case TokenSemicolon:
			// A ";" separates statements: end the current line so the next
			// statement starts fresh.
			newlineIfNeeded()

		case TokenComment:
			if atLineStart {
				// Full-line comment: own line at current indentation.
				startLine()
				b.WriteString(t.Text)
				newlineIfNeeded()
			} else {
				// Trailing comment: keep on the statement line.
				b.WriteByte(' ')
				b.WriteString(t.Text)
				newlineIfNeeded()
			}

		case TokenOpenBrace:
			// Attach the brace to the current line; if the line is empty (brace
			// on its own line in the source), start a fresh indented line first.
			if atLineStart {
				startLine()
			} else {
				b.WriteByte(' ')
			}
			b.WriteByte('{')
			// Keep a trailing comment on the same source line as the "{" (e.g.
			// "name {  # note") attached to the brace line rather than relocating
			// it to its own line.
			if c, ok := trailingCommentAfter(toks, i, t.Line); ok {
				b.WriteByte(' ')
				b.WriteString(c.Text)
				i++ // consume the comment token
			}
			newlineIfNeeded()
			depth++
			pendingBlank = false
			suppressBlank = true

		case TokenCloseBrace:
			newlineIfNeeded()
			if depth > 0 {
				depth--
			}
			pendingBlank = false // no blank line right before a closing brace
			startLine()
			b.WriteByte('}')
			// Keep a trailing comment on the same source line as the "}" (e.g.
			// "}  # end") attached to the brace line.
			if c, ok := trailingCommentAfter(toks, i, t.Line); ok {
				b.WriteByte(' ')
				b.WriteString(c.Text)
				i++ // consume the comment token
			}
			newlineIfNeeded()

		case TokenWord:
			writeWord(formatWord(t))
		}
	}

	newlineIfNeeded()
	out := strings.TrimRight(b.String(), "\n")
	if out == "" {
		return []byte(""), nil
	}
	return []byte(out + "\n"), nil
}

// trailingCommentAfter reports whether the token immediately following index i is
// a comment on the same source line (line), i.e. a trailing comment that should
// stay attached to the current statement/brace line rather than being relocated
// to its own line. It returns that comment token when so.
func trailingCommentAfter(toks []Token, i, line int) (Token, bool) {
	if i+1 < len(toks) {
		nt := toks[i+1]
		if nt.Kind == TokenComment && nt.Line == line {
			return nt, true
		}
	}
	return Token{}, false
}

// formatWord renders a word token back to source form, re-quoting it when
// necessary. A token that was quoted in the input, or that contains characters
// that would not survive being re-lexed as a bare word (whitespace, or a
// structural character), is emitted as a double-quoted string with internal
// quotes and backslashes escaped. Otherwise it is emitted verbatim.
func formatWord(t Token) string {
	if t.Quoted || needsQuoting(t.Text) {
		return quote(t.Text)
	}
	return t.Text
}

// needsQuoting reports whether text must be double-quoted to survive a
// re-lex/re-parse round trip as a single bare word. An empty string needs
// quoting (to remain a token at all). Whitespace, a literal quote, and ';' would
// split or terminate a bare word. A trailing backslash would be re-read as a line
// continuation, so it forces quoting too. A leading '#' would start a comment.
// (Interior backslashes are fine: they are literal in bare words.)
func needsQuoting(text string) bool {
	if text == "" {
		return true
	}
	if text[len(text)-1] == '\\' {
		return true
	}
	if text[0] == '#' {
		return true
	}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case ' ', '\t', '\n', '\r', '"', ';':
			return true
		}
	}
	return false
}

// quote wraps text in double quotes, escaping embedded backslashes and quotes.
func quote(text string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteByte(text[i])
	}
	b.WriteByte('"')
	return b.String()
}
