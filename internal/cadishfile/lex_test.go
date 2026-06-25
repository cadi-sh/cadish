package cadishfile

import (
	"testing"
)

// tk is a compact expected-token used in the table tests. We compare Kind, Text,
// and (when nonzero) Line/Col so tests stay readable while still pinning
// positions where they matter.
type tk struct {
	kind   TokenKind
	text   string
	line   int
	col    int
	quoted bool
}

func lexAll(t *testing.T, src string) []Token {
	t.Helper()
	toks, err := tokenize("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("tokenize(%q) unexpected error: %v", src, err)
	}
	return toks
}

func TestLexBasic(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []tk
	}{
		{
			name: "single directive",
			src:  "cache_key url host\n",
			want: []tk{
				{kind: TokenWord, text: "cache_key", line: 1, col: 1},
				{kind: TokenWord, text: "url", line: 1, col: 11},
				{kind: TokenWord, text: "host", line: 1, col: 15},
				{kind: TokenNewline, line: 1, col: 19},
				{kind: TokenEOF},
			},
		},
		{
			name: "block braces and semicolons",
			src:  "cache { ram 10GiB; disk /x 2TiB }",
			want: []tk{
				{kind: TokenWord, text: "cache"},
				{kind: TokenOpenBrace, text: "{"},
				{kind: TokenWord, text: "ram"},
				{kind: TokenWord, text: "10GiB"},
				{kind: TokenSemicolon, text: ";"},
				{kind: TokenWord, text: "disk"},
				{kind: TokenWord, text: "/x"},
				{kind: TokenWord, text: "2TiB"},
				{kind: TokenCloseBrace, text: "}"},
				{kind: TokenEOF},
			},
		},
		{
			name: "quoted string preserves spaces",
			src:  `header X "GET, OPTIONS, POST"`,
			want: []tk{
				{kind: TokenWord, text: "header"},
				{kind: TokenWord, text: "X"},
				{kind: TokenWord, text: "GET, OPTIONS, POST", quoted: true},
				{kind: TokenEOF},
			},
		},
		{
			name: "matcher ref token kept as word",
			src:  "pass @ajax",
			want: []tk{
				{kind: TokenWord, text: "pass"},
				{kind: TokenWord, text: "@ajax"},
				{kind: TokenEOF},
			},
		},
		{
			name: "env placeholder is a single word, not a brace",
			src:  "purge token {$PURGE_TOKEN}",
			want: []tk{
				{kind: TokenWord, text: "purge"},
				{kind: TokenWord, text: "token"},
				{kind: TokenWord, text: "{$PURGE_TOKEN}"},
				{kind: TokenEOF},
			},
		},
		{
			name: "generic placeholder is a single word",
			src:  "x {http.X-Foo} {device}",
			want: []tk{
				{kind: TokenWord, text: "x"},
				{kind: TokenWord, text: "{http.X-Foo}"},
				{kind: TokenWord, text: "{device}"},
				{kind: TokenEOF},
			},
		},
		{
			name: "comment to end of line then directive",
			src:  "tls { # a comment\n  acme x\n}",
			want: []tk{
				{kind: TokenWord, text: "tls"},
				{kind: TokenOpenBrace, text: "{"},
				{kind: TokenComment, text: "# a comment"},
				{kind: TokenNewline},
				{kind: TokenWord, text: "acme"},
				{kind: TokenWord, text: "x"},
				{kind: TokenNewline},
				{kind: TokenCloseBrace, text: "}"},
				{kind: TokenEOF},
			},
		},
		{
			name: "line continuation joins arguments",
			src:  "a b \\\n   c d\n",
			want: []tk{
				{kind: TokenWord, text: "a"},
				{kind: TokenWord, text: "b"},
				{kind: TokenWord, text: "c"},
				{kind: TokenWord, text: "d"},
				{kind: TokenNewline},
				{kind: TokenEOF},
			},
		},
		{
			name: "trailing comma fused to address word",
			src:  "a.com, b.com {\n}",
			want: []tk{
				{kind: TokenWord, text: "a.com,"},
				{kind: TokenWord, text: "b.com"},
				{kind: TokenOpenBrace, text: "{"},
				{kind: TokenNewline},
				{kind: TokenCloseBrace, text: "}"},
				{kind: TokenEOF},
			},
		},
		{
			name: "regex argument keeps backslashes literally",
			src:  `strip_cookies path_regex \.(css|js)$`,
			want: []tk{
				{kind: TokenWord, text: "strip_cookies"},
				{kind: TokenWord, text: "path_regex"},
				{kind: TokenWord, text: `\.(css|js)$`},
				{kind: TokenEOF},
			},
		},
		{
			name: "empty input is just EOF",
			src:  "",
			want: []tk{{kind: TokenEOF}},
		},
		{
			name: "blank lines coalesced to single newline with count",
			src:  "a\n\n\nb",
			want: []tk{
				{kind: TokenWord, text: "a"},
				{kind: TokenNewline},
				{kind: TokenWord, text: "b"},
				{kind: TokenEOF},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lexAll(t, tt.src)
			if len(got) != len(tt.want) {
				t.Fatalf("token count = %d, want %d\ngot: %v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				g := got[i]
				if g.Kind != w.kind {
					t.Errorf("token %d kind = %v, want %v (%v)", i, g.Kind, w.kind, g)
				}
				if w.text != "" && g.Text != w.text {
					t.Errorf("token %d text = %q, want %q", i, g.Text, w.text)
				}
				if w.line != 0 && g.Line != w.line {
					t.Errorf("token %d line = %d, want %d", i, g.Line, w.line)
				}
				if w.col != 0 && g.Col != w.col {
					t.Errorf("token %d col = %d, want %d", i, g.Col, w.col)
				}
				if w.quoted && !g.Quoted {
					t.Errorf("token %d Quoted = false, want true", i)
				}
			}
		})
	}
}

func TestLexBlankBefore(t *testing.T) {
	// One blank line between two statements should set BlankBefore=1 on the
	// first token of the second statement.
	toks := lexAll(t, "a\n\nb\n")
	// tokens: a, NL, b, NL, EOF
	if toks[2].Text != "b" {
		t.Fatalf("expected token 2 to be 'b', got %v", toks[2])
	}
	if toks[2].BlankBefore != 1 {
		t.Errorf("BlankBefore = %d, want 1", toks[2].BlankBefore)
	}
}

func TestLexUnterminatedString(t *testing.T) {
	_, err := tokenize("f.cadish", []byte(`header X "unterminated`))
	if err == nil {
		t.Fatal("expected an error for unterminated string")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("error type = %T, want *ParseError", err)
	}
	if pe.Line != 1 {
		t.Errorf("error line = %d, want 1", pe.Line)
	}
	if got := pe.Error(); got != "f.cadish:1:10: unterminated quoted string" {
		t.Errorf("error = %q, want f.cadish:1:10: unterminated quoted string", got)
	}
}

func TestLexQuotedEscapes(t *testing.T) {
	toks := lexAll(t, `x "a \"b\" c"`)
	if toks[1].Text != `a "b" c` {
		t.Errorf("escaped quotes text = %q, want %q", toks[1].Text, `a "b" c`)
	}
	if !toks[1].Quoted {
		t.Error("expected Quoted=true")
	}
}

func TestLexColumnsUTF8(t *testing.T) {
	// Multi-byte runes should advance columns by one per rune, not per byte.
	toks := lexAll(t, "café x")
	if toks[1].Text != "x" {
		t.Fatalf("token 1 = %v", toks[1])
	}
	if toks[1].Col != 6 { // c a f é space x -> x at rune col 6
		t.Errorf("col = %d, want 6", toks[1].Col)
	}
}
