package cadishfile

import (
	"bytes"
	"strings"
	"testing"
)

func mustFormat(t *testing.T, src string) string {
	t.Helper()
	out, err := Format([]byte(src))
	if err != nil {
		t.Fatalf("Format(%q) error: %v", src, err)
	}
	return string(out)
}

func TestFormatBasic(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "collapses spacing and indents",
			in:   "example.com {\ncache_key   url    host\n}\n",
			want: "example.com {\n    cache_key url host\n}\n",
		},
		{
			name: "semicolons become newlines",
			in:   "x {\ncache { ram 10GiB; disk /x 2TiB }\n}\n",
			want: "x {\n    cache {\n        ram 10GiB\n        disk /x 2TiB\n    }\n}\n",
		},
		{
			name: "nested indentation",
			in:   "x {\ntls {\nacme me\n}\n}\n",
			want: "x {\n    tls {\n        acme me\n    }\n}\n",
		},
		{
			name: "blank lines collapse to one",
			in:   "x {\n\n\n\na b\n\n\nc d\n}\n",
			want: "x {\n    a b\n\n    c d\n}\n",
		},
		{
			name: "line continuation joined",
			in:   "x {\n@m path /a \\\n  /b /c\n}\n",
			want: "x {\n    @m path /a /b /c\n}\n",
		},
		{
			name: "full-line and trailing comments preserved",
			in:   "x {\n# top\na b # trailing\n}\n",
			want: "x {\n    # top\n    a b # trailing\n}\n",
		},
		{
			name: "placeholders preserved",
			in:   "x {\npurge t {$TOK} {http.X}\n}\n",
			want: "x {\n    purge t {$TOK} {http.X}\n}\n",
		},
		{
			name: "quoted strings preserved",
			in:   "x {\nheader A \"GET, POST\"\n}\n",
			want: "x {\n    header A \"GET, POST\"\n}\n",
		},
		{
			name: "empty input yields empty output",
			in:   "",
			want: "",
		},
		{
			name: "only comments",
			in:   "# just a comment\n",
			want: "# just a comment\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustFormat(t, tt.in)
			if got != tt.want {
				t.Errorf("Format mismatch\n--- got ---\n%q\n--- want ---\n%q", got, tt.want)
			}
		})
	}
}

// formatCorpus holds a variety of inputs (valid, messy, and edge cases) used to
// verify idempotency.
var formatCorpus = []string{
	"",
	"\n\n\n",
	"# only comment\n",
	"example.com {\n}\n",
	"a.com, *.a.com {\ncache_key   url   host\n}\n",
	"x{cache{ram 10GiB;disk /x 2TiB}}",
	"x {\n@nocache path /a/* /b/*\n@ajax header X Y\npass @ajax\n}\n",
	"{\ndebug on\n}\nsite.com {\ntls { acme me }\n}\n",
	"x {\n  header  -Server  -X-Powered-By\n  header A \"GET, OPTIONS, POST\"\n}\n",
	"x {\npurge when header X-Tok {$TOK} regex {http.X-Re}\n}\n",
	"x {\n\n\n\na\n\n\n\nb\n}\n",
	"x {\nupstream web {\nto k8s://x:8080\nsticky by cookie PHPSESSID else client_ip\n}\n}\n",
	"frag @m path /a /b\n@n header X Y\n",
	"x {\na b \\\n   c \\\n   d\n}\n",
	"x {\n# comment 1\n\n# comment 2\nthing here\n}\n",
}

func TestFormatIdempotent(t *testing.T) {
	for i, src := range formatCorpus {
		once, err := Format([]byte(src))
		if err != nil {
			t.Fatalf("corpus[%d] Format error: %v", i, err)
		}
		twice, err := Format(once)
		if err != nil {
			t.Fatalf("corpus[%d] re-Format error: %v", i, err)
		}
		if !bytes.Equal(once, twice) {
			t.Errorf("corpus[%d] not idempotent\nsrc:   %q\nonce:  %q\ntwice: %q", i, src, once, twice)
		}
	}
}

func TestFormatPreservesParseability(t *testing.T) {
	// Formatting then parsing should succeed and yield the same structure for
	// valid inputs.
	for i, src := range formatCorpus {
		if _, err := Parse("c", []byte(src)); err != nil {
			continue // skip inputs that don't fully parse
		}
		out, err := Format([]byte(src))
		if err != nil {
			t.Fatalf("corpus[%d] Format error: %v", i, err)
		}
		if _, err := Parse("c", out); err != nil {
			t.Errorf("corpus[%d] formatted output failed to parse: %v\noutput:\n%s", i, err, out)
		}
	}
}

func TestFormatTrailingNewline(t *testing.T) {
	out := mustFormat(t, "x {\na\n}")
	if !strings.HasSuffix(out, "}\n") {
		t.Errorf("output should end with newline, got %q", out)
	}
	if strings.HasSuffix(out, "\n\n") {
		t.Errorf("output should end with exactly one newline, got %q", out)
	}
}

func TestFormatPreservesRegexBackslashes(t *testing.T) {
	// Backslashes in regex arguments must survive formatting unchanged.
	in := "x {\n    strip_cookies path_regex \\.(css|js|png)$\n}\n"
	got := mustFormat(t, in)
	if got != in {
		t.Errorf("regex backslash mangled\n got: %q\nwant: %q", got, in)
	}
	// And it must still parse with the backslash intact.
	f, err := Parse("c", []byte(got))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	arg := f.Sites[0].Body[0].(*Directive).Args[1]
	if arg.Raw != `\.(css|js|png)$` {
		t.Errorf("regex arg = %q, want %q", arg.Raw, `\.(css|js|png)$`)
	}
}

func TestFormatTrailingBackslashQuoted(t *testing.T) {
	// A word ending in a backslash must be quoted so it is not re-read as a line
	// continuation, keeping Format idempotent.
	out, err := Format([]byte("x a\\"))
	if err != nil {
		t.Fatal(err)
	}
	out2, err := Format(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, out2) {
		t.Errorf("not idempotent: %q vs %q", out, out2)
	}
}

func TestFormatUnterminatedStringError(t *testing.T) {
	_, err := Format([]byte(`x { header A "oops`))
	if err == nil {
		t.Fatal("expected an error for unterminated string")
	}
}

// TestFormatClassifyBlock: a `classify {TOKEN} { … }` block formats canonically
// (block body indented one level, one row per line, arrows preserved) and is
// idempotent and re-parseable.
func TestFormatClassifyBlock(t *testing.T) {
	in := "example.com {\n@v cookie verified_prod\nclassify {age} { when @v -> ok ; default -> open }\ncache_key path {age}\n}"
	want := `example.com {
    @v cookie verified_prod
    classify {age} {
        when @v -> ok
        default -> open
    }
    cache_key path {age}
}
`
	got := mustFormat(t, in)
	if got != want {
		t.Errorf("classify format mismatch\n got: %q\nwant: %q", got, want)
	}
	// Idempotent.
	if again := mustFormat(t, got); again != got {
		t.Errorf("classify format not idempotent:\n once: %q\ntwice: %q", got, again)
	}
	// Still parses after formatting.
	if _, err := Parse("f.cadish", []byte(got)); err != nil {
		t.Errorf("formatted classify does not parse: %v", err)
	}
}

// TestFormatCookieJSONMatcher: a `cookie_json`/`header_json` matcher round-trips
// through Format (the parser is semantics-free: NAME PATH VALUE… are plain args)
// and is idempotent and re-parseable.
func TestFormatCookieJSONMatcher(t *testing.T) {
	in := "example.com {\n@nv   cookie_json  nsfwCookie   needVerify  true\n@pro header_json X-Session plan.tier pro enterprise\npass @nv @pro\n}"
	want := `example.com {
    @nv cookie_json nsfwCookie needVerify true
    @pro header_json X-Session plan.tier pro enterprise
    pass @nv @pro
}
`
	got := mustFormat(t, in)
	if got != want {
		t.Errorf("cookie_json format mismatch\n got: %q\nwant: %q", got, want)
	}
	if again := mustFormat(t, got); again != got {
		t.Errorf("cookie_json format not idempotent:\n once: %q\ntwice: %q", got, again)
	}
	if _, err := Parse("f.cadish", []byte(got)); err != nil {
		t.Errorf("formatted cookie_json does not parse: %v", err)
	}
}
