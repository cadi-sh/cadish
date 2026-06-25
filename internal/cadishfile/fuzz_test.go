package cadishfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParse exercises the lexer, parser, and formatter with arbitrary input. The
// invariant under test is robustness: none of Parse, Format, or SubstituteEnv may
// ever panic, regardless of input. It also checks the central correctness
// property of the formatter — idempotency — on every input that formats without
// error.
func FuzzParse(f *testing.F) {
	// Seed with the canonical corpus and a spread of tricky fragments.
	seeds := []string{
		"",
		"{",
		"}",
		"x {}",
		"x {\n}\n",
		"a.com, b.com {\n cache_key url host\n}\n",
		"@m path /a/* /b/*\n",
		"x {\n cache { ram 10GiB; disk /x 2TiB }\n}\n",
		"x {\n purge t {$TOK} {http.X}\n}\n",
		"x {\n header A \"a b c\"\n}\n",
		"x {\n a \\\n b\n}\n",
		"# comment only\n",
		"{ global }\nsite {\n}\n",
		"\"unterminated",
		"@",
		"@ \n",
		"{$",
		"{{{{{",
		"}}}}}",
		";;;;;",
		"{{ {",
		"x " + strings.Repeat("d {", 2000) + strings.Repeat("}", 2000),
		"x " + strings.Repeat("{", 200) + strings.Repeat("}", 200),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	// Also seed with the real testdata files if present.
	for _, name := range []string{"storefront.A-flat.cadish", "nocache.cadish"} {
		if b, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(b)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parsing must never panic. Errors are fine.
		file, err := Parse("fuzz", data)
		if err == nil && file != nil {
			// Env substitution must never panic on a valid AST.
			SubstituteEnv(file, func(string) (string, bool) { return "v", true })
		}

		// Formatting must never panic. If it succeeds, it must be idempotent.
		out, ferr := Format(data)
		if ferr == nil {
			out2, ferr2 := Format(out)
			if ferr2 != nil {
				t.Fatalf("re-Format of formatted output errored: %v\ninput: %q\nformatted: %q", ferr2, data, out)
			}
			if string(out) != string(out2) {
				t.Fatalf("Format not idempotent\ninput: %q\nonce: %q\ntwice: %q", data, out, out2)
			}
		}
	})
}
