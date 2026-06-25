package vcladapt

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzAdapt exercises the VCL lexer, parser, and skeleton builder with arbitrary
// input. adapt is best-effort and explicitly never errors, so the sole invariant
// under test is robustness: Adapt must never panic regardless of input —
// truncated long-strings, unbalanced braces, lone operators, deeply nested
// blocks, etc. — and must always return a non-nil Result.
func FuzzAdapt(f *testing.F) {
	seeds := []string{
		"",
		"{",
		"}",
		"{{{{{{{{",
		"}}}}}}}}",
		"\"unterminated",
		"{\" unterminated long string",
		"sub vcl_recv {",
		"sub vcl_recv { return (pass); }",
		"backend default { .host = \"127.0.0.1\"; .port = \"80\"; }",
		"backend",
		"backend {",
		"backend x { .host =",
		"if (req.url ~ \"^/api\") { return (pass); }",
		"set req.http.X = \"v\";",
		"unset req.http.X;",
		"acl purge { \"127.0.0.1\"; }",
		"// comment\n/* block */\n# hash\n",
		"-> == != !~ >= <= && || .",
		"123abc 60s 1h .5",
		"sub s { sub s { sub s { sub s {",
		// Deeply nested if/else inside a sub: the parseBlock recursion path the
		// depth cap (maxParseDepth, Fix 3) guards against a stack-overflow fatal.
		"sub vcl_recv { if(x){if(x){if(x){if(x){if(x){return(pass);}}}}} }",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	if b, err := os.ReadFile(filepath.Join("testdata", "sample.vcl")); err == nil {
		f.Add(string(b))
	}

	f.Fuzz(func(t *testing.T, src string) {
		res := Adapt("fuzz.vcl", src)
		if res == nil {
			t.Fatalf("Adapt returned nil Result for input %q", src)
		}
		// Re-adapting the generated skeleton must also not panic (it is itself
		// text that could be fed back in).
		_ = Adapt("fuzz2.vcl", res.Cadishfile)
	})
}
