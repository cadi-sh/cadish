package cadishfile

import "testing"

// TestQuoteArgRendersSafeTokens checks the canonical quoter used for generated
// Cadishfile text: every produced token must (a) match the literal when the input is a
// plain bare word, and (b) round-trip back to the EXACT original string as a single word
// token when embedded into a directive — including the block-structural braces that
// needsQuoting deliberately ignores.
func TestQuoteArgRendersSafeTokens(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/api", "/api"},
		{"plain", "plain"},
		{"GET", "GET"},
		{"X-Foo", "X-Foo"},
		{"", `""`},
		{"a b", `"a b"`},
		{"}", `"}"`},
		{"{", `"{"`},
		{"a}b", `"a}b"`},
		{"/a}", `"/a}"`},
		{"#x", `"#x"`},
		{"a;b", `"a;b"`},
		{"a\\", `"a\\"`},
	}
	for _, c := range cases {
		if got := QuoteArg(c.in); got != c.want {
			t.Errorf("QuoteArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestQuoteArgRoundTrips proves a QuoteArg token, embedded into a directive inside a
// site, parses back to a single word whose text is byte-for-byte the original — i.e. a
// hostile value can neither split into extra tokens nor close/open a block.
func TestQuoteArgRoundTrips(t *testing.T) {
	inputs := []string{
		"/api", "}", "{", "a}b", "/a}", "#x", "a b", "a;b", "a\\", "x\nevil.com {",
		"evil.com {", "}\nfoo.com {", `quote"inside`,
	}
	for _, in := range inputs {
		src := "h {\n\tdir " + QuoteArg(in) + "\n}\n"
		f, err := Parse("<test>", []byte(src))
		if err != nil {
			t.Errorf("QuoteArg(%q) produced un-parseable text %q: %v", in, src, err)
			continue
		}
		if len(f.Sites) != 1 {
			t.Errorf("QuoteArg(%q): broke out of its site — got %d sites from %q", in, len(f.Sites), src)
			continue
		}
		body := f.Sites[0].Body
		if len(body) != 1 {
			t.Errorf("QuoteArg(%q): expected exactly one directive, got %d (%q)", in, len(body), src)
			continue
		}
		d, ok := body[0].(*Directive)
		if !ok {
			t.Errorf("QuoteArg(%q): body[0] is not a directive (%q)", in, src)
			continue
		}
		if len(d.Args) != 1 || d.Args[0].Raw != in {
			t.Errorf("QuoteArg(%q): args = %#v, want single arg %q", in, d.Args, in)
		}
	}
}

// TestContainsEnvPlaceholder pins the canonical generated-token env guard: it detects an
// UNESCAPED "{$" span (the SubstituteEnv trigger, including R07's quoted-literal
// expansion) so generation code can reject a tenant token that would otherwise leak the
// controller pod's environment — while leaving legitimate generated values (a regex
// quantifier "{n,m}", a runtime placeholder "{device}", a backslash-escaped "\{$VAR}")
// untouched.
func TestContainsEnvPlaceholder(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"{$SECRET}", true},
		{"{$ADMIN_TOKEN:default}", true},
		{"/api/{$VAR}/x", true},
		{"x{$Y}", true},
		{"/api", false},
		{"/x{1,3}", false},  // regex quantifier: '{' + digit, NOT '{$'
		{"{device}", false}, // runtime placeholder, not env
		{"{http.X-Foo}", false},
		{`\{$VAR}`, false}, // backslash-escaped: not an active placeholder
		{"GET", false},
		{"", false},
	}
	for _, c := range cases {
		if got := ContainsEnvPlaceholder(c.in); got != c.want {
			t.Errorf("ContainsEnvPlaceholder(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestSubstituteEnvExpandsQuotedEnvSpan documents WHY the generated-token guard exists: a
// quoted literal carrying "{$VAR}" — exactly what QuoteArg emits for a tenant value like
// `{$SECRET}` — IS expanded against the environment at SubstituteEnv time (R07). So a
// generated token must be rejected upstream by ContainsEnvPlaceholder; QuoteArg alone does
// NOT neutralize it.
func TestSubstituteEnvExpandsQuotedEnvSpan(t *testing.T) {
	src := "s {\n h A " + QuoteArg("{$SECRET}") + "\n}\n"
	f, err := Parse("p", []byte(src))
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	SubstituteEnv(f, func(n string) (string, bool) {
		if n == "SECRET" {
			return "LEAKED", true
		}
		return "", false
	})
	got := f.Sites[0].Body[0].(*Directive).Args[1].Raw
	if got != "LEAKED" {
		t.Fatalf("quoted {$SECRET} arg = %q, want %q (proves the guard is required)", got, "LEAKED")
	}
}
