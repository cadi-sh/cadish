package cadishfile

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse("test.cadish", []byte(src))
	if err != nil {
		t.Fatalf("Parse(%q) unexpected error: %v", src, err)
	}
	return f
}

func TestParseSiteBasic(t *testing.T) {
	f := mustParse(t, `example.com {
    cache_key url host
}
`)
	if len(f.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(f.Sites))
	}
	s := f.Sites[0]
	if len(s.Addresses) != 1 || s.Addresses[0] != "example.com" {
		t.Errorf("addresses = %v, want [example.com]", s.Addresses)
	}
	if len(s.Body) != 1 {
		t.Fatalf("body = %d, want 1", len(s.Body))
	}
	d, ok := s.Body[0].(*Directive)
	if !ok {
		t.Fatalf("body[0] type = %T, want *Directive", s.Body[0])
	}
	if d.Name != "cache_key" {
		t.Errorf("directive name = %q, want cache_key", d.Name)
	}
	if len(d.Args) != 2 || d.Args[0].Raw != "url" || d.Args[1].Raw != "host" {
		t.Errorf("args = %v, want [url host]", d.Args)
	}
}

func TestParseMultipleAddresses(t *testing.T) {
	f := mustParse(t, "a.com, *.a.com {\n}\n")
	s := f.Sites[0]
	want := []string{"a.com", "*.a.com"}
	if len(s.Addresses) != len(want) {
		t.Fatalf("addresses = %v, want %v", s.Addresses, want)
	}
	for i := range want {
		if s.Addresses[i] != want[i] {
			t.Errorf("address %d = %q, want %q", i, s.Addresses[i], want[i])
		}
	}
}

func TestParseMatcherDef(t *testing.T) {
	f := mustParse(t, `x {
    @nocache path /a/* /b/*
    @ajax header X-Requested-With XMLHttpRequest
    @static host_regex ^static
}
`)
	s := f.Sites[0]
	if len(s.Body) != 3 {
		t.Fatalf("body = %d, want 3", len(s.Body))
	}
	m0 := s.Body[0].(*MatcherDef)
	if m0.Name != "nocache" || m0.Type != "path" {
		t.Errorf("m0 = @%s %s, want @nocache path", m0.Name, m0.Type)
	}
	if len(m0.Args) != 2 || m0.Args[0].Raw != "/a/*" || m0.Args[1].Raw != "/b/*" {
		t.Errorf("m0 args = %v", m0.Args)
	}
	m1 := s.Body[1].(*MatcherDef)
	if m1.Name != "ajax" || m1.Type != "header" || len(m1.Args) != 2 {
		t.Errorf("m1 = @%s %s args=%v", m1.Name, m1.Type, m1.Args)
	}
	m2 := s.Body[2].(*MatcherDef)
	if m2.Name != "static" || m2.Type != "host_regex" {
		t.Errorf("m2 = @%s %s", m2.Name, m2.Type)
	}
}

func TestParseNestedBlocks(t *testing.T) {
	f := mustParse(t, `x {
    tls {
        acme me@example.com
    }
    upstream web {
        to https://x
        sticky by cookie PHPSESSID else client_ip
    }
}
`)
	s := f.Sites[0]
	tls := s.Body[0].(*Directive)
	if tls.Name != "tls" || !tls.HasBlock {
		t.Fatalf("tls = %+v", tls)
	}
	if len(tls.Block) != 1 {
		t.Fatalf("tls block = %d, want 1", len(tls.Block))
	}
	acme := tls.Block[0].(*Directive)
	if acme.Name != "acme" || len(acme.Args) != 1 || acme.Args[0].Raw != "me@example.com" {
		t.Errorf("acme = %+v", acme)
	}
	up := s.Body[1].(*Directive)
	if up.Name != "upstream" || len(up.Args) != 1 || up.Args[0].Raw != "web" {
		t.Errorf("upstream args = %v", up.Args)
	}
	if len(up.Block) != 2 {
		t.Errorf("upstream block = %d, want 2", len(up.Block))
	}
}

func TestParseArgKinds(t *testing.T) {
	f := mustParse(t, `x {
    route @static images
    purge token {$PURGE_TOKEN} {http.X-Foo} plain "quoted @notref"
}
`)
	s := f.Sites[0]
	route := s.Body[0].(*Directive)
	if route.Args[0].Kind != ArgMatcherRef {
		t.Errorf("@static kind = %v, want matcher-ref", route.Args[0].Kind)
	}
	if route.Args[1].Kind != ArgLiteral {
		t.Errorf("images kind = %v, want literal", route.Args[1].Kind)
	}
	purge := s.Body[1].(*Directive)
	kinds := map[string]ArgKind{
		"{$PURGE_TOKEN}": ArgPlaceholder,
		"{http.X-Foo}":   ArgPlaceholder,
		"plain":          ArgLiteral,
		"quoted @notref": ArgLiteral, // quoted, so not a matcher ref
	}
	for _, a := range purge.Args {
		if want, ok := kinds[a.Raw]; ok && a.Kind != want {
			t.Errorf("arg %q kind = %v, want %v", a.Raw, a.Kind, want)
		}
	}
}

func TestParseSemicolonSeparator(t *testing.T) {
	f := mustParse(t, "x {\n cache { ram 10GiB; disk /x 2TiB }\n}\n")
	cache := f.Sites[0].Body[0].(*Directive)
	if len(cache.Block) != 2 {
		t.Fatalf("cache block = %d, want 2 (ram, disk)", len(cache.Block))
	}
	if cache.Block[0].(*Directive).Name != "ram" {
		t.Errorf("block[0] = %q, want ram", cache.Block[0].(*Directive).Name)
	}
	if cache.Block[1].(*Directive).Name != "disk" {
		t.Errorf("block[1] = %q, want disk", cache.Block[1].(*Directive).Name)
	}
}

func TestParseTopLevelFragment(t *testing.T) {
	// A sub-config (importable fragment) has no site wrapper.
	f := mustParse(t, "@nocache path /a/*\n@ajax header X Y\n")
	if len(f.Sites) != 0 {
		t.Errorf("sites = %d, want 0", len(f.Sites))
	}
	if len(f.Body) != 2 {
		t.Fatalf("body = %d, want 2", len(f.Body))
	}
	if f.Body[0].(*MatcherDef).Name != "nocache" {
		t.Errorf("body[0] = %v", f.Body[0])
	}
}

func TestParseGlobalOptions(t *testing.T) {
	f := mustParse(t, "{\n    debug on\n}\nexample.com {\n}\n")
	if f.Global == nil {
		t.Fatal("expected a global options block")
	}
	if len(f.Global.Body) != 1 {
		t.Errorf("global body = %d, want 1", len(f.Global.Body))
	}
	if len(f.Sites) != 1 {
		t.Errorf("sites = %d, want 1", len(f.Sites))
	}
}

func TestParseEmptyBlock(t *testing.T) {
	f := mustParse(t, "x {\n}\n")
	s := f.Sites[0]
	if s.Body == nil {
		t.Error("empty site body should be non-nil empty slice")
	}
	if len(s.Body) != 0 {
		t.Errorf("body = %d, want 0", len(s.Body))
	}
}

func TestParseDirectiveEmptyBlockVsNoBlock(t *testing.T) {
	f := mustParse(t, "x {\n a\n b { }\n}\n")
	s := f.Sites[0]
	a := s.Body[0].(*Directive)
	if a.HasBlock {
		t.Error("directive 'a' should have no block")
	}
	b := s.Body[1].(*Directive)
	if !b.HasBlock {
		t.Error("directive 'b' should have an (empty) block")
	}
	if b.Block == nil || len(b.Block) != 0 {
		t.Errorf("directive 'b' block = %v, want non-nil empty", b.Block)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantSub string
		line    int
		col     int
	}{
		{
			name:    "unexpected close brace at top level",
			src:     "}\n",
			wantSub: "unexpected '}'",
			line:    1, col: 1,
		},
		{
			name:    "unterminated block",
			src:     "x {\n cache_key url\n",
			wantSub: "unterminated block",
		},
		{
			name:    "site without address",
			src:     "{\n}\nexample.com {\n}\n",
			wantSub: "", // first {} is parsed as global options; no error
		},
		{
			name:    "matcher without type",
			src:     "x {\n @foo\n}\n",
			wantSub: "missing a type",
		},
		{
			name:    "unterminated string",
			src:     "x {\n header A \"oops\n}\n",
			wantSub: "unterminated quoted string",
		},
		{
			name:    "empty matcher name",
			src:     "x {\n @ path /a\n}\n",
			wantSub: "matcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse("f.cadish", []byte(tt.src))
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if tt.line != 0 && pe.Line != tt.line {
				t.Errorf("error line = %d, want %d (%v)", pe.Line, tt.line, pe)
			}
			if tt.col != 0 && pe.Col != tt.col {
				t.Errorf("error col = %d, want %d (%v)", pe.Col, tt.col, pe)
			}
		})
	}
}

func TestParseErrorFormat(t *testing.T) {
	_, err := Parse("conf.cadish", []byte("}\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	if !strings.HasPrefix(got, "conf.cadish:1:1: ") {
		t.Errorf("error = %q, want prefix conf.cadish:1:1: ", got)
	}
}

func TestParsePositions(t *testing.T) {
	f := mustParse(t, "example.com {\n    cache_key url\n}\n")
	s := f.Sites[0]
	if s.Pos.Line != 1 || s.Pos.Col != 1 {
		t.Errorf("site pos = %v, want 1:1", s.Pos)
	}
	d := s.Body[0].(*Directive)
	if d.Pos.Line != 2 || d.Pos.Col != 5 {
		t.Errorf("directive pos = %v, want 2:5", d.Pos)
	}
}

func TestSubstituteEnv(t *testing.T) {
	f := mustParse(t, "x {\n purge token {$TOK} {device}\n}\n")
	env := map[string]string{"TOK": "secret123"}
	SubstituteEnv(f, func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	})
	d := f.Sites[0].Body[0].(*Directive)
	if d.Args[1].Raw != "secret123" {
		t.Errorf("env arg = %q, want secret123", d.Args[1].Raw)
	}
	if d.Args[1].Kind != ArgLiteral {
		t.Errorf("after substitution kind = %v, want literal", d.Args[1].Kind)
	}
	// generic placeholder untouched
	if d.Args[2].Raw != "{device}" {
		t.Errorf("generic placeholder = %q, want {device}", d.Args[2].Raw)
	}
	if d.Args[2].Kind != ArgPlaceholder {
		t.Errorf("generic placeholder kind = %v, want placeholder", d.Args[2].Kind)
	}
}

func TestSubstituteEnvUnset(t *testing.T) {
	f := mustParse(t, "x {\n a {$MISSING}b\n}\n")
	SubstituteEnv(f, func(string) (string, bool) { return "", false })
	d := f.Sites[0].Body[0].(*Directive)
	if d.Args[0].Raw != "b" {
		t.Errorf("unset env -> %q, want b", d.Args[0].Raw)
	}
}

// TestSubstituteEnvDefault covers Caddy-style "{$VAR:default}" env defaults: the
// span after the first ':' is used when the variable is unset, and ignored when it
// is set. Plain "{$VAR}" (no ':') is unchanged.
func TestSubstituteEnvDefault(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		set  map[string]string
		want string
	}{
		{"set-ignores-default", "{$PORT:8080}", map[string]string{"PORT": "9000"}, "9000"},
		{"unset-uses-default", "{$PORT:8080}", nil, "8080"},
		{"unset-no-default", "{$PORT}", nil, ""},
		{"empty-default", "{$PORT:}", nil, ""},
		{"set-empty-string-uses-value", "{$PORT:8080}", map[string]string{"PORT": ""}, ""},
		{"url-default", "http://localhost:{$PORT:8080}", nil, "http://localhost:8080"},
		{"default-with-colon", "{$ADDR:http://localhost:8080}", nil, "http://localhost:8080"},
		{"plain-set", "{$TOK}", map[string]string{"TOK": "secret"}, "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandEnv(tc.raw, func(name string) (string, bool) {
				v, ok := tc.set[name]
				return v, ok
			})
			if got != tc.want {
				t.Errorf("expandEnv(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestDirectiveRegistry(t *testing.T) {
	r := NewDefaultDirectiveRegistry()
	for _, name := range []string{"tls", "cache", "upstream", "cache_ttl"} {
		if !r.Has(name) {
			t.Errorf("expected %q to be known", name)
		}
	}
	if r.Has("frobnicate") {
		t.Error("frobnicate should be unknown")
	}
	r.Add("frobnicate")
	if !r.Has("frobnicate") {
		t.Error("frobnicate should be known after Add")
	}
	if len(r.Names()) == 0 {
		t.Error("Names() should be non-empty")
	}
}
