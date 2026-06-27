package cadishfile

import (
	"reflect"
	"testing"
)

// zeroPositions recursively clears every Pos in a node list so two ASTs parsed at
// different source offsets (a fragment vs. the same lines inline in a site body)
// can be compared for structural identity.
func zeroPositions(nodes []Node) {
	for _, n := range nodes {
		switch d := n.(type) {
		case *Directive:
			d.Pos = Pos{}
			for i := range d.Args {
				d.Args[i].Pos = Pos{}
			}
			zeroPositions(d.Block)
		case *MatcherDef:
			d.Pos = Pos{}
			for i := range d.Args {
				d.Args[i].Pos = Pos{}
			}
		}
	}
}

// TestParseFragmentMatchesInlineSiteBody is the core regression for the
// import-flattens-braced-directives bug: a fragment containing a brace-bodied
// directive must parse to the SAME AST those lines produce inline in a site body,
// instead of being mis-read as a site header and flattened (each body line
// orphaned into a top-level statement).
func TestParseFragmentMatchesInlineSiteBody(t *testing.T) {
	cases := []struct {
		name string
		frag string
	}{
		{"classify", "@verified header X-V 1\nclassify {age} {\n  when @verified -> ok\n  default -> open\n}\ncache_key {age}\n"},
		{"upstream", "upstream web {\n  to http://127.0.0.1:8080\n  timeout connect 5s\n}\n"},
		{"tls", "tls {\n  acme ops@example.com\n}\n"},
		{"cache", "cache {\n  ram 10GiB\n  disk /var/cache/cadish 2TiB\n}\n"},
		{"geo", "geo {\n  source header CF-IPCountry\n  trust_proxy 10.0.0.0/8\n}\ncache_key {geo}\n"},
		{"device_detect", "device_detect {\n  mobile ua_contains Mobile Android\n  default desktop\n}\ncache_key {device}\n"},
		{"mixed-blocks", "@verified header X-V 1\ntls {\n  acme ops@example.com\n}\nupstream web {\n  to http://127.0.0.1:8080\n}\nclassify {age} {\n  when @verified -> ok\n  default -> open\n}\nheader X-Test hi\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fragNodes, err := ParseFragment("frag.cadish", []byte(tc.frag))
			if err != nil {
				t.Fatalf("ParseFragment: %v", err)
			}
			inline, err := Parse("inline.cadish", []byte("example.com {\n"+tc.frag+"\n}\n"))
			if err != nil {
				t.Fatalf("Parse inline: %v", err)
			}
			if len(inline.Sites) != 1 {
				t.Fatalf("inline: want 1 site, got %d", len(inline.Sites))
			}
			siteBody := inline.Sites[0].Body
			zeroPositions(fragNodes)
			zeroPositions(siteBody)
			if !reflect.DeepEqual(fragNodes, siteBody) {
				t.Errorf("fragment AST != inline site-body AST\nfragment: %#v\ninline:   %#v", fragNodes, siteBody)
			}
			// Sanity: the braced directive must have been kept as a single block node,
			// never flattened. Every top-level node is a Directive or MatcherDef and no
			// body keyword (when/default/to/ram/source/mobile) leaked to the top level.
			for _, n := range fragNodes {
				if d, ok := n.(*Directive); ok {
					switch d.Name {
					case "when", "default", "to", "ram", "disk", "source", "mobile", "acme":
						t.Errorf("body keyword %q leaked to top level (fragment was flattened)", d.Name)
					}
				}
			}
		})
	}
}

// TestParseFragmentUnclosedBlock: a fragment with an unterminated brace block is a
// positioned *ParseError, never a silent truncation or flatten.
func TestParseFragmentUnclosedBlock(t *testing.T) {
	_, err := ParseFragment("frag.cadish", []byte("classify {age} {\n  when @v -> ok\n"))
	if err == nil {
		t.Fatal("want error for unterminated block, got nil")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("err type = %T, want *ParseError", err)
	}
	if pe.File != "frag.cadish" || pe.Line == 0 {
		t.Errorf("error not positioned: %+v", pe)
	}
}

// TestParseFragmentStrayCloseBrace: a fragment whose braces are unbalanced from the
// top (a leading/extra '}') is a positioned error, not a silent stop.
func TestParseFragmentStrayCloseBrace(t *testing.T) {
	_, err := ParseFragment("frag.cadish", []byte("header X 1\n}\n"))
	if err == nil {
		t.Fatal("want error for stray '}', got nil")
	}
	if _, ok := err.(*ParseError); !ok {
		t.Fatalf("err type = %T, want *ParseError", err)
	}
}
