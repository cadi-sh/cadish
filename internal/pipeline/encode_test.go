package pipeline

import (
	"net/http"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func compileEncodeSite(t *testing.T, src string) (*Pipeline, error) {
	t.Helper()
	f, err := cadishfile.Parse("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Compile(f.Sites[0])
}

// TestEncodeDefaults checks a bare `encode` yields the default codec order, the
// text-like include list, and the 1024-byte floor, surfaced on EvalDeliver.
func TestEncodeDefaults(t *testing.T) {
	p, err := compileEncodeSite(t, `example.com {
		upstream b { to http://x:80 }
		encode
		cache_ttl default ttl 5m
	}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dd := p.EvalDeliver(&Request{Path: "/"}, http.Header{"Content-Type": {"text/html"}}, CacheStatusMiss)
	if dd.Encode == nil {
		t.Fatal("EvalDeliver did not surface an EncodeDecision")
	}
	wantCodecs := []string{"zstd", "br", "gzip"}
	if got := dd.Encode.Codecs; len(got) != 3 || got[0] != wantCodecs[0] || got[1] != wantCodecs[1] || got[2] != wantCodecs[2] {
		t.Errorf("Codecs = %v, want %v", got, wantCodecs)
	}
	if dd.Encode.MinLength != 1024 {
		t.Errorf("MinLength = %d, want 1024", dd.Encode.MinLength)
	}
	if len(dd.Encode.Types) == 0 {
		t.Error("Types is empty, want the default text-like list")
	}
}

// TestEncodeSubset checks an explicit codec subset is honored in order.
func TestEncodeSubset(t *testing.T) {
	p, err := compileEncodeSite(t, `example.com {
		upstream b { to http://x:80 }
		encode gzip br
	}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dd := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if dd.Encode == nil {
		t.Fatal("no EncodeDecision")
	}
	if got := dd.Encode.Codecs; len(got) != 2 || got[0] != "gzip" || got[1] != "br" {
		t.Errorf("Codecs = %v, want [gzip br]", got)
	}
}

// TestEncodeBrotliAlias checks `brotli` is accepted as an alias for `br`.
func TestEncodeBrotliAlias(t *testing.T) {
	p, err := compileEncodeSite(t, `example.com {
		upstream b { to http://x:80 }
		encode brotli
	}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dd := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if dd.Encode == nil || len(dd.Encode.Codecs) != 1 || dd.Encode.Codecs[0] != "br" {
		t.Fatalf("brotli alias not normalized to br: %+v", dd.Encode)
	}
}

func TestEncodeNoneWhenAbsent(t *testing.T) {
	p, err := compileEncodeSite(t, `example.com {
		upstream b { to http://x:80 }
		cache_ttl default ttl 5m
	}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dd := p.EvalDeliver(&Request{Path: "/"}, nil, CacheStatusMiss)
	if dd.Encode != nil {
		t.Fatalf("EncodeDecision surfaced without an encode directive: %+v", dd.Encode)
	}
}

func TestEncodeCompileErrors(t *testing.T) {
	cases := []struct{ name, src string }{
		{"unknown codec", `e.com {
			encode deflate
		}`},
		{"duplicate codec", `e.com {
			encode gzip gzip
		}`},
		{"two encode directives", `e.com {
			encode gzip
			encode br
		}`},
		{"block form rejected", `e.com {
			encode { types text/* }
		}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := compileEncodeSite(t, c.src); err == nil {
				t.Fatalf("expected a compile error for %q", c.name)
			}
		})
	}
}
