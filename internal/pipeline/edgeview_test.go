package pipeline

import (
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func compileSite(t *testing.T, src string) *Pipeline {
	t.Helper()
	f, err := cadishfile.Parse("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := Compile(f.Sites[0])
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// TestEdgeViewMatcherPatterns checks the read-only edge view reconstructs the
// original path/host matcher pattern strings from the factored compiled sets.
func TestEdgeViewMatcherPatterns(t *testing.T) {
	p := compileSite(t, `example.com {
        @paths host example.com
        @globs path /a/* *.css /exact *mid*end
        cache_ttl default ttl 1m
    }`)
	ms := p.EdgeMatchers()

	host := ms["paths"]
	if host.Kind != "host" || strings.Join(host.Patterns, ",") != "example.com" {
		t.Errorf("host matcher = %+v", host)
	}

	globs := ms["globs"]
	if globs.Kind != "path" {
		t.Fatalf("globs kind = %q", globs.Kind)
	}
	want := map[string]bool{"/a/*": true, "*.css": true, "/exact": true, "*mid*end": true}
	for _, pat := range globs.Patterns {
		if !want[pat] {
			t.Errorf("unexpected reconstructed pattern %q (have %v)", pat, globs.Patterns)
		}
		delete(want, pat)
	}
	if len(want) != 0 {
		t.Errorf("missing reconstructed patterns: %v", want)
	}
}

// TestEdgeViewHostWildcard checks `*.suffix` host patterns round-trip.
func TestEdgeViewHostWildcard(t *testing.T) {
	p := compileSite(t, `example.com {
        @h host *.example.com api.example.com
        cache_ttl default ttl 1m
    }`)
	h := p.EdgeMatchers()["h"]
	joined := strings.Join(h.Patterns, ",")
	if !strings.Contains(joined, "*.example.com") || !strings.Contains(joined, "api.example.com") {
		t.Errorf("host patterns = %v", h.Patterns)
	}
}

// TestEdgeViewKeyTokens checks the key-token projection names.
func TestEdgeViewKeyTokens(t *testing.T) {
	p := compileSite(t, `example.com {
        cache_key method host path query_allow a b* header:X-Foo {sticky}
        cache_ttl default ttl 1m
    }`)
	toks := p.EdgeKeyTokens()
	var kinds []string
	for _, tk := range toks {
		kinds = append(kinds, tk.Kind)
	}
	got := strings.Join(kinds, ",")
	if got != "method,host,path,query_allow,header,sticky" {
		t.Errorf("key kinds = %q", got)
	}
	// header token carries its name in Arg; query_allow carries the allowlist.
	for _, tk := range toks {
		if tk.Kind == "header" && tk.Arg != "X-Foo" {
			t.Errorf("header arg = %q, want X-Foo", tk.Arg)
		}
		if tk.Kind == "query_allow" && len(tk.Allow) != 2 {
			t.Errorf("query_allow allow = %v, want 2 names", tk.Allow)
		}
	}
}

// TestEdgeViewDefaultKey confirms the default method/host/path key surfaces when no
// cache_key is declared.
func TestEdgeViewDefaultKey(t *testing.T) {
	p := compileSite(t, `example.com {
        cache_ttl default ttl 1m
    }`)
	toks := p.EdgeKeyTokens()
	if len(toks) != 3 || toks[0].Kind != "method" || toks[2].Kind != "path" {
		t.Errorf("default key = %+v", toks)
	}
}

// TestEdgeViewTTLFromHeader: a `cache_ttl … from_header HEADER` rule surfaces the
// header name in the edge IR view (the worker reads the origin response header).
func TestEdgeViewTTLFromHeader(t *testing.T) {
	p := compileSite(t, `example.com {
        cache_ttl default from_header X-Cache-Ttl grace 1h
    }`)
	rules := p.EdgeTTLRules()
	if len(rules) != 1 {
		t.Fatalf("ttl rules = %d, want 1", len(rules))
	}
	if rules[0].FromHeader != "X-Cache-Ttl" {
		t.Errorf("FromHeader = %q, want X-Cache-Ttl", rules[0].FromHeader)
	}
	if rules[0].Grace == 0 {
		t.Errorf("grace not projected: %+v", rules[0])
	}
}

// TestEdgeKindNameIPGuard: edgeKindName(kindIP) returns an explicit server-only
// sentinel (NOT "unknown"), so a future caller that leaks an `ip` matcher toward
// the edge IR is caught loudly rather than projecting as an "unknown" kind.
func TestEdgeKindNameIPGuard(t *testing.T) {
	if got := edgeKindName(kindIP); got == "unknown" || got == "ip" {
		t.Fatalf("edgeKindName(kindIP) = %q, want an explicit server-only sentinel", got)
	}
}

// TestEdgeViewIPMatcherPanics: projecting an `ip` matcher to the edge view must
// fail closed (panic) — security is server-only (D49). EdgeMatchers() skips kindIP
// before reaching edgeView(), so this guards against a future caller bypassing it.
func TestEdgeViewIPMatcherPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("edgeView() on a kindIP matcher did not panic (security must never reach the edge IR)")
		}
	}()
	m := &matcher{kind: kindIP}
	_ = m.edgeView()
}

// TestEdgeMatchersStillSkipsIP: the public projection path never yields an `ip`
// (or "unknown") matcher even when the site declares one in the security gate.
func TestEdgeMatchersStillSkipsIP(t *testing.T) {
	p := compileSite(t, `example.com {
        @office ip 203.0.113.43/32
        @ru geo country RU
        allow @office
        deny @ru
        cache_ttl default ttl 1m
    }`)
	for name, em := range p.EdgeMatchers() {
		if em.Kind == "ip" || em.Kind == "unknown" || em.Kind == "server-only-ip" {
			t.Errorf("matcher %q leaked to edge IR (kind=%q)", name, em.Kind)
		}
	}
	if _, ok := p.EdgeMatchers()["office"]; ok {
		t.Error("@office ip matcher must not be projected to the edge IR")
	}
}
