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

// TestEdgeViewKeyTokensQueryStrip checks the query_strip token projects its denylist.
func TestEdgeViewKeyTokensQueryStrip(t *testing.T) {
	p := compileSite(t, `example.com {
        cache_key method host path query_strip utm_* gclid
        cache_ttl default ttl 1m
    }`)
	toks := p.EdgeKeyTokens()
	var found bool
	for _, tk := range toks {
		if tk.Kind == "query_strip" {
			found = true
			if len(tk.Deny) != 2 {
				t.Errorf("query_strip deny = %v, want 2 names", tk.Deny)
			}
			if len(tk.Allow) != 0 {
				t.Errorf("query_strip must not carry an allowlist, got %v", tk.Allow)
			}
		}
	}
	if !found {
		t.Fatalf("no query_strip token projected, got %+v", toks)
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

// TestEdgeKindNameIP: edgeKindName(kindIP) returns "ip" — the SERVER-ONLY kind name in
// serverOnlyEdgeKinds. The projector (projectMatcher) marks an "ip" matcher ServerOnly and
// delegates / fails open every directive that references it, instead of skipping it and
// leaving a dangling scope reference the runtime silently mis-evaluates (R02).
func TestEdgeKindNameIP(t *testing.T) {
	if got := edgeKindName(kindIP); got != "ip" {
		t.Fatalf("edgeKindName(kindIP) = %q, want \"ip\" (the server-only kind)", got)
	}
}

// TestEdgeViewIPMatcherNoPanic: projecting an `ip` matcher to the edge view must NOT panic
// (an inline `pass ip 10.0.0.0/8` would otherwise crash `cadish edge build`, R02). It returns a
// fields-less `ip` view — no IP/CIDR data leaks to the worker; projectMatcher then marks it
// ServerOnly.
func TestEdgeViewIPMatcherNoPanic(t *testing.T) {
	m := &matcher{kind: kindIP}
	em := m.edgeView()
	if em.Kind != "ip" {
		t.Fatalf("edgeView(ip).Kind = %q, want \"ip\"", em.Kind)
	}
}

// TestEdgeMatchersProjectsIPServerOnly: a NAMED `ip` matcher IS projected (as kind "ip") so the
// projector can see it and treat any directive scoping it as fail-closed — it is no longer
// silently dropped (R02). The ip/cidr values are NOT carried (the edge has no client-IP concept).
func TestEdgeMatchersProjectsIPServerOnly(t *testing.T) {
	p := compileSite(t, `example.com {
        @office ip 203.0.113.43/32
        @ru geo country RU
        allow @office
        deny @ru
        cache_ttl default ttl 1m
    }`)
	em, ok := p.EdgeMatchers()["office"]
	if !ok {
		t.Fatal("@office ip matcher must be projected (as a server-only `ip` view) so an ip-scoped directive fails closed")
	}
	if em.Kind != "ip" {
		t.Errorf("@office projected with kind=%q, want \"ip\"", em.Kind)
	}
	if len(em.Patterns) != 0 || em.Regex != "" {
		t.Errorf("an `ip` edge view must carry no IP/CIDR data, got %+v", em)
	}
}
