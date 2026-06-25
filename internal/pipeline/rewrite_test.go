package pipeline

import (
	"net/url"
	"testing"
)

func evalReq(t *testing.T, p *Pipeline, path, rawQuery string) RequestDecision {
	t.Helper()
	var q url.Values
	if rawQuery != "" {
		parsed, err := url.ParseQuery(rawQuery)
		if err != nil {
			t.Fatalf("bad query %q: %v", rawQuery, err)
		}
		q = parsed
	}
	return p.EvalRequest(&Request{Method: "GET", Host: "x", Path: path, Query: q})
}

// rewrite path: a regex replace on the origin path (HAProxy replace-path style).
func TestRewritePathReplace(t *testing.T) {
	p := compileSrc(t, `x {
		rewrite path ^/old/(.*)$ /new/$1
	}
`)
	dec := evalReq(t, p, "/old/page", "")
	if dec.Rewrite == nil || dec.Rewrite.Path != "/new/page" {
		t.Fatalf("rewrite path = %+v, want /new/page", dec.Rewrite)
	}
	// Non-matching path -> no rewrite.
	if dec := evalReq(t, p, "/keep", ""); dec.Rewrite != nil {
		t.Fatalf("non-matching path should not rewrite, got %+v", dec.Rewrite)
	}
}

// rewrite strip_query: drop utm_* before forwarding; keep the rest.
func TestRewriteStripQuery(t *testing.T) {
	p := compileSrc(t, `x {
		rewrite strip_query utm_*
	}
`)
	dec := evalReq(t, p, "/p", "genre=rock&utm_source=fb&utm_medium=cpc")
	if dec.Rewrite == nil {
		t.Fatal("want a rewrite")
	}
	if dec.Rewrite.RawQuery != "genre=rock" {
		t.Errorf("stripped query = %q, want genre=rock", dec.Rewrite.RawQuery)
	}
	if dec.Rewrite.Path != "/p" {
		t.Errorf("path changed unexpectedly: %q", dec.Rewrite.Path)
	}
}

// rewrite set_query: add/reconstruct a param (the SSR publi-param case).
func TestRewriteSetQuery(t *testing.T) {
	p := compileSrc(t, `x {
		rewrite set_query publi 1
	}
`)
	dec := evalReq(t, p, "/p", "genre=rock")
	if dec.Rewrite == nil {
		t.Fatal("want a rewrite")
	}
	if dec.Rewrite.RawQuery != "genre=rock&publi=1" {
		t.Errorf("set_query = %q, want genre=rock&publi=1", dec.Rewrite.RawQuery)
	}
	// set_query overrides an existing value.
	dec2 := evalReq(t, p, "/p", "publi=0")
	if dec2.Rewrite.RawQuery != "publi=1" {
		t.Errorf("set_query override = %q, want publi=1", dec2.Rewrite.RawQuery)
	}
}

// Multiple rewrite rules compose in order (strip then set, plus a path replace).
func TestRewriteCompose(t *testing.T) {
	p := compileSrc(t, `x {
		rewrite path ^/old(.*)$ /new$1
		rewrite strip_query utm_*
		rewrite set_query publi 1
	}
`)
	dec := evalReq(t, p, "/old/x", "genre=rock&utm_source=fb")
	if dec.Rewrite.Path != "/new/x" {
		t.Errorf("path = %q, want /new/x", dec.Rewrite.Path)
	}
	if dec.Rewrite.RawQuery != "genre=rock&publi=1" {
		t.Errorf("query = %q, want genre=rock&publi=1", dec.Rewrite.RawQuery)
	}
}

// CRITICAL: a rewrite must NOT change the cache key. Two requests differing only in
// a rewritten-away param share one cache key (computed from the client URL).
func TestRewriteDoesNotChangeCacheKey(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path query_allow genre
		rewrite strip_query utm_*
	}
`)
	a := evalReq(t, p, "/p", "genre=rock&utm_source=fb")
	b := evalReq(t, p, "/p", "genre=rock&utm_source=tw")
	if a.CacheKey != b.CacheKey {
		t.Fatalf("cache keys differ despite differing only in stripped utm: %q vs %q", a.CacheKey, b.CacheKey)
	}
	// And the key reflects the CLIENT request (genre kept), not the rewrite.
	want := evalReq(t, p, "/p", "genre=rock").CacheKey
	if a.CacheKey != want {
		t.Fatalf("cache key = %q, want client-URL key %q", a.CacheKey, want)
	}
}

// A set_query rewrite that adds a param the cache key would otherwise include must
// still not poison the key (key stays on the client URL).
func TestRewriteSetQueryDoesNotPoisonKey(t *testing.T) {
	p := compileSrc(t, `x {
		cache_key path query
		rewrite set_query publi 1
	}
`)
	withPubli := evalReq(t, p, "/p", "genre=rock")
	plain := evalReq(t, p, "/p", "genre=rock")
	if withPubli.CacheKey != plain.CacheKey {
		t.Fatalf("set_query poisoned the key: %q", withPubli.CacheKey)
	}
	// The origin, however, receives publi=1.
	if withPubli.Rewrite == nil || withPubli.Rewrite.RawQuery != "genre=rock&publi=1" {
		t.Fatalf("origin query = %+v, want genre=rock&publi=1", withPubli.Rewrite)
	}
}

// A conditional (@scope) rewrite only fires when the scope matches.
func TestRewriteScoped(t *testing.T) {
	p := compileSrc(t, `x {
		@old path /legacy/*
		rewrite @old path ^/legacy/(.*)$ /v2/$1
	}
`)
	if dec := evalReq(t, p, "/legacy/a", ""); dec.Rewrite == nil || dec.Rewrite.Path != "/v2/a" {
		t.Fatalf("scoped rewrite should fire: %+v", dec.Rewrite)
	}
	if dec := evalReq(t, p, "/other", ""); dec.Rewrite != nil {
		t.Fatalf("scoped rewrite should not fire off-scope: %+v", dec.Rewrite)
	}
}

// No rewrite rules -> nil decision (zero work on the common path).
func TestRewriteAbsent(t *testing.T) {
	p := compileSrc(t, "x {\n cache_ttl default ttl 1m\n}\n")
	if dec := evalReq(t, p, "/p", "a=1"); dec.Rewrite != nil {
		t.Fatalf("want nil Rewrite when no rule, got %+v", dec.Rewrite)
	}
}

func TestRewriteCompileErrors(t *testing.T) {
	for _, src := range []string{
		"x {\n rewrite\n}\n",
		"x {\n rewrite path ^/a$\n}\n",       // missing replacement
		"x {\n rewrite strip_query\n}\n",     // no names
		"x {\n rewrite set_query publi\n}\n", // missing value
		"x {\n rewrite bogus a b\n}\n",       // unknown op
		"x {\n rewrite path [ /x\n}\n",       // invalid regex
	} {
		if ce := compileErr(t, src); ce == nil {
			t.Errorf("want compile error for %q", src)
		}
	}
}
