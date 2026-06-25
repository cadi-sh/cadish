package check

import "testing"

// `rewrite` is a known RECV directive; its `path` op contributes a regex eval.
func TestRewritePathCounted(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	rewrite path ^/old/(.*)$ /new/$1
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Fatalf("unknown-directive = %d, want 0 (rewrite is known)\n%s", n, render(t, r))
	}
	sr := r.Sites[0]
	if sr.RegexEvalsPerRequest < 1 {
		t.Fatalf("regex evals/request = %d, want >= 1 (rewrite path regex)", sr.RegexEvalsPerRequest)
	}
	if sr.PhaseCounts[PhaseRECV] < 1 {
		t.Fatalf("RECV phase count = %d, want >= 1", sr.PhaseCounts[PhaseRECV])
	}
}

// `rewrite strip_query`/`set_query` are known and add no regex eval.
func TestRewriteQueryOpsCounted(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	rewrite strip_query utm_*
	rewrite set_query publi 1
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Fatalf("unknown-directive = %d, want 0\n%s", n, render(t, r))
	}
}

// A matcher referenced only by a scoped `rewrite` must NOT be flagged unused
// (mirrors the `replace` regression).
func TestRewriteReferencesMatcher(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	@old path /legacy/*
	rewrite @old path ^/legacy/(.*)$ /v2/$1
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unused-matcher"] != 0 {
		t.Fatalf("unused-matcher = %d, want 0 (@old is used by rewrite)\n%s", c["unused-matcher"], render(t, r))
	}
	if c["undefined-matcher"] != 0 {
		t.Fatalf("undefined-matcher = %d, want 0\n%s", c["undefined-matcher"], render(t, r))
	}
}

// `cache_ttl from_header HEADER` is accepted by the lint catalog (ORIGIN phase) and
// not flagged.
func TestCacheTTLFromHeaderChecks(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	cache_ttl default from_header X-Cache-Ttl grace 1h
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Fatalf("unknown-directive = %d, want 0\n%s", n, render(t, r))
	}
	if r.Sites[0].PhaseCounts[PhaseORIGIN] < 1 {
		t.Fatalf("ORIGIN phase count = %d, want >= 1", r.Sites[0].PhaseCounts[PhaseORIGIN])
	}
}
