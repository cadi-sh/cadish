package check

import "testing"

// A `redirect PATH_REGEX CODE TARGET` directive must be a known RECV directive and
// contribute one regex eval/request (the leading path regex), not be flagged
// unknown.
func TestRedirectRegexCounted(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	redirect (?i)^/es(/.*)?$ 301 https://{host}/espanol$1
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Fatalf("unknown-directive warnings = %d, want 0 (redirect is known)\n%s", n, render(t, r))
	}
	if len(r.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(r.Sites))
	}
	sr := r.Sites[0]
	if sr.RegexEvalsPerRequest < 1 {
		t.Fatalf("regex evals/request = %d, want >= 1 (redirect path regex)", sr.RegexEvalsPerRequest)
	}
	if sr.PhaseCounts[PhaseRECV] < 1 {
		t.Fatalf("RECV phase count = %d, want >= 1", sr.PhaseCounts[PhaseRECV])
	}
}

// The `redirect CODE map { … }` form is also a known directive and counts a regex
// eval.
func TestRedirectMapCounted(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	redirect 301 map {
		/registro -> /register
	}
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
	if r.Sites[0].RegexEvalsPerRequest < 1 {
		t.Fatalf("regex evals = %d, want >= 1", r.Sites[0].RegexEvalsPerRequest)
	}
}

// The scoped form `redirect @scope CODE TARGET` references its matcher: the matcher
// must count as referenced (no unused-matcher warning) and not be misread as a path
// regex.
func TestRedirectScopedReferencesMatcher(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	@es classify {lang}==es
	classify {lang} {
		when header Accept-Language es -> es
		default                        -> en
	}
	redirect @es 302 https://{host}/es{path}
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unknown-directive"] != 0 {
		t.Fatalf("unknown-directive = %d, want 0\n%s", c["unknown-directive"], render(t, r))
	}
	if c["unused-matcher"] != 0 {
		t.Fatalf("unused-matcher = %d, want 0 (redirect @es references @es)\n%s", c["unused-matcher"], render(t, r))
	}
	if c["undefined-matcher"] != 0 {
		t.Fatalf("undefined-matcher = %d, want 0\n%s", c["undefined-matcher"], render(t, r))
	}
	if r.Sites[0].PhaseCounts[PhaseRECV] < 1 {
		t.Fatalf("RECV phase count = %d, want >= 1", r.Sites[0].PhaseCounts[PhaseRECV])
	}
}

// The combined form `redirect @scope PATH_REGEX CODE TARGET` references its matcher
// (no unused-matcher warning) AND counts the path regex as one regex eval/request.
func TestRedirectScopedRegexCombinedCounted(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	@es classify {lang}==es
	classify {lang} {
		when header Accept-Language es -> es
		default                        -> en
	}
	redirect @es (?i)^(.*)/(couples|parejas)/?$ 301 https://{host}$1/parejas
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unknown-directive"] != 0 {
		t.Fatalf("unknown-directive = %d, want 0\n%s", c["unknown-directive"], render(t, r))
	}
	if c["unused-matcher"] != 0 {
		t.Fatalf("unused-matcher = %d, want 0 (combined redirect references @es)\n%s", c["unused-matcher"], render(t, r))
	}
	if c["undefined-matcher"] != 0 {
		t.Fatalf("undefined-matcher = %d, want 0\n%s", c["undefined-matcher"], render(t, r))
	}
	if r.Sites[0].RegexEvalsPerRequest < 1 {
		t.Fatalf("regex evals/request = %d, want >= 1 (combined path regex)", r.Sites[0].RegexEvalsPerRequest)
	}
}

// An undefined scope on a scoped redirect is flagged.
func TestRedirectScopedUndefinedFlagged(t *testing.T) {
	src := `site.example {
	upstream b { to http://x:80 }
	redirect @nope 302 https://{host}/x
	cache_ttl default ttl 5m
}
`
	r, err := CheckSource("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["undefined-matcher"] < 1 {
		t.Fatalf("undefined-matcher = %d, want >= 1\n%s", codes(r)["undefined-matcher"], render(t, r))
	}
}
