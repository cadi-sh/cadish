package edgeir

import (
	"strings"
	"testing"
)

// TestClassifyIPRowFailCloses (revert of the unsound P2 drop): a classify `when` row that
// AND-requires an `ip` matcher must NOT be dropped from the projected classifier. The `ip`
// matcher resolves the REAL client IP, which a public visitor presents to BOTH the Cadish
// server and the edge worker — so dropping the row would make the edge classify that visitor
// DIFFERENTLY than the server, computing a divergent cache key and serving a variant the server
// would never produce. Instead the `ip` row (ServerOnly) fail-closes the WHOLE classifier, and a
// cache_key reading it fail-opens → the site delegates to the Cadish server behind (which CAN
// evaluate `ip`). The server keeps every row; the edge keeps every row too — it just refuses to
// resolve the classifier natively.
func TestClassifyIPRowFailCloses(t *testing.T) {
	const src = `example.com {
		@testverify ip 199.115.194.231/32
		@verified   cookie verified
		@us         geo country US
		classify {age} {
			when @testverify @verified -> 0
			when @us @verified         -> 0
			when @testverify           -> 1
			when @us                   -> 1
			default                    -> 2
		}
		cache_key method host path {age}
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	c, ok := ir.Classifiers["age"]
	if !ok {
		t.Fatalf("classifier {age} must be projected")
	}
	// EVERY row is kept — including the two @testverify (ip) rows. No row is dropped.
	if len(c.Rows) != 4 {
		t.Fatalf("want all 4 rows kept (no drop), got %d: %+v", len(c.Rows), c.Rows)
	}
	sawTestverify := false
	for _, r := range c.Rows {
		for _, id := range r.Conj {
			if id == "testverify" {
				sawTestverify = true
			}
		}
	}
	if !sawTestverify {
		t.Errorf("the @testverify ip rows must be KEPT (not dropped): %+v", c.Rows)
	}
	// The classifier fail-closes at the edge (the ip row is ServerOnly), so a cache_key reading
	// {age} CANNOT be projected native — the recipe fail-opens to a site-wide pass / delegate.
	if rep.ForcedPass == 0 {
		t.Error("an ip row keeps the {age} classifier fail-closed → a cache_key reading it must force a pass; ForcedPass>0")
	}
	sawAlwaysPass := false
	for _, sc := range ir.Recv.Pass {
		if sc.Always {
			sawAlwaysPass = true
		}
	}
	if !sawAlwaysPass {
		t.Error("the site must fail OPEN to a site-wide pass (delegate) when a cache_key reads an ip-bearing classifier")
	}
	// No "dropped row" coverage line is emitted — nothing is dropped.
	for _, w := range rep.Warnings {
		if strings.Contains(w, "unsatisfiable at the edge") || strings.Contains(w, "dropped") {
			t.Errorf("no row must be reported dropped (the unsound drop was withdrawn); got: %q", w)
		}
	}
}

// TestClassifyIPRegexFailCloses (revert): an `ip` row AND an untranslatable-regex row both keep
// the classifier fail-closed. Neither is dropped; both are unknowable/unevaluable at the edge,
// so the classifier stays fail-closed and a cache_key reading it forces a pass.
func TestClassifyIPRegexFailCloses(t *testing.T) {
	const src = `example.com {
		@testverify ip 199.115.194.231/32
		@ungreedy   path_regex (?U)^/(gate|block)
		@verified   cookie verified
		classify {age} {
			when @testverify @verified -> 0
			when @ungreedy             -> 1
			when @verified             -> 0
			default                    -> 2
		}
		cache_key host path {age}
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	c := ir.Classifiers["age"]
	// All 3 rows survive — neither the ip row nor the regex row is dropped.
	if len(c.Rows) != 3 {
		t.Fatalf("want all 3 rows kept, got %d: %+v", len(c.Rows), c.Rows)
	}
	sawUngreedy, sawTestverify := false, false
	for _, r := range c.Rows {
		for _, id := range r.Conj {
			if id == "ungreedy" {
				sawUngreedy = true
			}
			if id == "testverify" {
				sawTestverify = true
			}
		}
	}
	if !sawUngreedy || !sawTestverify {
		t.Errorf("both the ip row and the regex row must SURVIVE: %+v", c.Rows)
	}
	// The classifier fail-closes → cache_key {age} fails open → ForcedPass>0.
	if rep.ForcedPass == 0 {
		t.Error("an ip row and/or an untranslatable-regex row must keep the classifier fail-closed → ForcedPass>0")
	}
	// No dropped-row line.
	for _, w := range rep.Warnings {
		if strings.Contains(w, "unsatisfiable at the edge") || strings.Contains(w, "dropped") {
			t.Errorf("no row must be reported dropped; got: %q", w)
		}
	}
}

// TestClassifyUpstreamHealthyRowNotDropped: an `upstream_healthy` row fires whenever the lb pool
// is healthy (the common case on the server), so treating it as constant-false at the edge would
// DIVERGE. It is NOT dropped — the row survives and (being ServerOnly) keeps the whole classifier
// fail-closed, so a cache_key reading it fails open. (This always held; it is unchanged by the
// `ip`-drop revert.)
func TestClassifyUpstreamHealthyRowNotDropped(t *testing.T) {
	const src = `example.com {
		@live     upstream_healthy pool
		@verified cookie verified
		classify {age} {
			when @live @verified -> 0
			when @verified       -> 0
			default              -> 2
		}
		cache_key host path {age}
		cache_ttl default ttl 1h
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	c := ir.Classifiers["age"]
	// The upstream_healthy row is NOT dropped — both rows survive.
	if len(c.Rows) != 2 {
		t.Fatalf("the upstream_healthy row must NOT be dropped; want 2 rows, got %d: %+v", len(c.Rows), c.Rows)
	}
	sawLive := false
	for _, r := range c.Rows {
		for _, id := range r.Conj {
			if id == "live" {
				sawLive = true
			}
		}
	}
	if !sawLive {
		t.Errorf("the @live upstream_healthy row must SURVIVE: %+v", c.Rows)
	}
	// It keeps the classifier fail-closed → cache_key {age} fails open → ForcedPass>0.
	if rep.ForcedPass == 0 {
		t.Error("a surviving upstream_healthy row must keep the classifier fail-closed → ForcedPass>0")
	}
	// No dropped-row line is emitted.
	for _, w := range rep.Warnings {
		if strings.Contains(w, "unsatisfiable at the edge") {
			t.Errorf("no row must be reported dropped for an upstream_healthy classifier; got: %q", w)
		}
	}
}
