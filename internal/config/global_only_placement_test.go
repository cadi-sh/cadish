package config

import (
	"strings"
	"testing"
)

// Finding 2 (round-3): `cadish check` (ValidateStructure → pipeline.Compile) must REJECT a
// global-only block placed inside a SITE body with a positioned error — not report 0 errors
// while the block is silently ignored at runtime. ValidateStructure shares the Compile entry
// point with `cadish run`, so the two fail identically (the check≡run invariant).
func TestCheckRejectsGlobalOnlyServerInSiteBody(t *testing.T) {
	src := `example.com {
    upstream u { to http://127.0.0.1:9 }
    server { maxconn 5 }
    cache_ttl default ttl 60s
}`
	err := ValidateStructure("test.Cadishfile", src, t.TempDir())
	if err == nil {
		t.Fatal("`cadish check` must FAIL on a misplaced `server {}` in a site body, not report 0 errors")
	}
	if !strings.Contains(err.Error(), "server") || !strings.Contains(err.Error(), "global-only") {
		t.Fatalf("error must be a positioned global-only placement error naming `server`; got %q", err.Error())
	}
}

// The SAME config with `server {}` in the leading global-options block is accepted — the
// rejection is placement-specific.
func TestCheckAcceptsGlobalServerBlock(t *testing.T) {
	src := `{
    server { maxconn 5 }
}
example.com {
    upstream u { to http://127.0.0.1:9 }
    cache_ttl default ttl 60s
}`
	if err := ValidateStructure("test.Cadishfile", src, t.TempDir()); err != nil {
		t.Fatalf("a global `server {}` block must validate clean; got %v", err)
	}
}
