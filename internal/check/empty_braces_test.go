package check

import (
	"testing"
)

// TestEmptyBracesWarns: an empty `{}` argument (e.g. `cache_key {}`) is silently
// kept as a literal token by the lexer; check must warn that it is treated as a
// literal, not a block or placeholder (F13 bug 4).
func TestEmptyBracesWarns(t *testing.T) {
	src := "example.com {\n  upstream web { to http://127.0.0.1:8080 }\n  cache_key {}\n}\n"
	rep, err := CheckSource("c.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	found := false
	for _, s := range rep.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == "empty-braces" {
				found = true
				if d.Severity != SevWarning {
					t.Errorf("empty-braces severity = %s, want warning", d.Severity)
				}
			}
		}
	}
	if !found {
		t.Errorf("expected an empty-braces warning; diagnostics: %+v", rep.Sites)
	}
}
