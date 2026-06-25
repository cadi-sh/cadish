package check

import "testing"

// TestEmptyCacheKeyWarns: `cache_key` with NO tokens at all silently falls back to
// the default key (method host path) — a likely typo. check must warn. (This is
// distinct from the empty-braces `{}` case, which is its own warning.)
func TestEmptyCacheKeyWarns(t *testing.T) {
	src := "example.com {\n  upstream web { to http://127.0.0.1:8080 }\n  cache_key\n}\n"
	rep, err := CheckSource("c.cadish", []byte(src))
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	found := false
	for _, s := range rep.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == "cache-key-empty" {
				found = true
				if d.Severity != SevWarning {
					t.Errorf("cache-key-empty severity = %s, want warning", d.Severity)
				}
			}
		}
	}
	if !found {
		t.Errorf("expected a cache-key-empty warning; diagnostics: %+v", rep.Sites)
	}
}
