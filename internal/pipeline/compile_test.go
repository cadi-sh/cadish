package pipeline

import (
	"strings"
	"testing"
)

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantSub string // substring expected in the error message
	}{
		{"unknown-matcher-type", "x {\n @m bogus foo\n}\n", "unknown matcher type"},
		{"bad-path-regex", "x {\n @m path_regex (\n pass @m\n}\n", "invalid regex"},
		{"bad-ttl-duration", "x {\n cache_ttl default ttl 5y\n}\n", "duration"},
		{"bad-ttl-selector", "x {\n cache_ttl bogus ttl 5s\n}\n", "unknown selector"},
		{"status-no-codes", "x {\n cache_ttl status ttl 5s\n}\n", "at least one code"},
		{"ttl-missing-action", "x {\n cache_ttl default\n}\n", "ttl"},
		{"storage-bad-tier", "x {\n storage default -> ssd\n}\n", "ram or disk"},
		{"storage-missing-arrow", "x {\n storage default ram\n}\n", "->"},
		{"undefined-matcher", "x {\n pass @ghost\n}\n", "undefined matcher"},
		{"and-not-supported", "x {\n @a path /a/*\n @b path /b/*\n pass @a and @b\n}\n", "not supported in v1"},
		{"unresolved-import", "x {\n import other.cadish\n}\n", "SpliceImports"},
		{"unknown-directive", "x {\n frobnicate foo\n}\n", "unknown directive"},
		{"header-no-op", "x {\n cache_key path\n header\n}\n", "operation"},
		{"header-set-no-value", "x {\n cache_key path\n header X-Foo\n}\n", "needs a value"},
		{"route-unknown-upstream", "x {\n upstream web { to http://x }\n @s host_regex ^s\n route @s -> ghost\n}\n", "not a declared upstream"},
		{"respond-bad-code", "x {\n respond /h abc OK\n}\n", "status must be a number"},
		{"duplicate-matcher", "x {\n @m path /a/*\n @m path /b/*\n}\n", "duplicate matcher"},
		{"purge-no-when", "x {\n purge header X-T t\n}\n", "when"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ce := compileErr(t, tt.src)
			if !strings.Contains(ce.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", ce.Error(), tt.wantSub)
			}
			if ce.Pos.Line == 0 {
				t.Errorf("error %q should carry a source position", ce.Error())
			}
		})
	}
}

func TestCompileErrorPosition(t *testing.T) {
	// The bad selector is on line 3; the error must point there.
	ce := compileErr(t, "x {\n cache_key path\n cache_ttl nope ttl 5s\n}\n")
	if ce.Pos.Line != 3 {
		t.Errorf("Pos.Line = %d, want 3 (%s)", ce.Pos.Line, ce.Error())
	}
}
