package edgeir

import "testing"

func TestSplitRE2Flags(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		wantPattern string
		wantFlags   string
		wantOK      bool
	}{
		{"plain", `^/cams/?$`, `^/cams/?$`, "", true},
		{"caseInsensitive", `(?i)^/cams/?$`, `^/cams/?$`, "i", true},
		{"caseInsensitiveDotall", `(?is)^/(atvpanel|admin)`, `^/(atvpanel|admin)`, "is", true},
		{"caseInsensitiveMultiline", `(?im)^/x`, `^/x`, "im", true},
		{"dotall", `(?s).*`, `.*`, "s", true},
		{"multiline", `(?m)^/y`, `^/y`, "m", true},
		// JS-supported group constructs in the body must survive untouched.
		{"nonCapturing", `^/(?:a|b)$`, `^/(?:a|b)$`, "", true},
		{"lookahead", `^/(?=x)`, `^/(?=x)`, "", true},
		{"namedCaptureBody", `^/(?<id>\d+)$`, `^/(?<id>\d+)$`, "", true},
		{"leadingFlagThenNonCapturing", `(?i)^/(?:a|b)$`, `^/(?:a|b)$`, "i", true},
		// A pattern that STARTS with a non-flag group must project edge-native — these
		// constructs are identical in RE2 and JS and must not be mistaken for a leading
		// inline flag group and delegated (finding 3).
		{"leadingNonCapturing", `(?:foo|bar)/baz`, `(?:foo|bar)/baz`, "", true},
		{"leadingLookahead", `(?=foo)bar`, `(?=foo)bar`, "", true},
		{"leadingNegLookahead", `(?!foo)bar`, `(?!foo)bar`, "", true},
		{"leadingNamedCapture", `(?<id>\d+)$`, `(?<id>\d+)$`, "", true},
		{"leadingLookbehind", `(?<=foo)bar`, `(?<=foo)bar`, "", true},
		{"leadingNegLookbehind", `(?<!foo)bar`, `(?<!foo)bar`, "", true},
		// Untranslatable: ungreedy, negation, scoped flag group, mid-pattern flag.
		{"ungreedy", `(?U)a+`, "", "", false},
		{"negation", `(?-i)abc`, "", "", false},
		{"scopedFlagGroup", `(?i:abc)def`, "", "", false},
		{"midPatternFlag", `^/a(?i)b`, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pat, flags, ok := splitRE2Flags(c.src)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if pat != c.wantPattern {
				t.Errorf("pattern = %q, want %q", pat, c.wantPattern)
			}
			if flags != c.wantFlags {
				t.Errorf("flags = %q, want %q", flags, c.wantFlags)
			}
		})
	}
}

// TestHasInlineFlagGroup pins the detector that decides whether a regex contains an
// inline flag group `(?flags…)` JS cannot compile. JS-supported group constructs
// (`(?:` `(?=` `(?!` `(?<name>` `(?<=` `(?<!`) must NOT be flagged. Two edge cases
// (finding 3): a `(?` that follows a LITERAL backslash `\\(` is a real `(` group
// opener (the `\\` is the escaped backslash, not an escape of the paren), and a `(?`
// INSIDE a character class `[(?]` is two literal chars, not a group.
func TestHasInlineFlagGroup(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{`(?i)x`, true},
		{`(?ms)x`, true},
		{`(?U)x`, true},
		{`(?-i)x`, true},
		{`(?P<n>x)`, true},
		{`^/a(?i)b`, true},
		// JS-supported constructs: not flag groups.
		{`(?:a|b)`, false},
		{`(?=x)`, false},
		{`(?!x)`, false},
		{`(?<n>x)`, false},
		{`(?<=x)`, false},
		{`(?<!x)`, false},
		{`^/cams/?$`, false},
		// Edge cases.
		{`\\(?i)`, true}, // literal backslash THEN a real flag group → flagged
		{`\(?i)`, false}, // escaped paren `\(` then literal `?i)` → no group
		{`[(?]x`, false}, // `(?` inside a char class → literal chars, no group
	}
	for _, c := range cases {
		if got := hasInlineFlagGroup(c.src); got != c.want {
			t.Errorf("hasInlineFlagGroup(%q) = %v, want %v", c.src, got, c.want)
		}
	}
}
