package classify

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// parseSite lexes+parses a single site body and returns its *cadishfile.Site so
// FromSite (the single source of truth for compiling a `device_detect` block) can
// be exercised end-to-end through the real Cadishfile parser.
func parseSite(t *testing.T, body string) *cadishfile.Site {
	t.Helper()
	file, err := cadishfile.Parse("test.cadish", []byte("example.com {\n"+body+"\n}\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(file.Sites) != 1 {
		t.Fatalf("want 1 site, got %d", len(file.Sites))
	}
	return file.Sites[0]
}

// TestFromSite_AbsentUsesDefault: a site with no device_detect block gets the
// built-in default classifier so `{device}` works out of the box.
func TestFromSite_AbsentUsesDefault(t *testing.T) {
	c, err := FromSite(parseSite(t, `respond 200`))
	if err != nil {
		t.Fatalf("FromSite: %v", err)
	}
	if !c.IsDefault() {
		t.Errorf("absent block should yield the default classifier")
	}
	// And it actually classifies like the default.
	if got := c.Classify("Googlebot/2.1"); got != "bot" {
		t.Errorf("default Classify(Googlebot) = %q, want bot", got)
	}
}

// TestFromSite_CustomRules: a custom ruleset compiles and classifies by ITS rules,
// first-match-wins, case-insensitively — and is NOT considered the default ruleset
// (so the edge projector will not omit it).
func TestFromSite_CustomRules(t *testing.T) {
	c, err := FromSite(parseSite(t, `
device_detect {
    bot    ua_contains curl wget
    tablet ua_contains iPad
    mobile ua_contains Mobile iPhone
    default desktop
}`))
	if err != nil {
		t.Fatalf("FromSite: %v", err)
	}
	cases := map[string]string{
		"curl/8.0":              "bot",
		"Mozilla (iPad) Safari": "tablet",
		"iPhone Mobile":         "mobile",
		"Firefox on Linux":      "desktop", // default
		"CURL/8.0":              "bot",     // case-insensitive substring
	}
	for ua, want := range cases {
		if got := c.Classify(ua); got != want {
			t.Errorf("Classify(%q) = %q, want %q", ua, got, want)
		}
	}
	if c.IsDefault() {
		t.Errorf("a customized ruleset must not report IsDefault()=true (edge would drop it)")
	}
}

// TestFromSite_UaExcludes: the `ua_excludes` form compiles into a Rule.Exclude so
// "Android but not Mobile" => tablet works, identical to the built-in heuristic.
func TestFromSite_UaExcludes(t *testing.T) {
	c, err := FromSite(parseSite(t, `
device_detect {
    tablet ua_contains Android ua_excludes Mobile
    mobile ua_contains Android Mobile
    default desktop
}`))
	if err != nil {
		t.Fatalf("FromSite: %v", err)
	}
	if got := c.Classify("Linux; Android 13; SM-X710 Safari"); got != "tablet" {
		t.Errorf("Android-without-Mobile = %q, want tablet", got)
	}
	if got := c.Classify("Linux; Android 13; Pixel Mobile Safari"); got != "mobile" {
		t.Errorf("Android-with-Mobile = %q, want mobile", got)
	}
}

// TestFromSite_FoldsOnlyBuildsOnDefault: a block with ONLY folds builds on the
// built-in ruleset (so the four default classes collapse), and the result is not
// the default classifier (folds present).
func TestFromSite_FoldsOnlyBuildsOnDefault(t *testing.T) {
	c, err := FromSite(parseSite(t, `
device_detect {
    fold tablet desktop
    fold bot    desktop
}`))
	if err != nil {
		t.Fatalf("FromSite: %v", err)
	}
	// The default rules still classify, but tablet/bot fold into desktop.
	if got := c.Classify("Mozilla (iPad) Safari"); got != "desktop" {
		t.Errorf("iPad folded = %q, want desktop", got)
	}
	if got := c.Classify("Googlebot/2.1"); got != "desktop" {
		t.Errorf("bot folded = %q, want desktop", got)
	}
	if got := c.Classify("iPhone Mobile"); got != "mobile" {
		t.Errorf("iPhone = %q, want mobile (not folded)", got)
	}
	classes := c.Classes()
	sort.Strings(classes)
	if want := []string{"desktop", "mobile"}; !reflect.DeepEqual(classes, want) {
		t.Errorf("folded Classes() = %v, want %v", classes, want)
	}
	if c.IsDefault() {
		t.Errorf("a folds-only classifier must not report IsDefault()=true")
	}
}

// TestFromSite_DefaultOnly: a block with only `default CLASS` overrides the
// fallback while keeping the built-in rules.
func TestFromSite_DefaultOnly(t *testing.T) {
	c, err := FromSite(parseSite(t, `
device_detect {
    default other
}`))
	if err != nil {
		t.Fatalf("FromSite: %v", err)
	}
	if got := c.DefaultClass(); got != "other" {
		t.Errorf("DefaultClass = %q, want other", got)
	}
	if got := c.Classify("plain desktop browser"); got != "other" {
		t.Errorf("no-rule-match = %q, want other (custom default)", got)
	}
	// Built-in rules still apply.
	if got := c.Classify("Googlebot/2.1"); got != "bot" {
		t.Errorf("Classify(Googlebot) = %q, want bot", got)
	}
}

// TestFromSite_Errors pins the validation that protects the {device} key from a
// malformed block (a wrong/loose rule = a wrong cached variant).
func TestFromSite_Errors(t *testing.T) {
	cases := map[string]string{
		"no block":        `device_detect`,
		"empty block":     `device_detect { }`,
		"duplicate block": "device_detect {\n default a \n}\n device_detect {\n default b \n}",
		"duplicate default": `device_detect {
    default a
    default b
}`,
		"default arity": `device_detect {
    default a b
}`,
		"fold arity": `device_detect {
    fold tablet
}`,
		"rule no ua_contains": `device_detect {
    mobile iPhone
}`,
		"rule empty substrings": `device_detect {
    mobile ua_contains ua_excludes Mobile
}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := FromSite(parseSite(t, body)); err == nil {
				t.Fatalf("expected an error for %q", name)
			}
		})
	}
}

// TestFromSite_PositionedError: a malformed block surfaces a file:line positioned
// error (so `cadish check` points at the offending line).
func TestFromSite_PositionedError(t *testing.T) {
	_, err := FromSite(parseSite(t, `device_detect {
    mobile iPhone
}`))
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "test.cadish:") {
		t.Errorf("error not positioned: %v", err)
	}
}

// TestClassifyUACapBoundsWork pins the maxClassifyUALen cap (CLS-P2): a matching
// token that sits ENTIRELY beyond the cap is not seen (the UA is truncated before
// the scan), so an adversary cannot smuggle a class via a megabyte of padding.
func TestClassifyUACapBoundsWork(t *testing.T) {
	c := Default()
	// Token within the cap: matched.
	near := "Googlebot/2.1 " + strings.Repeat("x", 100)
	if got := c.Classify(near); got != "bot" {
		t.Errorf("token within cap: got %q, want bot", got)
	}
	// Token entirely beyond the cap: NOT matched (truncated away) => default.
	far := strings.Repeat("x", maxClassifyUALen+10) + " Googlebot/2.1"
	if got := c.Classify(far); got != "desktop" {
		t.Errorf("token beyond cap: got %q, want desktop (truncated away)", got)
	}
}
