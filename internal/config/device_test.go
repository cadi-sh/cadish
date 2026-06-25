package config

import (
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func parseSite(t *testing.T, src string) *cadishfile.Site {
	t.Helper()
	f, err := cadishfile.Parse("t.cadish", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Sites) == 0 {
		t.Fatal("no site parsed")
	}
	return f.Sites[0]
}

// TestBuildClassifierDefault: no device_detect block → the built-in ruleset.
func TestBuildClassifierDefault(t *testing.T) {
	c, err := buildClassifier(parseSite(t, "example.com {\n cache_key path {device}\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Classify("iPhone Mobile Safari"); got != "mobile" {
		t.Errorf("default classifier iPhone => %q, want mobile", got)
	}
	if got := c.Classify("Mozilla Firefox"); got != "desktop" {
		t.Errorf("default classifier firefox => %q, want desktop", got)
	}
}

// TestBuildClassifierCustom: a device_detect block defines an ordered ruleset.
func TestBuildClassifierCustom(t *testing.T) {
	c, err := buildClassifier(parseSite(t, `example.com {
    device_detect {
        bot     ua_contains bot crawler spider
        tablet  ua_contains iPad Tablet
        mobile  ua_contains Mobile Android iPhone
        default desktop
    }
    cache_key path {device}
}`))
	if err != nil {
		t.Fatal(err)
	}
	for ua, want := range map[string]string{
		"Mozilla (iPad) Mobile": "tablet", // tablet rule precedes mobile
		"Android Mobile":        "mobile",
		"Googlebot/2.1":         "bot",
		"Desktop Firefox":       "desktop",
	} {
		if got := c.Classify(ua); got != want {
			t.Errorf("Classify(%q) = %q, want %q", ua, got, want)
		}
	}
}

// TestBuildClassifierFoldOnly: a block with only folds builds on the built-in
// ruleset and collapses the enum to the cardinality-2 desktop/mobile case.
func TestBuildClassifierFoldOnly(t *testing.T) {
	c, err := buildClassifier(parseSite(t, `example.com {
    device_detect {
        fold tablet desktop
        fold bot     desktop
    }
    cache_key path {device}
}`))
	if err != nil {
		t.Fatal(err)
	}
	for ua, want := range map[string]string{
		"Mozilla (iPad) Safari": "desktop", // tablet folded → desktop
		"Googlebot/2.1":         "desktop", // bot folded → desktop
		"iPhone Mobile":         "mobile",
		"Windows Firefox":       "desktop",
	} {
		if got := c.Classify(ua); got != want {
			t.Errorf("Classify(%q) = %q, want %q", ua, got, want)
		}
	}
}

// TestBuildClassifierExcludes: a custom rule with ua_excludes (Android tablet).
func TestBuildClassifierExcludes(t *testing.T) {
	c, err := buildClassifier(parseSite(t, `example.com {
    device_detect {
        tablet  ua_contains Android ua_excludes Mobile
        mobile  ua_contains Android Mobile
        default desktop
    }
    cache_key path {device}
}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Classify("Linux; Android 13; SM-X710 Safari"); got != "tablet" {
		t.Errorf("android tablet => %q, want tablet", got)
	}
	if got := c.Classify("Linux; Android 13; Pixel Mobile Safari"); got != "mobile" {
		t.Errorf("android phone => %q, want mobile", got)
	}
}

func TestBuildClassifierErrors(t *testing.T) {
	cases := []struct{ name, src string }{
		{"fold arity", "example.com {\n device_detect {\n fold tablet\n}\n}"},
		{"excludes no contains", "example.com {\n device_detect {\n tablet ua_excludes Mobile\n}\n}"},
		{"no block", "example.com {\n device_detect mobile\n}"},
		{"empty block", "example.com {\n device_detect {\n}\n}"},
		{"bad rule", "example.com {\n device_detect {\n mobile foo bar\n}\n}"},
		{"default arity", "example.com {\n device_detect {\n default a b\n}\n}"},
		{"dup default", "example.com {\n device_detect {\n default a\n default b\n}\n}"},
		{"two blocks", "example.com {\n device_detect {\n default a\n}\n device_detect {\n default b\n}\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildClassifier(parseSite(t, tc.src)); err == nil {
				t.Errorf("expected a compile error for %s", tc.name)
			}
		})
	}
}
