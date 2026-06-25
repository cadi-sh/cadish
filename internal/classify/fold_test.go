package classify

import (
	"reflect"
	"sort"
	"testing"
)

// TestAndroidTabletHeuristic: an Android UA WITHOUT "Mobile" is a tablet; WITH
// "Mobile" it is a phone (the built-in exclude rule).
func TestAndroidTabletHeuristic(t *testing.T) {
	c := Default()
	tablet := "Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 Safari/537.36"
	if got := c.Classify(tablet); got != "tablet" {
		t.Errorf("Android-without-Mobile => %q, want tablet", got)
	}
	phone := "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Mobile Safari/537.36"
	if got := c.Classify(phone); got != "mobile" {
		t.Errorf("Android-with-Mobile => %q, want mobile", got)
	}
}

// TestExcludeRule: a custom rule with an exclude condition.
func TestExcludeRule(t *testing.T) {
	c := New([]Rule{
		{Class: "smarttv", Substrings: []string{"linux"}, Exclude: []string{"android", "mobile"}},
	}, "desktop")
	if got := c.Classify("SomeTV (Linux; SmartTV)"); got != "smarttv" {
		t.Errorf("linux-not-android => %q, want smarttv", got)
	}
	if got := c.Classify("Linux; Android Mobile"); got != "desktop" {
		t.Errorf("linux+android excluded => %q, want desktop (default)", got)
	}
}

// TestFoldCollapsesEnum: folding tablet→desktop and bot→desktop reduces the
// built-in four classes to the cardinality-2 desktop/mobile case.
func TestFoldCollapsesEnum(t *testing.T) {
	c := New(DefaultRules(), "desktop",
		Fold{From: "tablet", Into: "desktop"},
		Fold{From: "bot", Into: "desktop"},
	)
	cases := map[string]string{
		"Mozilla (iPad) Safari":   "desktop", // tablet → desktop
		"Googlebot/2.1":           "desktop", // bot → desktop
		"Windows NT 10.0 Firefox": "desktop",
		"iPhone Mobile Safari":    "mobile",
		"Android Pixel Mobile":    "mobile",
	}
	for ua, want := range cases {
		if got := c.Classify(ua); got != want {
			t.Errorf("Classify(%q) = %q, want %q", ua, got, want)
		}
	}
	// Classes() reflects the post-fold (collapsed) set.
	got := c.Classes()
	sort.Strings(got)
	if want := []string{"desktop", "mobile"}; !reflect.DeepEqual(got, want) {
		t.Errorf("folded Classes() = %v, want %v", got, want)
	}
}

// TestFoldChainTerminates: a fold cycle does not loop forever.
func TestFoldChainTerminates(t *testing.T) {
	c := New([]Rule{{Class: "a", Substrings: []string{"x"}}}, "a",
		Fold{From: "a", Into: "b"},
		Fold{From: "b", Into: "a"},
	)
	_ = c.Classify("x") // must return, not hang
}
