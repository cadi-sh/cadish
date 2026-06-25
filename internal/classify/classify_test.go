package classify

import (
	"reflect"
	"sort"
	"testing"
)

func TestDefaultClassifier(t *testing.T) {
	c := Default()
	cases := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120", "desktop"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605", "desktop"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148", "mobile"},
		{"Mozilla/5.0 (Linux; Android 13; Pixel 7) Mobile Safari/537", "mobile"},
		{"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit Mobile/15E148", "tablet"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot"},
		{"Mozilla/5.0 (compatible; bingbot/2.0)", "bot"},
		{"facebookexternalhit/1.1", "bot"},
		{"", "desktop"}, // empty UA → default
	}
	for _, tc := range cases {
		if got := c.Classify(tc.ua); got != tc.want {
			t.Errorf("Classify(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

// TestOrderFirstMatchWins: a bot UA that also contains "Mobile" classifies as bot
// (bot rule precedes mobile), and an iPad UA (contains "Mobile") as tablet.
func TestOrderFirstMatchWins(t *testing.T) {
	c := Default()
	if got := c.Classify("Mozilla/5.0 (Linux; Android 13) Mobile Googlebot/2.1"); got != "bot" {
		t.Errorf("bot-before-mobile: got %q, want bot", got)
	}
	if got := c.Classify("Mozilla/5.0 (iPad; CPU OS 17_0) Mobile/15E148"); got != "tablet" {
		t.Errorf("tablet-before-mobile: got %q, want tablet", got)
	}
}

func TestCustomClassifier(t *testing.T) {
	c := New([]Rule{
		{Class: "bot", Substrings: []string{"curl", "wget"}},
		{Class: "mobile", Substrings: []string{"iphone"}},
	}, "desktop")
	if got := c.Classify("curl/8.0"); got != "bot" {
		t.Errorf("curl => %q, want bot", got)
	}
	if got := c.Classify("iPhone Safari"); got != "mobile" {
		t.Errorf("iphone => %q, want mobile", got)
	}
	if got := c.Classify("Mozilla Firefox"); got != "desktop" {
		t.Errorf("firefox => %q, want desktop (default)", got)
	}
}

func TestEmptyDefaultFallsBack(t *testing.T) {
	c := New(nil, "") // no rules, empty default → "desktop"
	if got := c.Classify("anything"); got != "desktop" {
		t.Errorf("empty classifier => %q, want desktop", got)
	}
}

func TestNilClassifierSafe(t *testing.T) {
	var c *Classifier
	if got := c.Classify("iPhone"); got != "desktop" {
		t.Errorf("nil classifier => %q, want desktop", got)
	}
	if got := c.Classes(); !reflect.DeepEqual(got, []string{"desktop"}) {
		t.Errorf("nil Classes() = %v, want [desktop]", got)
	}
}

func TestClassesBounded(t *testing.T) {
	got := Default().Classes()
	sort.Strings(got)
	want := []string{"bot", "desktop", "mobile", "tablet"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Classes() = %v, want %v", got, want)
	}
}

// TestSubstringMatchesParams: a substring matches inside a larger token.
func TestSubstringMatch(t *testing.T) {
	c := New([]Rule{{Class: "mobile", Substrings: []string{"android"}}}, "desktop")
	if got := c.Classify("Mozilla/5.0 (Linux; Android 14; SM-S911B)"); got != "mobile" {
		t.Errorf("android substring => %q, want mobile", got)
	}
}
