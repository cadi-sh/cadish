package pipeline

import (
	"net/http"
	"regexp"
	"testing"
)

// TestPurgeRegexPathAnchorsPath verifies the `regex-path EXPR` form rewrites a
// Varnish-style path-anchored pattern (`^/foo`) so it matches the PATH component
// of the cache key (`METHOD\x1fHOST\x1fPATH…`), not the whole key. The plain
// `regex` form is unchanged (matches the whole key).
func TestPurgeRegexPathAnchorsPath(t *testing.T) {
	p := compileSrc(t, `x {
		purge when header X-Purge-Token secret regex-path {http.X-Purge-Path}
	}
`)
	dec := p.EvalRequest(&Request{
		Method: "PURGE", Path: "/",
		Header: http.Header{"X-Purge-Token": {"secret"}, "X-Purge-Path": {`^/nocookie`}},
	})
	if dec.Purge == nil || dec.Purge.Regex == "" {
		t.Fatalf("purge decision = %+v, want a non-empty regex", dec.Purge)
	}
	re, err := regexp.Compile(dec.Purge.Regex)
	if err != nil {
		t.Fatalf("compiled purge regex %q invalid: %v", dec.Purge.Regex, err)
	}
	// A real default cache key (method host path).
	key := "GET\x1fexample.com\x1f/nocookie/v.ts"
	if !re.MatchString(key) {
		t.Errorf("regex-path %q did not match key %q (regex=%q)", "^/nocookie", key, dec.Purge.Regex)
	}
	// Must NOT match a key whose HOST happens to contain the path text but whose
	// path does not begin with /nocookie.
	other := "GET\x1fnocookie.example.com\x1f/other"
	if re.MatchString(other) {
		t.Errorf("regex-path %q wrongly matched key %q (regex=%q)", "^/nocookie", other, dec.Purge.Regex)
	}
}

// TestPurgePlainRegexWholeKey confirms the existing `regex` form is untouched: it
// matches the whole key, so a path-anchored `^/foo` never matches (the key starts
// with the method/host).
func TestPurgePlainRegexWholeKey(t *testing.T) {
	p := compileSrc(t, `x {
		purge when header X-Purge-Token secret regex {http.X-Purge-Regex}
	}
`)
	dec := p.EvalRequest(&Request{
		Method: "PURGE", Path: "/",
		Header: http.Header{"X-Purge-Token": {"secret"}, "X-Purge-Regex": {`^/list/`}},
	})
	if dec.Purge == nil || dec.Purge.Regex != `^/list/` {
		t.Fatalf("plain regex form should pass through verbatim, got %+v", dec.Purge)
	}
}

func TestPathToKeyRegex(t *testing.T) {
	tests := []struct {
		in      string
		matches []string
		nomatch []string
	}{
		{
			in:      `^/nocookie`,
			matches: []string{"GET\x1fexample.com\x1f/nocookie", "GET\x1fexample.com\x1f/nocookie/a.ts"},
			nomatch: []string{"GET\x1fnocookie.com\x1f/other", "GET\x1fexample.com\x1f/foo/nocookie"},
		},
		{
			in:      `/list/`, // unanchored: matches the path token anywhere
			matches: []string{"GET\x1fexample.com\x1f/list/", "GET\x1fexample.com\x1f/a/list/b"},
			nomatch: []string{"GET\x1fexample.com\x1f/other"},
		},
		{
			// Finding 1: a key whose FIRST token is the path (e.g. `cache_key url`).
			// The leading `^` must anchor at start-of-key OR a token boundary, so a
			// path-leading key still matches.
			in:      `^/foo`,
			matches: []string{"/foo/bar.ts", "GET\x1fexample.com\x1f/foo"},
			nomatch: []string{"GET\x1fexample.com\x1f/bar/foo"},
		},
		{
			// Finding 2: a slashless UNANCHORED pattern must NOT match the
			// HOST/method tokens (over-purge). It only matches within a path token.
			in:      `list`,
			matches: []string{"GET\x1flist.example.com\x1f/video/list.ts", "GET\x1fexample.com\x1f/list"},
			nomatch: []string{"GET\x1flist.example.com\x1f/video.ts", "list\x1fexample.com\x1f/video.ts"},
		},
	}
	for _, tt := range tests {
		got := pathToKeyRegex(tt.in)
		re, err := regexp.Compile(got)
		if err != nil {
			t.Fatalf("pathToKeyRegex(%q)=%q invalid: %v", tt.in, got, err)
		}
		for _, m := range tt.matches {
			if !re.MatchString(m) {
				t.Errorf("pathToKeyRegex(%q)=%q should match %q", tt.in, got, m)
			}
		}
		for _, n := range tt.nomatch {
			if re.MatchString(n) {
				t.Errorf("pathToKeyRegex(%q)=%q should NOT match %q", tt.in, got, n)
			}
		}
	}
}
