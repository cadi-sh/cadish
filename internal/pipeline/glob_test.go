package pipeline

import "testing"

func TestPathSet(t *testing.T) {
	s := newPathSet()
	for _, p := range []string{"/panel/*", "/media/image_server.php", "*sitemap*", "/a/*/b", "/exact"} {
		s.add(p)
	}
	tests := []struct {
		path string
		want bool
	}{
		{"/panel/", true},                 // prefix
		{"/panel/settings/x", true},       // prefix deep
		{"/panelx", false},                // prefix requires the slash
		{"/media/image_server.php", true}, // exact
		{"/media/image_server.phpx", false},
		{"/exact", true},
		{"/exactly", false},
		{"/foo/sitemap.xml", true}, // contains
		{"sitemap", true},
		{"/no/match/here", false},
		{"/a/zzz/b", true},   // interior glob
		{"/a/zzz/bc", false}, // suffix anchored
	}
	for _, tt := range tests {
		if got := s.Match(tt.path); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPathSetMatchAll(t *testing.T) {
	s := newPathSet()
	s.add("*")
	for _, p := range []string{"", "/", "/anything/at/all"} {
		if !s.Match(p) {
			t.Errorf("matchAll: Match(%q) = false, want true", p)
		}
	}
}

func TestTriePrefix(t *testing.T) {
	tr := newTrie()
	tr.insert("/a/")
	tr.insert("/bb/")
	if !tr.hasPrefixOf("/a/x") {
		t.Error("want /a/x matched by prefix /a/")
	}
	if tr.hasPrefixOf("/a") {
		t.Error("/a should not be matched by prefix /a/")
	}
	if !tr.hasPrefixOf("/bb/deep/path") {
		t.Error("want /bb/deep matched")
	}
	if tr.hasPrefixOf("/c/") {
		t.Error("/c/ should not match")
	}
}

func TestHostSet(t *testing.T) {
	s := newHostSet()
	s.add("example.com")
	s.add("*.example.com")
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"ExamplE.com", true}, // case-insensitive
		{"example.com:8443", true},
		{"www.example.com", true},
		{"a.b.example.com", true},
		{"example.org", false},
		{"notexample.com", false},
	}
	for _, tt := range tests {
		if got := s.Match(tt.host); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pat, s string
		want   bool
	}{
		{"*sitemap*", "x-sitemap-y", true},
		{"*sitemap*", "nope", false},
		{"abc*", "abcdef", true},
		{"abc*", "xabc", false},
		{"*xyz", "wwwxyz", true},
		{"*xyz", "xyzw", false},
		{"a*c", "abbbc", true},
		{"a*c", "ac", true},
		{"a*c", "abx", false},
	}
	for _, tt := range tests {
		g := compileGlob(tt.pat)
		if got := g.match(tt.s); got != tt.want {
			t.Errorf("glob %q match %q = %v, want %v", tt.pat, tt.s, got, tt.want)
		}
	}
}
