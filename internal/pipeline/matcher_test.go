package pipeline

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

func mkMatcher(t *testing.T, typ string, args ...string) *matcher {
	t.Helper()
	m, err := compileMatcher("m", typ, args, cadishfile.Pos{})
	if err != nil {
		t.Fatalf("compileMatcher(%s %v): %v", typ, args, err)
	}
	return m
}

func TestMatcherTypes(t *testing.T) {
	req := &Request{
		Method:   "GET",
		Host:     "static.example.com",
		Path:     "/panel/x",
		Query:    url.Values{},
		Header:   http.Header{"X-Requested-With": {"XMLHttpRequest"}},
		ClientIP: "1.2.3.4",
	}
	tests := []struct {
		name     string
		m        *matcher
		upstream string
		want     bool
	}{
		{"path-prefix", mkMatcher(t, "path", "/panel/*"), "", true},
		{"path-miss", mkMatcher(t, "path", "/other/*"), "", false},
		{"path-or", mkMatcher(t, "path", "/nope/*", "/panel/*"), "", true}, // OR within matcher
		{"path_regex", mkMatcher(t, "path_regex", `^/panel/`), "", true},
		{"path_regex-miss", mkMatcher(t, "path_regex", `^/admin/`), "", false},
		{"host", mkMatcher(t, "host", "static.example.com"), "", true},
		{"host-wild", mkMatcher(t, "host", "*.example.com"), "", true},
		{"host-miss", mkMatcher(t, "host", "example.com"), "", false},
		{"host_regex", mkMatcher(t, "host_regex", "^static"), "", true},
		{"host_regex-miss", mkMatcher(t, "host_regex", "^www"), "", false},
		{"header-present", mkMatcher(t, "header", "X-Requested-With"), "", true},
		{"header-absent", mkMatcher(t, "header", "X-Absent"), "", false},
		{"header-equals", mkMatcher(t, "header", "X-Requested-With", "XMLHttpRequest"), "", true},
		{"header-equals-miss", mkMatcher(t, "header", "X-Requested-With", "nope"), "", false},
		{"header-equals-or", mkMatcher(t, "header", "X-Requested-With", "a", "XMLHttpRequest"), "", true},
		{"method", mkMatcher(t, "method", "GET"), "", true},
		{"method-or", mkMatcher(t, "method", "POST", "GET"), "", true},
		{"method-miss", mkMatcher(t, "method", "POST"), "", false},
		{"upstream-hit", mkMatcher(t, "upstream", "images"), "images", true},
		{"upstream-miss", mkMatcher(t, "upstream", "images"), "web", false},
		{"upstream-empty", mkMatcher(t, "upstream", "images"), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newMatchContext(req, tt.upstream)
			if got := tt.m.match(c); got != tt.want {
				t.Errorf("match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherMethodCaseInsensitive(t *testing.T) {
	m := mkMatcher(t, "method", "post")
	req := &Request{Method: "POST"}
	if !m.match(newMatchContext(req, "")) {
		t.Error("method matcher should be case-insensitive")
	}
}

func TestScopeOR(t *testing.T) {
	// A scope with multiple matchers is OR across them.
	a := mkMatcher(t, "path", "/a/*")
	b := mkMatcher(t, "method", "POST")
	sc := &scope{matchers: []*matcher{a, b}}
	c1 := newMatchContext(&Request{Method: "GET", Path: "/a/x"}, "")
	if !c1.scopeMatches(sc) {
		t.Error("scope should match via path arm")
	}
	c2 := newMatchContext(&Request{Method: "POST", Path: "/z"}, "")
	if !c2.scopeMatches(sc) {
		t.Error("scope should match via method arm")
	}
	c3 := newMatchContext(&Request{Method: "GET", Path: "/z"}, "")
	if c3.scopeMatches(sc) {
		t.Error("scope should not match")
	}
	if !newMatchContext(&Request{}, "").scopeMatches(nil) {
		t.Error("nil scope should always match")
	}
}

// TestQueryPresentMatcher: `query_present NAME…` matches if ANY named param is
// present (presence-OR), with `*` globs. Absent params do not match.
func TestQueryPresentMatcher(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		query url.Values
		want  bool
	}{
		{"exact-present", []string{"t"}, url.Values{"t": {"1"}}, true},
		{"exact-absent", []string{"t"}, url.Values{"x": {"1"}}, false},
		{"empty-value-present", []string{"a"}, url.Values{"a": {""}}, true}, // present even with empty value
		{"or-any-present", []string{"adult_content", "t", "a"}, url.Values{"a": {"1"}}, true},
		{"or-none-present", []string{"adult_content", "t", "a"}, url.Values{"z": {"1"}}, false},
		{"glob-present", []string{"ff-*"}, url.Values{"ff-x": {"1"}}, true},
		{"glob-absent", []string{"ff-*"}, url.Values{"ff": {"1"}}, false}, // "ff" is not "ff-*"
		{"glob-or-exact", []string{"adult_content", "t", "a", "p", "ff-*", "pub-*"}, url.Values{"pub-foo": {""}}, true},
		{"glob-or-exact-miss", []string{"adult_content", "t", "a", "p", "ff-*", "pub-*"}, url.Values{"utm_source": {"g"}}, false},
		{"no-query", []string{"t"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mkMatcher(t, "query_present", tt.args...)
			req := &Request{Path: "/", Query: tt.query}
			if got := m.match(newMatchContext(req, "")); got != tt.want {
				t.Errorf("query_present %v over %v = %v, want %v", tt.args, tt.query, got, tt.want)
			}
		})
	}
}

func TestQueryPresentNeedsName(t *testing.T) {
	if _, err := compileMatcher("m", "query_present", nil, cadishfile.Pos{}); err == nil {
		t.Fatal("want error for query_present with no param names")
	}
}

func TestUnknownMatcherType(t *testing.T) {
	_, err := compileMatcher("m", "bogus", []string{"x"}, cadishfile.Pos{File: "f", Line: 3, Col: 5})
	if err == nil {
		t.Fatal("want error for unknown matcher type")
	}
	ce, ok := err.(*CompileError)
	if !ok || ce.Pos.Line != 3 {
		t.Errorf("want CompileError with Pos.Line=3, got %v", err)
	}
}
