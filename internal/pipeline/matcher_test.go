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

// mustParseQuery parses a raw query string the way the server does (url.ParseQuery,
// the same parser feeding Request.Query), so a test can prove the parse path — e.g.
// that a bare `?p` (no `=`) yields {"p":[""]}.
func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery(%q): %v", raw, err)
	}
	return v
}

// TestQueryPresentNonEmpty tests the `+` modifier: a `+`-flagged name requires the
// param to be present AND have at least one non-empty value. An unflagged name keeps
// plain presence semantics (empty value still matches).
func TestQueryPresentNonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		query url.Values
		want  bool
	}{
		// +modifier: non-empty required
		{"nonempty-match", []string{"p+"}, url.Values{"p": {"x"}}, true},
		{"nonempty-empty-val", []string{"p+"}, url.Values{"p": {""}}, false},
		// Bare `?p` (no `=`): url.ParseQuery("p") yields {"p":[""]} — present with an
		// empty value, IDENTICAL to `?p=` and DISTINCT from "param absent entirely". A
		// `+`-flagged name must NOT match it (no non-empty value), proving the bare-param
		// form is treated as empty (Varnish `=[^&]+` parity). Built from the real parser
		// so the parse path itself is exercised, not just a hand-built map.
		{"nonempty-bare-param", []string{"p+"}, mustParseQuery(t, "p"), false},
		// Same bare param, but the name is UNflagged (presence-only) → it DOES match,
		// confirming the bare-param form is "present".
		{"plain-bare-param", []string{"p"}, mustParseQuery(t, "p"), true},
		{"nonempty-absent", []string{"p+"}, url.Values{"other": {"x"}}, false},
		// +modifier: repeated param, at least one non-empty wins
		{"nonempty-repeated-one-nonempty", []string{"p+"}, url.Values{"p": {"", "abc"}}, true},
		{"nonempty-repeated-all-empty", []string{"p+"}, url.Values{"p": {"", ""}}, false},
		// unflagged name still matches with empty value
		{"plain-empty-val", []string{"q"}, url.Values{"q": {""}}, true},
		{"plain-nonempty-val", []string{"q"}, url.Values{"q": {"y"}}, true},
		// mixed: one +flagged, one plain
		{"mixed-flagged-hits", []string{"p+", "q"}, url.Values{"p": {"x"}}, true},
		{"mixed-plain-empty-hits", []string{"p+", "q"}, url.Values{"q": {""}}, true},
		{"mixed-flagged-empty-plain-absent", []string{"p+", "q"}, url.Values{"p": {""}}, false},
		// glob with + modifier
		{"glob-nonempty-match", []string{"ff-*+"}, url.Values{"ff-foo": {"bar"}}, true},
		{"glob-nonempty-empty-val", []string{"ff-*+"}, url.Values{"ff-foo": {""}}, false},
		{"glob-plain-name", []string{"ff-*"}, url.Values{"ff-foo": {""}}, true},
		// no query params
		{"no-query", []string{"p+"}, nil, false},
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

// TestQueryPresentBarePlusRejected: a degenerate bare `+` (no name before it) strips to
// an empty name and must be rejected at compile, not silently become a dead empty-name
// glob.
func TestQueryPresentBarePlusRejected(t *testing.T) {
	if _, err := compileMatcher("m", "query_present", []string{"+"}, cadishfile.Pos{}); err == nil {
		t.Fatal("want error for query_present with a bare `+` arg")
	}
	// Also reject it when mixed with a valid name.
	if _, err := compileMatcher("m", "query_present", []string{"ok", "+"}, cadishfile.Pos{}); err == nil {
		t.Fatal("want error for query_present with a bare `+` among valid names")
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
