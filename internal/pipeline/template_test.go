package pipeline

import (
	"net/http"
	"net/url"
	"testing"
)

func TestExpandTemplate(t *testing.T) {
	env := &TemplateEnv{
		Host:    "example.com",
		Path:    "/es/registro",
		Query:   "a=1&b=2",
		Capture: []string{"/es/registro", "registro"}, // $0 whole, $1 group
	}
	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"plain", "https://example.com/new", "https://example.com/new"},
		{"host", "https://{host}/x", "https://example.com/x"},
		{"path", "https://h{path}", "https://h/es/registro"},
		{"query", "https://h/p?{query}", "https://h/p?a=1&b=2"},
		{"uri", "https://h{uri}", "https://h/es/registro?a=1&b=2"},
		{"capture1", "https://{host}/en/$1", "https://example.com/en/registro"},
		{"capture0", "https://{host}$0", "https://example.com/es/registro"},
		{"capture-out-of-range", "x$5y", "xy"},
		{"dollar-literal", "price$$5", "price$5"},
		{"dollar-non-digit", "a$b", "a$b"},
		{"unknown-brace-kept", "{nope}/x", "{nope}/x"},
		{"unterminated-brace", "a{host", "a{host"},
		{"trailing-dollar", "a$", "a$"},
		{"empty", "", ""},
		{"combined", "https://{host}/en/$1?{query}", "https://example.com/en/registro?a=1&b=2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandTemplate(tc.tmpl, env, classifyResolver{}); got != tc.want {
				t.Fatalf("expandTemplate(%q) = %q, want %q", tc.tmpl, got, tc.want)
			}
		})
	}
}

func TestExpandTemplateNoCapture(t *testing.T) {
	// No capture slice: $1 expands to empty, named placeholders still work.
	env := &TemplateEnv{Host: "h", Path: "/p"}
	if got := expandTemplate("{host}$1{path}", env, classifyResolver{}); got != "h/p" {
		t.Fatalf("got %q, want %q", got, "h/p")
	}
}

func TestExpandTemplateQueryUriNoQuery(t *testing.T) {
	env := &TemplateEnv{Host: "h", Path: "/p"} // no query
	if got := expandTemplate("{uri}", env, classifyResolver{}); got != "/p" {
		t.Fatalf("uri without query = %q, want /p", got)
	}
}

// TestExpandTemplateRequestTokens covers the request-scoped tokens added by #17:
// {http.NAME} (a request header value) and {client_ip} (the resolved client IP).
func TestExpandTemplateRequestTokens(t *testing.T) {
	env := &TemplateEnv{
		Host:     "example.com",
		Path:     "/p",
		ClientIP: "203.0.113.7",
		Header: http.Header{
			"Origin":           {"https://app.example.com"},
			"X-Requested-With": {"XMLHttpRequest"},
		},
	}
	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"http-origin", "{http.Origin}", "https://app.example.com"},
		{"http-origin-canonicalized", "{http.origin}", "https://app.example.com"}, // header lookup is canonicalized
		{"http-embedded", "ACAO=({http.Origin})", "ACAO=(https://app.example.com)"},
		{"http-other", "{http.X-Requested-With}", "XMLHttpRequest"},
		{"http-absent", "[{http.X-Missing}]", "[]"}, // absent header -> empty
		{"client-ip", "{client_ip}", "203.0.113.7"},
		{"client-ip-embedded", "ip={client_ip};", "ip=203.0.113.7;"},
		{"http-empty-name", "{http.}", "{http.}"}, // no header name -> kept verbatim (unknown)
		{"static-with-host", "{host}/{client_ip}", "example.com/203.0.113.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expandTemplate(tc.tmpl, env, classifyResolver{}); got != tc.want {
				t.Fatalf("expandTemplate(%q) = %q, want %q", tc.tmpl, got, tc.want)
			}
		})
	}
}

// TestExpandTemplateRequestTokensNilHeader: {http.X} against a nil header set is
// empty, and {client_ip} against an empty ClientIP is empty.
func TestExpandTemplateRequestTokensNilHeader(t *testing.T) {
	env := &TemplateEnv{Host: "h"}
	if got := expandTemplate("a{http.Origin}b{client_ip}c", env, classifyResolver{}); got != "abc" {
		t.Fatalf("got %q, want %q", got, "abc")
	}
}

// TestExpandTemplateQueryParam covers {query.NAME}: resolves the first decoded value
// of the named query param, or "" when absent.
func TestExpandTemplateQueryParam(t *testing.T) {
	q := url.Values{}
	q.Set("genre", "comedy")
	q.Add("genre", "drama") // multi-value: only first is used
	q.Set("age", "25")
	// URL-encoded value: url.Values stores already-decoded values
	q.Set("cam_lang", "en-US")
	env := &TemplateEnv{
		Host:        "example.com",
		Path:        "/page",
		QueryParams: q,
	}
	tests := []struct {
		name string
		tmpl string
		want string
	}{
		{"present-first", "{query.genre}", "comedy"},    // first value only
		{"present-second-ignored", "{query.age}", "25"}, // single value
		{"cam-lang", "{query.cam_lang}", "en-US"},       // hyphenated key
		{"absent", "{query.missing}", ""},               // absent -> ""
		{"embedded", "x={query.genre}&y={query.age}", "x=comedy&y=25"},
		{"nil-params", "{query.x}", ""}, // nil QueryParams -> ""
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := *env // copy
			if tc.name == "nil-params" {
				e.QueryParams = nil
			}
			got := expandTemplate(tc.tmpl, &e, classifyResolver{})
			if got != tc.want {
				t.Fatalf("expandTemplate(%q) = %q, want %q", tc.tmpl, got, tc.want)
			}
		})
	}
}

// TestExpandTemplateDeviceToken covers {device}: resolves to the pre-pass device bucket.
func TestExpandTemplateDeviceToken(t *testing.T) {
	env := &TemplateEnv{Host: "example.com", Device: "mobile"}
	if got := expandTemplate("d={device}", env, classifyResolver{}); got != "d=mobile" {
		t.Fatalf("got %q, want %q", got, "d=mobile")
	}
	// empty Device expands to "" (consumed, not kept verbatim)
	env2 := &TemplateEnv{Host: "example.com"}
	if got := expandTemplate("[{device}]", env2, classifyResolver{}); got != "[]" {
		t.Fatalf("empty device: got %q, want %q", got, "[]")
	}
}
