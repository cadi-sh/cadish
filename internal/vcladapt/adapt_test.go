package vcladapt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// TestAdaptIdioms is table-driven over small VCL snippets, asserting the emitted
// Cadishfile contains the expected fragment(s).
func TestAdaptIdioms(t *testing.T) {
	tests := []struct {
		name string
		vcl  string
		want []string // substrings that must appear
		not  []string // substrings that must NOT appear
	}{
		{
			name: "backend with probe",
			vcl:  `backend web { .host = "10.0.0.1"; .port = "8080"; .probe = { .url = "/"; .expected_response = 200; .interval = 5s; } }`,
			want: []string{"upstream web {", "to http://10.0.0.1:8080", "health GET / expect 200 interval 5s"},
		},
		{
			name: "pass url rules collapse to @nocache",
			vcl:  `sub vcl_recv { if (req.url ~ "/admin/" || req.url ~ "/panel/") { return(pass); } }`,
			want: []string{"@nocache path /admin/* /panel/*", "pass @nocache"},
		},
		{
			name: "pass method POST",
			vcl:  `sub vcl_recv { if (req.method == "POST") { return(pass); } }`,
			want: []string{"pass method POST"},
		},
		{
			name: "regex url → pass path_regex",
			vcl:  `sub vcl_recv { if (req.url ~ "\.(jpg|png)$") { return(pass); } }`,
			want: []string{`pass path_regex "\.(jpg|png)$"`},
		},
		{
			name: "header presence → pass header",
			vcl:  `sub vcl_recv { if (req.http.X-Requested-With) { return(pass); } }`,
			want: []string{"pass header X-Requested-With"},
		},
		{
			name: "synth health → respond",
			vcl:  `sub vcl_recv { if (req.url == "/health") { return(synth(200, "OK")); } }`,
			want: []string{`respond /health 200 "OK"`},
		},
		{
			name: "backend_hint by host → route",
			vcl:  `sub vcl_recv { if (req.http.host ~ "static") { set req.backend_hint = images; } }`,
			want: []string{`host_regex "static"`, "route @host1 -> images"},
		},
		{
			name: "status ttl/grace",
			vcl:  `sub vcl_backend_response { if (beresp.status == 404 || beresp.status == 410) { set beresp.ttl = 60s; set beresp.grace = 1h; } }`,
			want: []string{"cache_ttl status 404 410 ttl 60s grace 1h"},
		},
		{
			name: "status not 200 uncacheable → hit_for_miss",
			vcl:  `sub vcl_backend_response { if (beresp.status != 200) { set beresp.ttl = 5s; set beresp.uncacheable = true; } }`,
			want: []string{"cache_ttl status not 200 hit_for_miss 5s"},
		},
		{
			name: "default ttl",
			vcl:  `sub vcl_backend_response { set beresp.ttl = 2s; set beresp.grace = 24h; }`,
			want: []string{"cache_ttl default ttl 2s grace 24h"},
		},
		{
			name: "hash → cache_key",
			vcl:  `sub vcl_hash { hash_data(req.url); hash_data(req.http.host); hash_data(req.http.X-Currency); }`,
			want: []string{"cache_key url host header:X-Currency"},
		},
		{
			name: "strip cookies + headers",
			vcl:  `sub vcl_backend_response { unset beresp.http.Set-Cookie; unset beresp.http.Server; set beresp.http.X-Foo = "bar"; }`,
			want: []string{"strip_cookies", "header -Server", `header X-Foo "bar"`},
		},
		{
			name: "deliver response headers",
			vcl:  `sub vcl_deliver { set resp.http.X-Cache = "HIT"; unset resp.http.X-Varnish; }`,
			want: []string{`header X-Cache "HIT"`, "header -X-Varnish"},
		},
		{
			name: "acl + import → TODO",
			vcl:  `import std; acl purgers { "127.0.0.1"; }`,
			want: []string{"TODO(adapt): acl purgers", "TODO(adapt): import std"},
		},
		{
			name: "regsub header value → TODO not a literal header",
			vcl:  `sub vcl_recv { set req.http.X-Sticky = regsub(req.http.Cookie, "a", "b"); }`,
			want: []string{"TODO(adapt)"},
			not:  []string{"header X-Sticky"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Adapt("t.vcl", tt.vcl).Cadishfile
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in:\n%s", w, out)
				}
			}
			for _, nw := range tt.not {
				if strings.Contains(out, nw) {
					t.Errorf("unexpected %q in:\n%s", nw, out)
				}
			}
		})
	}
}

// TestAdaptCounts checks the mapped/TODO accounting.
func TestAdaptCounts(t *testing.T) {
	r := Adapt("t.vcl", `import std; acl a { "1.2.3.4"; } sub vcl_recv { if (req.method == "POST") { return(pass); } }`)
	if r.Mapped != 1 {
		t.Errorf("Mapped = %d, want 1", r.Mapped)
	}
	if r.TODOs != 2 { // import + acl
		t.Errorf("TODOs = %d, want 2", r.TODOs)
	}
}

// TestAdaptedSkeletonParses adapts the full synthetic VCL and asserts the emitted
// Cadishfile actually parses (the skeleton must be a valid starting point).
func TestAdaptedSkeletonParses(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sample.vcl"))
	if err != nil {
		t.Fatal(err)
	}
	r := Adapt("sample.vcl", string(src))
	if r.Mapped < 10 {
		t.Errorf("Mapped = %d, want >= 10 for the sample", r.Mapped)
	}
	if _, err := cadishfile.Parse("adapted.cadish", []byte(r.Cadishfile)); err != nil {
		t.Fatalf("adapted skeleton does not parse: %v\n%s", err, r.Cadishfile)
	}
	// Formatting it must also succeed (stronger: it round-trips through fmt).
	if _, err := cadishfile.Format([]byte(r.Cadishfile)); err != nil {
		t.Fatalf("adapted skeleton does not format: %v", err)
	}
}

// TestAdaptDeeplyNestedIfDoesNotOverflow (Fix 3, security completeness): pathologically
// deep `if(){…}` nesting must NOT recurse without bound and abort the process with an
// uncatchable "goroutine stack exceeds" fatal. parseBlock->parseIf->parseBraceBlock->
// parseBlock now carries a depth cap (mirrors cadishfile's maxBlockDepth), so an
// adversarial VCL drains cleanly into a non-nil Result instead of crashing. Reachable via
// `cadish adapt` on operator-supplied VCL.
func TestAdaptDeeplyNestedIfDoesNotOverflow(t *testing.T) {
	// Far above maxParseDepth so the cap definitely engages, yet small enough to build fast.
	const n = maxParseDepth + 5000
	var b strings.Builder
	b.WriteString("sub vcl_recv {\n")
	for i := 0; i < n; i++ {
		b.WriteString("if (req.url ~ \"x\") {\n")
	}
	for i := 0; i < n; i++ {
		b.WriteString("}\n")
	}
	b.WriteString("}\n")

	r := Adapt("deep.vcl", b.String())
	if r == nil {
		t.Fatalf("Adapt returned nil for deeply-nested VCL")
	}
}

// TestAdaptEmpty handles trivial/empty input without panicking.
func TestAdaptEmpty(t *testing.T) {
	r := Adapt("e.vcl", "vcl 4.1;\n")
	if r == nil || !strings.Contains(r.Cadishfile, "example.com") {
		t.Errorf("empty adapt did not produce a skeleton: %+v", r)
	}
}
