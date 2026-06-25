package lb

import (
	"strings"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// parseDirective parses a single Cadishfile directive block from src and returns
// it, failing the test on a parse error.
func parseDirective(t *testing.T, src string) *cadishfile.Directive {
	t.Helper()
	// A bare `upstream x { ... }` at top level parses as a Site header; wrap it in
	// a site block so it parses as a nested Directive (how it appears in a real
	// Cadishfile).
	wrapped := "site.test {\n" + src + "\n}\n"
	f, err := cadishfile.Parse("test.cadish", []byte(wrapped))
	if err != nil {
		t.Fatalf("cadishfile.Parse: %v", err)
	}
	if len(f.Sites) == 0 {
		t.Fatalf("no site parsed from %q", src)
	}
	for _, n := range f.Sites[0].Body {
		if d, ok := n.(*cadishfile.Directive); ok {
			return d
		}
	}
	t.Fatalf("no directive parsed from %q", src)
	return nil
}

func TestParseUpstreamFull(t *testing.T) {
	src := `upstream web {
    to       http://10.0.0.1:8080 http://10.0.0.2:8080
    to       dns://varnish:8080
    sticky   by cookie PHPSESSID else client_ip
    health   GET / expect 301 interval 5s window 6 threshold 3
    timeout  connect 5s first_byte 600s between_bytes 30s
    max_conns 800
}`
	d := parseDirective(t, src)
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	if cfg.Name != "web" || cfg.Kind != "upstream" {
		t.Errorf("name/kind = %q/%q", cfg.Name, cfg.Kind)
	}
	if len(cfg.Backends) != 3 {
		t.Fatalf("backends = %d, want 3", len(cfg.Backends))
	}
	if cfg.Backends[2].Scheme != SchemeDNS || cfg.Backends[2].Port != "8080" {
		t.Errorf("3rd backend = %+v", cfg.Backends[2])
	}
	if cfg.Policy != Sticky {
		t.Errorf("policy = %v, want sticky", cfg.Policy)
	}
	if cfg.Sticky == nil || cfg.Sticky.Source != "cookie" || cfg.Sticky.Cookie != "PHPSESSID" || cfg.Sticky.Fallback != "client_ip" {
		t.Errorf("sticky = %+v", cfg.Sticky)
	}
	if cfg.Health == nil || cfg.Health.ExpectCode != 301 || cfg.Health.Interval != 5*time.Second || cfg.Health.Window != 6 || cfg.Health.Threshold != 3 {
		t.Errorf("health = %+v", cfg.Health)
	}
	if cfg.Timeouts.Connect != 5*time.Second || cfg.Timeouts.FirstByte != 600*time.Second || cfg.Timeouts.BetweenBytes != 30*time.Second {
		t.Errorf("timeouts = %+v", cfg.Timeouts)
	}
	if cfg.MaxConns != 800 {
		t.Errorf("max_conns = %d", cfg.MaxConns)
	}
}

// TestParseHealthExpectForms covers the single-int back-compat, exact-list, and
// class forms of `health … expect …` (gap G2).
func TestParseHealthExpectForms(t *testing.T) {
	tests := []struct {
		name    string
		expect  string
		code    int
		codes   []int
		classes []int
	}{
		{"single", "expect 301", 301, nil, nil},
		{"list", "expect 200 301", 0, []int{200, 301}, nil},
		{"class", "expect 2xx", 0, nil, []int{2}},
		{"class-list", "expect 2xx 3xx", 0, nil, []int{2, 3}},
		{"mixed", "expect 418 2xx", 0, []int{418}, []int{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "upstream web {\n  to http://10.0.0.1:8080\n  health GET / " + tt.expect + " interval 5s\n}"
			d := parseDirective(t, src)
			cfg, err := ParseUpstream(d)
			if err != nil {
				t.Fatalf("ParseUpstream: %v", err)
			}
			h := cfg.Health
			if h == nil {
				t.Fatal("health nil")
			}
			if h.ExpectCode != tt.code {
				t.Errorf("ExpectCode = %d, want %d", h.ExpectCode, tt.code)
			}
			if !intsEqual(h.ExpectCodes, tt.codes) {
				t.Errorf("ExpectCodes = %v, want %v", h.ExpectCodes, tt.codes)
			}
			if !intsEqual(h.ExpectClasses, tt.classes) {
				t.Errorf("ExpectClasses = %v, want %v", h.ExpectClasses, tt.classes)
			}
		})
	}
}

// TestParseHealthWindowBounds (Fix 4, security completeness) verifies the health
// `window N` is bounded: a sane value is accepted, while an absurd one (which would
// `make([]bool, N)` ~2GB per backend at pool construction) is rejected loudly rather
// than driving the allocation. Mirrors the replicas cap.
func TestParseHealthWindowBounds(t *testing.T) {
	ok := "upstream web {\n  to http://10.0.0.1:8080\n  health GET / expect 200 interval 5s window 5\n}"
	d := parseDirective(t, ok)
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatalf("window 5: unexpected error: %v", err)
	}
	if cfg.Health == nil || cfg.Health.Window != 5 {
		t.Fatalf("window = %v, want 5", cfg.Health)
	}

	bad := "upstream web {\n  to http://10.0.0.1:8080\n  health GET / expect 200 interval 5s window 2000000000\n}"
	d = parseDirective(t, bad)
	if _, err := ParseUpstream(d); err == nil {
		t.Fatalf("window 2000000000: want error, got nil")
	}
}

// TestParseHealthExpectBad rejects garbage expect tokens.
func TestParseHealthExpectBad(t *testing.T) {
	for _, expect := range []string{"expect", "expect abc", "expect 6xx", "expect 99"} {
		src := "upstream web {\n  to http://10.0.0.1:8080\n  health GET / " + expect + "\n}"
		d := parseDirective(t, src)
		if _, err := ParseUpstream(d); err == nil {
			t.Errorf("%q: want error, got nil", expect)
		}
	}
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseClusterShard(t *testing.T) {
	src := `cluster peers {
    to k8s://varnish-peers.default:6081
    shard_by url
}`
	d := parseDirective(t, src)
	cfg, err := ParseCluster(d)
	if err != nil {
		t.Fatalf("ParseCluster: %v", err)
	}
	if cfg.Kind != "cluster" || cfg.Policy != Shard || cfg.Shard != ShardURL {
		t.Errorf("cfg = %+v", cfg)
	}
	if cfg.Backends[0].Scheme != SchemeK8s {
		t.Errorf("scheme = %v", cfg.Backends[0].Scheme)
	}
}

func TestParseStickyClientIP(t *testing.T) {
	d := parseDirective(t, "upstream u {\n to http://h:80\n sticky by client_ip\n}")
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy != Sticky || cfg.Sticky.Source != "client_ip" {
		t.Errorf("sticky = %+v policy=%v", cfg.Sticky, cfg.Policy)
	}
}

func TestParseExplicitPolicy(t *testing.T) {
	d := parseDirective(t, "upstream u {\n to http://h:80\n policy least_conn\n}")
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy != LeastConn {
		t.Errorf("policy = %v", cfg.Policy)
	}
}

func TestParseDefaultsRoundRobin(t *testing.T) {
	d := parseDirective(t, "upstream u {\n to http://h:80\n}")
	cfg, err := ParseUpstream(d)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy != RoundRobin {
		t.Errorf("policy = %v, want round_robin", cfg.Policy)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring of the error message
	}{
		{"no name", "upstream {\n to http://h:80\n}", "exactly one name"},
		{"no backends", "upstream u {\n max_conns 5\n}", "no backends"},
		{"bad scheme", "upstream u {\n to ftp://h:80\n}", "unsupported backend scheme"},
		{"dns no port", "upstream u {\n to dns://svc\n}", "must include a port"},
		{"unknown directive", "upstream u {\n to http://h:80\n frobnicate x\n}", "unknown directive"},
		{"sticky+shard", "upstream u {\n to http://h:80\n sticky by client_ip\n shard_by url\n}", "mutually exclusive"},
		{"bad shard_by", "upstream u {\n to http://h:80\n shard_by sideways\n}", "want `url` or `key`"},
		{"health no expect", "upstream u {\n to http://h:80\n health GET / interval 5s\n}", "missing `expect"},
		{"bad policy", "upstream u {\n to http://h:80\n policy magic\n}", "unknown policy"},
		{"bad max_conns", "upstream u {\n to http://h:80\n max_conns abc\n}", "wants an integer"},
		{"bad timeout dur", "upstream u {\n to http://h:80\n timeout connect 5z\n}", "bad duration"},
		{"sticky bad src", "upstream u {\n to http://h:80\n sticky by token X\n}", "unknown source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := parseDirective(t, tc.src)
			var cfg Config
			var err error
			if d.Name == "cluster" {
				cfg, err = ParseCluster(d)
			} else {
				cfg, err = ParseUpstream(d)
			}
			_ = cfg
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
			// Positioned error: must be a *cadishfile.ParseError rendering file:line.
			if pe, ok := err.(*cadishfile.ParseError); !ok {
				t.Errorf("error is %T, want *cadishfile.ParseError", err)
			} else if !strings.Contains(pe.Error(), "test.cadish") {
				t.Errorf("error %q lacks file position", pe.Error())
			}
		})
	}
}

func TestParseWrongDirectiveName(t *testing.T) {
	d := parseDirective(t, "cluster peers {\n to http://h:80\n}")
	if _, err := ParseUpstream(d); err == nil {
		t.Fatal("ParseUpstream on a cluster directive should error")
	}
}

func TestParseTargetK8s(t *testing.T) {
	t.Run("numeric port", func(t *testing.T) {
		got, err := parseTarget("k8s://web.prod:8080", cadishfile.Pos{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Scheme != SchemeK8s || got.Service != "web" || got.Namespace != "prod" || got.Port != "8080" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("named port", func(t *testing.T) {
		got, err := parseTarget("k8s://web.prod:http", cadishfile.Pos{})
		if err != nil || got.Port != "http" || got.Service != "web" || got.Namespace != "prod" {
			t.Fatalf("got %+v err %v", got, err)
		}
	})
	t.Run("missing namespace is rejected", func(t *testing.T) {
		if _, err := parseTarget("k8s://web:8080", cadishfile.Pos{}); err == nil {
			t.Fatal("expected error for missing namespace")
		}
	})
	t.Run("fqdn-style namespace is rejected", func(t *testing.T) {
		if _, err := parseTarget("k8s://web.prod.svc.cluster.local:8080", cadishfile.Pos{}); err == nil {
			t.Fatal("expected error: namespace must be a single label")
		}
	})
	t.Run("missing port is rejected", func(t *testing.T) {
		if _, err := parseTarget("k8s://web.prod", cadishfile.Pos{}); err == nil {
			t.Fatal("expected error for missing port (dynamic target)")
		}
	})
}

// TestParseTargetRejectsLinkLocal is the SSRF defense-in-depth guard (FIX 1): a `to`
// target whose host is a link-local / cloud-metadata literal must be rejected, so a
// config (or a leaked policy fragment) cannot make cadish proxy the cloud IMDS at
// 169.254.169.254. Private/RFC1918 ranges and k8s:// targets stay legal (pod IPs and
// private origins are legitimate).
func TestParseTargetRejectsLinkLocal(t *testing.T) {
	blocked := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254",
		"https://169.254.0.1",
		"169.254.169.254:80",
		"http://[fe80::1]:80",
		"dns://169.254.169.254:80",
		"k8s://169.254.169.254:80", // host is not a valid svc.ns but the IP guard catches it
	}
	for _, tok := range blocked {
		if _, err := parseTarget(tok, cadishfile.Pos{}); err == nil {
			t.Errorf("expected link-local/metadata target %q to be rejected", tok)
		}
	}
	allowed := []string{
		"http://10.0.0.5",
		"http://10.0.0.5:8080",
		"http://192.168.1.1:80",
		"http://172.16.0.1:80",
		"k8s://svc.ns:80",
		"http://example.com:80",
	}
	for _, tok := range allowed {
		if _, err := parseTarget(tok, cadishfile.Pos{}); err != nil {
			t.Errorf("expected legitimate target %q to parse, got %v", tok, err)
		}
	}
}
