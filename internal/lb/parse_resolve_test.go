package lb

import (
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// parseUpstreamSrc parses a single `upstream NAME { ... }` block from src.
func parseUpstreamSrc(t *testing.T, src string) (Config, error) {
	t.Helper()
	f, err := cadishfile.Parse("test", []byte(src))
	if err != nil {
		t.Fatalf("cadishfile.Parse: %v", err)
	}
	for _, n := range f.Sites {
		for _, bn := range n.Body {
			if d, ok := bn.(*cadishfile.Directive); ok && d.Name == "upstream" {
				return ParseUpstream(d)
			}
		}
	}
	t.Fatal("no upstream directive found")
	return Config{}, nil
}

func TestParseResolveForms(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantIv  time.Duration
		wantNS  []string
		wantErr bool
	}{
		{
			name:   "interval only",
			body:   "resolve 10s",
			wantIv: 10 * time.Second,
		},
		{
			name:   "nameserver only",
			body:   "resolve nameserver 10.134.8.94:53",
			wantNS: []string{"10.134.8.94:53"},
		},
		{
			name:   "interval and multiple nameservers",
			body:   "resolve 10s nameserver 10.134.8.94:53 10.134.8.95:53",
			wantIv: 10 * time.Second,
			wantNS: []string{"10.134.8.94:53", "10.134.8.95:53"},
		},
		{
			name:    "bare resolve is an error",
			body:    "resolve",
			wantErr: true,
		},
		{
			name:    "nameserver keyword without value",
			body:    "resolve nameserver",
			wantErr: true,
		},
		{
			name:    "garbage interval",
			body:    "resolve notaduration nameserver 1.2.3.4:53",
			wantErr: true,
		},
		{
			// Finding 8: a `host:label` shape passes net.SplitHostPort but the non-numeric
			// port is almost certainly a typo and fails at dial time — reject it at parse.
			name:    "non-numeric port",
			body:    "resolve nameserver dns.internal:domain",
			wantErr: true,
		},
		{
			name:    "out-of-range port",
			body:    "resolve nameserver 10.0.0.1:70000",
			wantErr: true,
		},
		{
			name:    "bare hostname (no port)",
			body:    "resolve nameserver dns.internal",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "example.com {\n  upstream legacy_dns {\n    to dns://legacy.invalid:80\n    " + tc.body + "\n  }\n}\n"
			cfg, err := parseUpstreamSrc(t, src)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error for %q, got nil", tc.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUpstream(%q): %v", tc.body, err)
			}
			if cfg.ResolveInterval != tc.wantIv {
				t.Fatalf("ResolveInterval = %v, want %v", cfg.ResolveInterval, tc.wantIv)
			}
			if len(cfg.Nameservers) != len(tc.wantNS) {
				t.Fatalf("Nameservers = %v, want %v", cfg.Nameservers, tc.wantNS)
			}
			for i := range tc.wantNS {
				if cfg.Nameservers[i] != tc.wantNS[i] {
					t.Fatalf("Nameservers[%d] = %q, want %q", i, cfg.Nameservers[i], tc.wantNS[i])
				}
			}
		})
	}
}
