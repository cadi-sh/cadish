package check

import "testing"

// TestCacheTTLDeadStatusWarns is the D6 guard: `cadish check` warns that a
// `cache_ttl status <code>` caching rule on a status cadish never stores (anything
// other than 200 / 404 / 410) is dead config, instead of silently accepting it.
func TestCacheTTLDeadStatusWarns(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantWarn bool
	}{
		{
			name:     "cache_ttl status 301 ttl is dead (redirects not cached)",
			src:      "example.com {\n  cache_ttl status 301 ttl 1h\n  upstream a { to http://localhost:8080 }\n}\n",
			wantWarn: true,
		},
		{
			name:     "cache_ttl status 500 ttl is NOT dead (explicit status opts into error caching)",
			src:      "example.com {\n  cache_ttl status 500 ttl 30s\n  upstream a { to http://localhost:8080 }\n}\n",
			wantWarn: false,
		},
		{
			name:     "cache_ttl status 404 410 ttl is fine (negative caching)",
			src:      "example.com {\n  cache_ttl status 404 410 ttl 60s\n  upstream a { to http://localhost:8080 }\n}\n",
			wantWarn: false,
		},
		{
			name:     "cache_ttl status 200 ttl is fine",
			src:      "example.com {\n  cache_ttl status 200 ttl 5m\n  upstream a { to http://localhost:8080 }\n}\n",
			wantWarn: false,
		},
		{
			name:     "cache_ttl status 500 hit_for_miss is NOT dead (HFM is a non-store decision)",
			src:      "example.com {\n  cache_ttl status 500 hit_for_miss 5s\n  upstream a { to http://localhost:8080 }\n}\n",
			wantWarn: false,
		},
		{
			name:     "storage status 302 -> disk is dead",
			src:      "example.com {\n  storage status 302 -> disk\n  upstream a { to http://localhost:8080 }\n}\n",
			wantWarn: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := CheckSource("d6.cadish", []byte(tc.src))
			if err != nil {
				t.Fatalf("CheckSource: %v", err)
			}
			got := codes(r)["dead-status-rule"] > 0
			if got != tc.wantWarn {
				t.Errorf("dead-status-rule warning = %v, want %v; codes=%v", got, tc.wantWarn, codes(r))
			}
		})
	}
}
