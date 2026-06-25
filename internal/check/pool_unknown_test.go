package check

import (
	"strings"
	"testing"
)

// TestPoolUnknownDirective is the G4 headline: a typo'd key inside an
// `upstream {}` pool block is a `cadish check` error (it would otherwise silently
// fall back to a default — e.g. host_hedaer → default Host → Apache 421). The lb
// build layer (internal/lb/parse.go) rejects it; the pre-flight gate surfaces that
// as a positioned `build-error` — exactly ONE diagnostic for the typo, no
// double-report.
func TestPoolUnknownDirective(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream blog {\n" +
		"    to https://1.2.3.4:443\n" +
		"    host_hedaer www.placercams.com\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	all := append([]Diagnostic{}, r.Diagnostics...)
	for _, s := range r.Sites {
		all = append(all, s.Diagnostics...)
	}
	var typo []Diagnostic
	for _, d := range all {
		if strings.Contains(d.Message, "host_hedaer") {
			typo = append(typo, d)
		}
	}
	if len(typo) != 1 {
		t.Fatalf("got %d diagnostics naming the typo (want exactly 1, no double-report): %v", len(typo), typo)
	}
	if d := typo[0]; d.Severity != SevError || d.Code != "build-error" || !strings.Contains(d.Position, ":") {
		t.Errorf("pool typo diagnostic = {sev:%v code:%q pos:%q}, want {error build-error file:line}", d.Severity, d.Code, d.Position)
	}
}

// TestPoolAllValidKeysClean verifies every valid pool key passes the unknown lint.
func TestPoolAllValidKeysClean(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream pool {\n" +
		"    to https://a:443 https://b:443\n" +
		"    policy round_robin\n" +
		"    sticky by cookie SID else client_ip\n" +
		"    health GET / expect 2xx 3xx interval 5s window 3 threshold 2\n" +
		"    timeout connect 5s first_byte 30s between_bytes 20s\n" +
		"    max_conns 800\n" +
		"    sni www.placercams.com\n" +
		"    http_reuse never\n" +
		"    host_header preserve\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("valid pool keys flagged unknown-directive: %d (%v)", n, codes(r))
	}
}

// TestPoolShardAndSignClean covers the shard_by + sign keys (a cluster pool and a
// CloudFront-signing upstream) — both valid, neither flagged.
func TestPoolShardAndSignClean(t *testing.T) {
	src := []byte("example.com {\n" +
		"  cluster peers {\n" +
		"    to k8s://varnish.default:6081\n" +
		"    shard_by url\n" +
		"  }\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("cluster pool valid keys flagged unknown-directive: %d (%v)", n, codes(r))
	}
}

// TestClusterMembershipKeysStillClean is a regression guard: the membership
// `cluster { self peers region mode fallback }` block (no name) must NOT be linted
// against the pool key set.
func TestClusterMembershipKeysStillClean(t *testing.T) {
	src := []byte(`example.com {
	cache { ram 64MiB }
	upstream backend { to http://origin.example.com }
	cluster {
		self     http://10.0.0.1:6081
		peers    http://10.0.0.1:6081 http://10.0.0.2:6081
		region   gra
		mode     owner
		fallback degraded
	}
	cache_ttl default ttl 60s
}
`)
	r, err := CheckSource("test.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unknown-directive"]; n != 0 {
		t.Errorf("membership block flagged unknown-directive: %d (%v)", n, codes(r))
	}
}
