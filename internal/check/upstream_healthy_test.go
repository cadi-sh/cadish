package check

import (
	"strings"
	"testing"
)

// TestUpstreamHealthyRecognized: `upstream_healthy` is a known matcher type, and a
// matcher used ONLY to scope a terminal `respond @probe @live 200` must NOT be flagged
// unused (the scoped-respond named-matcher pass charges it — same path as the existing
// scoped-respond / security regression guards).
func TestUpstreamHealthyRecognized(t *testing.T) {
	src := []byte(`example.com {
    @probe path /aws-health-check
    @live  upstream_healthy cache_pool
    respond @probe @live 200 "OK"
    respond @probe 503
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	c := codes(r)
	if c["unknown-matcher-type"] != 0 {
		t.Errorf("upstream_healthy is a known matcher type; codes=%v", c)
	}
	if c["unused-matcher"] != 0 {
		t.Errorf("@live (and @probe) scope a terminal respond and must not be flagged unused; codes=%v", c)
	}
}

// TestUpstreamHealthyNonPoolWarns is the R03 check diagnostic: `upstream_healthy single`
// where `single` is a TRIVIAL single-backend upstream (httporigin, no health FSM) warns
// — the matcher can never report it down. The warning carries the pool name and the
// `health { … }` remedy.
func TestUpstreamHealthyNonPoolWarns(t *testing.T) {
	src := []byte(`example.com {
    cache { ram 16MiB }
    upstream single { to https://1.2.3.4:443 }
    @probe path /aws-health-check
    @live  upstream_healthy single
    respond @probe @live 200 "OK"
    respond @probe 503
    cache_ttl default ttl 300s
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if codes(r)["upstream-healthy-non-pool"] == 0 {
		t.Fatalf("expected an upstream-healthy-non-pool warning for a trivial single-backend upstream; codes=%v", codes(r))
	}
	var msg string
	for _, s := range r.Sites {
		for _, d := range s.Diagnostics {
			if d.Code == "upstream-healthy-non-pool" {
				msg = d.Message
			}
		}
	}
	if !strings.Contains(msg, "single") || !strings.Contains(msg, "health") {
		t.Errorf("warning should name the pool and the `health` remedy; got %q", msg)
	}
}

// TestUpstreamHealthyRealPoolClean is the negative case: a multi-backend (or
// health-probed) pool DOES carry pool health, so it must NOT warn.
func TestUpstreamHealthyRealPoolClean(t *testing.T) {
	src := []byte(`example.com {
    cache { ram 16MiB }
    upstream pool {
        to https://a:443
        health GET /healthz expect 200 interval 5s window 1 threshold 1
    }
    @probe path /aws-health-check
    @live  upstream_healthy pool
    respond @probe @live 200 "OK"
    respond @probe 503
    cache_ttl default ttl 300s
}`)
	r, err := CheckSource("c.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["upstream-healthy-non-pool"]; n != 0 {
		t.Errorf("a health-probed pool carries pool health and must not warn; got %d (%v)", n, codes(r))
	}
}
