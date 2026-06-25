package pipeline

import (
	"net/http"
	"testing"
)

// TestDenyExactHeaderNotBypassedByDuplicate is the WAF1 security guard: a `deny` gated
// on an exact `header NAME VALUE` matcher must fire when VALUE appears in ANY of the
// header's values — not only the first. A benign first value must not hide a blocked
// second value (an access-control bypass).
func TestDenyExactHeaderNotBypassedByDuplicate(t *testing.T) {
	p := compileSrc(t, `example.com {
	@badagent header User-Agent BadBot/1.0
	deny @badagent
	cache_ttl default ttl 60s
}
`)
	mk := func(vals ...string) *Request {
		return &Request{Host: "example.com", Path: "/", Header: http.Header{"User-Agent": vals}}
	}
	cases := []struct {
		name  string
		req   *Request
		block bool
	}{
		{"only bad", mk("BadBot/1.0"), true},
		{"bad first, good second", mk("BadBot/1.0", "GoodBot/2.0"), true},
		{"good first, bad second (the bypass)", mk("GoodBot/2.0", "BadBot/1.0"), true},
		{"only good", mk("GoodBot/2.0"), false},
		{"absent", &Request{Host: "example.com", Path: "/"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := p.EvalSecurity(c.req).Block; got != c.block {
				t.Errorf("Block = %v, want %v", got, c.block)
			}
		})
	}
}
