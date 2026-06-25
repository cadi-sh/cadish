package pipeline

import (
	"net/http"
	"testing"
)

// TestHeaderPresentMatcher is the G3 fix: a templated reflected-Origin CORS header
// scoped on `@has_origin header_present Origin` fires ONLY when the request carries
// an Origin header — so a non-CORS request keeps the default ACAO and never gets a
// malformed empty `Access-Control-Allow-Origin:`.
func TestHeaderPresentMatcher(t *testing.T) {
	p := compileSrc(t, `x {
		@has_origin header_present Origin
		cache_key host path
		header Access-Control-Allow-Origin https://{host}
		header @has_origin +Access-Control-Allow-Origin {http.Origin}
		header @has_origin +Vary Origin
	}
`)

	// No Origin → the scoped ops do NOT fire: only the default ACAO is present, no
	// empty ACAO, no Vary: Origin.
	got := deliverHeaderOps(t, p, &Request{Host: "site.example", Path: "/vast", Header: http.Header{}})
	if v, ok := got["Access-Control-Allow-Origin"]; !ok {
		t.Fatalf("default ACAO missing; ops=%v", got)
	} else if len(v) != 1 {
		t.Errorf("with no Origin, ACAO should have exactly the default value, got %v", v)
	}
	if _, ok := got["Vary"]; ok {
		t.Errorf("with no Origin, Vary: Origin must not be emitted; ops=%v", got)
	}

	// With an Origin → the scoped ops fire: ACAO is reflected and Vary: Origin set.
	got = deliverHeaderOps(t, p, &Request{
		Host: "site.example", Path: "/vast",
		Header: http.Header{"Origin": {"https://app.partner.test"}},
	})
	acao := got["Access-Control-Allow-Origin"]
	if len(acao) == 0 || acao[len(acao)-1] != "https://app.partner.test" {
		t.Errorf("with Origin, ACAO should reflect it (last value), got %v", acao)
	}
	if got["Vary"] == nil {
		t.Errorf("with Origin, Vary: Origin should be emitted; ops=%v", got)
	}
}

// TestHeaderPresentEmptyValueStillPresent confirms an Origin header set to "" still
// counts as present (matches the raw header map, like the `header NAME` form).
func TestHeaderPresentEmptyValueStillPresent(t *testing.T) {
	p := compileSrc(t, `x {
		@has_origin header_present Origin
		cache_key host path
		header @has_origin +X-Had-Origin yes
	}
`)
	got := deliverHeaderOps(t, p, &Request{Host: "x", Path: "/", Header: http.Header{"Origin": {""}}})
	if got["X-Had-Origin"] == nil {
		t.Errorf("empty-but-present Origin should match header_present; ops=%v", got)
	}
}

// deliverHeaderOps runs the deliver-phase header ops for a request and returns them
// as an http.Header-shaped multimap (op order preserved per name).
func deliverHeaderOps(t *testing.T, p *Pipeline, req *Request) http.Header {
	t.Helper()
	dec := p.EvalDeliver(req, http.Header{}, CacheStatusMiss)
	h := http.Header{}
	for _, op := range dec.RespHeaderOps {
		h[op.Name] = append(h[op.Name], op.Value)
	}
	return h
}
