package pipeline

import (
	"strings"
	"testing"
)

// The `upstream_healthy NAME…` matcher composes with scoped `respond` to express the
// AWS LB probe: 200 when a named pool has a live backend, else 503. It names pools
// EXPLICITLY (independent of routing), resolving liveness via the server-injected
// Request.PoolHealthy view.
const probeSrc = `x {
	@probe path /aws-health-check
	@live  upstream_healthy cache_pool
	respond @probe @live 200 "OK"
	respond @probe 503
}
`

func TestUpstreamHealthyProbeLive(t *testing.T) {
	p := compileSrc(t, probeSrc)
	if !p.NeedsPoolHealth() {
		t.Fatal("a pipeline referencing upstream_healthy must report NeedsPoolHealth")
	}
	// Pool live ⇒ @live true ⇒ first respond fires 200.
	req := &Request{Method: "GET", Path: "/aws-health-check", PoolHealthy: func(name string) bool {
		return name == "cache_pool"
	}}
	dec := p.EvalRequest(req)
	if dec.Synthetic == nil || dec.Synthetic.Status != 200 || dec.Synthetic.Body != "OK" {
		t.Fatalf("live probe synthetic = %+v, want {200 OK}", dec.Synthetic)
	}
}

func TestUpstreamHealthyProbeDown(t *testing.T) {
	p := compileSrc(t, probeSrc)
	// Pool down ⇒ @live false ⇒ falls through to the terminal `respond @probe 503`.
	req := &Request{Method: "GET", Path: "/aws-health-check", PoolHealthy: func(string) bool { return false }}
	dec := p.EvalRequest(req)
	if dec.Synthetic == nil || dec.Synthetic.Status != 503 {
		t.Fatalf("down probe synthetic = %+v, want status 503", dec.Synthetic)
	}
}

// A non-probe path matches neither respond and is not synthetic.
func TestUpstreamHealthyNonProbePath(t *testing.T) {
	p := compileSrc(t, probeSrc)
	req := &Request{Method: "GET", Path: "/other", PoolHealthy: func(string) bool { return true }}
	if dec := p.EvalRequest(req); dec.Synthetic != nil {
		t.Fatalf("non-probe path should not be synthetic, got %+v", dec.Synthetic)
	}
}

// When PoolHealthy is nil (server did not inject it) the matcher fails CLOSED — the
// pool is treated as down, so the probe answers 503 rather than spuriously 200.
func TestUpstreamHealthyNilViewFailsClosed(t *testing.T) {
	p := compileSrc(t, probeSrc)
	req := &Request{Method: "GET", Path: "/aws-health-check"} // PoolHealthy nil
	dec := p.EvalRequest(req)
	if dec.Synthetic == nil || dec.Synthetic.Status != 503 {
		t.Fatalf("nil PoolHealthy must fail closed (503), got %+v", dec.Synthetic)
	}
}

// ANY semantics across multiple named pools: true as soon as ONE listed pool is live.
func TestUpstreamHealthyMultiPoolANY(t *testing.T) {
	p := compileSrc(t, `x {
		@probe path /h
		@live  upstream_healthy a b
		respond @probe @live 200 "OK"
		respond @probe 503
	}
`)
	// Only b is live ⇒ ANY ⇒ 200.
	req := &Request{Method: "GET", Path: "/h", PoolHealthy: func(name string) bool { return name == "b" }}
	if dec := p.EvalRequest(req); dec.Synthetic == nil || dec.Synthetic.Status != 200 {
		t.Fatalf("ANY: one live pool should answer 200, got %+v", dec.Synthetic)
	}
	// Neither live ⇒ 503.
	req2 := &Request{Method: "GET", Path: "/h", PoolHealthy: func(string) bool { return false }}
	if dec := p.EvalRequest(req2); dec.Synthetic == nil || dec.Synthetic.Status != 503 {
		t.Fatalf("ANY: no live pool should answer 503, got %+v", dec.Synthetic)
	}
}

// A site that does NOT use the matcher must report NeedsPoolHealth()==false so the
// server keeps the fast path zero-cost (no per-request pool-health snapshot).
func TestNeedsPoolHealthFalseWhenAbsent(t *testing.T) {
	p := compileSrc(t, "x {\n respond /health 200 \"OK\"\n}\n")
	if p.NeedsPoolHealth() {
		t.Fatal("a pipeline with no upstream_healthy matcher must report NeedsPoolHealth()==false")
	}
}

// upstream_healthy needs at least one pool name.
func TestUpstreamHealthyNeedsAname(t *testing.T) {
	compileErr(t, "x {\n @x upstream_healthy\n pass @x\n}\n")
}

// Finding I1: an `upstream_healthy NAME…` argument that does NOT resolve to a DECLARED
// upstream/cluster pool is a positioned compile error — exactly like a `route -> UPSTREAM`
// or `origin chain` naming an undeclared pool. A typo there makes the matcher fail closed
// at runtime (PoolHealthy returns false for an unknown pool) so the AWS health probe
// answers 503 forever and an L4/DNS LB pulls the node — the worst, silent degradation.
// check≡run: both reach Compile, so both reject identically.
func TestUpstreamHealthyUndeclaredPoolRejected(t *testing.T) {
	ce := compileErr(t, `x {
		upstream cache_pool { to http://h:80 }
		@probe path /aws-health-check
		@live  upstream_healthy nope
		respond @probe @live 200 "OK"
		respond @probe 503
	}
`)
	if !strings.Contains(ce.Error(), "nope") {
		t.Errorf("error should name the unknown pool %q; got %q", "nope", ce.Error())
	}
	if !strings.Contains(ce.Error(), "not a declared upstream/cluster") {
		t.Errorf("error should read like the route/origin-chain undeclared-upstream error; got %q", ce.Error())
	}
	if ce.Pos.Line == 0 {
		t.Errorf("undeclared upstream_healthy error must carry a source position; got %q", ce.Error())
	}
}

// The SAME config naming the REAL declared pool compiles cleanly (no over-rejection).
func TestUpstreamHealthyDeclaredPoolPasses(t *testing.T) {
	compileSrc(t, `x {
		upstream cache_pool { to http://h:80 }
		@probe path /aws-health-check
		@live  upstream_healthy cache_pool
		respond @probe @live 200 "OK"
		respond @probe 503
	}
`)
}

// A `cluster` pool name is equally valid (clusters are pools too).
func TestUpstreamHealthyClusterPoolPasses(t *testing.T) {
	compileSrc(t, `x {
		cluster peers { to k8s://varnish.default:6081 }
		@probe path /h
		@live  upstream_healthy peers
		respond @probe @live 200 "OK"
		respond @probe 503
	}
`)
}

// ANY semantics: EACH listed name is validated, so an undeclared name beside a declared
// one is still rejected (the typo must not hide behind a valid sibling).
func TestUpstreamHealthyMultiNameEachValidated(t *testing.T) {
	ce := compileErr(t, `x {
		upstream a { to http://h:80 }
		@probe path /h
		@live  upstream_healthy a nope
		respond @probe @live 200 "OK"
		respond @probe 503
	}
`)
	if !strings.Contains(ce.Error(), "nope") {
		t.Errorf("error should name the undeclared sibling %q; got %q", "nope", ce.Error())
	}
}

// Minor 1: a `resp_header NAME` with the VALUE position omitted (here `ttl` — a cache_ttl
// action keyword — got mis-read as the value) is a hard compile error whose message guides
// the user to the presence form `resp_header NAME *`.
func TestRespHeaderMissingValueGuidesPresenceForm(t *testing.T) {
	ce := compileErr(t, "x {\n cache_ttl resp_header X-Foo ttl 1m\n}\n")
	msg := ce.Error()
	if !strings.Contains(msg, "resp_header NAME *") {
		t.Errorf("error should suggest `resp_header NAME *`; got %q", msg)
	}
	if !strings.Contains(msg, "NAME VALUE") {
		t.Errorf("error should state resp_header needs NAME VALUE; got %q", msg)
	}
}
