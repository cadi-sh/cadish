package edgeir

import "testing"

// TestCacheCredentialedProjects (D101): a translatable `cache_credentialed @scope` projects
// into EdgeIR.CacheCredentialed so the worker applies the SAME origin-authoritative precedence,
// and does NOT force a fail-open pass.
func TestCacheCredentialedProjects(t *testing.T) {
	const src = `example.com {
		@rm path_regex ^/v3/readmodel/cache/
		cache_credentialed @rm
		cache_key host path
		cache_ttl @rm from_header X-Cache-Ttl
	}`
	p := compile(t, src)
	ir, rep, err := Project(p)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if len(ir.CacheCredentialed) != 1 {
		t.Fatalf("want 1 projected cache_credentialed scope, got %d", len(ir.CacheCredentialed))
	}
	if rep.ForcedPass != 0 {
		t.Errorf("a translatable cache_credentialed scope must NOT trip ForcedPass, got %d", rep.ForcedPass)
	}
	for _, sc := range ir.Recv.Pass {
		if sc.Always {
			t.Error("a translatable cache_credentialed scope must NOT force a site-wide pass")
		}
	}
}

// TestCacheCredentialedFailsClosed (D101): a `cache_credentialed` scope referencing a
// ServerOnly/untranslatable matcher (here `upstream_healthy`, server-only) CANNOT be evaluated
// at the edge, so the projector fails CLOSED — a site-wide fail-open pass + ForcedPass++ so
// `cadish edge build` fails loud — and does NOT project the scope.
func TestCacheCredentialedFailsClosed(t *testing.T) {
	const src = `example.com {
		@live upstream_healthy cache_pool
		upstream cache_pool { to http://127.0.0.1:9 }
		cache_credentialed @live
		cache_key host path
		cache_ttl default from_header X-Cache-Ttl
	}`
	p := compile(t, src)
	ir, rep, err := Project(p) // must not panic
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if len(ir.CacheCredentialed) != 0 {
		t.Errorf("an untranslatable cache_credentialed scope must NOT project, got %d", len(ir.CacheCredentialed))
	}
	sawAlwaysPass := false
	for _, sc := range ir.Recv.Pass {
		if sc.Always {
			sawAlwaysPass = true
		}
	}
	if !sawAlwaysPass {
		t.Errorf("an untranslatable cache_credentialed scope must force a site-wide fail-open pass; recv.pass = %+v", ir.Recv.Pass)
	}
	if rep.ForcedPass == 0 {
		t.Error("an untranslatable cache_credentialed scope must increment ForcedPass (so `cadish edge build` fails non-zero)")
	}
}
