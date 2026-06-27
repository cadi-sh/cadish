package check

import "testing"

// A `normalize NAME { … }` whose {NAME} token is referenced by NO cache_key recipe is
// dead config: its only effect is to feed a bounded {NAME} cache-key token, so an unkeyed
// normalizer means the cache silently does not vary on the dimension the operator bucketed.
// check must warn (unused-normalize-token).
func TestUnusedNormalizeTokenWarns(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  normalize plan { from header X-Plan; map premium -> p; default free }\n" +
		"  cache_key host path\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-normalize-token"]; n != 1 {
		t.Fatalf("got %d unused-normalize-token diagnostics, want 1; diags=%+v", n, r.Sites[0].Diagnostics)
	}
}

// A normalizer whose {NAME} token IS keyed must NOT warn.
func TestKeyedNormalizeTokenNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  normalize plan { from header X-Plan; map premium -> p; default free }\n" +
		"  cache_key host path {plan}\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-normalize-token"]; n != 0 {
		t.Fatalf("got %d unused-normalize-token diagnostics, want 0", n)
	}
}

// Keyed in ONE scoped recipe but not another is still covered (the token is used): no warn.
func TestNormalizeKeyedInScopedRecipeNoWarn(t *testing.T) {
	src := []byte("example.com {\n" +
		"  @ssr path /app/*\n" +
		"  upstream app { to http://127.0.0.1:8080 }\n" +
		"  normalize plan { from header X-Plan; map premium -> p; default free }\n" +
		"  cache_key @ssr host path {plan}\n" +
		"  cache_key default host path\n" +
		"  cache_ttl default ttl 1m\n" +
		"}\n")
	r, err := CheckSource("Cadishfile", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-normalize-token"]; n != 0 {
		t.Fatalf("got %d unused-normalize-token diagnostics, want 0", n)
	}
}

// A bare imported fragment (no sites, analyzed as "(top-level)") legitimately defines a
// normalizer for its importer to key on — it must NOT warn (mirrors unused-matcher).
func TestUnusedNormalizeTokenTopLevelNoWarn(t *testing.T) {
	src := []byte("normalize plan { from header X-Plan; map premium -> p; default free }\n")
	r, err := CheckSource("frag.cadish", src)
	if err != nil {
		t.Fatalf("CheckSource: %v", err)
	}
	if n := codes(r)["unused-normalize-token"]; n != 0 {
		t.Fatalf("got %d unused-normalize-token diagnostics for a bare fragment, want 0", n)
	}
}
