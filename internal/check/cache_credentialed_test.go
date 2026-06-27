package check

import "testing"

// TestCacheCredentialedChecks covers the `cadish check` diagnostics for cache_credentialed
// (D101): the origin-trust warning (always, like cache_unsafe), the no-op warning when no
// positive-store cache_ttl rule exists, and that a well-formed scope emits only the trust
// warning. The Guard A strip_cookies combo is a COMPILE error (asserted in the pipeline).
func TestCacheCredentialedChecks(t *testing.T) {
	t.Run("origin-trust-warning-always", func(t *testing.T) {
		src := []byte("x {\n @rm path_regex ^/v3/readmodel/cache/\n cache_credentialed @rm\n cache_key host path\n cache_ttl @rm from_header X-Cache-Ttl\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cache-credentialed-origin-trust"]; n != 1 {
			t.Errorf("origin-trust warning count = %d, want 1\n%s", n, render(t, r))
		}
		if n := codes(r)["cache-credentialed-noop"]; n != 0 {
			t.Errorf("no-op warning count = %d, want 0 (a positive from_header rule exists)\n%s", n, render(t, r))
		}
	})

	t.Run("noop-when-no-positive-ttl", func(t *testing.T) {
		// Only a hit_for_miss rule (non-store) → cache_credentialed can never store → no-op.
		src := []byte("x {\n @rm path_regex ^/v3/readmodel/cache/\n cache_credentialed @rm\n cache_key host path\n cache_ttl default hit_for_miss 0s\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cache-credentialed-noop"]; n != 1 {
			t.Errorf("no-op warning count = %d, want 1 (no positive-store cache_ttl)\n%s", n, render(t, r))
		}
	})

	t.Run("positive-ttl-literal-clears-noop", func(t *testing.T) {
		src := []byte("x {\n @rm path_regex ^/v3/readmodel/cache/\n cache_credentialed @rm\n cache_key host path\n cache_ttl @rm ttl 60s\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cache-credentialed-noop"]; n != 0 {
			t.Errorf("no-op warning count = %d, want 0 (a positive `ttl` rule exists)\n%s", n, render(t, r))
		}
	})
}
