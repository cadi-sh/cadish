package check

import "testing"

// TestScopedCacheKeyLints covers the cadish check lints for scoped cache_key:
// required-default (error), unreachable recipe after a catch-all, duplicate
// selector, and that a matcher used ONLY as a cache_key selector is not flagged
// unused.
func TestScopedCacheKeyLints(t *testing.T) {
	t.Run("missing-default-is-error", func(t *testing.T) {
		src := []byte("x {\n @ssr header X-S 1\n cache_key @ssr host path\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cache-key-no-default"]; n != 1 {
			t.Errorf("cache-key-no-default count = %d, want 1\n%s", n, render(t, r))
		}
		if code := r.ExitCode(false); code != 1 {
			t.Errorf("ExitCode = %d, want 1 (error present)", code)
		}
	})

	t.Run("unreachable-after-catchall", func(t *testing.T) {
		// A recipe after an unscoped (catch-all) cache_key is dead.
		src := []byte("x {\n @ssr header X-S 1\n cache_key host path\n cache_key @ssr host url\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["dead-rule"]; n != 1 {
			t.Errorf("dead-rule count = %d, want 1\n%s", n, render(t, r))
		}
	})

	t.Run("duplicate-selector", func(t *testing.T) {
		src := []byte("x {\n @ssr header X-S 1\n cache_key @ssr host path\n cache_key @ssr host url\n cache_key default host path\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["dead-rule"]; n != 1 {
			t.Errorf("dead-rule count = %d, want 1\n%s", n, render(t, r))
		}
	})

	t.Run("selector-matcher-not-unused", func(t *testing.T) {
		// @ssr is referenced ONLY as a cache_key selector; it must not be flagged unused.
		src := []byte("x {\n @ssr header X-S 1\n cache_key @ssr host path\n cache_key default host url\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["unused-matcher"]; n != 0 {
			t.Errorf("unused-matcher count = %d, want 0 (@ssr is a cache_key selector)\n%s", n, render(t, r))
		}
	})

	t.Run("unscoped-single-line-clean", func(t *testing.T) {
		// The 100%-backward-compatible case: one unscoped cache_key, no lints.
		src := []byte("x {\n cache_key host path\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		c := codes(r)
		if c["cache-key-no-default"] != 0 || c["dead-rule"] != 0 {
			t.Errorf("unscoped cache_key should be clean, got %v\n%s", c, render(t, r))
		}
	})
}
