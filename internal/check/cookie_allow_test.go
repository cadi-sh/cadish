package check

import "testing"

// TestCookieAllowUnkeyedWarning covers the `cookie-allow-unkeyed` footgun net: a
// cookie_allow that admits a request cookie the cache_key does not vary on is forwarded
// to the origin and can personalize the shared response, so check warns (key it or strip
// it). A keyed cookie, a whole-header key, and a strip-all `cookie_allow` are clean.
func TestCookieAllowUnkeyedWarning(t *testing.T) {
	t.Run("unkeyed-allow-warns", func(t *testing.T) {
		// lang is keyed (safe); darkMode and the wp_logged_in_* glob are NOT → 2 warnings.
		src := []byte("x {\n cookie_allow lang darkMode wp_logged_in_*\n cache_key host path cookie:lang\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 2 {
			t.Errorf("cookie-allow-unkeyed count = %d, want 2 (darkMode + wp_logged_in_*)\n%s", n, render(t, r))
		}
		// Advisory only: the diagnostic is a warning (it does not, by itself, fail the
		// check). Assert the severity directly rather than the process exit code, which a
		// minimal bare-site fixture can also raise for unrelated structural reasons.
		for _, s := range r.Sites {
			for _, d := range s.Diagnostics {
				if d.Code == "cookie-allow-unkeyed" && d.Severity != SevWarning {
					t.Errorf("cookie-allow-unkeyed severity = %q, want warning", d.Severity)
				}
			}
		}
	})

	t.Run("all-keyed-clean", func(t *testing.T) {
		src := []byte("x {\n cookie_allow lang darkMode\n cache_key host path cookie:lang cookie:darkMode\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 0 {
			t.Errorf("count = %d, want 0 (every allowed cookie is keyed)\n%s", n, render(t, r))
		}
	})

	t.Run("whole-cookie-header-covers-all", func(t *testing.T) {
		// header:Cookie keys the entire Cookie header → every allow-listed cookie is covered.
		src := []byte("x {\n cookie_allow lang darkMode wp_logged_in_*\n cache_key host path header:Cookie\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 0 {
			t.Errorf("count = %d, want 0 (header:Cookie covers all cookies)\n%s", n, render(t, r))
		}
	})

	t.Run("strip-all-is-clean", func(t *testing.T) {
		// An empty cookie_allow strips EVERY cookie — nothing is forwarded, nothing to key.
		src := []byte("x {\n cookie_allow\n cache_key host path\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 0 {
			t.Errorf("count = %d, want 0 (empty cookie_allow strips all cookies)\n%s", n, render(t, r))
		}
	})

	t.Run("scoped-recipe-omitting-cookie-warns", func(t *testing.T) {
		// lang is keyed in the @ssr recipe but the `default` recipe omits it → non-@ssr
		// requests are served under a cookie-agnostic key, so it must still warn (coverage
		// is judged per recipe, not as a union).
		src := []byte("x {\n @ssr header X-S 1\n cookie_allow lang\n cache_key @ssr host path cookie:lang\n cache_key default host path\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 1 {
			t.Errorf("count = %d, want 1 (default recipe omits cookie:lang)\n%s", n, render(t, r))
		}
	})

	t.Run("scoped-every-recipe-keys-is-clean", func(t *testing.T) {
		src := []byte("x {\n @ssr header X-S 1\n cookie_allow lang\n cache_key @ssr host path cookie:lang\n cache_key default host path cookie:lang\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 0 {
			t.Errorf("count = %d, want 0 (every recipe keys cookie:lang)\n%s", n, render(t, r))
		}
	})

	t.Run("no-cache-key-default-does-not-cover", func(t *testing.T) {
		// With no cache_key the default (method host path) covers no cookie → the allow warns.
		src := []byte("x {\n cookie_allow session\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 1 {
			t.Errorf("count = %d, want 1 (default key covers no cookie)\n%s", n, render(t, r))
		}
	})
}
