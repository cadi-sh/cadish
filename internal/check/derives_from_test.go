package check

import "testing"

// TestDerivesFromCoverage covers the COOKIE-NORM check awareness: a cookie consumed by
// a `derives_from cookie NAME` classify token that is IN a cache_key recipe is auto-
// stripped before origin, so it is no longer a `cookie-allow-unkeyed` footgun. A
// derives_from declaration whose token is NOT in any recipe is a different footgun: the
// cookie is read but never stripped (it leaks to origin) → a new warning.
func TestDerivesFromCoverage(t *testing.T) {
	t.Run("derives-from-covers-cookie-allow", func(t *testing.T) {
		// verified-prod + userType are derives_from inputs of {ageverify}, which IS in the
		// recipe → auto-stripped → NOT a cookie-allow-unkeyed footgun.
		src := []byte("x {\n @v cookie verified-prod 1\n classify {ageverify} {\n derives_from cookie verified-prod userType\n when @v -> 0\n default -> 2\n }\n cookie_allow verified-prod userType\n cache_key default host url {ageverify}\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 0 {
			t.Errorf("cookie-allow-unkeyed = %d, want 0 (derives_from covers both inputs)\n%s", n, render(t, r))
		}
		if n := codes(r)["derives-from-not-stripped"]; n != 0 {
			t.Errorf("derives-from-not-stripped = %d, want 0 (token is in the recipe)\n%s", n, render(t, r))
		}
	})

	t.Run("derives-from-token-not-in-recipe-warns", func(t *testing.T) {
		// {ageverify} declares derives_from but is NOT in any cache_key recipe → the cookie
		// is read but never stripped (would leak to origin). Warn.
		src := []byte("x {\n @v cookie verified-prod 1\n classify {ageverify} {\n derives_from cookie verified-prod\n when @v -> 0\n default -> 2\n }\n cookie_allow verified-prod\n cache_key default host url\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["derives-from-not-stripped"]; n != 1 {
			t.Errorf("derives-from-not-stripped = %d, want 1 (token absent from every recipe)\n%s", n, render(t, r))
		}
		// And since the cookie is NOT covered (token not in the recipe), the ordinary
		// cookie-allow-unkeyed footgun still fires for it.
		if n := codes(r)["cookie-allow-unkeyed"]; n != 1 {
			t.Errorf("cookie-allow-unkeyed = %d, want 1 (uncovered derives_from cookie)\n%s", n, render(t, r))
		}
	})

	t.Run("scoped-recipe-partial-coverage-warns", func(t *testing.T) {
		// {ageverify} is in the @special recipe but the default recipe omits it → for the
		// default-served requests verified-prod is forwarded unkeyed, so warn.
		src := []byte("x {\n @v cookie verified-prod 1\n @special path /s\n classify {ageverify} {\n derives_from cookie verified-prod\n when @v -> 0\n default -> 2\n }\n cookie_allow verified-prod\n cache_key @special host url {ageverify}\n cache_key default host url\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 1 {
			t.Errorf("cookie-allow-unkeyed = %d, want 1 (default recipe omits {ageverify})\n%s", n, render(t, r))
		}
	})
}
