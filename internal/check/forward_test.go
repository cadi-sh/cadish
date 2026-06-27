package check

import "testing"

// COOKIE-NORM `forward` mode in `cadish check`: a `derives_from cookie NAME… forward`
// cookie is FORWARDED to origin under a collapsed key, so check must (a) emit the loud
// opt-in warning `cookie-forward-uncollapsed`, (b) NOT emit `cookie-allow-unkeyed` for it
// (it is covered by {TOKEN}), and (c) still emit the not-stripped footgun when its token
// is NOT in any recipe (a forwarded-but-uncovered cookie).

func TestCookieForwardUncollapsedWarns(t *testing.T) {
	t.Run("forward cookie in a recipe → cookie-forward-uncollapsed, NOT cookie-allow-unkeyed", func(t *testing.T) {
		src := []byte("x {\n @a cookie AdultContent 1\n classify {adult_php} {\n derives_from cookie AdultContent forward\n when @a -> 1\n default -> 0\n }\n cookie_allow\n cache_key default host url {adult_php}\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-forward-uncollapsed"]; n != 1 {
			t.Errorf("cookie-forward-uncollapsed = %d, want 1\n%s", n, render(t, r))
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 0 {
			t.Errorf("cookie-allow-unkeyed = %d, want 0 (forward cookie is covered by {adult_php})\n%s", n, render(t, r))
		}
		if n := codes(r)["derives-from-not-stripped"]; n != 0 {
			t.Errorf("derives-from-not-stripped = %d, want 0 (token IS in a recipe)\n%s", n, render(t, r))
		}
		// The warning is advisory (a loud opt-in), like insecure-origin-tls.
		for _, sr := range r.Sites {
			for _, d := range sr.Diagnostics {
				if d.Code == "cookie-forward-uncollapsed" {
					if d.Severity != SevWarning {
						t.Errorf("cookie-forward-uncollapsed severity = %v, want warning", d.Severity)
					}
					if d.Position == "" {
						t.Errorf("cookie-forward-uncollapsed has no file:line position: %q", d.Position)
					}
				}
			}
		}
	})

	t.Run("forward cookie NOT in any recipe → not-stripped footgun, NOT forward-uncollapsed", func(t *testing.T) {
		// {adult_php} declares forward but is in NO cache_key recipe → the cookie is read
		// but never keyed and still forwarded → the not-stripped/leak footgun applies.
		src := []byte("x {\n @a cookie AdultContent 1\n classify {adult_php} {\n derives_from cookie AdultContent forward\n when @a -> 1\n default -> 0\n }\n cookie_allow AdultContent\n cache_key default host url\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-forward-uncollapsed"]; n != 0 {
			t.Errorf("cookie-forward-uncollapsed = %d, want 0 (token not keyed → not the opt-in case)\n%s", n, render(t, r))
		}
		if n := codes(r)["derives-from-not-stripped"]; n != 1 {
			t.Errorf("derives-from-not-stripped = %d, want 1 (forwarded but uncovered)\n%s", n, render(t, r))
		}
	})

	t.Run("forward cookie does not suppress cookie-allow-unkeyed for OTHER kept cookies", func(t *testing.T) {
		// AdultContent (forward, keyed via {adult_php}) is covered; uid (allow-listed,
		// unkeyed, not a derives_from input) is NOT — so it still warns.
		src := []byte("x {\n @a cookie AdultContent 1\n classify {adult_php} {\n derives_from cookie AdultContent forward\n when @a -> 1\n default -> 0\n }\n cookie_allow AdultContent uid\n cache_key default host url {adult_php}\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-forward-uncollapsed"]; n != 1 {
			t.Errorf("cookie-forward-uncollapsed = %d, want 1 (AdultContent)\n%s", n, render(t, r))
		}
		if n := codes(r)["cookie-allow-unkeyed"]; n != 1 {
			t.Errorf("cookie-allow-unkeyed = %d, want 1 (uid is still uncovered)\n%s", n, render(t, r))
		}
	})

	t.Run("a plain STRIP derives_from cookie does NOT warn forward-uncollapsed", func(t *testing.T) {
		src := []byte("x {\n @a cookie verified-prod 1\n classify {ageverify} {\n derives_from cookie verified-prod\n when @a -> 0\n default -> 2\n }\n cookie_allow\n cache_key default host url {ageverify}\n}\n")
		r, err := CheckSource("k.cadish", src)
		if err != nil {
			t.Fatal(err)
		}
		if n := codes(r)["cookie-forward-uncollapsed"]; n != 0 {
			t.Errorf("cookie-forward-uncollapsed = %d, want 0 (strip-mode is the safe default)\n%s", n, render(t, r))
		}
	})
}
