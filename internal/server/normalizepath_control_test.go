package server

import "testing"

// TestNormalizePathStripsControlBytes pins Fix #8: r.URL.Path can carry ASCII
// control bytes (NUL 0x00, 0x1f, DEL 0x7f) — Go's http server does not reject them.
// The cache key joins tokens with 0x1f and the variant fingerprint uses NUL, so a
// control byte in the path would break the "a control byte never appears in a cache
// key" invariant. normalizePath must sanitize them so matching == cache key ==
// dialed path stays consistent and no control byte leaks downstream.
func TestNormalizePathStripsControlBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"nul", "/foo\x00bar", "/foobar"},
		{"unit-sep", "/foo\x1fbar", "/foobar"},
		{"del", "/foo\x7fbar", "/foobar"},
		{"tab", "/foo\tbar", "/foobar"},
		{"newline", "/foo\nbar", "/foobar"},
		{"leading-nul", "\x00/foo", "/foo"},
		{"only-control", "\x00\x1f", "/"},
		{"clean-unchanged", "/foo/bar", "/foo/bar"},
		{"trailing-slash-kept", "/foo/", "/foo/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizePath(tc.in)
			if got != tc.want {
				t.Errorf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for i := 0; i < len(got); i++ {
				if c := got[i]; c < 0x20 || c == 0x7f {
					t.Errorf("normalizePath(%q) = %q still contains control byte 0x%02x", tc.in, got, c)
				}
			}
		})
	}
}
