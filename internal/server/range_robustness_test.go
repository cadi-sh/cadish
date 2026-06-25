package server

import (
	"errors"
	"testing"
)

// TestParseSingleRangeAdversarial covers overflowing, negative, and otherwise
// pathological Range headers. The invariant is that parseSingleRange never
// panics and never returns a range with a negative offset/length or one that
// reaches past the object — it returns a clean errInvalidRange (fall back to
// 200) or errUnsatisfiableRange (416) instead.
func TestParseSingleRangeAdversarial(t *testing.T) {
	const size = 1000

	cases := []struct {
		name   string
		header string
		want   error // nil => a satisfiable range is expected
	}{
		{"overflow suffix", "bytes=-99999999999999999999", errInvalidRange},
		{"overflow start", "bytes=99999999999999999999-", errInvalidRange},
		{"overflow end", "bytes=0-99999999999999999999", errInvalidRange}, // end overflows int64 -> malformed
		{"huge but valid suffix", "bytes=-99999999999", nil},              // clamps to whole object
		{"negative start sign", "bytes=-5", nil},                          // a suffix range, last 5
		{"explicit negative start", "bytes=-0", errUnsatisfiableRange},
		{"start beyond eof", "bytes=5000000000-", errUnsatisfiableRange},
		{"reversed", "bytes=10-5", errUnsatisfiableRange},
		{"garbage", "bytes=abc-def", errInvalidRange},
		{"no prefix", "0-10", errInvalidRange},
		{"multi range", "bytes=0-1,2-3", errInvalidRange},
		{"empty spec", "bytes=", errInvalidRange},
		{"only dash", "bytes=-", errInvalidRange},
		// A leading '+' is accepted by strconv.ParseInt, so "bytes=+5-" resolves to
		// a satisfiable [5, size). Safe (in-bounds) — kept here to document it.
		{"plus sign", "bytes=+5-", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parseSingleRange(tc.header, size)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("header %q: got err %v, want %v", tc.header, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("header %q: unexpected error %v", tc.header, err)
			}
			if r.start < 0 || r.length < 0 {
				t.Fatalf("header %q: negative range %+v", tc.header, r)
			}
			if r.start+r.length > size {
				t.Fatalf("header %q: range %+v exceeds size %d", tc.header, r, size)
			}
		})
	}
}

// TestParseSingleRangeNonPositiveSize ensures a zero/negative object size never
// yields a usable range (which would otherwise drive a bad slice downstream).
func TestParseSingleRangeNonPositiveSize(t *testing.T) {
	for _, sz := range []int64{0, -1, -1000} {
		if _, err := parseSingleRange("bytes=0-10", sz); !errors.Is(err, errUnsatisfiableRange) {
			t.Fatalf("size %d: got %v, want errUnsatisfiableRange", sz, err)
		}
	}
}
