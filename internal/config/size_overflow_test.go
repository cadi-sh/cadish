package config

import "testing"

// TestParseSizeRejectsOverflow: a huge size must error, not wrap to a negative/zero budget
// (which would silently cache nothing).
func TestParseSizeRejectsOverflow(t *testing.T) {
	for _, s := range []string{"100000PiB", "1e30GiB", "99999999999999999999B"} {
		if v, err := ParseSize(s); err == nil {
			t.Errorf("ParseSize(%q) = %d, want an error (overflow)", s, v)
		} else if v < 0 {
			t.Errorf("ParseSize(%q) returned a NEGATIVE budget %d", s, v)
		}
	}
	// A sane size still parses.
	if v, err := ParseSize("256MiB"); err != nil || v != 256*1024*1024 {
		t.Errorf("ParseSize(256MiB) = %d, %v; want %d", v, err, 256*1024*1024)
	}
}
