package config

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want time.Duration
	}{
		{"60s", true, 60 * time.Second},
		{"24h", true, 24 * time.Hour},
		{"365d", true, 365 * 24 * time.Hour}, // cadish "d" extension
		{"1w", true, 7 * 24 * time.Hour},     // cadish "w" extension
		{"1d12h", true, 36 * time.Hour},      // compound
		{"0", true, 0},
		{"0s", true, 0},
		{"5xz", false, 0},     // unknown unit
		{"1banana", false, 0}, // unknown unit
		{"", false, 0},        // empty
		{"abc", false, 0},     // no magnitude
	}
	for _, c := range cases {
		got, err := ParseDuration(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("ParseDuration(%q) = %v, want ok", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", c.in, got, c.want)
			}
		} else if err == nil {
			t.Errorf("ParseDuration(%q) = nil, want error", c.in)
		}
	}
}
