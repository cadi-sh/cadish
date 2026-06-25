package pipeline

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"60s", 60 * time.Second, false},
		{"5s", 5 * time.Second, false},
		{"1h", time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"2s", 2 * time.Second, false},
		{"365d", 365 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"1d12h", 36 * time.Hour, false},
		{"500ms", 500 * time.Millisecond, false},
		{"1h30m", 90 * time.Minute, false},
		{"0", 0, false},
		{"", 0, true},
		{"abc", 0, true},
		{"10", 0, true},  // no unit
		{"10x", 0, true}, // bad unit
		{"d", 0, true},   // no magnitude
		// Overflow guards: a magnitude large enough to blow past int64 nanoseconds
		// must ERROR, not silently wrap to a garbage (often negative) duration.
		{"9999999999h", 0, true},            // single huge term overflows on float→int64
		{"2562048h", 0, true},               // just past the int64-ns hour ceiling (~2562047.78h)
		{"9223372036855s", 0, true},         // just past the int64-ns second ceiling
		{"100000000000000000000d", 0, true}, // absurd magnitude → +Inf on the multiply
		// And a large-but-in-range duration still parses exactly (no false reject).
		{"2562047h", 2562047 * time.Hour, false},
	}
	for _, tt := range tests {
		got, err := parseDuration(tt.in)
		if tt.err {
			if err == nil {
				t.Errorf("parseDuration(%q) = %v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDuration(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
