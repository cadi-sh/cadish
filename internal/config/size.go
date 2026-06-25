package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// ParseSize parses a byte-size literal as used in `cache { ram 2GiB; disk … 2TiB }`.
// It accepts an optional suffix: binary (KiB/MiB/GiB/TiB/PiB, powers of 1024) or
// decimal (KB/MB/GB/TB/PB, powers of 1000), or a bare "B"/no suffix for bytes. The
// number may be fractional (e.g. "1.5GiB"). Parsing is case-insensitive.
func ParseSize(s string) (int64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("empty size")
	}
	lower := strings.ToLower(raw)

	type unit struct {
		suffix string
		mult   float64
	}
	// Longest suffixes first so "kib" is matched before "kb"/"b".
	units := []unit{
		{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40}, {"pib", 1 << 50},
		{"kb", 1e3}, {"mb", 1e6}, {"gb", 1e9}, {"tb", 1e12}, {"pb", 1e15},
		{"b", 1},
	}
	mult := 1.0
	numPart := lower
	for _, u := range units {
		if strings.HasSuffix(lower, u.suffix) {
			mult = u.mult
			numPart = strings.TrimSpace(lower[:len(lower)-len(u.suffix)])
			break
		}
	}
	if numPart == "" {
		return 0, fmt.Errorf("size %q has no numeric part", raw)
	}
	n, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: expected a value like 256MiB, 2GiB, 512KiB", raw)
	}
	if n < 0 {
		return 0, fmt.Errorf("size %q must not be negative", raw)
	}
	// Guard the float→int64 conversion: a huge value (e.g. `100000PiB`) overflows int64, which
	// is implementation-defined — on amd64 it WRAPS to a negative budget that silently caches
	// nothing. Reject it explicitly (Inf/NaN can't arise from a non-negative finite parse here,
	// but are cheap to exclude). MaxInt64 ≈ 8 EiB — far beyond any real cache.
	v := n * mult
	if math.IsInf(v, 0) || math.IsNaN(v) || v >= math.MaxInt64 {
		return 0, fmt.Errorf("size %q is too large (max ~8EiB)", raw)
	}
	return int64(v), nil
}
