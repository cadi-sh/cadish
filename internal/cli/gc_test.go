package cli

import "testing"

// These tests exercise ONLY the pure decision logic (gcDefaults / memLimitForCache).
// They never call applyGCDecision, so no global runtime GC state is mutated and nothing
// leaks across packages.

func TestGCDefaults_OperatorOverrideWins(t *testing.T) {
	const cacheRAM = 8 << 30 // 8 GiB → would otherwise yield a soft limit

	t.Run("both set: cadish touches nothing", func(t *testing.T) {
		d := gcDefaults(true, true, cacheRAM)
		if d.GCPercent != nil {
			t.Errorf("GOGC set by operator but cadish returned GCPercent=%d", *d.GCPercent)
		}
		if d.MemLimitBytes != nil {
			t.Errorf("GOMEMLIMIT set by operator but cadish returned MemLimitBytes=%d", *d.MemLimitBytes)
		}
	})

	t.Run("only GOGC set: cadish still defaults GOMEMLIMIT", func(t *testing.T) {
		d := gcDefaults(true, false, cacheRAM)
		if d.GCPercent != nil {
			t.Errorf("GOGC set by operator but cadish returned GCPercent=%d", *d.GCPercent)
		}
		if d.MemLimitBytes == nil {
			t.Fatal("GOMEMLIMIT unset: expected a defaulted soft limit, got nil")
		}
	})

	t.Run("only GOMEMLIMIT set: cadish still defaults GOGC", func(t *testing.T) {
		d := gcDefaults(false, true, cacheRAM)
		if d.MemLimitBytes != nil {
			t.Errorf("GOMEMLIMIT set by operator but cadish returned MemLimitBytes=%d", *d.MemLimitBytes)
		}
		if d.GCPercent == nil {
			t.Fatal("GOGC unset: expected the default, got nil")
		}
		if *d.GCPercent != defaultGCPercent {
			t.Errorf("GCPercent = %d, want %d", *d.GCPercent, defaultGCPercent)
		}
	})
}

func TestGCDefaults_AppliedWhenUnset(t *testing.T) {
	const cacheRAM = 8 << 30
	d := gcDefaults(false, false, cacheRAM)

	if d.GCPercent == nil {
		t.Fatal("expected GOGC default to be applied when unset")
	}
	if *d.GCPercent != defaultGCPercent {
		t.Errorf("GCPercent = %d, want %d", *d.GCPercent, defaultGCPercent)
	}
	if d.MemLimitBytes == nil {
		t.Fatal("expected GOMEMLIMIT default to be applied when unset")
	}
	want := memLimitForCache(cacheRAM)
	if *d.MemLimitBytes != want {
		t.Errorf("MemLimitBytes = %d, want %d", *d.MemLimitBytes, want)
	}
}

func TestGCDefaults_UnknownCacheBudget_NoMemLimit(t *testing.T) {
	// cacheRAM <= 0 means "unknown": cadish must NOT guess a soft limit (a wrong one can
	// cause a GC death-spiral), but GOGC should still be defaulted.
	for _, ram := range []int64{0, -1} {
		d := gcDefaults(false, false, ram)
		if d.MemLimitBytes != nil {
			t.Errorf("cacheRAM=%d: expected no soft limit, got %d", ram, *d.MemLimitBytes)
		}
		if d.GCPercent == nil || *d.GCPercent != defaultGCPercent {
			t.Errorf("cacheRAM=%d: expected GOGC=%d default", ram, defaultGCPercent)
		}
	}
}

func TestMemLimitForCache_Math(t *testing.T) {
	tests := []struct {
		name     string
		cacheRAM int64
		want     int64
	}{
		{
			name:     "8 GiB cache → 1.5x + 512 MiB headroom",
			cacheRAM: 8 << 30,
			want:     int64(float64(8<<30)*memLimitCacheMultiplier) + memLimitHeadroomBytes,
		},
		{
			name:     "44 GiB default-router cache",
			cacheRAM: 44 << 30,
			want:     int64(float64(44<<30)*memLimitCacheMultiplier) + memLimitHeadroomBytes,
		},
		{
			name:     "zero → no limit",
			cacheRAM: 0,
			want:     0,
		},
		{
			name:     "negative → no limit",
			cacheRAM: -5,
			want:     0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := memLimitForCache(tc.cacheRAM); got != tc.want {
				t.Errorf("memLimitForCache(%d) = %d, want %d", tc.cacheRAM, got, tc.want)
			}
		})
	}
}

func TestMemLimitForCache_SmallCacheBelowFloor(t *testing.T) {
	// A tiny cache (e.g. 8 MiB) yields a computed limit far below minMemLimitBytes, where
	// a soft limit risks a GC death-spiral. Expect 0 (no limit).
	small := int64(8 << 20) // 8 MiB
	if got := memLimitForCache(small); got != 0 {
		t.Errorf("memLimitForCache(%d) = %d, want 0 (below floor)", small, got)
	}
}

func TestMemLimitForCache_AtFloorBoundary(t *testing.T) {
	// The smallest cache whose computed limit reaches the floor must produce a non-zero
	// limit at or above minMemLimitBytes, and never a wrapped/overflowed value.
	// Solve (ram*1.5 + headroom) >= minMemLimitBytes.
	f := float64(minMemLimitBytes-memLimitHeadroomBytes) / memLimitCacheMultiplier
	ram := int64(f)
	if ram <= 0 {
		t.Fatalf("test setup: derived ram=%d", ram)
	}
	got := memLimitForCache(ram)
	if got != 0 && got < minMemLimitBytes {
		t.Errorf("memLimitForCache(%d) = %d: non-zero but below floor %d", ram, got, minMemLimitBytes)
	}
}

func TestMemLimitForCache_OverflowGuarded(t *testing.T) {
	// An absurd budget must not wrap to a negative/garbage soft limit.
	for _, ram := range []int64{1 << 62, 1<<63 - 1} {
		if got := memLimitForCache(ram); got < 0 {
			t.Errorf("memLimitForCache(%d) = %d: negative (overflow not guarded)", ram, got)
		}
	}
}
