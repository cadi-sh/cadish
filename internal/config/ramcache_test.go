package config

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/cadi-sh/cadish/internal/cache"
)

// TestTotalRAMCacheBytes_SumsSites loads a two-site config and checks the RAM budgets
// add up. This is the value the run path feeds to gcDefaults to size GOMEMLIMIT (D45).
func TestTotalRAMCacheBytes_SumsSites(t *testing.T) {
	dir := t.TempDir()
	cfgText := `a.com {
	cache { ram 8MiB }
	upstream o { to http://a.internal:8080 }
}
b.com {
	cache { ram 16MiB }
	upstream o { to http://b.internal:8080 }
}
`
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()

	const want = int64(8<<20) + int64(16<<20)
	if got := cfg.TotalRAMCacheBytes(); got != want {
		t.Errorf("TotalRAMCacheBytes() = %d, want %d", got, want)
	}
}

// TestTotalRAMCacheBytes_NilStoreSkipped ensures a site without a store contributes 0
// (and does not panic), and that the sum saturates at MaxInt64 instead of overflowing.
func TestTotalRAMCacheBytes_NilStoreAndSaturation(t *testing.T) {
	mk := func(ram int64) *Site {
		rc := cache.DefaultRouterConfig(t.TempDir())
		rc.RAMMaxBytes = ram
		st, err := cache.NewStore(rc)
		if err != nil {
			t.Fatal(err)
		}
		return &Site{Store: st}
	}

	c := &Config{Sites: []*Site{
		{Store: nil}, // nil store contributes nothing
		mk(math.MaxInt64),
		mk(math.MaxInt64),
	}}
	if got := c.TotalRAMCacheBytes(); got != math.MaxInt64 {
		t.Errorf("TotalRAMCacheBytes() = %d, want saturated MaxInt64", got)
	}
}
