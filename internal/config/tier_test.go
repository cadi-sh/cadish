package config

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cadi-sh/cadish/internal/cache"
)

// TestCacheTierExtension is the end-to-end config wiring: a
// `cache { tier .mp4 -> disk }` block routes an .mp4 object to the disk tier even
// though its small size would otherwise put it in RAM.
func TestCacheTierExtension(t *testing.T) {
	diskDir := t.TempDir()
	src := "test.local {\n" +
		"  cache {\n" +
		"    ram 8MiB\n" +
		"    disk " + diskDir + " 8MiB\n" +
		"    tier .mp4 .ts -> disk\n" +
		"    tier .html -> ram\n" +
		"  }\n" +
		"  upstream o { to http://127.0.0.1:9 }\n" +
		"}\n"
	path := filepath.Join(t.TempDir(), "Cadishfile")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Close()

	store := cfg.Sites[0].Store
	write := func(key string, size int64) {
		t.Helper()
		w, werr := store.Writer(cache.ObjectMeta{Key: key, Size: size})
		if werr != nil {
			t.Fatalf("Writer(%s): %v", key, werr)
		}
		_, _ = io.WriteString(w, "x")
		if cerr := w.Commit(); cerr != nil {
			t.Fatalf("Commit(%s): %v", key, cerr)
		}
	}

	write("clip.mp4", 1) // small → would be RAM, but `tier .mp4 -> disk`
	if _, tier, ok := store.GetTier("clip.mp4"); !ok || tier != "disk" {
		t.Errorf("clip.mp4 tier = %q (ok=%v), want disk", tier, ok)
	}
	write("seg.ts", 1)
	if _, tier, _ := store.GetTier("seg.ts"); tier != "disk" {
		t.Errorf("seg.ts tier = %q, want disk", tier)
	}
}
