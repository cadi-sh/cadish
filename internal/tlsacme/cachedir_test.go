package tlsacme

import (
	"path/filepath"
	"testing"
)

func TestDefaultCacheDir_EnvOverride(t *testing.T) {
	t.Setenv("CADISH_ACME_CACHE", "/custom/acme")
	if got := defaultCacheDir(); got != "/custom/acme" {
		t.Errorf("defaultCacheDir = %q, want /custom/acme", got)
	}
}

func TestDefaultCacheDir_XDGFallback(t *testing.T) {
	// Force the system path to be unusable so resolution falls through to XDG.
	orig := systemCacheDir
	systemCacheDir = filepath.Join(t.TempDir(), "no", "such", "parent", "acme")
	defer func() { systemCacheDir = orig }()

	t.Setenv("CADISH_ACME_CACHE", "")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	want := filepath.Join("/xdg", "cadish", "acme")
	if got := defaultCacheDir(); got != want {
		t.Errorf("defaultCacheDir = %q, want %q", got, want)
	}
}

func TestDefaultCacheDir_SystemWhenWritable(t *testing.T) {
	// Point the system path at a writable temp dir; it should be chosen.
	dir := filepath.Join(t.TempDir(), "acme")
	orig := systemCacheDir
	systemCacheDir = dir
	defer func() { systemCacheDir = orig }()

	t.Setenv("CADISH_ACME_CACHE", "")
	if got := defaultCacheDir(); got != dir {
		t.Errorf("defaultCacheDir = %q, want %q", got, dir)
	}
}
