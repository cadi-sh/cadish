package cache

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDiskCachePermissionDeniedMessage verifies that when the cache dir cannot be
// created because the mount is owned by another uid (the classic distroless-nonroot
// "fresh root-owned volume" crash, backlog #12), NewDiskTier returns an actionable
// error that names the uid and the fix instead of a bare "permission denied".
func TestDiskCachePermissionDeniedMessage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}

	// A parent directory with no write bit: MkdirAll of a child fails with EACCES,
	// exactly like a root-owned volume mounted under a uid-65532 process.
	parent := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(parent, "cadish")

	_, err := NewDiskTier(cacheDir, 1<<20)
	if err == nil {
		t.Fatal("expected an error creating the cache dir under a non-writable parent")
	}
	// The underlying os.PathError must still be unwrappable (callers / errors.Is on
	// fs.ErrPermission must keep working).
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error should wrap os.ErrPermission, got: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"65532", "fsGroup", "chown", cacheDir} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q\n got: %s", want, msg)
		}
	}
}
