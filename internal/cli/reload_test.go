package cli

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReloadSignalsViaPidfile proves `cadish reload -pidfile` reads the PID and
// delivers SIGHUP to it. It targets this test process and asserts the signal lands.
func TestReloadSignalsViaPidfile(t *testing.T) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	dir := t.TempDir()
	pidPath := filepath.Join(dir, "cadish.pid")
	if err := writePidFile(pidPath); err != nil {
		t.Fatalf("writePidFile: %v", err)
	}

	if code := Reload([]string{"-pidfile", pidPath}); code != 0 {
		t.Fatalf("Reload exit = %d, want 0", code)
	}

	select {
	case <-hup:
		// delivered
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP not delivered within 2s")
	}
}

// TestReloadMissingTarget rejects a reload with neither -pidfile nor -pid.
func TestReloadMissingTarget(t *testing.T) {
	if code := Reload(nil); code != 2 {
		t.Fatalf("Reload with no target: exit = %d, want 2", code)
	}
}

// TestReloadBadPidfile rejects a pidfile that does not exist.
func TestReloadBadPidfile(t *testing.T) {
	if code := Reload([]string{"-pidfile", filepath.Join(t.TempDir(), "nope.pid")}); code != 1 {
		t.Fatalf("Reload with missing pidfile: exit = %d, want 1", code)
	}
}

// TestWritePidFile writes the current PID and reads it back.
func TestWritePidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.pid")
	if err := writePidFile(path); err != nil {
		t.Fatalf("writePidFile: %v", err)
	}
	got, err := readPidFile(path)
	if err != nil {
		t.Fatalf("readPidFile: %v", err)
	}
	if got != os.Getpid() {
		t.Fatalf("readPidFile = %d, want %d", got, os.Getpid())
	}
}
