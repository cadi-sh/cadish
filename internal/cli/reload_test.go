package cli

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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

// TestReloadGarbagePidfile rejects a pidfile whose content is not a decimal PID
// (a clean error, not a crash) — e.g. a truncated/garbage write.
func TestReloadGarbagePidfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pid")
	if err := os.WriteFile(path, []byte("not-a-pid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := Reload([]string{"-pidfile", path}); code != 1 {
		t.Fatalf("Reload with garbage pidfile: exit = %d, want 1", code)
	}
}

// TestReloadRejectsNonPositivePID is the regression guard for a DANGEROUS foot-gun:
// os.FindProcess never validates the PID, so signaling a non-positive PID becomes
// kill(target, SIGHUP) — kill(-1,…) broadcasts SIGHUP to EVERY process the caller can
// signal, and kill(0,…) hits the caller's whole process group. `cadish reload -pid -1`
// (or a pidfile resolving to 0/-1) must refuse loudly (exit 1) and signal NOTHING.
//
// NOTE: this test must never run against the unguarded code — it would SIGHUP-storm the
// test runner's process group. It asserts the guard rejects before any signal is sent.
func TestReloadRejectsNonPositivePID(t *testing.T) {
	// A SIGHUP handler so that, if the guard ever regressed and a signal leaked to our
	// own process/group, we'd observe it and fail rather than silently pass.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	t.Run("explicit -pid -1", func(t *testing.T) {
		if code := Reload([]string{"-pid", "-1"}); code != 1 {
			t.Fatalf("reload -pid -1: exit = %d, want 1 (must refuse, never broadcast)", code)
		}
	})

	t.Run("pidfile resolves to 0", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "zero.pid")
		if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code := Reload([]string{"-pidfile", path}); code != 1 {
			t.Fatalf("reload -pidfile <0>: exit = %d, want 1 (0 would signal our process group)", code)
		}
	})

	t.Run("pidfile resolves to negative", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "neg.pid")
		if err := os.WriteFile(path, []byte("-1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code := Reload([]string{"-pidfile", path}); code != 1 {
			t.Fatalf("reload -pidfile <-1>: exit = %d, want 1", code)
		}
	})

	// Give any (erroneously) delivered SIGHUP a moment to land before we stop watching.
	select {
	case <-hup:
		t.Fatal("a SIGHUP was delivered — the non-positive-PID guard leaked a signal")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestReloadRejectsStrayPositional proves a stray positional (e.g. a bare PID where
// -pid was meant) fails loud (exit 2) rather than being silently ignored.
func TestReloadRejectsStrayPositional(t *testing.T) {
	if code := Reload([]string{"1234"}); code != 2 {
		t.Fatalf("reload 1234 (bare positional): exit = %d, want 2", code)
	}
	if code := Reload([]string{"-pid", "1", "extra"}); code != 2 {
		t.Fatalf("reload -pid 1 extra: exit = %d, want 2 (stray positional must reject)", code)
	}
}

// TestReloadViaPidDirect proves -pid N (no pidfile) signals the named process.
func TestReloadViaPidDirect(t *testing.T) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	if code := Reload([]string{"-pid", strconv.Itoa(os.Getpid())}); code != 0 {
		t.Fatalf("reload -pid <self>: exit = %d, want 0", code)
	}
	select {
	case <-hup:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP not delivered within 2s")
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
