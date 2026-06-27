package cli

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Reload signals a running `cadish run` process to hot-reload its Cadishfile
// (SIGHUP). It locates the process either by -pidfile FILE (the path passed to
// `cadish run -pidfile`) or by an explicit -pid N. The reload is zero-downtime and
// fail-safe in the server: a bad new config is rejected there and the old one keeps
// serving; this command only delivers the signal.
//
// Flags: -pidfile PATH (read the PID from this file) or -pid N (signal this PID).
// Exit code: 0 on a delivered signal, non-zero on a missing pidfile / bad PID /
// signal error.
func Reload(args []string) int {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	pidFile := fs.String("pidfile", "", "read the server PID from this file (written by `cadish run -pidfile`)")
	pid := fs.Int("pid", 0, "signal this PID directly (alternative to -pidfile)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// The target is set via -pidfile/-pid, never a positional. flag.Parse stops at the
	// first non-flag token, so a stray positional (e.g. `cadish reload 1234`, expecting
	// a bare PID, or trailing junk) would otherwise be SILENTLY ignored and the command
	// could signal the wrong/no process. Fail loud, like the other subcommands.
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "cadish reload: unexpected argument(s): %v\n(set the target with -pidfile FILE or -pid N)\n", fs.Args())
		return 2
	}

	target := *pid
	if target == 0 {
		if *pidFile == "" {
			fmt.Fprintln(os.Stderr, "usage: cadish reload (-pidfile FILE | -pid N)")
			return 2
		}
		p, err := readPidFile(*pidFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cadish reload: %v\n", err)
			return 1
		}
		target = p
	}

	// SAFETY: a non-positive PID is never a valid single-process target, and signaling
	// one is destructive on Unix — os.FindProcess never validates the PID, so a later
	// Signal becomes kill(target, SIGHUP): kill(-1, …) BROADCASTS the signal to every
	// process the caller may signal, and kill(0, …) signals the caller's whole process
	// group. So `cadish reload -pid -1` (or a pidfile whose content resolved to 0/-1)
	// would SIGHUP-storm the box instead of reloading one server. Refuse loudly.
	if target <= 0 {
		fmt.Fprintf(os.Stderr, "cadish reload: refusing to signal non-positive PID %d (a zero/negative PID targets a process group or every process, not one server)\n", target)
		return 1
	}

	proc, err := os.FindProcess(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish reload: find process %d: %v\n", target, err)
		return 1
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		fmt.Fprintf(os.Stderr, "cadish reload: signal process %d: %v\n", target, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "cadish reload: sent SIGHUP to %d\n", target)
	return 0
}

// readPidFile reads a decimal PID from a pidfile written by `cadish run -pidfile`.
func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("pidfile %s: invalid PID %q", path, strings.TrimSpace(string(data)))
	}
	return pid, nil
}
