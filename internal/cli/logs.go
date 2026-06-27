package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cadi-sh/cadish/internal/logs"
)

// Logs implements `cadish logs` — the NCSA-style access-log tail.
//
// Source (D44): by default `cadish logs` dials the running server's access-log unix
// socket (`-log-socket`, default ${TMPDIR}/cadish-access.sock) and streams the LIVE
// access log — the server keeps it in memory and fans it out only while a consumer
// is attached (no disk writes). It renders each request line with host/path/status/
// cache filters in a text|ncsa|json format. Redirect/pipe to persist:
// `cadish logs > access.log`.
//
// A FILE argument (or stdin) reads a previously-saved NDJSON log instead of the
// socket; `-f` then follows the file (tail -f) until interrupted. See docs/logs.md.
//
// Usage:
//
//	cadish logs [-format text|ncsa|json] [filters]            # live (socket)
//	cadish logs > access.log                                  # persist live stream
//	cadish logs [-f] [-format …] [filters] FILE              # saved-file tail
//	cat access.json | cadish logs -format ncsa                # piped/stdin
//
// Filters: -host SUB, -path SUB (case-insensitive substring), -cache TOKEN
// (HIT/MISS/…), -status CODE (exact), -status-class N (1..5 for Nxx),
// -min-status CODE (>=).
func Logs(args []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	follow := fs.Bool("f", false, "follow the file and stream new lines (tail -f); ignored on stdin/socket")
	fromStart := fs.Bool("from-start", false, "with -f, emit the whole file first, then tail (default: tail from end)")
	format := fs.String("format", "text", "output format: text | ncsa | json")
	addr := fs.String("addr", ":80", "listen address of the cadish instance to tail (selects its per-instance access-log socket; must match the instance's -addr)")
	logSocket := fs.String("log-socket", "", "access-log socket to stream live from (when no FILE is given; default: per-instance path derived from -addr, or $CADISH_ACCESS_SOCKET when set)")
	host := fs.String("host", "", "only lines whose host contains this substring")
	path := fs.String("path", "", "only lines whose path contains this substring")
	cache := fs.String("cache", "", "only this cache status (HIT, MISS, HIT-STALE, PASS, SYNTH, PURGE)")
	status := fs.Int("status", 0, "only this exact HTTP status code")
	statusClass := fs.Int("status-class", 0, "only this status class (1..5 for 1xx..5xx)")
	minStatus := fs.Int("min-status", 0, "only statuses >= this code (e.g. 400 for errors)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Resolve the live-source socket: explicit -log-socket wins; otherwise the
	// per-instance default keyed on -addr (or $CADISH_ACCESS_SOCKET), matching how
	// `cadish run` derives its bind path so the no-flag single-instance tail works.
	if *logSocket == "" {
		*logSocket = defaultLogSocketPathFor(*addr)
	}

	fmtSel, err := logs.ParseFormat(*format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish logs: %v\n", err)
		return 2
	}
	if *statusClass < 0 || *statusClass > 5 {
		fmt.Fprintln(os.Stderr, "cadish logs: -status-class must be 1..5")
		return 2
	}

	filter := logs.Filter{
		Host:        *host,
		Path:        *path,
		Cache:       *cache,
		Status:      *status,
		StatusClass: *statusClass,
		MinStatus:   *minStatus,
	}

	return runLogs(fs.Args(), *follow, *fromStart, *logSocket, filter, fmtSel, os.Stdin, os.Stdout, os.Stderr)
}

// runLogs is the testable core of Logs. With a file argument and follow=true it
// tails the file until SIGINT/SIGTERM; otherwise it streams the file to EOF. With no
// file argument it streams the LIVE access-log socket (D44) when stdin is a terminal,
// or reads stdin when it is a pipe/redirect (so existing `… | cadish logs` keeps
// working). socket is the unix path to dial for the live source.
func runLogs(files []string, follow, fromStart bool, socket string, filter logs.Filter, format logs.Format, stdin io.Reader, out, errOut io.Writer) int {
	if len(files) > 1 {
		// flag.Parse stops at the first non-flag token, so any flags placed AFTER the
		// FILE (e.g. `cadish logs access.log -host x`) arrive here as extra positionals.
		// Detect that and tell the operator flags must precede the FILE, rather than the
		// opaque "at most one FILE" — a flag silently dropped after a positional was the
		// staging foot-gun.
		for _, a := range files[1:] {
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(errOut, "cadish logs: flags must come before the FILE argument (got %q after %q)\n", a, files[0])
				return 2
			}
		}
		fmt.Fprintln(errOut, "cadish logs: at most one FILE argument")
		return 2
	}

	// No file argument.
	if len(files) == 0 {
		if follow {
			fmt.Fprintln(errOut, "cadish logs: -f requires a FILE (cannot tail stdin/socket; the socket is already a live stream)")
			return 2
		}
		// A piped/redirected stdin is read directly (offline log on stdin); otherwise
		// dial the live access-log socket.
		if stdinIsPipe(stdin) {
			if _, err := logs.Stream(stdin, out, errOut, filter, format); err != nil {
				fmt.Fprintf(errOut, "cadish logs: %v\n", err)
				return 1
			}
			return 0
		}
		return streamSocket(socket, filter, format, out, errOut)
	}

	path := files[0]
	if !follow {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(errOut, "cadish logs: %v\n", err)
			return 1
		}
		defer f.Close()
		if _, err := logs.Stream(f, out, errOut, filter, format); err != nil {
			fmt.Fprintf(errOut, "cadish logs: %v\n", err)
			return 1
		}
		return 0
	}

	// Follow mode: tail until interrupted.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := logs.Follow(ctx, path, out, errOut, filter, format, logs.FollowOptions{FromStart: fromStart}); err != nil {
		fmt.Fprintf(errOut, "cadish logs: %v\n", err)
		return 1
	}
	return 0
}

// stdinIsPipe reports whether stdin is a pipe/redirect (data to consume) rather than
// an interactive terminal. Only an *os.File stdin (the real process stdin) is probed;
// a test reader (bytes/strings) is treated as a pipe so unit tests exercise the
// stdin path without a tty. A terminal stdin means "no piped input" → use the socket.
func stdinIsPipe(stdin io.Reader) bool {
	f, ok := stdin.(*os.File)
	if !ok {
		return true
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

// streamSocket dials the access-log unix socket and streams the live NDJSON records
// through the SAME logs.Stream pipeline (ParseLine + Filter + Render) used for files,
// writing to out until the connection closes (server shutdown) or SIGINT/SIGTERM. It
// returns 0 on a clean end, 1 on a dial/stream error.
func streamSocket(path string, filter logs.Filter, format logs.Format, out, errOut io.Writer) int {
	conn, err := net.Dial("unix", path)
	if err != nil {
		fmt.Fprintf(errOut, "cadish logs: cannot reach access-log socket %s: %v\n", path, err)
		fmt.Fprintln(errOut, "cadish logs: is `cadish run` up? (or pass a FILE / pipe NDJSON on stdin)")
		return 1
	}
	defer conn.Close()

	// Close the connection on SIGINT/SIGTERM so the streaming read unblocks and we
	// exit promptly (mirrors the file-follow ctrl-C behaviour).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// logs.Stream consumes to EOF: the server closes the conn on shutdown, ctrl-C
	// closes it above. A use-of-closed-connection error after cancellation is a clean
	// exit, not a failure.
	if _, serr := logs.Stream(conn, out, errOut, filter, format); serr != nil && ctx.Err() == nil {
		fmt.Fprintf(errOut, "cadish logs: %v\n", serr)
		return 1
	}
	return 0
}
