package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cadi-sh/cadish/internal/admin"
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/check"
	"github.com/cadi-sh/cadish/internal/config"
	"github.com/cadi-sh/cadish/internal/metrics"
	"github.com/cadi-sh/cadish/internal/server"
	"github.com/cadi-sh/cadish/internal/vcladapt"
)

// Adapt converts a Varnish VCL file into a best-effort Cadishfile skeleton. It
// writes the Cadishfile to stdout (or -o FILE) and a mapped-vs-review summary to
// stderr. It is intentionally lenient: the output is a starting point a human
// finishes, not a runnable config — every uncertain construct becomes a
// `# TODO(adapt): …` comment.
func Adapt(args []string) int {
	fs := flag.NewFlagSet("adapt", flag.ContinueOnError)
	out := fs.String("o", "", "write the Cadishfile here instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: cadish adapt [-o FILE] <file.vcl>")
		return 2
	}
	path := fs.Arg(0)
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish adapt: %v\n", err)
		return 1
	}

	res := vcladapt.Adapt(path, string(src))

	if *out == "" {
		_, _ = io.WriteString(os.Stdout, res.Cadishfile)
	} else if err := os.WriteFile(*out, []byte(res.Cadishfile), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cadish adapt: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "cadish adapt: %s → %d idiom(s) mapped, %d need review (TODO(adapt)).\n",
		path, res.Mapped, res.TODOs)
	if res.TODOs > 0 {
		fmt.Fprintln(os.Stderr, "Review the TODO(adapt) comments, set the site host(s), then run `cadish check`.")
	}
	return 0
}

// defaultConfigPath is where cadish looks for a Cadishfile when -config is unset.
const defaultConfigPath = "Cadishfile"

// Run loads the Cadishfile, builds the caching reverse proxy, listens on the
// configured address (plain HTTP this milestone), and serves until SIGINT/SIGTERM,
// at which point it drains in-flight requests gracefully.
//
// Flags: -config PATH (the Cadishfile), -addr ADDR (listen address, default ":80").
func Run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath, "path to the Cadishfile")
	addr := fs.String("addr", ":80", "HTTP listen address (also ACME challenge + HTTPS redirect when TLS is on)")
	httpsAddr := fs.String("https-addr", ":443", "HTTPS listen address (used when a site declares tls)")
	idle := fs.Duration("idle-timeout", 60*time.Second, "abort an origin body that stalls this long (0 disables)")
	acmeCacheDir := fs.String("acme-cache", "", "directory for cached ACME certificates (empty = default resolution)")
	accessLog := fs.String("access-log", "", "access log control: `off` disables the in-memory access-log hub (zero cost); empty (default) keeps it on but idle-free until a `cadish logs` consumer attaches")
	logSocket := fs.String("log-socket", "", "unix socket `cadish logs` dials to stream the live access log (default: a per-instance path under $TMPDIR derived from -addr, or $CADISH_ACCESS_SOCKET when set)")
	securityAuditLog := fs.String("security-audit-log", "", "security audit log target: a directory (writes security-audit.log) or a file path for one JSON line per enforced/monitored security action; `off`/empty (default) disables it. Overrides `security { audit_log … }` when set. MAY record the real client IP")
	trace := fs.Bool("trace", false, "emit a per-request decision trace to stderr (off the hot path; opt-in)")
	pidFile := fs.String("pidfile", "", "write the server PID to this file (so `cadish reload -pidfile …` can signal it)")
	kubeconfig := fs.String("kubeconfig", "", "path to a kubeconfig for resolving k8s:// upstreams out-of-cluster (else KUBECONFIG / in-cluster / ~/.kube/config)")
	proxyProtocol := fs.Bool("proxy-protocol", false, "wrap the inbound listener(s) to read a PROXY v1/v2 header and recover the real client IP behind an L4/TCP-passthrough LB (requires -proxy-protocol-trust or a `proxy_protocol { trust … }` block; honored ONLY from trusted peers)")
	proxyProtocolTrust := fs.String("proxy-protocol-trust", "", "comma-separated trusted PROXY-header source CIDRs (the LB addresses). REQUIRED with -proxy-protocol — an empty trust set would let any peer forge its client IP")
	maxRequestBody := fs.String("max-request-body", "", "cap the client request body the proxy reads and forwards to origin (e.g. 25MiB); empty/`0` (default) means unlimited, suited to media/streaming uploads. Set a bound for non-streaming deployments — a body over the cap is rejected with 413. Applies only to body-carrying methods (not GET/HEAD)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rejectStrayConfigArgs("run", fs.Args()) {
		return 2
	}

	maxBodyBytes, mbErr := parseMaxRequestBodyFlag(*maxRequestBody)
	if mbErr != nil {
		fmt.Fprintf(os.Stderr, "cadish run: %v\n", mbErr)
		return 2
	}

	// Resolve the access-log socket path: an explicit -log-socket wins; otherwise the
	// per-instance default keyed on -addr (or $CADISH_ACCESS_SOCKET). Deriving from the
	// listen addr keeps co-located instances from clashing on one process-global socket.
	if *logSocket == "" {
		*logSocket = defaultLogSocketPathFor(*addr)
	}

	// The access log is no longer written to disk (D44): the server keeps it in an
	// in-memory fan-out hub and `cadish logs` streams it over a unix socket. The only
	// recognised -access-log value is `off`, which disables the hub. The server's slog
	// logger now carries ONLY warnings/info (cache errors, serving banners) on stderr.
	accessLogOff, lerr := parseAccessLogFlag(*accessLog)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "cadish run: %v\n", lerr)
		return 2
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadWithOptions(*cfgPath, config.LoadOptions{Kubeconfig: *kubeconfig})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish run: %v\n", err)
		return 1
	}
	// `access_log off` is honoured from either the Cadishfile global option or the
	// -access-log off flag (the flag OR's with the config).
	accessLogOff = accessLogOff || cfg.AccessLogOff

	// The opt-in PROXY-protocol listener can be enabled from the Cadishfile
	// (`proxy_protocol { trust … }`) or from the -proxy-protocol[-trust] flags; the
	// flag takes precedence when set. SECURITY: the trust set is REQUIRED and
	// non-empty — an enabled listener with no trusted sources would let any peer forge
	// its client IP, so an empty trust set is a fatal config error here.
	if *proxyProtocol {
		pp, perr := config.ParseProxyProtocolFlag(*proxyProtocolTrust)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "cadish run: -proxy-protocol: %v\n", perr)
			_ = cfg.Close()
			return 2
		}
		cfg.ProxyProtocol = pp // flag overrides the Cadishfile block
	}
	if cfg.ProxyProtocol != nil {
		log.Info("cadish proxy-protocol listener enabled", "trust_cidrs", len(cfg.ProxyProtocol.Trust))
	}

	// Apply cadish's default GC posture for a long-lived caching proxy: trade heap for
	// fewer GC cycles to tighten the p99 tail (D45). Startup-only; the datapath is
	// untouched. The operator always wins — GOGC / GOMEMLIMIT exported in the
	// environment are detected by presence (os.LookupEnv) and left exactly as the
	// runtime already applied them; cadish only fills in a lever the operator left
	// unset. The soft memory limit is sized from the configured RAM cache budget.
	_, gogcSet := os.LookupEnv("GOGC")
	_, memLimitSet := os.LookupEnv("GOMEMLIMIT")
	gcSet := applyGCDecision(gcDefaults(gogcSet, memLimitSet, cfg.TotalRAMCacheBytes()))
	if gcSet.GCPercent != nil {
		log.Info("cadish gc: applied default GOGC", "gogc", *gcSet.GCPercent)
	}
	if gcSet.MemLimitBytes != nil {
		log.Info("cadish gc: applied default GOMEMLIMIT", "bytes", *gcSet.MemLimitBytes)
	}

	// The metrics seam is created ONLY when an `admin` block is present; otherwise
	// it stays nil and the datapath pays nothing.
	var mx *metrics.Metrics
	if cfg.Admin != nil {
		mx = metrics.New()
	}

	// Security audit log (WAF v1c / D52): OFF by default. The path comes from the
	// `-security-audit-log` flag when set, else from `security { audit_log … }` in the
	// Cadishfile. A nil sink (the default) is a no-op on the datapath. The audit log MAY
	// record the real client IP (recording who was blocked is the point) — never the
	// query string / signed-URL signature.
	auditPath := *securityAuditLog
	if auditPath == "" && cfg.Security != nil {
		auditPath = cfg.Security.AuditLogPath
	}
	auditLog, aerr := server.NewAuditLog(auditPath)
	if aerr != nil {
		fmt.Fprintf(os.Stderr, "cadish run: security audit log: %v\n", aerr)
		_ = cfg.Close()
		return 1
	}
	if auditLog.Enabled() {
		log.Info("cadish security audit log", "target", auditPath)
	}

	// The trace seam is opt-in (`-trace` or CADISH_TRACE); nil otherwise so the
	// datapath pays nothing (mirrors the metrics seam gating).
	var tracer *server.Tracer
	if *trace || os.Getenv("CADISH_TRACE") != "" {
		tracer = server.NewTracer(os.Stderr, time.Now)
		log.Info("cadish trace enabled (per-request decision trace -> stderr)")
	}

	srv, err := server.NewServer(cfg, *addr, server.Options{
		Logger:              log,
		IdleTimeout:         *idle,
		HTTPSAddr:           *httpsAddr,
		ACMECacheDir:        *acmeCacheDir,
		Metrics:             mx,
		Tracer:              tracer,
		AccessLogOff:        accessLogOff,
		AuditLog:            auditLog,
		MaxRequestBodyBytes: maxBodyBytes,
		// Carry the startup --kubeconfig into reloads so a SIGHUP recompile resolves
		// k8s:// targets against the SAME kubeconfig the process started with (a plain
		// config.Load on reload would drop it and fall back to the default chain).
		ReloadOptions: config.LoadOptions{Kubeconfig: *kubeconfig},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cadish run: %v\n", err)
		_ = cfg.Close()
		return 1
	}

	// Always start the unix-socket access-log stream server (unless `access_log off`),
	// so `cadish logs` can attach and stream live records. The hub stays idle-free
	// until a consumer connects. A bind error is non-fatal: the server still serves
	// traffic; only live `cadish logs -socket` is unavailable.
	socketCtx, socketCancel := context.WithCancel(context.Background())
	defer socketCancel()
	if !accessLogOff {
		if sock, serr := server.ListenAccessSocket(socketCtx, srv.AccessHub(), *logSocket, log); serr != nil {
			log.Warn("access log socket unavailable; `cadish logs` live stream disabled", "err", serr)
		} else {
			log.Info("cadish access log", "socket", sock.Path())
			defer func() { _ = sock.Close() }()
		}
	}

	// Write the pidfile (so `cadish reload -pidfile …` can SIGHUP this process) and
	// remove it on exit. A pidfile write error is fatal — a stale/missing pidfile
	// would make `cadish reload` signal the wrong process or nothing.
	if *pidFile != "" {
		if werr := writePidFile(*pidFile); werr != nil {
			fmt.Fprintf(os.Stderr, "cadish run: %v\n", werr)
			_ = cfg.Close()
			return 1
		}
		defer func() { _ = os.Remove(*pidFile) }()
	}

	// Serve in the background; relay SIGINT/SIGTERM to a graceful shutdown and SIGHUP
	// to a fail-safe, zero-downtime config reload (backlog #24).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	// The startup config was applied at construction (NewServer built the routing table
	// before serving began), so a plain `cadish run` is warm the moment it serves: mark
	// it so the reserved /.cadish/readyz probe returns 200. (The ingress/gateway
	// controllers instead mark warm after their FIRST reconcile builds the routing table.)
	srv.MarkWarm()

	// Start the opt-in admin/dashboard server on its own listener.
	var adminSrv *admin.Server
	if cfg.Admin != nil {
		// Plain `cadish run` has no Ingress controller ⇒ nil source ⇒ the dashboard
		// omits the Kubernetes Ingress panel (it appears only under `cadish ingress`).
		adminSrv = admin.New(cfg.Admin, mx, liveAdapter{srv}, nil, cfg.Pools(), cfg.ConfigPath)
		go func() {
			if aerr := adminSrv.ListenAndServe(); aerr != nil {
				log.Error("admin server", "err", aerr)
			}
		}()
		log.Info("cadish admin", "listen", cfg.Admin.Listen, "metrics", cfg.Admin.Metrics)
		if w := config.AdminExposureWarning(cfg.Admin.Listen); w != "" {
			log.Warn("admin exposure", "warning", w)
		}
	}

	shutdownAll := func() {
		if adminSrv != nil {
			actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = adminSrv.Shutdown(actx)
			acancel()
		}
	}

	for {
		select {
		case <-hup:
			// SIGHUP: re-read + recompile the Cadishfile and atomically swap routing,
			// preserving the cache/freshness/in-flight requests. A bad new config is
			// rejected and the old one keeps serving (Server.Reload logs the error and
			// returns it). The listener and admin server are never dropped.
			log.Info("reloading config (SIGHUP)", "config", *cfgPath)
			if rerr := srv.Reload(); rerr != nil {
				log.Error("reload failed; keeping current config", "err", rerr)
			} else {
				log.Info("config reloaded")
			}
		case err := <-errCh:
			shutdownAll()
			if err != nil {
				fmt.Fprintf(os.Stderr, "cadish run: %v\n", err)
				_ = cfg.Close()
				return 1
			}
			return 0
		case <-ctx.Done():
			log.Info("shutting down")
			shutdownAll()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil {
				fmt.Fprintf(os.Stderr, "cadish run: shutdown: %v\n", err)
				return 1
			}
			return 0
		}
	}
}

// writePidFile writes the current process PID to path (one decimal line). It is used
// by `cadish run -pidfile` so `cadish reload -pidfile` can locate and SIGHUP the
// running server.
func writePidFile(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
}

// parseAccessLogFlag interprets the -access-log run flag (D44). The empty value is
// the default (hub on, idle-free); `off` disables the in-memory access-log hub. The
// old `-access-log FILE` behaviour is REMOVED — the server never writes the access
// log to disk; persist via `cadish logs > file`. Any other value is an error with a
// migration hint.
func parseAccessLogFlag(v string) (off bool, err error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return false, nil
	case "off":
		return true, nil
	default:
		return false, fmt.Errorf("-access-log only accepts `off` (the server no longer writes the access log to a file; "+
			"to persist, run `cadish logs > %s`)", v)
	}
}

// parseMaxRequestBodyFlag interprets the -max-request-body run flag. Empty or `0`
// means unlimited (the default; the field stays 0 so the ingress path streams the
// body straight through). Any other value is a byte-size literal (e.g. 25MiB) parsed
// like the cache sizes; it must be non-negative.
func parseMaxRequestBodyFlag(v string) (int64, error) {
	s := strings.TrimSpace(v)
	if s == "" || s == "0" {
		return 0, nil
	}
	n, err := config.ParseSize(s)
	if err != nil {
		return 0, fmt.Errorf("-max-request-body: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("-max-request-body %q: must be non-negative", v)
	}
	return n, nil
}

// accessSocketEnv is the env var that overrides the access-log socket path (highest
// precedence). When set, both `cadish run` (the bind path) and `cadish logs` (the
// dial path) use it verbatim, so an operator can pin a stable path regardless of the
// per-instance default.
const accessSocketEnv = "CADISH_ACCESS_SOCKET"

// defaultLogSocketPathFor returns the access-log socket path for an instance that
// listens on addr. Precedence: CADISH_ACCESS_SOCKET (verbatim override) > a
// PER-INSTANCE default keyed on the listen address. The per-instance default is what
// stops two co-located cadish instances from clashing on one process-global socket
// (the original `$TMPDIR/cadish-access.sock` bind race silently dropped the 2nd
// instance's `cadish logs` live stream). It is DETERMINISTIC for a given addr so
// `cadish run -addr X` and `cadish logs -addr X` derive the same path — the no-flag
// single-instance tail (both default to addr ":80") keeps working. Unix-socket only,
// local, created 0600 (D44).
func defaultLogSocketPathFor(addr string) string {
	if v := os.Getenv(accessSocketEnv); v != "" {
		return v
	}
	dir := os.TempDir()
	if dir == "" {
		dir = "/tmp"
	}
	// Hash the listen address into a short, stable, filename-safe suffix so distinct
	// addresses get distinct sockets without leaking the raw addr into a path.
	sum := sha256.Sum256([]byte(addr))
	return filepath.Join(dir, "cadish-access-"+hex.EncodeToString(sum[:6])+".sock")
}

// liveAdapter bridges the running *server.Server's per-site live state to the
// admin.LiveSource interface, translating server.SiteState into admin.SiteState
// (a copy that keeps internal/admin free of an internal/server import).
type liveAdapter struct{ srv *server.Server }

func (a liveAdapter) LiveState() []admin.SiteState {
	in := a.srv.LiveState()
	out := make([]admin.SiteState, 0, len(in))
	for _, s := range in {
		out = append(out, admin.SiteState{
			Name:      s.Name,
			Addresses: s.Addresses,
			Cache: admin.CacheStats{
				RAMObjects:        s.Cache.RAMObjects,
				DiskObjects:       s.Cache.DiskObjects,
				RAMBytes:          s.Cache.RAMBytes,
				DiskBytes:         s.Cache.DiskBytes,
				RAMMaxBytes:       s.Cache.RAMMaxBytes,
				DiskMaxBytes:      s.Cache.DiskMaxBytes,
				DiskPersistErrors: s.Cache.DiskPersistErrors,
			},
		})
	}
	return out
}

// Check parses and validates a Cadishfile and prints a per-site complexity
// report (regex evals per request, weighted cost, directives by phase, dead
// rules, unknown names, optimization suggestions). It resolves `import`
// directives relative to the importing file.
//
// Flags: -strict makes warnings fail the check; -json emits the report as JSON.
// Exit code: 0 on success (warnings allowed unless -strict), non-zero on errors
// or parse failures (printed as "file:line:col: msg").
// rejectStrayConfigArgs reports a loud error (and returns true) when flag parsing
// left unconsumed positional arguments. The config-loading subcommands take their
// path via -config, so a stray positional (e.g. `cadish check site.Cadishfile`)
// would otherwise be SILENTLY ignored and the default ./Cadishfile loaded instead —
// the operator would validate/serve a different file than they named. Fail loud.
func rejectStrayConfigArgs(cmd string, rest []string) bool {
	if len(rest) == 0 {
		return false
	}
	fmt.Fprintf(os.Stderr, "cadish %s: unexpected argument %q; the config path is set with -config (e.g. cadish %s -config %s)\n", cmd, rest[0], cmd, rest[0])
	return true
}

func Check(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfg := fs.String("config", defaultConfigPath, "path to the Cadishfile")
	strict := fs.Bool("strict", false, "treat warnings as errors")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if rejectStrayConfigArgs("check", fs.Args()) {
		return 2
	}
	return runCheck(*cfg, *strict, *asJSON, os.Stdout, os.Stderr)
}

// runCheck is the testable core of Check.
func runCheck(cfg string, strict, asJSON bool, out, errOut io.Writer) int {
	report, err := check.Check(cfg)
	if err != nil {
		// A cadishfile ParseError already reads as "file:line:col: msg"; an I/O
		// error (missing root file) is printed as-is. In -json mode also emit a
		// structured JSON error object to stdout so a JSON consumer always gets
		// valid, machine-readable JSON (never empty stdout) on a parse failure.
		fmt.Fprintf(errOut, "cadish check: %v\n", err)
		if asJSON {
			if jerr := check.WriteJSONError(out, cfg, strict, err); jerr != nil {
				fmt.Fprintf(errOut, "cadish check: %v\n", jerr)
			}
		}
		return 1
	}

	var werr error
	if asJSON {
		werr = report.WriteJSON(out, strict)
	} else {
		werr = report.WriteText(out)
	}
	if werr != nil {
		fmt.Fprintf(errOut, "cadish check: %v\n", werr)
		return 1
	}
	return report.ExitCode(strict)
}

// Fmt formats Cadishfiles. With -w it rewrites each file in place; otherwise it
// prints the formatted result to stdout. With no file arguments it reads from
// stdin and writes to stdout (-w is ignored for stdin). On a parse error it
// prints a "file:line:col: message" diagnostic to stderr and returns a non-zero
// exit code; other files are still processed.
func Fmt(args []string) int {
	fs := flag.NewFlagSet("fmt", flag.ContinueOnError)
	write := fs.Bool("w", false, "write result to (source) file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	files := fs.Args()

	if len(files) == 0 {
		return fmtStdin(os.Stdin, os.Stdout, os.Stderr)
	}
	return fmtFiles(files, *write, os.Stdout, os.Stderr)
}

// fmtFiles formats each path. With write it rewrites in place; otherwise it streams
// each file's formatted output to out. When more than one file is printed to stdout
// it prefixes each with a "# --- <path> ---" header and guarantees a trailing
// newline, so two files never glue together (PF-P2). The -w path is unaffected:
// in-place writes never emit a header. A per-file error is reported to errOut and
// makes the exit non-zero, but the remaining files are still processed.
func fmtFiles(files []string, write bool, out, errOut io.Writer) int {
	// A separator is only meaningful when multiple files share one stdout stream.
	separate := !write && len(files) > 1
	exit := 0
	for i, path := range files {
		if separate {
			if i > 0 {
				fmt.Fprintln(out)
			}
			fmt.Fprintf(out, "# --- %s ---\n", path)
		}
		if err := fmtFile(path, write, out, errOut); err != nil {
			fmt.Fprintf(errOut, "cadish fmt: %v\n", err)
			exit = 1
		}
	}
	return exit
}

// fmtStdin formats stdin to stdout.
func fmtStdin(in io.Reader, out, errOut io.Writer) int {
	src, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintf(errOut, "cadish fmt: reading stdin: %v\n", err)
		return 1
	}
	formatted, err := cadishfile.Format(src)
	if err != nil {
		fmt.Fprintf(errOut, "cadish fmt: <stdin>%s\n", errorWithoutLeadingFile(err))
		return 1
	}
	_, _ = out.Write(formatted)
	return 0
}

// fmtFile formats a single file. When write is true and the content changed, it
// is rewritten in place (preserving the original file mode); otherwise the
// formatted result is written to out.
func fmtFile(path string, write bool, out, errOut io.Writer) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	formatted, err := cadishfile.Format(src)
	if err != nil {
		// cadishfile errors carry "file:line:col"; Format lexes with an empty
		// filename, so splice in the real path.
		return fmt.Errorf("%s%s", path, errorWithoutLeadingFile(err))
	}
	if write {
		if bytes.Equal(src, formatted) {
			return nil
		}
		mode := os.FileMode(0o644)
		if info, statErr := os.Stat(path); statErr == nil {
			mode = info.Mode().Perm()
		}
		return os.WriteFile(path, formatted, mode)
	}
	_, _ = out.Write(formatted)
	return nil
}

// errorWithoutLeadingFile renders a cadishfile.ParseError without its leading
// filename placeholder so callers can prefix the real path. For a ParseError with
// an empty File the Error() string starts with "<input>:line:col: msg"; this
// returns ":line:col: msg". For any other error it returns ": " + message.
func errorWithoutLeadingFile(err error) string {
	const placeholder = "<input>"
	s := err.Error()
	if strings.HasPrefix(s, placeholder) {
		return s[len(placeholder):]
	}
	return ": " + s
}
