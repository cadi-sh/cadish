// Command cadish is a single-binary HTTP cache server: two-tier HTTP caching, load
// balancing, and Kubernetes ingress, with built-in TLS + ACME.
//
// Usage:
//
//	cadish run    [-config Cadishfile]  start the server
//	cadish reload (-pidfile F | -pid N)  SIGHUP a running server to hot-reload config
//	cadish check [-config Cadishfile]   parse + validate config, print a
//	                                    complexity report, exit non-zero on error
//	cadish fmt   [-w] [Cadishfile...]   format Cadishfile(s)
//	cadish logs  [-f] [filters] [FILE]  tail/stream the access log (NCSA-style)
//	cadish version                      print version information
package main

import (
	"fmt"
	"os"

	// Set GOMAXPROCS from the container's CPU quota (cgroup CFS) at startup, so a
	// pod with a CPU limit on a many-core node doesn't spin up GOMAXPROCS=host-cores
	// worth of P's (excess context-switching / GC pressure under the quota).
	_ "go.uber.org/automaxprocs"

	"github.com/cadi-sh/cadish/internal/cli"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		cli.Usage(os.Stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cli.Run(rest)
	case "reload":
		return cli.Reload(rest)
	case "check":
		return cli.Check(rest)
	case "fmt":
		return cli.Fmt(rest)
	case "adapt":
		return cli.Adapt(rest)
	case "edge":
		return cli.Edge(rest)
	case "ingress":
		return cli.Ingress(rest)
	case "gateway":
		return cli.Gateway(rest)
	case "logs":
		return cli.Logs(rest)
	case "version", "-v", "--version":
		return cli.Version()
	case "help", "-h", "--help":
		cli.Usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "cadish: unknown command %q\n\n", cmd)
		cli.Usage(os.Stderr)
		return 2
	}
}
