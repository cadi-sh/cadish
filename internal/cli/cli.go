// Package cli implements cadish's command-line subcommands.
package cli

import (
	"fmt"
	"io"

	"github.com/cadi-sh/cadish/internal/version"
)

const usageText = `cadish — single-binary HTTP cache server with TLS/ACME, load balancing, and Kubernetes ingress.

Usage:
  cadish run    [-config Cadishfile]   start the server
  cadish reload (-pidfile F | -pid N)   hot-reload a running server's config (SIGHUP)
  cadish check  [-config Cadishfile]   validate config + print complexity report
  cadish fmt    [-w] [Cadishfile...]   format Cadishfile(s)
  cadish adapt  [-o FILE] <file.vcl>   convert a Varnish VCL to a Cadishfile skeleton
  cadish edge   build [-strict]        project the config to the Cadish Edge IR + coverage
  cadish ingress [-config base]        run in-cluster as a Kubernetes Ingress controller
  cadish gateway [-config base]        run in-cluster as a Kubernetes Gateway API controller
  cadish logs   [-f] [filters] [FILE]  tail/stream the access log (NCSA-style)
  cadish version                       print version information
  cadish help                          show this help

Docs: https://cadi.sh
`

// Usage writes the top-level help text to w.
func Usage(w io.Writer) {
	fmt.Fprint(w, usageText)
}

// Version prints version information and returns the process exit code.
func Version() int {
	fmt.Println(version.String())
	return 0
}
