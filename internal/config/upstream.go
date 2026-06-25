package config

import (
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/lb"
)

// ParseUpstreamURL validates one `to …` backend target — the URL/scheme/host:port
// the load balancer dials. It delegates to lb.ParseTarget, the single source of
// truth for backend-target syntax (http/https static, dns/k8s dynamic, or a bare
// host:port ⇒ http), so a target that loads at runtime also lints clean.
//
// Exported so `cadish check` can reject a bogus `to ht!tp://[::bad`, an empty
// target, or an unsupported scheme at LINT time with a file:line, instead of
// leaving it to config load. The returned error is a positioned
// *cadishfile.ParseError carrying pos.
func ParseUpstreamURL(tok string, pos cadishfile.Pos) error {
	_, err := lb.ParseTarget(tok, pos)
	return err
}
