package config

import (
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// SecurityConfig is the parsed global `security { … }` block (WAF v1c, D52). It is
// NIL when no security block is present (the common case) — the audit log is OFF by
// default and the datapath pays nothing. The native security PRIMITIVES (allow /
// deny / rate_limit) are site-level directives and are NOT gated by this block; this
// block carries only cross-cutting security OBSERVABILITY for v1 (the audit log).
type SecurityConfig struct {
	// AuditLogPath is the `audit_log <dir|file|off>` target. "" / "off" means the
	// audit log is disabled (the default). A directory writes
	// <dir>/security-audit.log; a file path appends to that file. OFF by default
	// because the audit log MAY record the real client IP (recording who was
	// blocked is the point) — an operator must opt in explicitly.
	AuditLogPath string
}

// securityFromFile extracts the global `security { … }` block. Like `admin` /
// `access_log` it lives in the leading global-options block ("{ … }" at the top of
// the file). Returns (nil, nil) when absent. A malformed block is a positioned
// error.
func securityFromFile(f *cadishfile.File) (*SecurityConfig, error) {
	if f == nil || f.Global == nil {
		return nil, nil
	}
	var secDir *cadishfile.Directive
	for _, n := range f.Global.Body {
		d, ok := n.(*cadishfile.Directive)
		if ok && d.Name == "security" {
			secDir = d
		}
	}
	if secDir == nil {
		return nil, nil
	}

	sc := &SecurityConfig{}
	for _, bn := range secDir.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "audit_log":
			if len(bd.Args) != 1 {
				return nil, compileErr(bd.Pos, "security: `audit_log` needs exactly one value (`off`, a directory, or a file path)")
			}
			v := bd.Args[0].Raw
			if strings.EqualFold(v, "off") {
				sc.AuditLogPath = "off"
			} else {
				sc.AuditLogPath = v
			}
		default:
			return nil, compileErr(bd.Pos, "security: unknown directive "+quoteName(bd.Name)+" (v1 supports only `audit_log`)")
		}
	}
	return sc, nil
}
