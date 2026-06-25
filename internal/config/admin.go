package config

import (
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// accessLogOffFromFile reads the global `access_log` option (D44). It lives in the
// leading global-options block ("{ … }" at the top of the file), like `admin`. The
// only recognised value is `off`, which disables the in-memory access-log fan-out
// hub. Absent (the default) returns false (hub on). A value other than `off`, or
// the wrong arity, is a positioned config error.
func accessLogOffFromFile(f *cadishfile.File) (bool, error) {
	if f == nil || f.Global == nil {
		return false, nil
	}
	var dir *cadishfile.Directive
	for _, n := range f.Global.Body {
		d, ok := n.(*cadishfile.Directive)
		if ok && d.Name == "access_log" {
			dir = d
		}
	}
	if dir == nil {
		return false, nil
	}
	if len(dir.Args) != 1 || !strings.EqualFold(dir.Args[0].Raw, "off") {
		return false, compileErr(dir.Pos, "access_log: the only supported value is `off` (disables the in-memory access-log hub)")
	}
	return true, nil
}

// strictHostFromFile reads the global `strict_host` option. It lives in the leading
// global-options block ("{ … }" at the top of the file), like `access_log`. The bare
// directive (no args) enables strict-host routing: a request whose Host matches no
// declared site address is answered with 421 Misdirected Request instead of the
// lenient single-site fallback (which serves ANY Host from the only site). Absent
// (the default) returns false — lenient routing, unchanged behavior. Any argument is
// a positioned config error (it is a bare toggle).
func strictHostFromFile(f *cadishfile.File) (bool, error) {
	if f == nil || f.Global == nil {
		return false, nil
	}
	var dir *cadishfile.Directive
	for _, n := range f.Global.Body {
		d, ok := n.(*cadishfile.Directive)
		if ok && d.Name == "strict_host" {
			dir = d
		}
	}
	if dir == nil {
		return false, nil
	}
	if len(dir.Args) != 0 {
		return false, compileErr(dir.Pos, "strict_host takes no arguments (it is a bare toggle that rejects an undeclared Host with 421)")
	}
	return true, nil
}

// defaultAdminListen is where the admin/dashboard server binds when the `admin`
// block sets a token but no explicit `listen`. Loopback by default so the surface
// is not exposed beyond the host unless the operator opts in with an explicit
// bind address (defence in depth alongside the required auth token).
const defaultAdminListen = "127.0.0.1:9090"

// AdminConfig is the parsed `admin { … }` global block: the opt-in observability /
// dashboard surface. It is NIL when no admin block is present (the common case),
// in which case no admin listener is started and the datapath metrics seam stays
// nil (zero cost).
type AdminConfig struct {
	// Listen is the admin server bind address (e.g. ":9090", "127.0.0.1:9090").
	Listen string
	// AuthToken is the bearer token required on every admin request. Mandatory:
	// an admin block without one is a config error (an unauthenticated admin
	// surface would leak the config and live metrics).
	AuthToken string
	// Metrics enables the Prometheus text-format `/metrics` endpoint when true
	// (the JSON API + dashboard are always served; this is the extra scrape
	// endpoint). Off unless the bare `metrics` flag is present.
	Metrics bool
}

// adminFromFile extracts the admin configuration from a parsed Cadishfile. The
// `admin { … }` block lives inside the leading global options block ("{ … }" at
// the top of the file), Caddy-style. Returns (nil, nil) when no admin block is
// present. A malformed block returns a positioned error.
func adminFromFile(f *cadishfile.File) (*AdminConfig, error) {
	if f == nil || f.Global == nil {
		return nil, nil
	}
	var adminDir *cadishfile.Directive
	for _, n := range f.Global.Body {
		d, ok := n.(*cadishfile.Directive)
		if ok && d.Name == "admin" {
			adminDir = d
		}
	}
	if adminDir == nil {
		return nil, nil
	}

	ac := &AdminConfig{Listen: defaultAdminListen}
	for _, bn := range adminDir.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "listen":
			if len(bd.Args) != 1 {
				return nil, compileErr(bd.Pos, "admin: `listen` needs exactly one address")
			}
			if err := ValidateListenAddr(bd.Args[0].Raw); err != nil {
				return nil, compileErr(bd.Pos, "admin: "+err.Error())
			}
			ac.Listen = bd.Args[0].Raw
		case "auth_token":
			if len(bd.Args) != 1 {
				return nil, compileErr(bd.Pos, "admin: `auth_token` needs exactly one token")
			}
			ac.AuthToken = bd.Args[0].Raw
		case "metrics":
			if len(bd.Args) != 0 {
				return nil, compileErr(bd.Pos, "admin: `metrics` takes no arguments")
			}
			ac.Metrics = true
		default:
			return nil, compileErr(bd.Pos, "admin: unknown directive "+quoteName(bd.Name))
		}
	}

	if ac.AuthToken == "" {
		return nil, compileErr(adminDir.Pos, "admin: `auth_token` is required (an unauthenticated admin surface would leak config + metrics)")
	}
	return ac, nil
}
