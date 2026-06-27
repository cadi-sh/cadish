package config

import (
	"strconv"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// ServerConfig is the parsed global `server { … }` block: the inbound (data-plane)
// connection knobs HAProxy exposes as `maxconn` + read/idle timeouts. It is NIL when
// no block is present (the common case) — the server then uses its hardcoded default
// constants and installs no connection limiter, so the accept path is byte-for-byte
// unchanged (zero cost).
//
// Every field is OPTIONAL and zero-valued when omitted; the server resolves a zero
// field to the CURRENT default constant (read_timeout/idle_timeout) or to "no limit"
// (maxconn 0). So an absent block — or an omitted field — keeps the shipped defaults.
type ServerConfig struct {
	// MaxConn caps the number of simultaneously-accepted inbound connections on the
	// public data-plane listener(s) via golang.org/x/net/netutil.LimitListener.
	// 0 (the default / omitted) means NO limit — the bare listener, unchanged.
	MaxConn int
	// ReadTimeout overrides the inbound http.Server ReadTimeout (a slow-request /
	// slowloris bound). 0 (omitted) ⇒ the server's default const is kept.
	ReadTimeout time.Duration
	// IdleTimeout overrides the inbound http.Server IdleTimeout (how long a keep-alive
	// connection may sit idle). 0 (omitted) ⇒ the server's default const is kept.
	IdleTimeout time.Duration
}

// serverConfigFromFile parses the optional global `server { … }` block, which lives
// in the leading global-options block ("{ … }" at the top of the file), like
// `admin`/`proxy_protocol`. Returns (nil, nil) when absent. A negative/non-integer
// maxconn, a bad duration, or an unknown sub-directive is a positioned config error.
//
// The block form:
//
//	{
//	  server {
//	    maxconn 40960
//	    read_timeout 30s
//	    idle_timeout 120s
//	  }
//	}
func serverConfigFromFile(f *cadishfile.File) (*ServerConfig, error) {
	if f == nil || f.Global == nil {
		return nil, nil
	}
	var dir *cadishfile.Directive
	for _, n := range f.Global.Body {
		d, ok := n.(*cadishfile.Directive)
		if ok && d.Name == "server" {
			// A second global `server {}` block must be a positioned error, not a silent
			// last-write-wins that would drop the first block's knobs (Finding 8).
			if dir != nil {
				return nil, compileErr(d.Pos, "duplicate global `server` block (only one is allowed)")
			}
			dir = d
		}
	}
	if dir == nil {
		return nil, nil
	}

	sc := &ServerConfig{}
	for _, bn := range dir.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok {
			continue
		}
		switch bd.Name {
		case "maxconn":
			if len(bd.Args) != 1 {
				return nil, compileErr(bd.Pos, "server: `maxconn` needs exactly one integer argument")
			}
			n, err := strconv.Atoi(bd.Args[0].Raw)
			if err != nil {
				return nil, compileErr(bd.Pos, "server: maxconn: invalid integer "+quoteName(bd.Args[0].Raw))
			}
			if n < 0 {
				return nil, compileErr(bd.Pos, "server: maxconn must be >= 0 (0 = no limit)")
			}
			sc.MaxConn = n
		case "read_timeout":
			d, err := serverDuration(bd, "read_timeout")
			if err != nil {
				return nil, err
			}
			sc.ReadTimeout = d
		case "idle_timeout":
			d, err := serverDuration(bd, "idle_timeout")
			if err != nil {
				return nil, err
			}
			sc.IdleTimeout = d
		default:
			return nil, compileErr(bd.Pos, "server: unknown directive "+quoteName(bd.Name))
		}
	}
	return sc, nil
}

// serverDuration parses a single duration argument of a `server {}` sub-directive.
func serverDuration(bd *cadishfile.Directive, name string) (time.Duration, error) {
	if len(bd.Args) != 1 {
		return 0, compileErr(bd.Pos, "server: `"+name+"` needs exactly one duration argument")
	}
	d, err := ParseDuration(bd.Args[0].Raw)
	if err != nil {
		return 0, compileErr(bd.Pos, "server: "+name+": "+err.Error())
	}
	if d < 0 {
		return 0, compileErr(bd.Pos, "server: "+name+" must not be negative")
	}
	return d, nil
}
