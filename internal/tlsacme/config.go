// Package tlsacme implements cadish's TLS termination with automatic ACME
// (Let's Encrypt) certificate issuance — the "Caddy half" of cadish: a site that
// declares `tls { acme you@example.com }` gets HTTPS with auto-renewing certs and
// no proxy in front.
//
// The package is built around a pluggable CertSource (see source.go): the default
// is an autocert.Manager (ACME HTTP-01 / TLS-ALPN-01), but a static keypair or a
// future DNS-01 / multi-CA source slots in behind the same interface. A Manager
// aggregates the per-site TLS settings of a whole Cadishfile into one hardened
// *tls.Config plus the :80 challenge/redirect handler the server binds.
//
// It depends only on internal/cadishfile (to read the `tls` directive), never on
// the pipeline or server, so it can be wired into the listener setup without a
// dependency cycle.
package tlsacme

import (
	"fmt"
	"strings"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// Mode is how a site terminates TLS.
type Mode int

const (
	// ModeOff is plain HTTP: the site is served without TLS (e.g. behind a
	// load balancer that terminates TLS). This is the zero value, so a site with
	// no `tls` directive defaults to off.
	ModeOff Mode = iota
	// ModeACME obtains and renews certificates automatically via ACME.
	ModeACME
	// ModeStatic serves a static certificate/key pair from disk.
	ModeStatic
)

// String renders the mode keyword.
func (m Mode) String() string {
	switch m {
	case ModeACME:
		return "acme"
	case ModeStatic:
		return "static"
	default:
		return "off"
	}
}

// HSTS is the optional HTTP Strict-Transport-Security policy for a site.
type HSTS struct {
	// MaxAge is the max-age in seconds. Zero means "not configured".
	MaxAge int
	// IncludeSubdomains adds the includeSubDomains token.
	IncludeSubdomains bool
	// Preload adds the preload token.
	Preload bool
}

// HeaderValue renders the Strict-Transport-Security header value, or "" if the
// policy is not configured (MaxAge == 0).
func (h HSTS) HeaderValue() string {
	if h.MaxAge <= 0 {
		return ""
	}
	v := fmt.Sprintf("max-age=%d", h.MaxAge)
	if h.IncludeSubdomains {
		v += "; includeSubDomains"
	}
	if h.Preload {
		v += "; preload"
	}
	return v
}

// SiteTLS is the parsed TLS configuration of a single site.
type SiteTLS struct {
	Mode     Mode
	Email    string // ACME contact email (ModeACME)
	CertFile string // ModeStatic
	KeyFile  string // ModeStatic
	HSTS     HSTS
}

// SiteConfig binds a site's hostnames to its TLS configuration. The hostnames are
// the site's address tokens (e.g. "example.com", "*.example.com").
type SiteConfig struct {
	Hosts []string
	TLS   SiteTLS
}

// ParseSiteTLS interprets a site's `tls` directive into a SiteTLS. The cadishfile
// AST is semantics-free, so this is where the `tls` grammar is given meaning:
//
//	tls off                       → ModeOff
//	tls { off }                   → ModeOff
//	tls { acme EMAIL }            → ModeACME
//	tls acme EMAIL                → ModeACME
//	tls { cert FILE key FILE }    → ModeStatic
//	tls { cert FILE; key FILE }   → ModeStatic
//	tls { acme EMAIL; hsts max_age 31536000 includeSubdomains }
//
// A nil directive (no `tls` at all) yields ModeOff. Unrecognized inner directives
// produce a (soft) error in the returned slice but do not abort parsing; callers
// decide whether to treat them as fatal. Syntactic correctness is the parser's
// job; this only validates semantics.
func ParseSiteTLS(d *cadishfile.Directive) (SiteTLS, []error) {
	var cfg SiteTLS
	if d == nil {
		return cfg, nil
	}
	var errs []error
	addErr := func(pos cadishfile.Pos, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", pos, fmt.Sprintf(format, a...)))
	}

	// Inline form: `tls off` / `tls acme EMAIL` / `tls cert FILE key FILE`.
	if !d.HasBlock {
		// `tls {}` with no interior whitespace is lexed as a single literal `{}`
		// arg (not a block); it leaves cfg at ModeOff, equivalent to `tls off`.
		// Give the precise consequence rather than "unknown option {}" (TLS-P3).
		if len(d.Args) == 1 && !d.Args[0].Quoted && d.Args[0].Raw == "{}" {
			addErr(d.Pos, "empty `tls {}` block treated as `tls off` (TLS disabled) — add acme/cert or remove the block")
			return cfg, errs
		}
		applyTLSStatement(&cfg, d.Name, d.Args, d.Pos, addErr)
		// `tls` alone with no args is meaningless; treat as off but flag it.
		if len(d.Args) == 0 {
			addErr(d.Pos, "empty `tls` directive: specify acme/cert/off")
		}
		warnNoACMEEmail(&cfg, d.Pos, addErr)
		return cfg, errs
	}

	// An empty `tls { }` block (HasBlock, no inner statements) leaves cfg at the
	// zero value (ModeOff), i.e. it is equivalent to `tls off`. That is almost
	// never intended, so flag it with the precise consequence (TLS-P3).
	if len(d.Block) == 0 {
		addErr(d.Pos, "empty `tls {}` block treated as `tls off` (TLS disabled) — add acme/cert or remove the block")
		return cfg, errs
	}

	// Block form: each inner node is a statement like `acme EMAIL`. A site may
	// only express ONE TLS mode; mixing modes (e.g. `cert … key …; off`, or
	// `acme; off`) is a conflict resolved last-write-wins and silently discards
	// the earlier intent, so flag it (TLS-P1).
	var lastMode Mode
	var lastModePos cadishfile.Pos
	haveMode := false
	for _, n := range d.Block {
		inner, ok := n.(*cadishfile.Directive)
		if !ok {
			continue
		}
		applyTLSStatement(&cfg, inner.Name, inner.Args, inner.Pos, addErr)
		// A mode-setting statement (off/acme/cert/key) always asserts a mode; if it
		// disagrees with an earlier one, the earlier intent is silently discarded.
		if setsMode(inner.Name, inner.Args) {
			if haveMode && cfg.Mode != lastMode {
				addErr(inner.Pos, "conflicting `tls` mode: %s (here) overrides %s (at %s) — only the last wins, the earlier is discarded", cfg.Mode, lastMode, lastModePos)
			}
			lastMode = cfg.Mode
			lastModePos = inner.Pos
			haveMode = true
		}
	}
	warnNoACMEEmail(&cfg, d.Pos, addErr)
	return cfg, errs
}

// setsMode reports whether a `tls` sub-statement asserts a termination mode
// (off/acme/cert/key, including the inline `tls <mode>` recursion), as opposed
// to a modifier like `hsts`.
func setsMode(keyword string, args []cadishfile.Arg) bool {
	switch keyword {
	case "off", "acme", "cert", "key":
		return true
	case "tls":
		if len(args) >= 1 {
			return setsMode(args[0].Raw, args[1:])
		}
	}
	return false
}

// warnNoACMEEmail flags a `tls { acme }` configuration with no contact email
// (TLS-P2). Let's Encrypt uses the ACME account email for expiry and
// rate-limit notices; without one those notices have nowhere to go. The email
// is set per-site via `tls { acme you@example.com }` (or `tls acme you@…`), or
// fleet-wide via the manager's ACMEEmail; this warns only when neither a site
// email is present here.
func warnNoACMEEmail(cfg *SiteTLS, pos cadishfile.Pos, addErr func(cadishfile.Pos, string, ...any)) {
	if cfg.Mode == ModeACME && cfg.Email == "" {
		addErr(pos, "`tls { acme }` has no contact email — Let's Encrypt sends expiry/rate-limit notices to it; set one with `tls { acme you@example.com }`")
	}
}

// applyTLSStatement applies one `tls` sub-statement (keyword + args) to cfg.
func applyTLSStatement(cfg *SiteTLS, keyword string, args []cadishfile.Arg, pos cadishfile.Pos, addErr func(cadishfile.Pos, string, ...any)) {
	switch keyword {
	case "off":
		cfg.Mode = ModeOff
	case "acme":
		cfg.Mode = ModeACME
		if len(args) >= 1 {
			cfg.Email = args[0].Raw
		}
	case "cert":
		cfg.Mode = ModeStatic
		// `cert FILE [key FILE]` — the key may be fused into the same statement
		// or supplied as a separate `key FILE` statement.
		if len(args) >= 1 {
			cfg.CertFile = args[0].Raw
		}
		for i := 1; i < len(args); i++ {
			if args[i].Raw == "key" && i+1 < len(args) {
				cfg.KeyFile = args[i+1].Raw
			}
		}
	case "key":
		cfg.Mode = ModeStatic
		if len(args) >= 1 {
			cfg.KeyFile = args[0].Raw
		}
	case "hsts":
		cfg.HSTS = parseHSTS(args)
	case "tls":
		// Inline `tls <keyword> ...` where keyword is the first arg.
		if len(args) >= 1 {
			applyTLSStatement(cfg, args[0].Raw, args[1:], pos, addErr)
		}
	default:
		addErr(pos, "unknown tls option %q (want acme/cert/key/off/hsts)", keyword)
	}
}

// parseHSTS reads `hsts max_age N [includeSubdomains] [preload]` (tokens are
// case-insensitive and the `max_age`/`max-age` prefix is optional before N).
func parseHSTS(args []cadishfile.Arg) HSTS {
	var h HSTS
	for i := 0; i < len(args); i++ {
		tok := strings.ToLower(args[i].Raw)
		switch tok {
		case "max_age", "max-age":
			if i+1 < len(args) {
				h.MaxAge = atoiSafe(args[i+1].Raw)
				i++
			}
		case "includesubdomains", "include_subdomains":
			h.IncludeSubdomains = true
		case "preload":
			h.Preload = true
		default:
			// A bare number is taken as the max-age.
			if n := atoiSafe(tok); n > 0 {
				h.MaxAge = n
			}
		}
	}
	return h
}

// atoiSafe parses a non-negative integer, returning 0 on any error.
func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// SiteConfigFromSite extracts the hostnames and TLS settings from a parsed site.
// It scans the site body for the first `tls` directive; absent one, the site is
// ModeOff. The returned errors are soft semantic warnings from ParseSiteTLS.
func SiteConfigFromSite(site *cadishfile.Site) (SiteConfig, []error) {
	sc := SiteConfig{Hosts: append([]string(nil), site.Addresses...)}
	var first *cadishfile.Directive
	var errs []error
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || d.Name != "tls" {
			continue
		}
		if first == nil {
			first = d
			tlsCfg, e := ParseSiteTLS(d)
			sc.TLS = tlsCfg
			errs = e
			continue
		}
		// A site may carry only ONE `tls` directive; the first wins and any later
		// one is silently ignored (e.g. `tls off` then `tls { acme }` keeps off,
		// dropping ACME). Flag the duplicate so the discarded intent is visible
		// (TLS-P1).
		errs = append(errs, fmt.Errorf("%s: duplicate `tls` directive — the first (at %s) wins, this one is ignored", d.Pos, first.Pos))
	}
	return sc, errs
}
