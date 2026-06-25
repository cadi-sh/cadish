package tlsacme

import (
	"os"
	"path/filepath"
)

// systemCacheDir is the preferred on-disk ACME cache when cadish runs as a system
// service. It is a var (not const) so tests can examine the fallback logic.
var systemCacheDir = "/var/lib/cadish/acme"

// defaultCacheDir resolves where ACME certificates are cached on disk, in
// priority order:
//
//  1. $CADISH_ACME_CACHE if set (explicit override);
//  2. /var/lib/cadish/acme if it exists or its parent is writable (system service);
//  3. $XDG_DATA_HOME/cadish/acme, else $HOME/.local/share/cadish/acme.
//
// The cache must persist across restarts: losing it means re-issuing every
// certificate and risking Let's Encrypt rate limits.
func defaultCacheDir() string {
	if v := os.Getenv("CADISH_ACME_CACHE"); v != "" {
		return v
	}
	// System path: use it if the directory already exists or its parent is
	// writable (i.e. we are likely root / a service account).
	if dirUsable(systemCacheDir) {
		return systemCacheDir
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "cadish", "acme")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "share", "cadish", "acme")
	}
	return systemCacheDir
}

// dirUsable reports whether dir exists, or its parent exists and is writable, so
// autocert can create it.
func dirUsable(dir string) bool {
	if fi, err := os.Stat(dir); err == nil {
		return fi.IsDir()
	}
	parent := filepath.Dir(dir)
	fi, err := os.Stat(parent)
	if err != nil || !fi.IsDir() {
		return false
	}
	// Probe writability by attempting to create (and remove) a temp entry.
	probe, err := os.MkdirTemp(parent, ".cadish-acme-probe-")
	if err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}
