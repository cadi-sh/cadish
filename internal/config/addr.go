package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ValidateListenAddr checks that s is a usable bind address — "host:port", ":port", or
// "ip:port". A botched IP literal (e.g. "0.0.0.0.1") is rejected HERE, with a config
// position, instead of silently passing config load and only failing at net.Listen bind
// time. Hostnames are accepted (resolved at bind); only an IP-SHAPED host that fails to
// parse is an error, so "localhost" / "db" pass while "0.0.0.0.1" does not.
func ValidateListenAddr(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %v", s, err)
	}
	if port != "" {
		if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
			return fmt.Errorf("invalid listen address %q: port must be 0-65535, got %q", s, port)
		}
	}
	if host != "" && ipShaped(host) {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid listen address %q: %q is not a valid IP address", s, host)
		}
	}
	return nil
}

// AdminExposureWarning returns a human-readable warning when an admin listen
// address binds beyond loopback, or "" when the bind is loopback-only. The admin
// API is served over plain HTTP and gated only by a bearer token, so exposing it
// past loopback — a wildcard bind (`:9090`, `0.0.0.0`, `::`) or any routable IP /
// hostname — sends that token across the network in cleartext. Exposing admin is
// a supported deployment (behind your own TLS terminator / network controls), so
// this is a startup WARNING, not a hard error. A malformed address is left to
// ValidateListenAddr; this helper stays silent on it.
func AdminExposureWarning(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if strings.EqualFold(host, "localhost") {
		return ""
	}
	if host != "" {
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			return ""
		}
	}
	bind := addr
	if host == "" {
		bind = addr + " (all interfaces)"
	}
	return "admin listen " + bind + " is not loopback: the admin API is plain HTTP " +
		"gated only by a bearer token — expose it only behind your own TLS/network controls"
}

// ipShaped reports whether host looks like an attempt at an IP literal rather than a
// hostname: an IPv4 shape (only digits and dots, with at least one dot) or any host
// containing a colon (an IPv6 attempt). This lets a malformed IP ("0.0.0.0.1") be
// validated while a plain hostname ("localhost", "cache") is left to bind-time
// resolution. (A hostname never contains a colon and is never all-digits-and-dots.)
func ipShaped(host string) bool {
	if strings.ContainsRune(host, ':') {
		return true // IPv6 attempt
	}
	hasDot := false
	for _, c := range host {
		switch {
		case c == '.':
			hasDot = true
		case c >= '0' && c <= '9':
		default:
			return false // a non-digit, non-dot char => hostname, not an IPv4 literal
		}
	}
	return hasDot
}
