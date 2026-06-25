package proxyproto

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DefaultReadTimeout bounds how long the wrapper waits for the PROXY header on a
// freshly accepted connection, so a slow/garbage peer cannot pin an accept goroutine.
const DefaultReadTimeout = 5 * time.Second

// Config configures the PROXY-protocol listener wrapper.
//
// SECURITY (load-bearing): Trust is the set of CIDRs whose connections may carry an
// authoritative PROXY header. A PROXY header is honored ONLY when the immediate TCP
// peer (the socket RemoteAddr) is inside this set. A header from a peer OUTSIDE the
// set is REJECTED (the connection is closed) — it is never parsed, so a spoofed
// PROXY header from an untrusted peer can NEVER forge the client IP. The trust set
// MUST be non-empty (NewListener errors otherwise): an empty set would mean "trust
// everyone", i.e. anyone could forge their source address — the forgery hole this
// whole feature exists to prevent.
type Config struct {
	// Trust is the set of trusted PROXY-header source CIDRs (typically the LB's
	// addresses). REQUIRED and non-empty.
	Trust []netip.Prefix
	// ReadTimeout bounds the header read per connection. Zero uses DefaultReadTimeout.
	ReadTimeout time.Duration
	// OnReject, when non-nil, is called with the reason each time a connection is
	// dropped by the REQUIRE-from-trusted policy (untrusted peer, missing or malformed
	// header). It is an observability seam for the server's logger/metrics; Accept
	// never surfaces a per-connection rejection as a fatal error.
	OnReject func(error)
}

// Listener wraps a net.Listener so each accepted connection first reads a PROXY v1/v2
// header (under the REQUIRE-from-trusted policy) and reports the recovered client as
// its RemoteAddr, BEFORE the HTTP/TLS server sees it. It is installed ONLY when the
// operator enables the PROXY-protocol listener; the default path is the bare
// listener, untouched (zero cost when off).
type Listener struct {
	inner       net.Listener
	trust       []netip.Prefix
	readTimeout time.Duration

	// onReject, when non-nil, is called with the rejection error for each connection
	// dropped by the REQUIRE-from-trusted policy (untrusted peer / missing or
	// malformed header). It is an observability/test seam — Accept itself never
	// surfaces a per-connection rejection as a fatal error; it closes the offending
	// connection and accepts the next, so one spoofing peer cannot kill the loop.
	onReject func(error)
}

// NewListener wraps inner. It returns an error if the trust set is empty — an enabled
// PROXY listener with no trusted sources is a configuration error (it would let any
// peer forge its client IP). inner may be nil only in tests that inject the inner
// listener directly.
func NewListener(inner net.Listener, cfg Config) (*Listener, error) {
	if len(cfg.Trust) == 0 {
		return nil, errors.New("proxyproto: a trust set is REQUIRED when the PROXY-protocol listener is enabled (an empty trust set would let any peer forge its client IP)")
	}
	rt := cfg.ReadTimeout
	if rt <= 0 {
		rt = DefaultReadTimeout
	}
	return &Listener{inner: inner, trust: cfg.Trust, readTimeout: rt, onReject: cfg.OnReject}, nil
}

// Accept accepts the next connection, reads and applies its PROXY header, and returns
// a net.Conn whose RemoteAddr is the recovered client. A connection that violates the
// REQUIRE-from-trusted policy (untrusted peer, missing header from a trusted peer, or
// a malformed header) is CLOSED and skipped; Accept moves on to the next connection
// rather than surfacing one bad peer as a fatal listener error.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		conn, herr := l.handshake(raw)
		if herr != nil {
			_ = raw.Close()
			// A single misbehaving/spoofing peer must not kill the accept loop: close
			// the offending connection and accept the next one.
			if l.onReject != nil {
				l.onReject(herr)
			}
			continue
		}
		return conn, nil
	}
}

// handshake validates the peer against the trust set, reads the PROXY header under the
// REQUIRE policy, and returns a conn reporting the recovered RemoteAddr.
func (l *Listener) handshake(raw net.Conn) (net.Conn, error) {
	peer := peerAddr(raw.RemoteAddr())
	if !peer.IsValid() || !inAny(peer, l.trust) {
		// UNTRUSTED peer: never parse its bytes as a PROXY header — reject. This is the
		// load-bearing anti-forgery property.
		return nil, fmt.Errorf("proxyproto: PROXY header from untrusted peer %v rejected", raw.RemoteAddr())
	}

	if l.readTimeout > 0 {
		_ = raw.SetReadDeadline(time.Now().Add(l.readTimeout))
	}
	br := bufio.NewReader(raw)
	hdr, err := ReadHeader(br)
	if l.readTimeout > 0 {
		_ = raw.SetReadDeadline(time.Time{}) // clear the deadline for the connection's life
	}
	if err != nil {
		// REQUIRE policy: a trusted peer that sends no/garbled header is rejected (no
		// raw fallback — that would be an attacker-forceable downgrade).
		return nil, err
	}

	remote := raw.RemoteAddr()
	if !hdr.Local {
		if tcp := hdr.SourceTCPAddr(); tcp != nil {
			remote = tcp
		}
	}
	return &conn{Conn: raw, br: br, remote: remote}, nil
}

// peerAddr extracts a netip.Addr from a net.Addr (the socket peer).
func peerAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		if ap := v.AddrPort(); ap.IsValid() {
			return ap.Addr().Unmap()
		}
	}
	if a == nil {
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		if ip, perr := netip.ParseAddr(host); perr == nil {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

func inAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Close closes the underlying listener.
func (l *Listener) Close() error { return l.inner.Close() }

// Addr returns the underlying listener's address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// conn wraps the accepted connection: it reports the recovered RemoteAddr and serves
// reads through the bufio.Reader that already consumed the PROXY header (so the first
// application byte is preserved). Everything else delegates to the raw conn — the hot
// read/write path is untouched beyond the one-time buffered reader.
type conn struct {
	net.Conn
	br     *bufio.Reader
	remote net.Addr
}

func (c *conn) Read(p []byte) (int, error) { return c.br.Read(p) }
func (c *conn) RemoteAddr() net.Addr       { return c.remote }
