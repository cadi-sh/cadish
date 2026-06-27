package proxyproto

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
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

// Accept accepts the next connection, performs the cheap, NON-BLOCKING trust check, and
// returns a net.Conn whose PROXY header is read LAZILY on first use (R34). The blocking
// header read is deferred off the single accept loop onto the connection's own goroutine,
// so a slow trusted peer trickling header bytes can no longer serially starve every other
// connection from being accepted.
//
// SECURITY: the trust check (immediate-peer-in-trust-set) is synchronous here and parses
// NO peer bytes, so an UNTRUSTED peer is still rejected at Accept before any header is
// read — the load-bearing anti-forgery property is unchanged. The REQUIRE policy (a
// trusted peer MUST send a valid header) is still enforced, just at first use: a missing
// or malformed header surfaces as a Read/RemoteAddr error and the server closes the
// connection. RemoteAddr triggers the same lazy read, so no caller ever observes an
// unvalidated/forged client address (net/http reads RemoteAddr before serving).
func (l *Listener) Accept() (net.Conn, error) {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		peer := peerAddr(raw.RemoteAddr())
		if !peer.IsValid() || !inAny(peer, l.trust) {
			// UNTRUSTED peer: never parse its bytes as a PROXY header — reject. This is the
			// load-bearing anti-forgery property, and it stays on the accept loop because it
			// is non-blocking (it inspects only the already-known socket RemoteAddr).
			_ = raw.Close()
			if l.onReject != nil {
				l.onReject(fmt.Errorf("proxyproto: PROXY header from untrusted peer %v rejected", raw.RemoteAddr()))
			}
			continue
		}
		return &conn{Conn: raw, l: l}, nil
	}
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

// conn wraps an accepted, ALREADY-TRUSTED connection and reads its PROXY header LAZILY on
// the first Read or RemoteAddr (whichever comes first), on the connection's own goroutine
// — never the accept loop (R34). After the header is read it reports the recovered
// RemoteAddr and serves reads through the bufio.Reader that consumed the header (so the
// first application byte is preserved). Everything else delegates to the raw conn — the
// hot read/write path is untouched beyond the one-time buffered reader.
type conn struct {
	net.Conn
	l *Listener

	hsOnce sync.Once
	br     *bufio.Reader
	remote net.Addr
	hsErr  error
}

// handshake reads + validates the PROXY header EXACTLY ONCE under the REQUIRE policy. The
// peer was already proven trusted at Accept; here it recovers the client RemoteAddr and
// records any error so the connection fails closed (no raw fallback — that would be an
// attacker-forceable downgrade). It runs on the caller's goroutine (Read or RemoteAddr),
// so the bounded readTimeout it sets stalls only THIS connection, not the accept loop.
func (c *conn) handshake() {
	c.hsOnce.Do(func() {
		l := c.l
		if l.readTimeout > 0 {
			_ = c.Conn.SetReadDeadline(time.Now().Add(l.readTimeout))
		}
		br := bufio.NewReader(c.Conn)
		hdr, err := ReadHeader(br)
		if l.readTimeout > 0 {
			_ = c.Conn.SetReadDeadline(time.Time{}) // clear for the connection's life
		}
		c.br = br
		if err != nil {
			c.hsErr = err
			if l.onReject != nil {
				l.onReject(err)
			}
			return
		}
		remote := c.Conn.RemoteAddr()
		if !hdr.Local {
			if tcp := hdr.SourceTCPAddr(); tcp != nil {
				remote = tcp
			}
		}
		c.remote = remote
	})
}

func (c *conn) Read(p []byte) (int, error) {
	c.handshake()
	if c.hsErr != nil {
		return 0, c.hsErr
	}
	return c.br.Read(p)
}

func (c *conn) RemoteAddr() net.Addr {
	c.handshake()
	if c.remote != nil {
		return c.remote
	}
	// A failed/Local handshake reports the raw socket peer (the connection is failing
	// closed anyway on the next Read; a Local command legitimately keeps the socket peer).
	return c.Conn.RemoteAddr()
}
