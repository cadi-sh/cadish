package proxyproto

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// fakeConn wraps a net.Conn but reports a fixed RemoteAddr (the simulated socket
// peer = the LB or the direct attacker), so the listener's trust check sees it.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }

func tcpAddr(t *testing.T, s string) *net.TCPAddr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("ResolveTCPAddr(%q): %v", s, err)
	}
	return a
}

// drive runs one accept against a wrapped listener fed by an in-memory pipe whose
// far end has peerAddr as its socket RemoteAddr and writes header+payload. It
// returns the connection the wrapper produced (or the accept error).
func driveOne(t *testing.T, ln *Listener, peerAddr net.Addr, wire []byte) (net.Conn, error) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	pl := &pipeListener{conn: &fakeConn{Conn: serverSide, remote: peerAddr}}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = clientSide.Write(wire)
	}()

	ln.inner = pl
	var rejected error
	ln.onReject = func(e error) { rejected = e }
	conn, err := ln.Accept()
	// The PROXY header is now read LAZILY (R34): Accept returns a trusted conn without
	// reading the header. Trigger the deferred read here (via RemoteAddr) so the header
	// is validated exactly as a server touching the connection would — this consumes the
	// client's write (so wg.Wait below does not deadlock on the net.Pipe) and surfaces any
	// REQUIRE-policy rejection (missing/malformed header) through onReject. onReject runs
	// synchronously on THIS goroutine (handshake is inline in RemoteAddr), so reading
	// `rejected` is race-free.
	if err == nil && conn != nil {
		_ = conn.RemoteAddr()
	}
	// A rejection (untrusted peer at Accept, or a missing/malformed header surfaced by the
	// triggered handshake) is reported via onReject; prefer it as the error.
	if rejected != nil {
		if err == nil && conn != nil {
			_ = conn.Close()
		}
		err = rejected
	}
	wg.Wait()
	if err == nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	t.Cleanup(func() { _ = clientSide.Close() })
	if err != nil {
		return nil, err
	}
	return conn, err
}

// pipeListener returns its single conn once, then blocks/EOFs.
type pipeListener struct {
	once sync.Once
	conn net.Conn
}

func (p *pipeListener) Accept() (net.Conn, error) {
	var c net.Conn
	var err error
	p.once.Do(func() { c = p.conn })
	if c == nil {
		return nil, errors.New("closed")
	}
	return c, err
}
func (p *pipeListener) Close() error   { return nil }
func (p *pipeListener) Addr() net.Addr { return tcpAddrStatic }

var tcpAddrStatic = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}

func newTestListener(t *testing.T, trusted []netip.Prefix) *Listener {
	t.Helper()
	ln, err := NewListener(nil, Config{Trust: trusted})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	return ln
}

// 1. Trusted peer sends a v1 PROXY header -> RemoteAddr is rewritten to the client.
func TestListenerTrustedRewritesRemoteAddr(t *testing.T) {
	ln := newTestListener(t, mustPrefixes(t, "10.0.0.0/8"))
	conn, err := driveOne(t, ln, tcpAddr(t, "10.1.2.3:55000"),
		[]byte("PROXY TCP4 203.0.113.7 198.51.100.2 4000 443\r\nhello"))
	if err != nil {
		t.Fatalf("Accept from trusted peer: %v", err)
	}
	if got := conn.RemoteAddr().String(); got != "203.0.113.7:4000" {
		t.Fatalf("RemoteAddr = %q, want 203.0.113.7:4000 (the real client)", got)
	}
	// Payload after the header must still be readable.
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	got, _ := br.ReadString('o')
	if got != "hello" {
		t.Fatalf("payload = %q, want hello", got)
	}
}

// 3 (THE SECURITY TEST). An UNTRUSTED peer that sends a PROXY header is REJECTED —
// the spoofed IP must never be honored.
func TestListenerUntrustedPeerRejected(t *testing.T) {
	ln := newTestListener(t, mustPrefixes(t, "10.0.0.0/8"))
	conn, err := driveOne(t, ln, tcpAddr(t, "203.0.113.99:40000"),
		[]byte("PROXY TCP4 8.8.8.8 198.51.100.2 4000 443\r\nGET / HTTP/1.1\r\n"))
	if err == nil {
		t.Fatalf("expected REJECT from untrusted peer; got conn with RemoteAddr %q", conn.RemoteAddr())
	}
}

// 4. REQUIRE policy: a TRUSTED peer that sends NO PROXY header is rejected.
func TestListenerTrustedNoHeaderRejected(t *testing.T) {
	ln := newTestListener(t, mustPrefixes(t, "10.0.0.0/8"))
	_, err := driveOne(t, ln, tcpAddr(t, "10.1.2.3:55000"),
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if err == nil {
		t.Fatalf("expected REJECT (REQUIRE policy) when trusted peer sends no PROXY header")
	}
}

// 8. Malformed header from a trusted peer -> rejected (no raw fallback / downgrade).
func TestListenerTrustedMalformedRejected(t *testing.T) {
	ln := newTestListener(t, mustPrefixes(t, "10.0.0.0/8"))
	_, err := driveOne(t, ln, tcpAddr(t, "10.1.2.3:55000"),
		[]byte("PROXY TCP4 garbage\r\n"))
	if err == nil {
		t.Fatalf("expected REJECT of malformed header from trusted peer")
	}
}

// LOCAL command from a trusted peer -> fall back to the socket peer (health check).
func TestListenerLocalFallsBackToPeer(t *testing.T) {
	ln := newTestListener(t, mustPrefixes(t, "10.0.0.0/8"))
	conn, err := driveOne(t, ln, tcpAddr(t, "10.1.2.3:55000"),
		[]byte("PROXY UNKNOWN\r\nping"))
	if err != nil {
		t.Fatalf("LOCAL/UNKNOWN from trusted peer should succeed: %v", err)
	}
	if got := conn.RemoteAddr().String(); got != "10.1.2.3:55000" {
		t.Fatalf("RemoteAddr = %q, want the socket peer 10.1.2.3:55000 for LOCAL", got)
	}
}

// chanListener yields the connections queued on its channel, then blocks until Close.
type chanListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, errors.New("closed")
	}
}
func (l *chanListener) Close() error   { close(l.closed); return nil }
func (l *chanListener) Addr() net.Addr { return tcpAddrStatic }

// TestListenerSlowPeerDoesNotBlockAccept is the R34 pin: a trusted peer that has NOT yet
// sent its PROXY header must not block the single accept loop from returning OTHER
// connections. We queue several trusted peers whose header bytes never arrive and a
// generous readTimeout; with the old synchronous handshake the first Accept would block
// for the whole readTimeout before returning, starving the rest. With the lazy handshake
// every Accept returns promptly (the header read is deferred to first use).
func TestListenerSlowPeerDoesNotBlockAccept(t *testing.T) {
	inner := &chanListener{conns: make(chan net.Conn, 8), closed: make(chan struct{})}
	ln, err := NewListener(inner, Config{
		Trust:       mustPrefixes(t, "10.0.0.0/8"),
		ReadTimeout: 30 * time.Second, // huge: the old code would block this long per peer
	})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}

	const n = 5
	var partners []net.Conn
	for i := 0; i < n; i++ {
		clientSide, serverSide := net.Pipe() // clientSide never writes → header never arrives
		partners = append(partners, clientSide)
		inner.conns <- &fakeConn{Conn: serverSide, remote: tcpAddr(t, "10.1.2.3:55000")}
	}
	t.Cleanup(func() {
		for _, p := range partners {
			_ = p.Close()
		}
		_ = ln.Close()
	})

	// Every Accept must return well within the readTimeout (the slow headers are deferred).
	for i := 0; i < n; i++ {
		type res struct {
			c net.Conn
			e error
		}
		ch := make(chan res, 1)
		go func() { c, e := ln.Accept(); ch <- res{c, e} }()
		select {
		case r := <-ch:
			if r.e != nil {
				t.Fatalf("Accept %d returned error: %v", i, r.e)
			}
			conn := r.c
			t.Cleanup(func() { _ = conn.Close() })
		case <-time.After(3 * time.Second):
			t.Fatalf("Accept %d blocked: a slow-header trusted peer starved the accept loop", i)
		}
	}
}

// NewListener requires a non-empty trust set (the forgery hole guard).
func TestNewListenerEmptyTrustIsError(t *testing.T) {
	if _, err := NewListener(nil, Config{Trust: nil}); err == nil {
		t.Fatalf("expected error: an enabled PROXY listener with an empty trust set is a config error")
	}
}

// End-to-end over a real loopback TCP listener: a trusted-looking peer (127.0.0.1)
// gets its RemoteAddr rewritten; the trust set must include the loopback for this.
func TestListenerRealLoopback(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln, err := NewListener(base, Config{Trust: mustPrefixes(t, "127.0.0.0/8")})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	go func() {
		c, derr := net.Dial("tcp", base.Addr().String())
		if derr != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("PROXY TCP4 198.51.100.23 203.0.113.1 5000 443\r\npayload"))
		time.Sleep(50 * time.Millisecond)
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); !strings.HasPrefix(got, "198.51.100.23:") {
		t.Fatalf("RemoteAddr = %q, want the advertised client 198.51.100.23:5000", got)
	}
}
