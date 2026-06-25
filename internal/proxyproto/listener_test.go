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
	// After a rejection the single-shot inner listener has no next connection, so
	// Accept surfaces its "closed" error; prefer the recorded rejection reason.
	if err != nil && rejected != nil {
		err = rejected
	}
	wg.Wait()
	if err == nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	t.Cleanup(func() { _ = clientSide.Close() })
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
