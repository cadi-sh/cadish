package server

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/logs"
)

// shortSocketPath returns a unix-socket path short enough for the platform limit
// (macOS caps sun_path at ~104 bytes, which t.TempDir's deep path overflows). It
// creates a short-named dir directly under the system temp dir and unlinks it at
// test end.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cad")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

// End-to-end: publish a record on the hub, and a client connected over the unix
// socket receives the NDJSON line, which parses back to the same record via the
// SAME logs.ParseLine the `cadish logs` consumer uses.
func TestAccessSocketRoundTrip(t *testing.T) {
	path := shortSocketPath(t)

	hub := newAccessHub(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sock, err := ListenAccessSocket(ctx, hub, path, nil)
	if err != nil {
		t.Fatalf("ListenAccessSocket: %v", err)
	}
	defer sock.Close()

	// The socket must be created with 0600 perms (local-only, owner-only).
	if info, serr := os.Stat(path); serr != nil {
		t.Fatalf("stat socket: %v", serr)
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket perms = %o, want 600", perm)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the server to register our subscriber before publishing (no backlog,
	// so a record published before we subscribe is missed by design).
	deadline := time.Now().Add(2 * time.Second)
	for hub.subscriberCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never registered the subscriber")
		}
		time.Sleep(time.Millisecond)
	}

	rec := sampleRecord()
	hub.publish(rec)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read NDJSON line: %v", err)
	}
	parsed, ok, perr := logs.ParseLine(line)
	if perr != nil || !ok {
		t.Fatalf("ParseLine(socket line) ok=%v err=%v line=%s", ok, perr, line)
	}
	if parsed.Path != rec.Path || parsed.Cache != rec.Cache || parsed.Status != rec.Status {
		t.Errorf("round-trip mismatch: parsed=%+v want path/cache/status from %+v", parsed, rec)
	}
}

// A disabled hub (`access_log off`) accepts the connection but streams nothing and
// closes it promptly (subscribe returns nil → serveConn returns).
func TestAccessSocketDisabledHub(t *testing.T) {
	path := shortSocketPath(t)

	hub := newAccessHub(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sock, err := ListenAccessSocket(ctx, hub, path, nil)
	if err != nil {
		t.Fatalf("ListenAccessSocket: %v", err)
	}
	defer sock.Close()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The server closes the connection immediately (nothing to stream); a read sees
	// EOF rather than any data.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, rerr := conn.Read(buf); rerr == nil && n > 0 {
		t.Errorf("disabled hub streamed %d byte(s); want EOF/none", n)
	}
}

// Cancelling the serving context unblocks Accept and unlinks the socket file.
func TestAccessSocketCloseUnlinks(t *testing.T) {
	path := shortSocketPath(t)

	hub := newAccessHub(true)
	ctx, cancel := context.WithCancel(context.Background())
	sock, err := ListenAccessSocket(ctx, hub, path, nil)
	if err != nil {
		t.Fatalf("ListenAccessSocket: %v", err)
	}
	if _, serr := os.Stat(path); serr != nil {
		t.Fatalf("socket not created: %v", serr)
	}
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, serr := os.Stat(path); os.IsNotExist(serr) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket file not unlinked after ctx cancel")
		}
		time.Sleep(time.Millisecond)
	}
	_ = sock
}
