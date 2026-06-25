package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
)

// AccessSocket is a running unix-domain stream server: it accepts local consumer
// connections and streams each one the hub's live access records as NDJSON. It is
// the transport half of D44 — `cadish logs` dials this socket and reuses
// internal/logs (ParseLine/Filter/Render) verbatim on the stream.
//
// The socket is local-only and created with 0600 permissions, so no auth is needed
// (filesystem-permissioned, loopback-equivalent). There is no backlog: a consumer
// receives only records that arrive after it connects.
type AccessSocket struct {
	ln   net.Listener
	path string
	hub  *AccessHub
	log  *slog.Logger
}

// ListenAccessSocket binds the unix socket at path (removing a stale one first),
// chmods it to 0600, and starts accepting consumer connections until ctx is
// cancelled. It returns the running *AccessSocket (call Close to stop and unlink) or
// an error if the socket cannot be bound.
func ListenAccessSocket(ctx context.Context, hub *AccessHub, path string, log *slog.Logger) (*AccessSocket, error) {
	// Remove a stale socket from a previous run (a leftover file makes bind fail with
	// EADDRINUSE even though nothing is listening).
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("access socket: remove stale %s: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("access socket: listen %s: %w", path, err)
	}
	// Restrict to the owner: local-only, no auth, defence-in-depth on the filesystem.
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("access socket: chmod %s: %w", path, err)
	}

	s := &AccessSocket{ln: ln, path: path, hub: hub, log: log}

	// Close the listener when the serving context is cancelled (unblocks Accept).
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	go s.acceptLoop(ctx)
	return s, nil
}

// Close stops accepting and unlinks the socket file. Idempotent.
func (s *AccessSocket) Close() error {
	err := s.ln.Close()
	_ = os.Remove(s.path)
	return err
}

// Path is the bound socket path (useful for tests and logging).
func (s *AccessSocket) Path() string { return s.path }

// acceptLoop accepts connections until the listener is closed (by Close / ctx).
func (s *AccessSocket) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// A closed listener (shutdown) ends the loop cleanly; nothing else is
			// recoverable here, so return.
			return
		}
		go s.serveConn(ctx, conn)
	}
}

// serveConn registers a subscriber and streams its live records to conn as NDJSON
// until the client disconnects or the server shuts down. A client that stops reading
// (and overflows its buffer) loses records — counted on the subscriber, never
// blocking the publisher.
func (s *AccessSocket) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	sub := s.hub.subscribe()
	if sub == nil {
		// Hub disabled (`access_log off`): nothing to stream.
		return
	}
	defer s.hub.unsubscribe(sub)

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// `cadish logs` only reads; detect its disconnect by reading and cancelling on
	// EOF/error so the writer loop below exits promptly (otherwise it would block on
	// the channel until the next record).
	go func() {
		buf := make([]byte, 256)
		for {
			if _, err := conn.Read(buf); err != nil {
				cancel()
				return
			}
		}
	}()

	var line []byte
	for {
		select {
		case <-connCtx.Done():
			return
		case rec := <-sub.ch:
			var err error
			line, err = rec.appendNDJSON(line[:0])
			if err != nil {
				if s.log != nil {
					s.log.Warn("access socket: marshal record", "err", err)
				}
				continue
			}
			if _, err := conn.Write(line); err != nil {
				return
			}
		}
	}
}
