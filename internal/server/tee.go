package server

import (
	"io"
	"log/slog"

	"github.com/cadi-sh/cadish/internal/cache"
)

// cacheTee wraps the origin body so that bytes streamed to the client are also
// written to the cache tier (no full-file buffering — uses io.TeeReader
// semantics). The cache write is committed only if the whole body was read cleanly;
// any read or cache-write error aborts the partial write so a truncated object is
// never served as a hit later.
type cacheTee struct {
	src      io.Reader // tee: reads from origin, mirrors to cache writer
	cw       cache.TierWriter
	log      *slog.Logger
	key      string
	writeErr error // first cache-write error (stops mirroring, never fails client)
	done     bool
}

func newCacheTee(origin io.Reader, cw cache.TierWriter, log *slog.Logger, key string) *cacheTee {
	t := &cacheTee{cw: cw, log: log, key: key}
	t.src = io.TeeReader(origin, writerFunc(t.mirror))
	return t
}

// mirror writes to the cache, latching the first error and ceasing further writes.
// It always reports success to the TeeReader so the client stream is never disturbed
// by a cache-write failure.
func (t *cacheTee) mirror(p []byte) (int, error) {
	if t.writeErr != nil {
		return len(p), nil
	}
	if _, err := t.cw.Write(p); err != nil {
		t.writeErr = err
	}
	return len(p), nil
}

func (t *cacheTee) Read(p []byte) (int, error) { return t.src.Read(p) }

// finish commits the cache write only on a fully-received body: copyErr == nil, no
// cache-write error, AND complete == true. complete carries the caller's
// expected-vs-actual length verdict: even a clean io.EOF can be a TRUNCATED body
// when the origin closes before sending all Content-Length bytes, and committing
// that would serve a short object as a cache hit forever. When complete is false the
// partial write is aborted just like a copy/write error. Callers that cannot know
// the expected length (unknown Content-Length) pass complete == true.
func (t *cacheTee) finish(copyErr error, complete bool) bool {
	if t.done {
		return false
	}
	t.done = true
	if copyErr != nil || t.writeErr != nil || !complete {
		if err := t.cw.Abort(); err != nil && t.log != nil {
			t.log.Warn("cache abort failed", "key", t.key, "err", err)
		}
		return false
	}
	if err := t.cw.Commit(); err != nil {
		if t.log != nil {
			t.log.Warn("cache commit failed", "key", t.key, "err", err)
		}
		return false
	}
	return true
}

func (t *cacheTee) abort() {
	if t.done {
		return
	}
	t.done = true
	_ = t.cw.Abort()
}

// writerFunc adapts a function to io.Writer.
type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
