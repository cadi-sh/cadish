package server

import (
	"net/http"
	"time"
)

// statusRecorder wraps an http.ResponseWriter to capture the final status code and
// the total body bytes written, so the access log can report them after the handler
// returns. It is intentionally tiny (two integer fields, every call forwarded) to
// stay cheap on the hot path.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

// WriteHeader latches the status (only the first call counts, mirroring net/http).
func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

// logRequest records per-request metrics and, when a `cadish logs` consumer is
// attached, fan-outs one compact access record to the in-memory hub (D44). The
// access log is NEVER written to disk by the server — viewing/persisting is the
// consumer's job (`cadish logs > file`); D39's asyncWriter + slog file/stderr
// access-log path are retired.
//
// The hub fan-out is gated on a single atomic ("any consumer attached?"): with
// none attached, NOTHING is formatted, allocated or sent — the only cost is the
// atomic load (the Varnish-without-varnishncsa case). The record carries method,
// host, path (never the query string — signed-URL signatures are sensitive),
// status, response bytes, cache result, the upstream/cache tier that served it,
// and wall-clock duration in milliseconds.
func (h *Handler) logRequest(r *http.Request, rec *statusRecorder, info *reqInfo, dur time.Duration) {
	// Record per-request metrics first (a nil h.metrics is a no-op, so this is
	// free when no admin block is configured). This runs for EVERY request via the
	// ServeHTTP defer, capturing the final cache outcome and total wall time.
	h.metrics.IncRequest()
	h.metrics.RecordCacheStatus(info.cacheStatus)
	h.metrics.RecordLatency(dur)

	// Zero-cost idle path: with no consumer attached (or `access_log off`), one
	// atomic load and we are done — no record built, no allocation, no syscall.
	if h.accessHub.subscriberCount() == 0 {
		return
	}
	h.accessHub.publish(accessRecord{
		Time:     h.now(),
		Method:   methodOf(r),
		Host:     r.Host,
		Path:     r.URL.Path,
		Status:   rec.status,
		Bytes:    rec.bytes,
		Cache:    info.cacheStatus,
		Upstream: info.upstream,
		DurMs:    dur.Milliseconds(),
	})
}

func methodOf(r *http.Request) string {
	if r.Method == "" {
		return http.MethodGet
	}
	return r.Method
}
