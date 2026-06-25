package server

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// accessSubBuffer is the fixed per-subscriber channel depth. At ~120 bytes/record
// this is ~1 MiB of in-flight backlog per attached consumer — large enough that a
// consumer keeping up under normal load loses nothing, small enough to bound memory.
// Beyond it the hub drops + counts rather than ever blocking the serve path (D44).
const accessSubBuffer = 8192

// accessRecord is one compact, pre-format access-log fact built on the hot path. It
// carries only fields already on reqInfo/the recorder (no strings formatted, no
// allocation beyond the struct itself); formatting to NDJSON happens off the hot
// path, in each subscriber's connection goroutine. The query string and client IP
// are deliberately absent (signed-URL signatures are sensitive — see D18).
type accessRecord struct {
	Time     time.Time
	Method   string
	Host     string
	Path     string
	Status   int
	Bytes    int64
	Cache    string
	Upstream string
	DurMs    int64
}

// accessWire is the on-the-wire JSON shape. Its keys mirror the slog access line
// keys internal/logs already parses (time/msg/method/host/path/status/bytes/cache/
// upstream/dur_ms), so a consumer reuses logs.ParseLine verbatim. msg is always
// "request" so logs.ParseLine treats every streamed line as an access record.
type accessWire struct {
	Time     time.Time `json:"time"`
	Msg      string    `json:"msg"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Bytes    int64     `json:"bytes"`
	Cache    string    `json:"cache"`
	Upstream string    `json:"upstream"`
	DurMs    int64     `json:"dur_ms"`
}

// appendNDJSON marshals the record as one NDJSON line (trailing '\n') onto dst. It
// runs in the subscriber's connection goroutine, never on the request hot path.
func (r accessRecord) appendNDJSON(dst []byte) ([]byte, error) {
	b, err := json.Marshal(accessWire{
		Time:     r.Time,
		Msg:      "request",
		Method:   r.Method,
		Host:     r.Host,
		Path:     r.Path,
		Status:   r.Status,
		Bytes:    r.Bytes,
		Cache:    r.Cache,
		Upstream: r.Upstream,
		DurMs:    r.DurMs,
	})
	if err != nil {
		return dst, err
	}
	dst = append(dst, b...)
	dst = append(dst, '\n')
	return dst, nil
}

// accessSub is one attached consumer: a buffered channel of live records plus a
// drop counter. The channel is the ONLY buffering — there is no historical ring, so
// a subscriber receives only records published after it attached (D44).
type accessSub struct {
	ch      chan accessRecord
	dropped atomic.Uint64
}

// AccessHub is the in-memory access-log fan-out (the Varnish-VSL analogue). The hot
// path checks ONE atomic ("any subscribers?"); with none attached it does nothing —
// no record built, no formatting, no syscall, no disk. When consumers are attached
// it fan-outs each record to their buffered channels with a NON-BLOCKING send: a
// full channel drops + counts, so a slow consumer never slows the server.
//
// When the hub is disabled (`access_log off`) it registers no subscribers and the
// count stays 0 forever, so the idle atomic check is the only cost the server ever
// pays.
type AccessHub struct {
	enabled bool
	bufSize int

	mu    sync.Mutex
	subs  map[*accessSub]struct{}
	count atomic.Int64 // == len(subs); read lock-free on the hot path
}

// newAccessHub builds a hub. enabled=false models `access_log off` — subscribe is a
// no-op and the count never leaves 0.
func newAccessHub(enabled bool) *AccessHub {
	return newAccessHubSize(enabled, accessSubBuffer)
}

// newAccessHubSize is newAccessHub with an explicit per-subscriber buffer (tests use
// a tiny buffer to exercise the drop-on-full path deterministically).
func newAccessHubSize(enabled bool, bufSize int) *AccessHub {
	return &AccessHub{enabled: enabled, bufSize: bufSize, subs: map[*accessSub]struct{}{}}
}

// Enabled reports whether the hub accepts subscribers (false under `access_log off`).
func (h *AccessHub) Enabled() bool { return h != nil && h.enabled }

// subscriberCount is the lock-free hot-path probe: the number of attached consumers.
func (h *AccessHub) subscriberCount() int64 {
	if h == nil {
		return 0
	}
	return h.count.Load()
}

// publish fan-outs rec to every subscriber with a non-blocking send. A full channel
// drops the record and bumps that subscriber's counter; the server never blocks. The
// caller MUST gate on subscriberCount()==0 first so this is never reached when idle.
func (h *AccessHub) publish(rec accessRecord) {
	h.mu.Lock()
	for sub := range h.subs {
		select {
		case sub.ch <- rec:
		default:
			sub.dropped.Add(1)
		}
	}
	h.mu.Unlock()
}

// subscribe registers a new consumer and returns its record channel, or nil when the
// hub is disabled. Unsubscribe must be called when the consumer goes away.
func (h *AccessHub) subscribe() *accessSub {
	if h == nil || !h.enabled {
		return nil
	}
	sub := &accessSub{ch: make(chan accessRecord, h.bufSize)}
	h.mu.Lock()
	h.subs[sub] = struct{}{}
	h.count.Store(int64(len(h.subs)))
	h.mu.Unlock()
	return sub
}

// unsubscribe removes a consumer. It is safe to call with a nil sub (the disabled
// case) and idempotent.
func (h *AccessHub) unsubscribe(sub *accessSub) {
	if h == nil || sub == nil {
		return
	}
	h.mu.Lock()
	if _, ok := h.subs[sub]; ok {
		delete(h.subs, sub)
		h.count.Store(int64(len(h.subs)))
	}
	h.mu.Unlock()
}
