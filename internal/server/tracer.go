package server

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// Tracer is the varnishlog-style transaction-trace seam. It is NIL by default;
// every method has a nil-safe receiver and the hot path holds a (possibly nil)
// *traceRecord whose recorders are all no-ops when nil, so a non-tracing cadish
// pays nothing — no allocation, no formatting — mirroring how the metrics seam is
// gated (see internal/metrics). A Tracer is constructed only when `-trace` (or the
// CADISH_TRACE env) is set.
//
// One traceRecord accumulates the per-request DECISION as the request flows
// through the handler lifecycle (RECV -> KEY -> LOOKUP -> ORIGIN -> DELIVER), then
// the ServeHTTP defer flushes it as one multi-line transaction block, the way
// `varnishlog` groups a transaction. Safe for concurrent use: the shared Tracer
// only owns an io.Writer guarded by a mutex; each in-flight request owns its own
// traceRecord (no shared mutable state on the hot path).
type Tracer struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

// NewTracer builds a Tracer writing transaction blocks to w (e.g. os.Stderr). now
// is the clock used for the transaction timestamp; pass time.Now in production.
func NewTracer(w io.Writer, now func() time.Time) *Tracer {
	if now == nil {
		now = time.Now
	}
	return &Tracer{w: w, now: now}
}

// begin starts a transaction record for one request. A nil Tracer returns a nil
// record, so every subsequent hook is a no-op (zero cost when tracing is off).
func (t *Tracer) begin(method, host, path string) *traceRecord {
	if t == nil {
		return nil
	}
	return &traceRecord{
		t:      t,
		start:  t.now(),
		method: method,
		host:   host,
		path:   path,
	}
}

// traceEvent is one ordered step in a request's decision trace. Kind is a short
// varnishlog-style tag (e.g. "RECV", "KEY", "ORIGIN"); Detail is the human line.
type traceEvent struct {
	kind   string
	detail string
}

// traceRecord accumulates one request's decision trace. A nil *traceRecord is a
// valid no-op receiver for every recorder, so the handler can hold a nil one (when
// tracing is off) and call the hooks unconditionally without a guard at each site.
type traceRecord struct {
	t      *Tracer
	start  time.Time
	method string
	host   string
	path   string
	events []traceEvent
}

// add appends an event. Nil-safe: a nil record (tracing off) drops it.
func (r *traceRecord) add(kind, detail string) {
	if r == nil {
		return
	}
	r.events = append(r.events, traceEvent{kind: kind, detail: detail})
}

// --- decision hooks (one per handler decision point) ---

// recv records the RECV-phase request decision (route + pass/respond/purge).
func (r *traceRecord) recv(rd pipeline.RequestDecision) {
	if r == nil {
		return
	}
	up := rd.Upstream
	if up == "" {
		up = "(default)"
	}
	r.add("RECV", "upstream="+up)
	if rd.Synthetic != nil {
		r.add("RECV", "respond status="+strconv.Itoa(rd.Synthetic.Status))
	}
	if rd.Redirect != nil {
		r.add("RECV", "redirect status="+strconv.Itoa(rd.Redirect.Status)+" -> "+rd.Redirect.Location)
	}
	if rd.Purge != nil {
		detail := "purge authorized"
		if rd.Purge.Regex != "" {
			detail += " ban=" + rd.Purge.Regex
		}
		r.add("RECV", detail)
	}
	if rd.Pass {
		r.add("RECV", "pass (cache bypass)")
	}
	for _, op := range rd.ReqHeaderOps {
		r.add("REQHDR", headerOpString(op))
	}
}

// key records the computed cache key (KEY phase).
func (r *traceRecord) key(k string) {
	if r == nil {
		return
	}
	if k == "" {
		r.add("KEY", "(none)")
		return
	}
	r.add("KEY", k)
}

// lookup records the LOOKUP outcome (hit/stale/miss/hit-for-miss).
func (r *traceRecord) lookup(state string) { r.add("LOOKUP", state) }

// origin records the routed upstream actually fetched.
func (r *traceRecord) origin(upstream string) {
	if r == nil {
		return
	}
	if upstream == "" {
		upstream = "(default)"
	}
	r.add("ORIGIN", "fetch upstream="+upstream)
}

// response records the EvalResponse decision (ttl/grace/hit-for-miss/store).
func (r *traceRecord) response(status int, sd pipeline.ResponseDecision, doStore bool) {
	if r == nil {
		return
	}
	var b strings.Builder
	b.WriteString("status=")
	b.WriteString(strconv.Itoa(status))
	if sd.HitForMiss > 0 {
		b.WriteString(" hit_for_miss=")
		b.WriteString(sd.HitForMiss.String())
	} else if sd.Cacheable {
		b.WriteString(" cacheable ttl=")
		b.WriteString(sd.TTL.String())
		b.WriteString(" grace=")
		b.WriteString(sd.Grace.String())
	} else {
		b.WriteString(" uncacheable")
	}
	if sd.StoreTier != "" {
		b.WriteString(" tier=")
		b.WriteString(sd.StoreTier)
	}
	if doStore {
		b.WriteString(" store=yes")
	} else {
		b.WriteString(" store=no")
	}
	r.add("RESP", b.String())
}

// deliver records the DELIVER-phase body transforms applied (`replace`).
func (r *traceRecord) deliver(transforms []pipeline.Replacement) {
	if r == nil || len(transforms) == 0 {
		return
	}
	for _, tr := range transforms {
		r.add("DELIVER", "replace "+strconv.Quote(tr.Old)+" -> "+strconv.Quote(tr.New))
	}
}

// note records a free-form decision detail (e.g. cluster routing, origin error).
func (r *traceRecord) note(kind, detail string) { r.add(kind, detail) }

// flush renders the accumulated transaction as one varnishlog-style block and
// writes it under the Tracer's mutex. Nil-safe (a nil record writes nothing).
func (r *traceRecord) flush(status int, cacheStatus string, dur time.Duration) {
	if r == nil || r.t == nil {
		return
	}
	var b strings.Builder
	// Transaction header: timestamp + request line; footer: final status + cache.
	b.WriteString("* << Request >> ")
	b.WriteString(r.start.Format("15:04:05.000"))
	b.WriteByte('\n')
	b.WriteString("-   ReqLine     ")
	b.WriteString(r.method)
	b.WriteByte(' ')
	b.WriteString(r.host)
	b.WriteString(r.path)
	b.WriteByte('\n')
	for _, e := range r.events {
		b.WriteString("-   ")
		b.WriteString(padRight(e.kind, 11))
		b.WriteByte(' ')
		b.WriteString(e.detail)
		b.WriteByte('\n')
	}
	b.WriteString("-   End         status=")
	b.WriteString(strconv.Itoa(status))
	b.WriteString(" cache=")
	b.WriteString(cacheStatus)
	b.WriteString(" dur_ms=")
	b.WriteString(strconv.FormatInt(dur.Milliseconds(), 10))
	b.WriteByte('\n')

	r.t.mu.Lock()
	_, _ = io.WriteString(r.t.w, b.String())
	r.t.mu.Unlock()
}

// headerOpString renders a header op for the trace (set/add/del NAME[=VALUE]).
func headerOpString(op pipeline.HeaderOp) string {
	switch op.Op {
	case pipeline.OpSet:
		return "set " + op.Name + "=" + op.Value
	case pipeline.OpAppend:
		return "add " + op.Name + "=" + op.Value
	case pipeline.OpRemove:
		return "del " + op.Name
	default:
		return op.Name
	}
}

// padRight pads s with spaces to width n (for column alignment in the trace).
func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
