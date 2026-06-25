package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/pipeline"
)

// syncBuf is a goroutine-safe buffer (the Tracer may be written from concurrent
// requests; the test origin + background fetches make this a real possibility).
type syncBuf struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A nil Tracer must be a complete no-op: begin returns nil and every hook on the
// nil record does nothing (the zero-cost-when-off guarantee).
func TestNilTracerIsNoop(t *testing.T) {
	var tr *Tracer
	rec := tr.begin("GET", "x", "/y")
	if rec != nil {
		t.Fatalf("nil tracer begin should return nil record, got %v", rec)
	}
	// None of these may panic on a nil record.
	rec.recv(pipeline.RequestDecision{})
	rec.key("k")
	rec.lookup("MISS")
	rec.origin("up")
	rec.note("X", "y")
	rec.flush(200, "MISS", time.Millisecond)
}

// A wired Tracer must emit a transaction block recording each decision: the route
// (upstream), the cache key, the lookup outcome, the EvalResponse ttl, and the
// final status/cache footer.
func TestTracerEmitsTransactionMissThenHit(t *testing.T) {
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello")
	})
	h, _ := buildHandler(t, nil, cfgBasic, origin.srv.URL)
	var sink syncBuf
	h.tracer = NewTracer(&sink, time.Now)

	// First GET: cold MISS -> ORIGIN.
	if rec := do(h, "GET", "http://test.local/page", nil); rec.Code != 200 {
		t.Fatalf("miss status %d", rec.Code)
	}
	out := sink.String()
	for _, want := range []string{
		"<< Request >>",
		"ReqLine     GET test.local/page",
		"KEY",
		"LOOKUP      MISS",
		"ORIGIN      fetch upstream=(default)",
		"RESP",
		"cacheable ttl=1m0s",
		"store=yes",
		"End         status=200 cache=MISS",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("trace missing %q in:\n%s", want, out)
		}
	}

	// Second GET of the same key: a cache HIT, served from cache, no ORIGIN fetch.
	sink2 := &syncBuf{}
	h.tracer = NewTracer(sink2, time.Now)
	if rec := do(h, "GET", "http://test.local/page", nil); rec.Code != 200 {
		t.Fatalf("hit status %d", rec.Code)
	}
	hitOut := sink2.String()
	if !strings.Contains(hitOut, "LOOKUP      FRESH") {
		t.Errorf("hit trace missing FRESH lookup:\n%s", hitOut)
	}
	if !strings.Contains(hitOut, "cache=HIT") {
		t.Errorf("hit trace missing cache=HIT footer:\n%s", hitOut)
	}
	if strings.Contains(hitOut, "ORIGIN      fetch") {
		t.Errorf("HIT must not fetch origin, trace:\n%s", hitOut)
	}
}

// A `pass` rule must surface the bypass in the trace.
func TestTracerRecordsPass(t *testing.T) {
	const cfgPass = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	@api path /api/*
	pass @api
	cache_ttl default ttl 60s
}
`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "x")
	})
	h, _ := buildHandler(t, nil, cfgPass, origin.srv.URL)
	var sink syncBuf
	h.tracer = NewTracer(&sink, time.Now)

	if rec := do(h, "GET", "http://test.local/api/v1", nil); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	out := sink.String()
	if !strings.Contains(out, "pass (cache bypass)") {
		t.Errorf("trace missing pass decision:\n%s", out)
	}
	if !strings.Contains(out, "PASS (bypass cache)") {
		t.Errorf("trace missing PASS lookup:\n%s", out)
	}
	if !strings.Contains(out, "cache=PASS") {
		t.Errorf("trace missing cache=PASS footer:\n%s", out)
	}
}

// A `respond` synthetic must short-circuit and be traced.
func TestTracerRecordsSynthetic(t *testing.T) {
	const cfgResp = `test.local {
	cache { ram 64MiB }
	upstream backend { to %s }
	respond /health 200 "ok"
}
`
	origin := newCountingOrigin(t, func(w http.ResponseWriter, r *http.Request) {})
	h, _ := buildHandler(t, nil, cfgResp, origin.srv.URL)
	var sink syncBuf
	h.tracer = NewTracer(&sink, time.Now)

	if rec := do(h, "GET", "http://test.local/health", nil); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	out := sink.String()
	if !strings.Contains(out, "respond status=200") {
		t.Errorf("trace missing respond decision:\n%s", out)
	}
	if !strings.Contains(out, "cache=SYNTH") {
		t.Errorf("trace missing cache=SYNTH footer:\n%s", out)
	}
}

// Tracing off (default handler) must write nothing and not panic.
func TestNoTracerWritesNothing(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hi")
	}))
	defer origin.Close()
	h, _ := buildHandler(t, nil, cfgBasic, origin.URL)
	// h.tracer is nil (the default).
	if rec := do(h, "GET", "http://test.local/z", nil); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}

// A nil Tracer's per-request hooks must not allocate (the zero-cost-when-off
// guarantee that lets the handler call them unconditionally on the hot path).
func TestNilTracerHooksDoNotAllocate(t *testing.T) {
	var tr *Tracer
	rd := pipeline.RequestDecision{Upstream: "backend", Pass: true}
	sd := pipeline.ResponseDecision{TTL: time.Minute, Cacheable: true}
	allocs := testing.AllocsPerRun(1000, func() {
		rec := tr.begin("GET", "h", "/p") // nil record when tracing is off
		rec.recv(rd)
		rec.key("k")
		rec.lookup("MISS")
		rec.origin("backend")
		rec.response(200, sd, true)
		rec.deliver(nil)
		rec.note("X", "y")
		rec.flush(200, "MISS", time.Millisecond)
	})
	if allocs != 0 {
		t.Errorf("nil tracer hooks allocated %v/op, want 0 (zero-cost-when-off)", allocs)
	}
}
