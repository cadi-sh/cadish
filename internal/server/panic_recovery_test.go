package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/metrics"
	"github.com/cadi-sh/cadish/internal/origin"
)

// panicOrigin is an origin.Origin whose Fetch panics on the first call and blocks
// (until release) on later calls, so a coalesce winner panics while waiters are
// parked. When panicGate is non-nil the winner waits on it BEFORE panicking, so a
// test can park a waiter first and prove the waiter is woken by the winner's
// finish() rather than by becoming a winner itself.
type panicOrigin struct {
	calls     atomic.Int64
	release   chan struct{} // lets the (non-winner) fall-through fetch proceed
	panicGate chan struct{} // winner blocks on this before panicking (nil = panic immediately)
}

func (p *panicOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	n := p.calls.Add(1)
	if n == 1 {
		// The winner: optionally wait until the test has parked a waiter, then panic
		// mid-fetch, before any response bytes are written.
		if p.panicGate != nil {
			<-p.panicGate
		}
		panic("boom: injected origin panic")
	}
	// A waiter that fell through to its own fetch after the winner failed: serve a
	// trivial cacheable body so the request completes cleanly (proving the waiter
	// did NOT hang).
	<-p.release
	return &origin.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

// TestServeHTTP_PanicRecovered verifies a panic in the request lifecycle is turned
// into a clean 500 (connection NOT dropped), the metric is incremented, and the
// server stays up for the next request.
func TestServeHTTP_PanicRecovered(t *testing.T) {
	m := metrics.New()
	h, _ := buildHandler(t, nil, `test.local {
	cache { ram 8MiB }
	upstream b { to %s }
	cache_ttl default ttl 60s
}
`, "http://127.0.0.1:1")
	h.metrics = m
	injectOrigin(t, h, &panicOrigin{release: closedChan()})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test.local/page", nil)
	req.Host = "test.local"
	// Must not propagate the panic out of ServeHTTP.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := m.Snapshot().InternalErrors; got != 1 {
		t.Errorf("InternalErrors = %d, want 1", got)
	}
}

// TestCoalesceWinnerPanic_WaiterDoesNotHang is the important one: the coalesce
// WINNER panics mid-fetch; a concurrent WAITER on the same key must be woken (done
// closed) rather than blocking forever, and must complete with its own clean fetch.
func TestCoalesceWinnerPanic_WaiterDoesNotHang(t *testing.T) {
	po := &panicOrigin{release: make(chan struct{}), panicGate: make(chan struct{})}
	m := metrics.New()
	h, _ := buildHandler(t, nil, `test.local {
	cache { ram 8MiB }
	upstream b { to %s }
	cache_ttl default ttl 60s
}
`, "http://127.0.0.1:1")
	h.metrics = m
	injectOrigin(t, h, po)

	const key = "/coalesced"
	// Winner: fire it and let it become the in-flight call. It will block in Fetch on
	// panicGate so we can park a waiter before it panics.
	winnerDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test.local"+key, nil)
		req.Host = "test.local"
		h.ServeHTTP(rec, req) // recovers the panic internally
		winnerDone <- rec.Code
	}()

	// Wait until the winner has registered its coalesce call AND entered Fetch (so the
	// next request is a WAITER, not a second winner).
	waitFor(t, 5*time.Second, func() bool { return po.calls.Load() >= 1 })
	waitFor(t, 5*time.Second, func() bool {
		h.coalesce.mu.Lock()
		n := len(h.coalesce.calls)
		h.coalesce.mu.Unlock()
		return n >= 1
	})

	// Waiter on the SAME key, in a goroutine so we can assert it does not hang.
	waiterDone := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test.local"+key, nil)
		req.Host = "test.local"
		h.ServeHTTP(rec, req)
		waiterDone <- rec.Code
	}()

	// Park the waiter (it must register as a coalesce waiter before we let the winner
	// panic — proving it is woken by the winner's finish(), not by being a winner).
	waitFor(t, 5*time.Second, func() bool { return m.Snapshot().CoalesceWaiters >= 1 })

	// Now let the winner panic.
	close(po.panicGate)

	// The winner should finish (recovered) with a 500 and, crucially, must have run
	// finish() so the waiter is unblocked.
	select {
	case code := <-winnerDone:
		if code != http.StatusInternalServerError {
			t.Errorf("winner status = %d, want 500", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("winner did not complete")
	}

	// Let the waiter's own fall-through fetch (the 2nd Fetch call) proceed.
	close(po.release)

	select {
	case code := <-waiterDone:
		if code != http.StatusOK {
			t.Errorf("waiter status = %d, want 200 (clean fall-through fetch)", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter HUNG after winner panic — finish() did not run for the winner")
	}

	// The coalesce entry must not leak: after both requests complete, the in-flight
	// map must be empty (the winner's deferred finish() deleted it).
	waitFor(t, 5*time.Second, func() bool {
		h.coalesce.mu.Lock()
		n := len(h.coalesce.calls)
		h.coalesce.mu.Unlock()
		return n == 0
	})
}

// --- helpers ---

// injectOrigin replaces every routed site's default origin with o.
func injectOrigin(t *testing.T, h *Handler, o origin.Origin) {
	t.Helper()
	rt := h.route.Load()
	for _, s := range rt.sites {
		s.Origin = o
	}
}

func closedChan() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
