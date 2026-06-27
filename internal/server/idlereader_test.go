package server

import (
	"io"
	"sync"
	"testing"
	"time"
)

// nopBody is an inert ReadCloser used by the register/deregister tests/benchmarks: it
// is never actually read (we only exercise the sweeper bookkeeping, not the watchdog).
type nopBody struct{}

func (nopBody) Read(p []byte) (int, error) { return 0, io.EOF }
func (nopBody) Close() error               { return nil }

// TestSweeperIntervalTracksMinTimeoutViaCounts is the R06 correctness pin: the scan
// period must track the SMALLEST active reader timeout regardless of how that min is
// derived (now via the bounded timeoutCounts map, not an O(N) scan). Registering and
// then deregistering readers with different timeouts must move the interval to the
// live min and back, and the bookkeeping (active set + timeout buckets) must stay
// exactly in lockstep so a reaped/duplicated reader can never corrupt the min.
func TestSweeperIntervalTracksMinTimeoutViaCounts(t *testing.T) {
	sw := newIdleSweeper(sweepInterval(60 * time.Second))
	defer sw.Stop()

	big := newIdleTimeoutReader(sw, nopBody{}, 40*time.Second, nil, "big")
	want := sweepInterval(40 * time.Second)
	if got := sw.curInterval(); got != want {
		t.Fatalf("after one 40s reader: interval=%v want %v", got, want)
	}

	// A tighter reader must pull the interval DOWN to its (smaller) period.
	small := newIdleTimeoutReader(sw, nopBody{}, 2*time.Second, nil, "small")
	want = sweepInterval(2 * time.Second)
	if got := sw.curInterval(); got != want {
		t.Fatalf("after adding a 2s reader: interval=%v want %v", got, want)
	}

	// A SECOND reader sharing the small timeout must not change the interval, and
	// deregistering only ONE of the two must keep the interval at the small period
	// (the bucket still has a member) — the count-map must not drop to zero early.
	small2 := newIdleTimeoutReader(sw, nopBody{}, 2*time.Second, nil, "small2")
	small.deregister()
	if got := sw.curInterval(); got != want {
		t.Fatalf("after removing one of two 2s readers: interval=%v want %v (bucket not empty)", got, want)
	}

	// Removing the LAST small reader must relax the interval back to the 40s period.
	small2.deregister()
	want = sweepInterval(40 * time.Second)
	if got := sw.curInterval(); got != want {
		t.Fatalf("after removing the last 2s reader: interval=%v want %v", got, want)
	}

	// An idempotent double-deregister must NOT underflow a bucket and corrupt the min.
	small2.deregister()
	if got := sw.curInterval(); got != want {
		t.Fatalf("after a redundant deregister: interval=%v want %v", got, want)
	}

	big.deregister()
	if got, w := sw.curInterval(), sweepInterval(60*time.Second); got != w {
		t.Fatalf("after removing all readers: interval=%v want base %v", got, w)
	}
	if sw.activeLen() != 0 {
		t.Fatalf("active set not empty after deregistering all: %d", sw.activeLen())
	}
}

// BenchmarkSweeperRegisterDeregister is the R06 perf pin: a register immediately
// followed by a deregister must be ~O(1) regardless of how many readers are already
// registered. The old code scanned the whole active set under the lock on each
// register/deregister, so a steady-state of N readers made each op O(N). With the
// bounded timeoutCounts map the cost is independent of N. Run e.g.
//
//	go test ./internal/server -run x -bench BenchmarkSweeperRegisterDeregister -benchmem
//
// across a range of preloaded N (below) and observe ns/op stays flat.
func BenchmarkSweeperRegisterDeregister(b *testing.B) {
	for _, n := range []int{0, 100, 1000, 10000} {
		sw := newIdleSweeper(sweepInterval(60 * time.Second))
		// Preload N steady-state readers (varied timeouts → a few distinct buckets).
		preload := make([]*idleTimeoutReader, n)
		for i := range preload {
			preload[i] = newIdleTimeoutReader(sw, nopBody{}, time.Duration(10+i%5)*time.Second, nil, "p")
		}
		// A long timeout so a background sweep never reaps r mid-benchmark (it is never
		// read, so its progress clock never advances).
		r := &idleTimeoutReader{rc: nopBody{}, idleTimeout: 10 * time.Minute, sweeper: sw}
		r.lastProgressNanos.Store(time.Now().UnixNano())
		b.Run(itoa(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sw.register(r)
				sw.deregister(r)
			}
		})
		sw.Stop()
	}
}

// blockingBody is a ReadCloser whose Read blocks until Close is called (simulating
// a black-holed origin that goes silent mid-body). After Close, Read returns EOF.
type blockingBody struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingBody() *blockingBody { return &blockingBody{closed: make(chan struct{})} }

func (b *blockingBody) Read(p []byte) (int, error) {
	<-b.closed
	return 0, io.EOF
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// TestSweepIntervalForReader pins the helper that floors the scan period at a small
// lower bound so a tight per-reader timeout is detected promptly, not on the next
// coarse global tick.
func TestSweepIntervalForReader(t *testing.T) {
	// A small between_bytes (5s) must yield a sub-second-ish scan, not the
	// ~30s the global 60s idle would produce.
	if got := sweepIntervalForTimeout(5 * time.Second); got > 3*time.Second {
		t.Errorf("sweepIntervalForTimeout(5s) = %v, want a tight interval", got)
	}
	// The interval is floored so we never busy-spin.
	if got := sweepIntervalForTimeout(10 * time.Millisecond); got < minSweepInterval {
		t.Errorf("sweepIntervalForTimeout(10ms) = %v, want >= floor %v", got, minSweepInterval)
	}
}

// TestSweeperReapsSmallBetweenBytesPromptly is the regression for finding 5: a
// reader registered with a SMALL between-bytes budget must be reaped close to that
// budget, even when the sweeper was created from a LARGE global idle timeout. With
// the old fixed interval (idle/2 = 30s for a 60s idle) the 100ms reader would not
// be reaped for ~30s; now the sweeper tightens its tick to the smallest active
// timeout.
func TestSweeperReapsSmallBetweenBytesPromptly(t *testing.T) {
	// Sweeper born from a large global idle (coarse default interval).
	sw := newIdleSweeper(sweepInterval(60 * time.Second))
	defer sw.Stop()

	body := newBlockingBody()
	// Effective per-reader timeout is tiny (the min(idle, between_bytes) the handler
	// passes in): 100ms.
	ir := newIdleTimeoutReader(sw, body, 100*time.Millisecond, nil, "k")

	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(ir)
		done <- err
	}()

	select {
	case <-done:
		if !ir.stalled() {
			t.Fatal("reader returned but was not reaped by the watchdog")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("small-between-bytes reader was NOT reaped promptly (bounded by global interval)")
	}
}
