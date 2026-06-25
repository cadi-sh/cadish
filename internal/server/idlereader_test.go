package server

import (
	"io"
	"sync"
	"testing"
	"time"
)

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
