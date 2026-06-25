package lb

import (
	"context"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// hangingResolver blocks until its context is cancelled, then returns the
// context error. It models a stuck DNS server that never answers.
type hangingResolver struct{}

func (hangingResolver) Resolve(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestResolveTargetTimedBoundsHang verifies that a hanging resolver does not
// block resolveTargetTimed indefinitely: the per-target deadline (here supplied
// via a short parent context) cancels the wedged lookup so the reconcile loop can
// proceed to the next target. Before the per-target timeout, a single stuck
// dns:// or k8s:// target would wedge re-resolution of the whole pool.
func TestResolveTargetTimedBoundsHang(t *testing.T) {
	tgt, err := parseTarget("dns://stuck.example:8080", cadishfile.Pos{})
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}

	// A parent context tighter than perTargetResolveTimeout keeps the test fast
	// while still proving the call returns rather than hanging forever.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		_, _ = resolveTargetTimed(ctx, hangingResolver{}, nil, &tgt)
		close(done)
	}()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("resolveTargetTimed took too long to abort: %v", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resolveTargetTimed did not return on a hanging resolver (no timeout)")
	}
}

// TestResolveTargetTimedStaticNoTimeout confirms static targets skip the timeout
// wrapper entirely and resolve immediately even when the parent context is
// already cancelled (they do no I/O).
func TestResolveTargetTimedStaticNoTimeout(t *testing.T) {
	tgt, err := parseTarget("http://10.0.0.1:80", cadishfile.Pos{})
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	eps, err := resolveTargetTimed(ctx, hangingResolver{}, nil, &tgt)
	if err != nil {
		t.Fatalf("static resolve errored: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("static target: got %d endpoints, want 1", len(eps))
	}
}
