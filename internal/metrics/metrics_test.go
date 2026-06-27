package metrics

import (
	"sync"
	"testing"
	"time"
)

// A nil *Metrics must be a safe no-op on every recorder so the datapath pays
// nothing when no admin block is configured.
func TestNilMetricsIsNoOp(t *testing.T) {
	var m *Metrics
	// None of these may panic.
	m.IncRequest()
	m.RecordCacheStatus("HIT")
	m.IncCoalesceWinner()
	m.IncCoalesceWaiter()
	m.IncOriginFetch()
	m.IncOriginError()
	m.RecordSecurity("deny", "scanners")
	m.RecordLatency(5 * time.Millisecond)
	got := m.Snapshot()
	if got.Requests != 0 {
		t.Fatalf("nil Snapshot Requests = %d, want 0", got.Requests)
	}
}

func TestCountersAccumulate(t *testing.T) {
	m := New()
	m.IncRequest()
	m.IncRequest()
	m.RecordCacheStatus("HIT")
	m.RecordCacheStatus("HIT")
	m.RecordCacheStatus("MISS")
	m.RecordCacheStatus("HIT-STALE")
	m.RecordCacheStatus("PASS")
	m.IncCoalesceWinner()
	m.IncCoalesceWaiter()
	m.IncCoalesceWaiter()
	m.IncOriginFetch()
	m.IncOriginError()
	m.RecordSecurity("allow", "office")
	m.RecordSecurity("deny", "scanners")
	m.RecordSecurity("deny", "scanners")
	m.RecordSecurity("monitor", "admin")
	m.RecordSecurity("bogus", "x") // ignored

	s := m.Snapshot()
	if s.SecurityAllow != 1 {
		t.Errorf("SecurityAllow = %d, want 1", s.SecurityAllow)
	}
	if s.SecurityDeny != 2 {
		t.Errorf("SecurityDeny = %d, want 2", s.SecurityDeny)
	}
	if s.SecurityMonitor != 1 {
		t.Errorf("SecurityMonitor = %d, want 1", s.SecurityMonitor)
	}
	if s.Requests != 2 {
		t.Errorf("Requests = %d, want 2", s.Requests)
	}
	if s.Hits != 2 {
		t.Errorf("Hits = %d, want 2", s.Hits)
	}
	if s.Misses != 1 {
		t.Errorf("Misses = %d, want 1", s.Misses)
	}
	if s.HitsStale != 1 {
		t.Errorf("HitsStale = %d, want 1", s.HitsStale)
	}
	if s.Passes != 1 {
		t.Errorf("Passes = %d, want 1", s.Passes)
	}
	if s.CoalesceWinners != 1 {
		t.Errorf("CoalesceWinners = %d, want 1", s.CoalesceWinners)
	}
	if s.CoalesceWaiters != 2 {
		t.Errorf("CoalesceWaiters = %d, want 2", s.CoalesceWaiters)
	}
	if s.OriginFetches != 1 {
		t.Errorf("OriginFetches = %d, want 1", s.OriginFetches)
	}
	if s.OriginErrors != 1 {
		t.Errorf("OriginErrors = %d, want 1", s.OriginErrors)
	}
}

// HitRatio is hits / (hits+misses+stale), guarding the zero-traffic divide.
func TestHitRatio(t *testing.T) {
	m := New()
	if got := m.Snapshot().HitRatio(); got != 0 {
		t.Fatalf("empty HitRatio = %v, want 0", got)
	}
	for i := 0; i < 3; i++ {
		m.RecordCacheStatus("HIT")
	}
	m.RecordCacheStatus("MISS")
	if got := m.Snapshot().HitRatio(); got < 0.74 || got > 0.76 {
		t.Fatalf("HitRatio = %v, want ~0.75", got)
	}
}

// The latency histogram must yield monotonic, sane percentiles.
func TestLatencyPercentiles(t *testing.T) {
	m := New()
	// 100 samples 1ms..100ms.
	for i := 1; i <= 100; i++ {
		m.RecordLatency(time.Duration(i) * time.Millisecond)
	}
	s := m.Snapshot()
	p50 := s.LatencyP50()
	p99 := s.LatencyP99()
	if p50 <= 0 || p99 <= 0 {
		t.Fatalf("percentiles non-positive: p50=%v p99=%v", p50, p99)
	}
	if p99 < p50 {
		t.Fatalf("p99 (%v) < p50 (%v)", p99, p50)
	}
	if s.LatencyCount != 100 {
		t.Fatalf("LatencyCount = %d, want 100", s.LatencyCount)
	}
}

// Concurrent recorders must not race (run under -race) and must total correctly.
func TestConcurrentRecording(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	const goroutines, each = 8, 1000
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				m.IncRequest()
				m.RecordCacheStatus("HIT")
				m.RecordLatency(2 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	s := m.Snapshot()
	want := int64(goroutines * each)
	if s.Requests != want {
		t.Errorf("Requests = %d, want %d", s.Requests, want)
	}
	if s.Hits != want {
		t.Errorf("Hits = %d, want %d", s.Hits, want)
	}
	if s.LatencyCount != want {
		t.Errorf("LatencyCount = %d, want %d", s.LatencyCount, want)
	}
}

func TestUptimeAndStart(t *testing.T) {
	m := New()
	if m.Snapshot().UptimeSeconds < 0 {
		t.Fatal("negative uptime")
	}
}

// TestLatencyMeanMs: the mean is sum/count converted ns->ms. Ten samples of 10ms
// must average to 10ms (guards the unit conversion that a dashboard reads).
func TestLatencyMeanMs(t *testing.T) {
	m := New()
	if got := m.Snapshot().LatencyMeanMs(); got != 0 {
		t.Fatalf("empty mean = %v, want 0", got)
	}
	for i := 0; i < 10; i++ {
		m.RecordLatency(10 * time.Millisecond)
	}
	if got := m.Snapshot().LatencyMeanMs(); got < 9.99 || got > 10.01 {
		t.Errorf("LatencyMeanMs = %v, want ~10", got)
	}
}

// TestUpgradeGaugeSymmetry: upgradesActive is a live gauge — each IncUpgrade must
// be undone one-to-one by DecUpgrade, returning to zero (a leak here would falsely
// report open WebSocket tunnels forever).
func TestUpgradeGaugeSymmetry(t *testing.T) {
	m := New()
	m.IncUpgrade()
	m.IncUpgrade()
	m.IncUpgrade()
	if got := m.Snapshot().UpgradesActive; got != 3 {
		t.Fatalf("after 3 Inc, UpgradesActive = %d, want 3", got)
	}
	m.DecUpgrade()
	m.DecUpgrade()
	m.DecUpgrade()
	if got := m.Snapshot().UpgradesActive; got != 0 {
		t.Errorf("after Inc/Dec balance, UpgradesActive = %d, want 0", got)
	}
}

// TestRecordRateLimitRouting: each action increments ONLY its own counter, and an
// unknown action is ignored (no miscounting on the security dashboard).
func TestRecordRateLimitRouting(t *testing.T) {
	m := New()
	m.RecordRateLimit("throttle", "r1")
	m.RecordRateLimit("monitor", "r1")
	m.RecordRateLimit("monitor", "r1")
	m.RecordRateLimit("pass", "r1")
	m.RecordRateLimit("bogus", "r1") // ignored
	s := m.Snapshot()
	if s.RateLimitThrottle != 1 || s.RateLimitMonitor != 2 || s.RateLimitPass != 1 {
		t.Errorf("rate-limit counters = throttle %d monitor %d pass %d, want 1/2/1",
			s.RateLimitThrottle, s.RateLimitMonitor, s.RateLimitPass)
	}
}

// TestIncInternalError: the internal-error counter increments independently of
// origin errors (they are distinct failure classes on the dashboard).
func TestIncInternalError(t *testing.T) {
	m := New()
	m.IncInternalError()
	m.IncInternalError()
	s := m.Snapshot()
	if s.InternalErrors != 2 {
		t.Errorf("InternalErrors = %d, want 2", s.InternalErrors)
	}
	if s.OriginErrors != 0 {
		t.Errorf("OriginErrors = %d, want 0 (must not bleed into origin errors)", s.OriginErrors)
	}
}
