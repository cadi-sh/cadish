package server

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// idleTimeoutReader wraps an origin response body with a stall/idle watchdog.
//
// WHY: the origin layer bounds only connection-ESTABLISHMENT phases (dial, TLS,
// response headers). Once headers arrive the body streams uncapped, and the
// per-request context only cancels on a *client* disconnect — NOT when the origin
// goes silent mid-body. A slow or black-holed origin would otherwise pin a
// goroutine, a socket and an FD indefinitely.
//
// HOW (shared-sweeper design): every Read that makes progress stamps a single
// atomic nanosecond clock — no channel, no per-stream goroutine, no timer. A SINGLE
// process-wide sweeper goroutine periodically scans registered readers and Closes
// any whose last progress is older than its idleTimeout. Closing the underlying body
// makes the blocked Read return an error, aborting both the client copy AND the
// cache write — so a stalled stream is never committed as a truncated cache hit.
//
// A non-positive idleTimeout disables the watchdog: a thin pass-through that never
// registers with the sweeper.
type idleTimeoutReader struct {
	rc  io.ReadCloser
	log *slog.Logger
	key string

	sweeper     *idleSweeper
	idleTimeout time.Duration

	lastProgressNanos atomic.Int64
	watchdogHit       atomic.Bool

	closeOnce sync.Once
	closeErr  error
	deregOnce sync.Once
}

// newIdleTimeoutReader wraps rc so a body that stalls for idleTimeout is aborted by
// the shared sweeper. A non-positive idleTimeout (or a nil sweeper) returns a
// pass-through wrapper that registers nothing and spawns nothing.
func newIdleTimeoutReader(sw *idleSweeper, rc io.ReadCloser, idleTimeout time.Duration, log *slog.Logger, key string) *idleTimeoutReader {
	r := &idleTimeoutReader{rc: rc, log: log, key: key, idleTimeout: idleTimeout}
	if idleTimeout <= 0 || sw == nil {
		return r
	}
	r.sweeper = sw
	r.lastProgressNanos.Store(time.Now().UnixNano())
	sw.register(r)
	return r
}

// Read delegates to the underlying body and, on any successful (n>0) read, stamps
// the progress clock with a single atomic store. ANY terminal error deregisters
// from the sweeper.
func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if r.sweeper != nil && n > 0 {
		r.lastProgressNanos.Store(time.Now().UnixNano())
	}
	if err != nil && r.sweeper != nil {
		r.deregister()
	}
	return n, err
}

// Close deregisters from the sweeper and closes the underlying body. Idempotent.
func (r *idleTimeoutReader) Close() error {
	r.deregister()
	return r.closeUnderlying()
}

func (r *idleTimeoutReader) deregister() {
	if r.sweeper == nil {
		return
	}
	r.deregOnce.Do(func() { r.sweeper.deregister(r) })
}

func (r *idleTimeoutReader) closeUnderlying() error {
	r.closeOnce.Do(func() { r.closeErr = r.rc.Close() })
	return r.closeErr
}

// stalled reports whether the sweeper reaped this reader (the body was aborted
// because the origin went idle).
func (r *idleTimeoutReader) stalled() bool { return r.watchdogHit.Load() }

// reap is called by the sweeper when this reader is past its idle deadline.
func (r *idleTimeoutReader) reap() {
	r.watchdogHit.Store(true)
	if r.log != nil {
		r.log.Warn("origin stalled", "key", r.key, "idle_timeout", r.idleTimeout.String())
	}
	r.closeUnderlying()
}

// minSweepInterval floors the scan period so a tiny per-reader timeout never makes
// the sweeper busy-spin. 250ms is fine-grained enough for a body-stall watchdog.
const minSweepInterval = 250 * time.Millisecond

// idleSweeper is the SINGLE process-wide stall watchdog shared by all
// idleTimeoutReaders. The goroutine starts lazily on the first register.
//
// The scan period is DYNAMIC: it tracks the SMALLEST active reader timeout (the
// effective min(global idle, per-upstream between_bytes) each reader was created
// with), so a tight `between_bytes 5s` is reaped close to its budget instead of
// only on the next coarse global-idle tick (finding 5). The period is recomputed
// whenever readers register/deregister and the run loop is woken to re-arm its
// timer; it is floored at minSweepInterval to avoid busy-spin.
type idleSweeper struct {
	baseInterval time.Duration // derived from the GLOBAL idle timeout (the upper bound)

	mu     sync.Mutex
	active map[*idleTimeoutReader]struct{}
	// timeoutCounts is the count of currently-active readers per idleTimeout value
	// (R06). The min-timeout that drives the scan period is derived by iterating THIS
	// map, whose size is bounded by the number of DISTINCT timeout values in the config
	// (effectively a small constant: the global idle plus each upstream's between_bytes)
	// — NOT by the number of active readers. So register/deregister stay O(distinct
	// timeouts) instead of the old O(N) scan of the whole active set, which made
	// stream setup/teardown O(N^2) and serialized at high concurrency. Membership is
	// kept in lockstep with `active`: a reader's bucket is incremented exactly when it
	// enters `active` and decremented exactly when it leaves (register / deregister /
	// collectStale), via addLocked/removeLocked, so the counts never drift.
	timeoutCounts map[time.Duration]int
	interval      time.Duration // current desired scan period
	started       bool
	stop          chan struct{}
	wake          chan struct{} // signals the run loop to re-arm its timer
	now           func() int64
}

// sweepInterval derives the scan period from the idle timeout: half the timeout,
// floored at minSweepInterval.
func sweepInterval(idleTimeout time.Duration) time.Duration {
	return sweepIntervalForTimeout(idleTimeout)
}

// sweepIntervalForTimeout maps an effective stall timeout to a scan period: half
// the timeout, floored at minSweepInterval so we detect a stall within ~timeout +
// half-timeout while never spinning faster than the floor. A non-positive timeout
// yields the floor.
func sweepIntervalForTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return minSweepInterval
	}
	d := timeout / 2
	if d < minSweepInterval {
		d = minSweepInterval
	}
	return d
}

func newIdleSweeper(interval time.Duration) *idleSweeper {
	if interval <= 0 {
		interval = minSweepInterval
	}
	return &idleSweeper{
		baseInterval:  interval,
		interval:      interval,
		active:        make(map[*idleTimeoutReader]struct{}),
		timeoutCounts: make(map[time.Duration]int),
		stop:          make(chan struct{}),
		wake:          make(chan struct{}, 1),
		now:           func() int64 { return time.Now().UnixNano() },
	}
}

func (s *idleSweeper) register(r *idleTimeoutReader) {
	s.mu.Lock()
	s.addLocked(r)
	changed := s.recomputeIntervalLocked()
	if !s.started {
		s.started = true
		go s.run()
	}
	s.mu.Unlock()
	if changed {
		s.signalWake()
	}
}

func (s *idleSweeper) deregister(r *idleTimeoutReader) {
	s.mu.Lock()
	s.removeLocked(r)
	changed := s.recomputeIntervalLocked()
	s.mu.Unlock()
	if changed {
		s.signalWake()
	}
}

// addLocked inserts r into the active set and increments its timeout bucket EXACTLY
// once (idempotent if r is already present). Caller holds s.mu.
func (s *idleSweeper) addLocked(r *idleTimeoutReader) {
	if _, exists := s.active[r]; exists {
		return
	}
	s.active[r] = struct{}{}
	s.timeoutCounts[r.idleTimeout]++
}

// removeLocked deletes r from the active set and decrements its timeout bucket EXACTLY
// once (no-op if r was already removed — e.g. reaped by collectStale before its Read
// errored and called deregister). Dropping a bucket to zero deletes the key so the
// map stays bounded by the live distinct-timeout set. Caller holds s.mu.
func (s *idleSweeper) removeLocked(r *idleTimeoutReader) {
	if _, ok := s.active[r]; !ok {
		return
	}
	delete(s.active, r)
	if s.timeoutCounts[r.idleTimeout] <= 1 {
		delete(s.timeoutCounts, r.idleTimeout)
	} else {
		s.timeoutCounts[r.idleTimeout]--
	}
}

// recomputeIntervalLocked sets s.interval to the scan period for the SMALLEST
// active reader timeout, never exceeding the global baseInterval. It derives the min
// by iterating timeoutCounts (bounded by the number of DISTINCT active timeouts), so
// it is O(distinct timeouts), not O(active readers) — the R06 fix. Returns true when
// the interval changed (so the run loop must re-arm). Caller holds s.mu.
func (s *idleSweeper) recomputeIntervalLocked() bool {
	want := s.baseInterval
	var minTimeout time.Duration
	for d := range s.timeoutCounts {
		if minTimeout == 0 || d < minTimeout {
			minTimeout = d
		}
	}
	if minTimeout > 0 {
		if d := sweepIntervalForTimeout(minTimeout); d < want {
			want = d
		}
	}
	if want != s.interval {
		s.interval = want
		return true
	}
	return false
}

// signalWake nudges the run loop (non-blocking; the wake channel is buffered 1).
func (s *idleSweeper) signalWake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *idleSweeper) curInterval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interval
}

func (s *idleSweeper) run() {
	t := time.NewTimer(s.curInterval())
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-s.wake:
			// Interval changed (a reader registered/deregistered) — re-arm.
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(s.curInterval())
		case <-t.C:
			for _, r := range s.collectStale() {
				r.reap()
			}
			t.Reset(s.curInterval())
		}
	}
}

func (s *idleSweeper) collectStale() []*idleTimeoutReader {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var stale []*idleTimeoutReader
	for r := range s.active {
		if now-r.lastProgressNanos.Load() > int64(r.idleTimeout) {
			stale = append(stale, r)
			s.removeLocked(r) // keep timeoutCounts in lockstep with the active set
		}
	}
	return stale
}

// Stop terminates the sweeper goroutine (if started). Idempotent.
func (s *idleSweeper) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

func (s *idleSweeper) activeLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}
