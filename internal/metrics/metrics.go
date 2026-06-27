// Package metrics is the cheap, lock-free observability seam between the request
// datapath (internal/server) and the admin/dashboard surface (internal/admin).
//
// Design constraints:
//
//   - Zero cost when no admin block is configured: a *Metrics is threaded through
//     the server, and is NIL when there is no admin block. Every recorder is a
//     nil-safe no-op, so the datapath pays nothing.
//   - Never block a request: all live counters are atomic.Int64 (no mutex on the
//     hot path). The latency histogram is fixed-bucket atomic counters.
//   - State that already lives somewhere authoritative (cache fill, upstream
//     health) is NOT mirrored here — it is read on demand from the live objects by
//     the admin layer, so it can never drift.
package metrics

import (
	"sync/atomic"
	"time"
)

// latencyBucketsMs are the upper bounds (inclusive, milliseconds) of the fixed
// latency histogram. A sample falls into the first bucket whose bound it does not
// exceed; samples above the last bound land in the overflow bucket. Chosen to span
// a cache edge's realistic range (sub-ms hits to multi-second cold misses) with
// enough resolution around the p50/p99 a dashboard cares about.
var latencyBucketsMs = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// Metrics holds the process-wide live counters fed from the request datapath. The
// zero value is not usable; construct with New. A nil *Metrics is a valid no-op
// receiver for every method (so the server can hold a nil one with no overhead).
type Metrics struct {
	startNanos int64

	requests atomic.Int64

	hits      atomic.Int64
	misses    atomic.Int64
	hitsStale atomic.Int64
	passes    atomic.Int64
	synth     atomic.Int64
	purges    atomic.Int64

	coalesceWinners atomic.Int64
	coalesceWaiters atomic.Int64

	originFetches atomic.Int64
	originErrors  atomic.Int64

	// internalErrors counts requests the handler answered with a 500 because a panic
	// was recovered mid-request (handler.go ServeHTTP). A non-zero value flags a bug
	// in the datapath; the connection is NOT dropped (the client gets a clean 500).
	internalErrors atomic.Int64

	// security gate (WAF v1a): per-action counters for allow / deny (enforced) /
	// monitor (would-block, passed). Lock-free, nil-safe like every other counter;
	// extensible (rate_limit/OWASP slot in later as new counters).
	secAllow   atomic.Int64
	secDeny    atomic.Int64
	secMonitor atomic.Int64

	// rate_limit (WAF v1b): per-action counters. throttle = an enforced 429; monitor
	// = a would-429 that passed; pass = a rate_limit rule applied but admitted the
	// request. Lock-free / nil-safe like every other counter.
	rlThrottle atomic.Int64
	rlMonitor  atomic.Int64
	rlPass     atomic.Int64

	// upgradesActive is a GAUGE (not a monotonic counter): the number of currently-open
	// connection-upgrade (WebSocket / `Connection: Upgrade`) passthrough tunnels. A live
	// tunnel is long-lived and bidirectional, so it does not fit the request/response
	// latency histogram; it is tracked as an up/down gauge instead — incremented when a
	// tunnel is established (the 101 hijack) and decremented when either side tears it
	// down. Lock-free / nil-safe like every other meter.
	upgradesActive atomic.Int64

	// latency histogram: one atomic counter per bucket plus an overflow bucket,
	// and a running sum (nanoseconds) + count for the mean.
	latBuckets []atomic.Int64 // len == len(latencyBucketsMs)+1
	latCount   atomic.Int64
	latSumNs   atomic.Int64
}

// New builds an empty Metrics with the clock started now.
func New() *Metrics {
	return &Metrics{
		startNanos: time.Now().UnixNano(),
		latBuckets: make([]atomic.Int64, len(latencyBucketsMs)+1),
	}
}

// IncRequest counts one served request (any outcome).
func (m *Metrics) IncRequest() {
	if m == nil {
		return
	}
	m.requests.Add(1)
}

// RecordCacheStatus buckets a request by its final cache-status string
// (HIT/MISS/HIT-STALE/PASS/SYNTH/PURGE). Unknown values are ignored.
func (m *Metrics) RecordCacheStatus(status string) {
	if m == nil {
		return
	}
	switch status {
	case "HIT":
		m.hits.Add(1)
	case "MISS":
		m.misses.Add(1)
	case "HIT-STALE":
		m.hitsStale.Add(1)
	case "PASS":
		m.passes.Add(1)
	case "SYNTH":
		m.synth.Add(1)
	case "PURGE":
		m.purges.Add(1)
	}
}

// IncCoalesceWinner counts a request that won the single-flight (did the fetch).
func (m *Metrics) IncCoalesceWinner() {
	if m == nil {
		return
	}
	m.coalesceWinners.Add(1)
}

// IncCoalesceWaiter counts a request that waited on another's in-flight fetch.
func (m *Metrics) IncCoalesceWaiter() {
	if m == nil {
		return
	}
	m.coalesceWaiters.Add(1)
}

// IncOriginFetch counts an origin fetch that was attempted.
func (m *Metrics) IncOriginFetch() {
	if m == nil {
		return
	}
	m.originFetches.Add(1)
}

// IncOriginError counts an origin fetch that failed (transport/5xx).
func (m *Metrics) IncOriginError() {
	if m == nil {
		return
	}
	m.originErrors.Add(1)
}

// IncInternalError counts a request that ended in a recovered panic (answered with
// a 500 by the ServeHTTP recover guard). Nil-safe.
func (m *Metrics) IncInternalError() {
	if m == nil {
		return
	}
	m.internalErrors.Add(1)
}

// RecordSecurity counts one security-gate decision by action: "allow" (an
// allowlist short-circuited the gate), "deny" (a deny was enforced -> 403), or
// "monitor" (a deny would have fired but monitor mode passed it). The rule name is
// accepted for a future per-rule breakdown (audit log slice); the v1a counter is
// per-action. Unknown actions are ignored.
func (m *Metrics) RecordSecurity(action, _ string) {
	if m == nil {
		return
	}
	switch action {
	case "allow":
		m.secAllow.Add(1)
	case "deny":
		m.secDeny.Add(1)
	case "monitor":
		m.secMonitor.Add(1)
	}
}

// RecordRateLimit counts one rate_limit decision by action: "throttle" (an enforced
// 429), "monitor" (a would-429 that passed), or "pass" (the rule applied but
// admitted the request). The rule name is accepted for a future per-rule breakdown
// (audit log slice). Unknown actions are ignored; nil-safe.
func (m *Metrics) RecordRateLimit(action, _ string) {
	if m == nil {
		return
	}
	switch action {
	case "throttle":
		m.rlThrottle.Add(1)
	case "monitor":
		m.rlMonitor.Add(1)
	case "pass":
		m.rlPass.Add(1)
	}
}

// RecordLatency records one request's total wall time into the histogram.
func (m *Metrics) RecordLatency(d time.Duration) {
	if m == nil {
		return
	}
	ms := float64(d) / float64(time.Millisecond)
	idx := len(latencyBucketsMs) // overflow by default
	for i, bound := range latencyBucketsMs {
		if ms <= bound {
			idx = i
			break
		}
	}
	m.latBuckets[idx].Add(1)
	m.latCount.Add(1)
	m.latSumNs.Add(int64(d))
}

// IncUpgrade records one newly-established connection-upgrade tunnel (the 101
// hijack). Paired one-to-one with DecUpgrade on teardown so upgradesActive is an
// accurate live gauge. Nil-safe (a non-admin server pays nothing).
func (m *Metrics) IncUpgrade() {
	if m == nil {
		return
	}
	m.upgradesActive.Add(1)
}

// DecUpgrade records one torn-down connection-upgrade tunnel. Must be called exactly
// once per IncUpgrade (the tunnel's Close path guards single-call). Nil-safe.
func (m *Metrics) DecUpgrade() {
	if m == nil {
		return
	}
	m.upgradesActive.Add(-1)
}

// Snapshot reads a consistent-enough point-in-time copy of the counters. Because
// reads are independent atomics it is not a single linearizable instant, but for a
// monotonic-counter dashboard that is fine (and never blocks the datapath).
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	s := Snapshot{
		Requests:          m.requests.Load(),
		Hits:              m.hits.Load(),
		Misses:            m.misses.Load(),
		HitsStale:         m.hitsStale.Load(),
		Passes:            m.passes.Load(),
		Synth:             m.synth.Load(),
		Purges:            m.purges.Load(),
		CoalesceWinners:   m.coalesceWinners.Load(),
		CoalesceWaiters:   m.coalesceWaiters.Load(),
		OriginFetches:     m.originFetches.Load(),
		OriginErrors:      m.originErrors.Load(),
		InternalErrors:    m.internalErrors.Load(),
		SecurityAllow:     m.secAllow.Load(),
		SecurityDeny:      m.secDeny.Load(),
		SecurityMonitor:   m.secMonitor.Load(),
		RateLimitThrottle: m.rlThrottle.Load(),
		RateLimitMonitor:  m.rlMonitor.Load(),
		RateLimitPass:     m.rlPass.Load(),
		UpgradesActive:    m.upgradesActive.Load(),
		LatencyCount:      m.latCount.Load(),
		latSumNs:          m.latSumNs.Load(),
		UptimeSeconds:     float64(time.Now().UnixNano()-m.startNanos) / float64(time.Second),
	}
	s.LatencyBucketBoundsMs = latencyBucketsMs
	s.LatencyBuckets = make([]int64, len(m.latBuckets))
	for i := range m.latBuckets {
		s.LatencyBuckets[i] = m.latBuckets[i].Load()
	}
	return s
}

// Snapshot is an immutable point-in-time view of the metrics, suitable for JSON
// and Prometheus rendering.
type Snapshot struct {
	UptimeSeconds float64 `json:"uptime_seconds"`

	Requests  int64 `json:"requests"`
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	HitsStale int64 `json:"hits_stale"`
	Passes    int64 `json:"passes"`
	Synth     int64 `json:"synth"`
	Purges    int64 `json:"purges"`

	CoalesceWinners int64 `json:"coalesce_winners"`
	CoalesceWaiters int64 `json:"coalesce_waiters"`

	OriginFetches  int64 `json:"origin_fetches"`
	OriginErrors   int64 `json:"origin_errors"`
	InternalErrors int64 `json:"internal_errors"`

	// Security gate (WAF v1a) per-action counters.
	SecurityAllow   int64 `json:"security_allow"`
	SecurityDeny    int64 `json:"security_deny"`
	SecurityMonitor int64 `json:"security_monitor"`

	// rate_limit (WAF v1b) per-action counters.
	RateLimitThrottle int64 `json:"rate_limit_throttle"`
	RateLimitMonitor  int64 `json:"rate_limit_monitor"`
	RateLimitPass     int64 `json:"rate_limit_pass"`

	// UpgradesActive is a GAUGE: connection-upgrade (WebSocket) tunnels currently open.
	UpgradesActive int64 `json:"upgrades_active"`

	// LatencyBucketBoundsMs are the inclusive upper bounds (ms) of LatencyBuckets;
	// LatencyBuckets has one extra trailing overflow bucket.
	LatencyBucketBoundsMs []float64 `json:"latency_bucket_bounds_ms"`
	LatencyBuckets        []int64   `json:"latency_buckets"`
	LatencyCount          int64     `json:"latency_count"`

	latSumNs int64
}

// HitRatio is hits / (hits + misses + stale-hits), or 0 when there is no
// cacheable traffic yet. Stale hits count as cache wins.
func (s Snapshot) HitRatio() float64 {
	served := s.Hits + s.HitsStale
	denom := served + s.Misses
	if denom == 0 {
		return 0
	}
	return float64(served) / float64(denom)
}

// LatencyMeanMs is the mean request latency in milliseconds (0 with no samples).
func (s Snapshot) LatencyMeanMs() float64 {
	if s.LatencyCount == 0 {
		return 0
	}
	return float64(s.latSumNs) / float64(s.LatencyCount) / float64(time.Millisecond)
}

// LatencyP50 returns the 50th-percentile latency in milliseconds (bucket-bound
// estimate). Returns 0 with no samples.
func (s Snapshot) LatencyP50() float64 { return s.percentileMs(0.50) }

// LatencyP99 returns the 99th-percentile latency in milliseconds (bucket-bound
// estimate). Returns 0 with no samples.
func (s Snapshot) LatencyP99() float64 { return s.percentileMs(0.99) }

// percentileMs estimates a percentile from the cumulative histogram, returning
// the upper bound (ms) of the bucket the rank falls in. The overflow bucket maps
// to the top finite bound (its real value is unbounded; we report the cap).
func (s Snapshot) percentileMs(q float64) float64 {
	if s.LatencyCount == 0 || len(s.LatencyBuckets) == 0 {
		return 0
	}
	target := int64(float64(s.LatencyCount) * q)
	if target < 1 {
		target = 1
	}
	var cum int64
	for i, c := range s.LatencyBuckets {
		cum += c
		if cum >= target {
			if i < len(s.LatencyBucketBoundsMs) {
				return s.LatencyBucketBoundsMs[i]
			}
			// overflow bucket: report the top finite bound as a floor estimate.
			return s.LatencyBucketBoundsMs[len(s.LatencyBucketBoundsMs)-1]
		}
	}
	return s.LatencyBucketBoundsMs[len(s.LatencyBucketBoundsMs)-1]
}
