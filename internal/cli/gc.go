package cli

import (
	"runtime/debug"
)

// GC tuning for the `run` path.
//
// cadish is a long-lived caching proxy that intentionally holds a large RAM cache.
// Go's default GC posture (GOGC=100, no soft memory limit) is tuned for short-lived,
// small-heap programs: it triggers a collection whenever the heap doubles relative to
// the *live* set. For a proxy whose live set is dominated by a big, mostly-static cache
// that means frequent, large mark phases — and the resulting GC pauses are exactly what
// drove the plaintext-HIT p99 tail in a benchmark against Varnish (34 ms vs 8 ms;
// see docs/benchmarks.md).
//
// The fix is a startup-only posture change — NOT a datapath change:
//
//   - GOGC=200: let the heap grow to 3× the live set before collecting (default is 2×).
//     Fewer GC cycles → fewer/shorter stop-the-world assists → a tighter p99 and higher
//     throughput, at the cost of more resident heap. A caching proxy is built to trade
//     RAM for latency, so this is the right trade.
//   - GOMEMLIMIT tied to the configured RAM cache budget: a *soft* limit set comfortably
//     above the cache so the cache fits without the limit ever forcing a GC death-spiral,
//     while still capping total heap so GOGC=200 cannot run away under a burst and OOM
//     the box. The pacer treats it as a backstop: it only tightens GC once the heap
//     approaches the limit, so under normal load GOGC=200 dominates and the limit just
//     prevents the worst case.
//
// PRECEDENCE — the operator always wins. If the operator exported GOGC or GOMEMLIMIT,
// the Go runtime has already applied it at process start, and cadish does NOT touch that
// lever (it leaves the corresponding *return* nil). cadish only fills in a default for a
// lever the operator left unset. This is detected per-lever via os.LookupEnv at the call
// site (presence, not value — an explicit empty value is still "set" and is respected).

// Default GC tuning constants. Exported intent in comments above; values chosen in D45.
const (
	// defaultGCPercent is cadish's GOGC default for the run path (Go's default is 100).
	defaultGCPercent = 200

	// memLimitCacheMultiplier scales the configured RAM cache budget to leave room for
	// the cache plus the proxy's transient working set (in-flight bodies, buffers,
	// goroutine stacks, net/http allocations) before the soft limit bites.
	memLimitCacheMultiplier = 3.0 / 2.0 // 1.5×

	// memLimitHeadroomBytes is added on top of the scaled cache budget so very small
	// caches still get an absolute floor of working-set headroom.
	memLimitHeadroomBytes int64 = 512 << 20 // 512 MiB

	// minMemLimitBytes is the floor for the computed soft limit. Below this a soft limit
	// is more likely to harm (GC death-spiral) than help, so we skip it entirely.
	minMemLimitBytes int64 = 1 << 30 // 1 GiB
)

// gcDecision is the result of gcDefaults: which runtime GC levers cadish should set, and
// to what. A nil field means "leave this lever alone" — either the operator set the env
// var (override wins) or there is no sensible default to apply (e.g. an unknown cache
// budget for GOMEMLIMIT). It is a pure value so the decision logic is unit-testable
// without mutating global runtime state.
type gcDecision struct {
	// GCPercent, when non-nil, is the value to pass to debug.SetGCPercent.
	GCPercent *int
	// MemLimitBytes, when non-nil, is the value to pass to debug.SetMemoryLimit.
	MemLimitBytes *int64
}

// gcDefaults computes cadish's startup GC posture. It is PURE: it reads only its
// arguments and returns the decision; it does not call into the runtime or read the
// environment itself. The caller passes the env-var presence (from os.LookupEnv) so the
// override check stays testable.
//
//   - gogcSet:     was GOGC present in the environment? (value irrelevant — presence wins)
//   - memLimitSet: was GOMEMLIMIT present in the environment?
//   - cacheRAMBytes: the total configured RAM-tier cache budget across all sites, or <=0
//     if unknown. Used to size the GOMEMLIMIT soft limit.
//
// If an env var is set, the corresponding lever is left nil (the operator's value, which
// the runtime already applied at start, stands untouched). Otherwise cadish's default is
// returned. GOMEMLIMIT is only defaulted when the cache budget yields a soft limit at or
// above minMemLimitBytes; otherwise it is left nil (Go's default = no limit).
func gcDefaults(gogcSet, memLimitSet bool, cacheRAMBytes int64) gcDecision {
	var d gcDecision

	if !gogcSet {
		p := defaultGCPercent
		d.GCPercent = &p
	}

	if !memLimitSet {
		if lim := memLimitForCache(cacheRAMBytes); lim > 0 {
			d.MemLimitBytes = &lim
		}
	}

	return d
}

// memLimitForCache derives the GOMEMLIMIT soft limit from the configured RAM cache
// budget: 1.5× the budget plus a fixed headroom, floored at minMemLimitBytes. It returns
// 0 (meaning "do not set a limit") when the cache budget is unknown (<=0) or when the
// computed limit would fall below the floor — in those cases a soft limit is more likely
// to hurt than help. Overflow is guarded: an absurd budget that would overflow int64
// yields 0 (no limit) rather than a wrapped value.
func memLimitForCache(cacheRAMBytes int64) int64 {
	if cacheRAMBytes <= 0 {
		return 0
	}
	scaled := int64(float64(cacheRAMBytes) * memLimitCacheMultiplier)
	if scaled < cacheRAMBytes { // float overflow/inf → unusable
		return 0
	}
	lim := scaled + memLimitHeadroomBytes
	if lim < scaled { // int64 addition overflow
		return 0
	}
	if lim < minMemLimitBytes {
		return 0
	}
	return lim
}

// applyGCDecision mutates the global runtime GC state per the decision. It is the ONLY
// place that touches runtime/debug, kept separate from the pure gcDefaults so tests never
// leak global GC state across packages. It returns the values it actually set (for
// logging); nil fields mean "left as-is".
func applyGCDecision(d gcDecision) gcDecision {
	if d.GCPercent != nil {
		debug.SetGCPercent(*d.GCPercent)
	}
	if d.MemLimitBytes != nil {
		debug.SetMemoryLimit(*d.MemLimitBytes)
	}
	return d
}
