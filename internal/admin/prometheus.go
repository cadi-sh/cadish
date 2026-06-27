package admin

import (
	"fmt"
	"net/http"
	"strconv"
)

// handlePrometheus renders the live metrics in Prometheus text exposition format
// (version 0.0.4). Hand-rolled to avoid the prometheus client dependency (keeping
// the supply chain tiny) — the surface is a flat set of counters,
// gauges and a latency histogram. Enabled only when the `admin` block sets the
// bare `metrics` flag.
func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	snap := s.metrics.Snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	counter := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n", name, help, name, name, strconv.FormatFloat(v, 'g', -1, 64))
	}

	counter("cadish_requests_total", "Total requests served.", snap.Requests)
	counter("cadish_cache_hits_total", "Fresh cache hits.", snap.Hits)
	counter("cadish_cache_misses_total", "Cache misses (origin fetched).", snap.Misses)
	counter("cadish_cache_hits_stale_total", "Stale (grace) cache hits.", snap.HitsStale)
	counter("cadish_pass_total", "Requests passed straight to origin.", snap.Passes)
	counter("cadish_synthetic_total", "Synthetic (respond) responses.", snap.Synth)
	counter("cadish_purge_total", "Purge requests.", snap.Purges)
	counter("cadish_coalesce_winners_total", "Coalesce winners (did the fetch).", snap.CoalesceWinners)
	counter("cadish_coalesce_waiters_total", "Coalesce waiters (rode another fetch).", snap.CoalesceWaiters)
	counter("cadish_origin_fetches_total", "Origin fetches attempted.", snap.OriginFetches)
	counter("cadish_origin_errors_total", "Origin fetches that failed.", snap.OriginErrors)
	counter("cadish_internal_errors_total", "Requests answered with 500 after a recovered panic.", snap.InternalErrors)
	counter("cadish_security_allow_total", "Security gate: requests allow-listed (short-circuit).", snap.SecurityAllow)
	counter("cadish_security_deny_total", "Security gate: requests denied (403).", snap.SecurityDeny)
	counter("cadish_security_monitor_total", "Security gate: would-block recorded in monitor mode (passed).", snap.SecurityMonitor)
	counter("cadish_rate_limit_throttle_total", "Rate limit: requests throttled (429).", snap.RateLimitThrottle)
	counter("cadish_rate_limit_monitor_total", "Rate limit: would-429 recorded in monitor mode (passed).", snap.RateLimitMonitor)
	counter("cadish_rate_limit_pass_total", "Rate limit: requests a rate_limit rule applied to but admitted.", snap.RateLimitPass)

	gauge("cadish_upgrades_active", "Connection-upgrade (WebSocket) passthrough tunnels currently open.", float64(snap.UpgradesActive))
	gauge("cadish_hit_ratio", "Cache hit ratio (hits+stale)/(hits+stale+misses).", snap.HitRatio())
	gauge("cadish_uptime_seconds", "Process uptime in seconds.", snap.UptimeSeconds)
	gauge("cadish_latency_p50_ms", "Estimated p50 request latency (ms).", snap.LatencyP50())
	gauge("cadish_latency_p99_ms", "Estimated p99 request latency (ms).", snap.LatencyP99())

	// Latency histogram (cumulative buckets, Prometheus le-labelled).
	fmt.Fprintf(w, "# HELP cadish_request_latency_ms Request latency histogram (ms).\n# TYPE cadish_request_latency_ms histogram\n")
	var cum int64
	for i, bound := range snap.LatencyBucketBoundsMs {
		if i < len(snap.LatencyBuckets) {
			cum += snap.LatencyBuckets[i]
		}
		fmt.Fprintf(w, "cadish_request_latency_ms_bucket{le=\"%s\"} %d\n", strconv.FormatFloat(bound, 'g', -1, 64), cum)
	}
	// overflow bucket -> +Inf
	if len(snap.LatencyBuckets) > len(snap.LatencyBucketBoundsMs) {
		cum += snap.LatencyBuckets[len(snap.LatencyBucketBoundsMs)]
	}
	fmt.Fprintf(w, "cadish_request_latency_ms_bucket{le=\"+Inf\"} %d\n", cum)
	fmt.Fprintf(w, "cadish_request_latency_ms_count %d\n", snap.LatencyCount)

	// Per-site cache fill (labelled gauges).
	if s.live != nil {
		fmt.Fprintf(w, "# HELP cadish_cache_ram_bytes RAM tier bytes used.\n# TYPE cadish_cache_ram_bytes gauge\n")
		for _, st := range s.live.LiveState() {
			fmt.Fprintf(w, "cadish_cache_ram_bytes{site=%q} %d\n", st.Name, st.Cache.RAMBytes)
		}
		fmt.Fprintf(w, "# HELP cadish_cache_disk_bytes Disk tier bytes used.\n# TYPE cadish_cache_disk_bytes gauge\n")
		for _, st := range s.live.LiveState() {
			fmt.Fprintf(w, "cadish_cache_disk_bytes{site=%q} %d\n", st.Name, st.Cache.DiskBytes)
		}
	}
}
