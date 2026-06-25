package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/check"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/metrics"
)

// writeJSON encodes v as JSON with a no-store cache header (live data).
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// handleConfig projects the compiled site/rule model as JSON by re-running the
// same complexity analysis `cadish check` uses (no duplicated rule logic — the
// check.Report already carries json tags). This is the data source for the
// dashboard's "config view" (matchers → phase → cost).
//
// Before returning the report, the absolute Cadishfile path is stripped to just
// the filename (defense-in-depth: the CLI `cadish check` legitimately shows the
// full path, but the admin API response must not disclose the host directory layout
// to any token holder — fix for #16).
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	report, err := check.Check(s.cfgPath)
	if err != nil {
		// Strip the absolute directory from the error message (defense-in-depth:
		// the error string from cadishfile.ParseFile / os.ReadFile includes the
		// full on-disk path; we expose only the base filename so the host layout
		// is not disclosed to token holders — same policy as stripReportPaths).
		writeJSON(w, map[string]string{"error": stripPathFromError(err, s.cfgPath)})
		return
	}
	writeJSON(w, stripReportPaths(report, s.cfgPath))
}

// stripReportPaths returns a shallow copy of report with the on-disk directory
// removed from Path and every Diagnostic.Position string. The source *Report is
// NOT mutated so that `cadish check` (which calls check.Check and renders its own
// report) continues to show the full path.
//
// Position strings have the form "file:line:col". We replace the absolute
// directory prefix (cfgPath's dir + separator) with just the base filename so
// a position like "/home/u/deploy/Cadishfile:3:5" becomes "Cadishfile:3:5".
func stripReportPaths(r *check.Report, cfgPath string) *check.Report {
	dir := filepath.Dir(cfgPath) + string(filepath.Separator)
	base := filepath.Base(cfgPath)

	stripPos := func(pos string) string {
		return strings.ReplaceAll(pos, dir, "")
	}

	stripDiags := func(ds []check.Diagnostic) []check.Diagnostic {
		if len(ds) == 0 {
			return ds
		}
		out := make([]check.Diagnostic, len(ds))
		for i, d := range ds {
			d.Position = stripPos(d.Position)
			out[i] = d
		}
		return out
	}

	out := &check.Report{
		Path:        base,
		Diagnostics: stripDiags(r.Diagnostics),
	}
	for _, s := range r.Sites {
		sc := *s // shallow copy of SiteReport
		sc.Position = stripPos(s.Position)
		sc.Diagnostics = stripDiags(s.Diagnostics)
		out.Sites = append(out.Sites, &sc)
	}
	return out
}

// stripPathFromError replaces the absolute directory prefix in an error message
// with just the base filename so callers cannot learn the host directory layout
// from a failed check.Check call (e.g. "open /abs/path/Cadishfile: no such file"
// becomes "open Cadishfile: no such file"). Uses the same stripping logic as
// stripReportPaths.
func stripPathFromError(err error, cfgPath string) string {
	dir := filepath.Dir(cfgPath) + string(filepath.Separator)
	base := filepath.Base(cfgPath)
	msg := strings.ReplaceAll(err.Error(), dir, "")
	// Also replace a bare cfgPath (without trailing sep, e.g. as used by os.Open).
	msg = strings.ReplaceAll(msg, cfgPath, base)
	return msg
}

// handleMetrics projects the live atomic counters + derived ratios/percentiles as
// JSON for the live tiles.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, metricsViewFromSnapshot(s.metrics.Snapshot()))
}

// handleLive projects per-site cache fill state.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"sites": s.siteStates()})
}

// handleUpstreams projects every lb pool's backend health (the lb FSM view).
func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"upstreams": s.upstreamHealth()})
}

// handleIngress projects the Kubernetes Ingress controller's reconcile stats. When no
// ingress source is wired (plain `cadish run`) the body is {"present": false} and the
// dashboard hides the panel.
func (s *Server) handleIngress(w http.ResponseWriter, r *http.Request) {
	if st, ok := s.ingressStats(); ok {
		writeJSON(w, map[string]any{"present": true, "ingress": st})
		return
	}
	writeJSON(w, map[string]any{"present": false})
}

// ingressStats reads the controller's reconcile snapshot, or (zero,false) when no
// ingress source is wired. Shared by /api/ingress and the SSE stream.
func (s *Server) ingressStats() (IngressStats, bool) {
	if s.ingress == nil {
		return IngressStats{}, false
	}
	return s.ingress.IngressStats()
}

// siteStates reads the current per-site cache state, or nil when no live
// source is wired. Shared by /api/live and the SSE stream.
func (s *Server) siteStates() []SiteState {
	if s.live == nil {
		return nil
	}
	return s.live.LiveState()
}

// upstreamHealth snapshots every lb pool's backend health. Shared by
// /api/upstreams and the SSE stream.
func (s *Server) upstreamHealth() []lb.UpstreamHealth {
	pools := make([]lb.UpstreamHealth, 0, len(s.pools))
	for _, p := range s.pools {
		pools = append(pools, p.HealthSnapshot())
	}
	return pools
}

// metricsView is the JSON shape for /api/metrics: the raw snapshot plus the
// derived figures the dashboard tiles show (hit ratio, percentiles, mean).
type metricsView struct {
	HitRatio      float64 `json:"hit_ratio"`
	LatencyMeanMs float64 `json:"latency_mean_ms"`
	LatencyP50Ms  float64 `json:"latency_p50_ms"`
	LatencyP99Ms  float64 `json:"latency_p99_ms"`

	Snapshot metricsSnapshot `json:"snapshot"`
}

// metricsSnapshot is the embedded raw counter view (a re-declared shape so the
// JSON is stable even if metrics.Snapshot grows unexported helpers).
type metricsSnapshot struct {
	UptimeSeconds     float64 `json:"uptime_seconds"`
	Requests          int64   `json:"requests"`
	Hits              int64   `json:"hits"`
	Misses            int64   `json:"misses"`
	HitsStale         int64   `json:"hits_stale"`
	Passes            int64   `json:"passes"`
	Synth             int64   `json:"synth"`
	Purges            int64   `json:"purges"`
	CoalesceWinners   int64   `json:"coalesce_winners"`
	CoalesceWaiters   int64   `json:"coalesce_waiters"`
	OriginFetches     int64   `json:"origin_fetches"`
	OriginErrors      int64   `json:"origin_errors"`
	InternalErrors    int64   `json:"internal_errors"`
	SecurityAllow     int64   `json:"security_allow"`
	SecurityDeny      int64   `json:"security_deny"`
	SecurityMonitor   int64   `json:"security_monitor"`
	RateLimitThrottle int64   `json:"rate_limit_throttle"`
	RateLimitMonitor  int64   `json:"rate_limit_monitor"`
	RateLimitPass     int64   `json:"rate_limit_pass"`
	LatencyCount      int64   `json:"latency_count"`
}

func metricsViewFromSnapshot(snap metrics.Snapshot) metricsView {
	return metricsView{
		HitRatio:      snap.HitRatio(),
		LatencyMeanMs: snap.LatencyMeanMs(),
		LatencyP50Ms:  snap.LatencyP50(),
		LatencyP99Ms:  snap.LatencyP99(),
		Snapshot: metricsSnapshot{
			UptimeSeconds:     snap.UptimeSeconds,
			Requests:          snap.Requests,
			Hits:              snap.Hits,
			Misses:            snap.Misses,
			HitsStale:         snap.HitsStale,
			Passes:            snap.Passes,
			Synth:             snap.Synth,
			Purges:            snap.Purges,
			CoalesceWinners:   snap.CoalesceWinners,
			CoalesceWaiters:   snap.CoalesceWaiters,
			OriginFetches:     snap.OriginFetches,
			OriginErrors:      snap.OriginErrors,
			InternalErrors:    snap.InternalErrors,
			SecurityAllow:     snap.SecurityAllow,
			SecurityDeny:      snap.SecurityDeny,
			SecurityMonitor:   snap.SecurityMonitor,
			RateLimitThrottle: snap.RateLimitThrottle,
			RateLimitMonitor:  snap.RateLimitMonitor,
			RateLimitPass:     snap.RateLimitPass,
			LatencyCount:      snap.LatencyCount,
		},
	}
}

// handleStream is a Server-Sent Events push of the live metrics + per-site state,
// emitted once a second, for the dashboard's live tiles (no polling, no websocket
// dependency — stdlib http.Flusher only). It ends when the client disconnects.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	emit := func() bool {
		payload := s.streamPayload()
		b, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !emit() { // send one immediately so the UI is not blank for a second
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !emit() {
				return
			}
		}
	}
}

// streamPayload bundles the live tiles' data for one SSE frame. The "ingress" key is
// present only in `cadish ingress` mode (an ingress source is wired) so plain runs send
// no Ingress data and the dashboard never shows the panel.
func (s *Server) streamPayload() map[string]any {
	p := map[string]any{
		"metrics":   metricsViewFromSnapshot(s.metrics.Snapshot()),
		"sites":     s.siteStates(),
		"upstreams": s.upstreamHealth(),
		"ts":        time.Now().UnixMilli(),
	}
	if st, ok := s.ingressStats(); ok {
		p["ingress"] = st
	}
	return p
}
