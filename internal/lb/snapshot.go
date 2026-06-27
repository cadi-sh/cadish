package lb

import "time"

// UpstreamHealth is a point-in-time view of an Upstream pool and its backends,
// for observability (the admin dashboard / Prometheus export). It exposes only
// immutable, copied values — never the live backend pointers — so a reader cannot
// mutate pool state.
type UpstreamHealth struct {
	Name     string          `json:"name"`
	Policy   string          `json:"policy"`
	Backends []BackendHealth `json:"backends"`
}

// BackendHealth is one backend's current health/capacity state.
type BackendHealth struct {
	ID      string `json:"id"`
	BaseURL string `json:"base_url"`
	// Healthy is the active health-FSM verdict (true when no health spec).
	Healthy bool `json:"healthy"`
	// Ejected is true while the backend is passively ejected (consecutive
	// connection/5xx failures over the passive threshold).
	Ejected bool `json:"ejected"`
	// InFlight is the current in-flight request count.
	InFlight int64 `json:"inflight"`
	// ConsecFail is the current consecutive-failure count feeding ejection.
	ConsecFail int `json:"consec_fail"`
}

// AnyHealthy reports whether the pool currently has at least one ELIGIBLE backend —
// one whose health FSM is up AND which is not passively ejected — i.e. Varnish's
// nbsrv()>0. It is the O(1)-ish, no-dial liveness signal behind the
// `upstream_healthy NAME…` matcher (the AWS /aws-health-check probe): it reads only
// the maintained health/ejection state, never opening a connection or running a
// probe. It takes the same cheap read snapshot the picker uses, then short-circuits
// on the first live backend under that backend's own mutex (the same lock the fetch
// path already takes), so it is race-clean and never blocks the datapath.
func (u *Upstream) AnyHealthy() bool {
	backends, _, _ := u.snapshot()
	now := u.now()
	for _, b := range backends {
		if b.eligible(now) {
			return true
		}
	}
	return false
}

// HealthSnapshot returns a copied, immutable view of the pool's current backends
// and their health. It takes the same read snapshot the picker uses, then copies
// each backend's state under its own mutex, so it is race-clean and never blocks
// the datapath beyond a brief per-backend lock already on the fetch path.
func (u *Upstream) HealthSnapshot() UpstreamHealth {
	backends, _, _ := u.snapshot()
	now := time.Now()
	out := UpstreamHealth{
		Name:     u.cfg.Name,
		Policy:   u.cfg.Policy.String(),
		Backends: make([]BackendHealth, 0, len(backends)),
	}
	for _, b := range backends {
		b.mu.Lock()
		bh := BackendHealth{
			ID:         b.id,
			BaseURL:    b.baseURL,
			Healthy:    b.fsm.healthy(),
			Ejected:    b.ejectUntil.After(now),
			InFlight:   b.inflight.Load(),
			ConsecFail: b.consecFail,
		}
		b.mu.Unlock()
		out.Backends = append(out.Backends, bh)
	}
	return out
}
