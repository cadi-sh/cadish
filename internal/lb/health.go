package lb

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// maxWindow bounds the health `window N` sample count. newHealthFSM allocates a
// `make([]bool, window)` ring PER backend at pool construction, so an absurd window
// (e.g. a stray "window 2000000000") would allocate ~2 GB per backend and stall/OOM at
// startup. A health window of thousands of samples is already unreasonable (a window is
// "the last N probe outcomes"); this cap is far above any real tuning need and turns the
// attack into a clean parse error. Mirrors maxReplicas (ring.go).
const maxWindow = 100_000

// Doer is the minimal HTTP client surface the active prober needs. *http.Client
// satisfies it; tests inject a fake so probing never touches the network.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// healthFSM is the pure health state machine for one backend. It keeps a sliding
// window of the last `window` probe outcomes and flips state on `threshold`:
// a backend goes UP once it has `threshold` successes within the window, and
// DOWN once it has `threshold` failures within the window. It holds no locks and
// no clock — the caller serializes access and decides when to record — so it is
// trivially unit-testable.
type healthFSM struct {
	window    int
	threshold int
	results   []bool // ring buffer of recent outcomes (true = success)
	idx       int    // next write position
	filled    int    // number of valid entries (<= window)
	up        bool
}

// newHealthFSM builds the FSM. startUp is the initial state: an upstream with no
// active health spec starts UP (always eligible); one WITH a spec starts DOWN
// until it earns `threshold` successes.
func newHealthFSM(window, threshold int, startUp bool) *healthFSM {
	if window <= 0 {
		window = 1
	}
	if threshold <= 0 {
		threshold = 1
	}
	if threshold > window {
		threshold = window
	}
	return &healthFSM{
		window:    window,
		threshold: threshold,
		results:   make([]bool, window),
		up:        startUp,
	}
}

// record adds one probe outcome and returns whether the up/down state changed.
func (f *healthFSM) record(success bool) (changed bool) {
	f.results[f.idx] = success
	f.idx = (f.idx + 1) % f.window
	if f.filled < f.window {
		f.filled++
	}
	var succ, fail int
	for i := 0; i < f.filled; i++ {
		if f.results[i] {
			succ++
		} else {
			fail++
		}
	}
	switch {
	case !f.up && succ >= f.threshold:
		f.up = true
		return true
	case f.up && fail >= f.threshold:
		f.up = false
		return true
	default:
		return false
	}
}

// healthy reports the current state.
func (f *healthFSM) healthy() bool { return f.up }

// probe runs one active health check against base (the backend's endpoint base
// URL) using the spec and Doer, then folds the outcome into the FSM. A success
// is "the response status matches one of the spec's expectations" (exact code,
// list, or 2xx/3xx class — see HealthSpec.Matches); any transport error or other
// status is a failure. It returns whether the health state changed. probe holds
// mu for the duration so concurrent probers/readers stay race-clean.
func probe(ctx context.Context, doer Doer, base string, spec *HealthSpec, mu *sync.Mutex, fsm *healthFSM) (changed bool) {
	method := strings.ToUpper(spec.Method)
	if method == "" {
		method = http.MethodGet
	}
	path := spec.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := strings.TrimRight(base, "/") + path

	success := false
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err == nil {
		resp, derr := doer.Do(req)
		if derr == nil {
			// Drain+close so the keep-alive connection can be reused.
			drainClose(resp.Body)
			success = spec.Matches(resp.StatusCode)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	return fsm.record(success)
}
