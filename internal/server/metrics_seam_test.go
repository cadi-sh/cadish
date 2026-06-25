package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cadi-sh/cadish/internal/metrics"
)

// A nil metrics seam (the default, no admin block) must not panic on the datapath.
func TestNilMetricsSeamServes(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public")
		_, _ = w.Write([]byte("hello"))
	}))
	defer origin.Close()

	h, _ := buildHandler(t, nil, cfgBasic, origin.URL)
	// h.metrics is nil here (Options.Metrics unset). A request must still serve.
	rec := do(h, "GET", "/x", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}

// With a metrics seam wired, a MISS then a HIT must move the counters, proving the
// datapath increments flow into the snapshot the dashboard reads.
func TestMetricsSeamCountsHitAndMiss(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public")
		_, _ = w.Write([]byte("hello world"))
	}))
	defer origin.Close()

	m := metrics.New()
	h, _ := buildHandler(t, nil, cfgBasic, origin.URL)
	h.metrics = m // inject the seam (buildHandler doesn't expose Options.Metrics)

	// First GET: cold MISS -> origin fetch.
	if rec := do(h, "GET", "/page", nil); rec.Code != http.StatusOK {
		t.Fatalf("miss status %d", rec.Code)
	}
	// Second GET of the same key: should be a cache HIT.
	if rec := do(h, "GET", "/page", nil); rec.Code != http.StatusOK {
		t.Fatalf("hit status %d", rec.Code)
	}

	s := m.Snapshot()
	if s.Requests != 2 {
		t.Errorf("Requests = %d, want 2", s.Requests)
	}
	if s.Misses < 1 {
		t.Errorf("Misses = %d, want >=1", s.Misses)
	}
	if s.Hits < 1 {
		t.Errorf("Hits = %d, want >=1 (second request should hit cache)", s.Hits)
	}
	if s.OriginFetches < 1 {
		t.Errorf("OriginFetches = %d, want >=1", s.OriginFetches)
	}
	if s.LatencyCount != 2 {
		t.Errorf("LatencyCount = %d, want 2", s.LatencyCount)
	}
}
