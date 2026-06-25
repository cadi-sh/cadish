package lb

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

// TestHealthFSMUpDown drives the pure FSM through window/threshold transitions.
func TestHealthFSMUpDown(t *testing.T) {
	// window 6, threshold 3, start DOWN (active health configured).
	f := newHealthFSM(6, 3, false)
	if f.healthy() {
		t.Fatal("should start DOWN")
	}

	// Two successes: not yet up (need 3 in window).
	if f.record(true) || f.healthy() {
		t.Fatal("up after 1 success")
	}
	if f.record(true) || f.healthy() {
		t.Fatal("up after 2 successes")
	}
	// Third success: flips UP, change reported.
	if !f.record(true) || !f.healthy() {
		t.Fatal("expected UP after 3 successes")
	}

	// Now drive failures. Window holds [T,T,T]; one failure -> [T,T,T,F].
	if f.record(false) || !f.healthy() {
		t.Fatal("1 failure should not drop (need 3)")
	}
	if f.record(false) || !f.healthy() {
		t.Fatal("2 failures should not drop")
	}
	// Third failure within window: flips DOWN.
	if !f.record(false) || f.healthy() {
		t.Fatal("expected DOWN after 3 failures")
	}
}

// TestHealthFSMWindowSlides checks that old outcomes age out of the window so a
// success streak separated by enough probes still flips state.
func TestHealthFSMWindowSlides(t *testing.T) {
	f := newHealthFSM(3, 2, false)
	// [F] [F,F] -> still down. [F,F,T] -> 1 success. window=3.
	f.record(false)
	f.record(false)
	f.record(false)
	if f.healthy() {
		t.Fatal("down expected")
	}
	// Two successes within the 3-window flips up.
	f.record(true)
	if !f.record(true) || !f.healthy() {
		t.Fatal("expected up after 2 successes in window")
	}
}

// TestHealthFSMStartUp confirms an upstream with no health spec starts UP.
func TestHealthFSMStartUp(t *testing.T) {
	f := newHealthFSM(1, 1, true)
	if !f.healthy() {
		t.Fatal("startUp=true must begin healthy")
	}
}

// fakeDoer returns a canned status (or error) and counts calls.
type fakeDoer struct {
	mu     sync.Mutex
	status int
	err    error
	calls  int
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.err != nil {
		return nil, d.err
	}
	return &http.Response{StatusCode: d.status, Body: http.NoBody, Header: http.Header{}}, nil
}

func (d *fakeDoer) set(status int, err error) {
	d.mu.Lock()
	d.status, d.err = status, err
	d.mu.Unlock()
}

// TestProbeFoldsOutcome runs probe() with a fake Doer and verifies the expected
// status counts as success and others as failure.
func TestProbeFoldsOutcome(t *testing.T) {
	spec := &HealthSpec{Method: "GET", Path: "/", ExpectCode: 301, Window: 2, Threshold: 2}
	var mu sync.Mutex
	fsm := newHealthFSM(2, 2, false)
	d := &fakeDoer{status: 301}

	// Two 301s -> up.
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	if !fsm.healthy() {
		t.Fatal("expected healthy after two expect-code probes")
	}

	// Two 500s -> down.
	d.set(500, nil)
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	if fsm.healthy() {
		t.Fatal("expected unhealthy after two wrong-code probes")
	}
	if d.calls != 4 {
		t.Fatalf("expected 4 probe calls, got %d", d.calls)
	}
}

// TestHealthSpecMatches covers the single-int back-compat, exact-list, and class
// forms of `expect`.
func TestHealthSpecMatches(t *testing.T) {
	tests := []struct {
		name string
		spec HealthSpec
		ok   []int
		bad  []int
	}{
		{"single", HealthSpec{ExpectCode: 301}, []int{301}, []int{200, 302, 500}},
		{"list", HealthSpec{ExpectCodes: []int{200, 301}}, []int{200, 301}, []int{302, 404}},
		{"class-2xx-3xx", HealthSpec{ExpectClasses: []int{2, 3}}, []int{200, 204, 301, 399}, []int{404, 500, 199}},
		{"mixed", HealthSpec{ExpectCode: 418, ExpectClasses: []int{2}}, []int{418, 200, 299}, []int{301, 500}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, c := range tt.ok {
				if !tt.spec.Matches(c) {
					t.Errorf("Matches(%d) = false, want true", c)
				}
			}
			for _, c := range tt.bad {
				if tt.spec.Matches(c) {
					t.Errorf("Matches(%d) = true, want false", c)
				}
			}
		})
	}
}

// TestProbeExpectClassKeepsBackendUp is the G2 headline: `expect 2xx 3xx` keeps the
// backend healthy whether a flapping WordPress root answers 200 or 301.
func TestProbeExpectClassKeepsBackendUp(t *testing.T) {
	spec := &HealthSpec{Method: "GET", Path: "/list/", ExpectClasses: []int{2, 3}, Window: 2, Threshold: 2}
	var mu sync.Mutex
	fsm := newHealthFSM(2, 2, false)
	d := &fakeDoer{status: 200}

	// A 200 then a 301 (deploy flap) — both accepted by 2xx/3xx — keeps it up.
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	d.set(301, nil)
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	if !fsm.healthy() {
		t.Fatal("expect 2xx 3xx should stay healthy across a 200→301 flap")
	}

	// A 404 is outside both classes → folds toward down.
	d.set(404, nil)
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	probe(context.Background(), d, "http://backend.local", spec, &mu, fsm)
	if fsm.healthy() {
		t.Fatal("two 404s should mark the backend down")
	}
}
