package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/logs"
)

// sampleRecord is a representative access record for the hub/socket tests.
func sampleRecord() accessRecord {
	return accessRecord{
		Time:     time.Date(2026, 6, 24, 13, 0, 0, 0, time.UTC),
		Method:   "GET",
		Host:     "example.com",
		Path:     "/a",
		Status:   200,
		Bytes:    1234,
		Cache:    "HIT",
		Upstream: "cache:ram",
		DurMs:    7,
	}
}

// A subscriber receives records published after it attaches.
func TestHubFanOutDelivers(t *testing.T) {
	h := newAccessHub(true)
	sub := h.subscribe()
	if sub == nil {
		t.Fatal("subscribe returned nil on an enabled hub")
	}
	defer h.unsubscribe(sub)

	if got := h.subscriberCount(); got != 1 {
		t.Fatalf("subscriberCount = %d, want 1", got)
	}

	rec := sampleRecord()
	h.publish(rec)

	select {
	case got := <-sub.ch:
		if got != rec {
			t.Errorf("delivered record = %+v, want %+v", got, rec)
		}
	default:
		t.Fatal("expected a delivered record, channel was empty")
	}
}

// Fan-out delivers to EVERY attached subscriber.
func TestHubFanOutMultiple(t *testing.T) {
	h := newAccessHub(true)
	a := h.subscribe()
	b := h.subscribe()
	defer h.unsubscribe(a)
	defer h.unsubscribe(b)

	if got := h.subscriberCount(); got != 2 {
		t.Fatalf("subscriberCount = %d, want 2", got)
	}
	h.publish(sampleRecord())
	for i, sub := range []*accessSub{a, b} {
		select {
		case <-sub.ch:
		default:
			t.Errorf("subscriber %d did not receive the record", i)
		}
	}
}

// With zero subscribers, the hot-path probe is 0 and publish is a no-op (the caller
// gates on subscriberCount()==0; this asserts the idle invariant holds).
func TestHubIdleIsNoOp(t *testing.T) {
	h := newAccessHub(true)
	if got := h.subscriberCount(); got != 0 {
		t.Fatalf("idle subscriberCount = %d, want 0", got)
	}
	// publish with no subscribers must not panic or block.
	h.publish(sampleRecord())
}

// A full per-subscriber channel drops + counts rather than blocking the publisher.
func TestHubDropsOnFullBuffer(t *testing.T) {
	h := newAccessHubSize(true, 2) // tiny buffer to overflow deterministically
	sub := h.subscribe()
	defer h.unsubscribe(sub)

	// Publish more than the buffer can hold; the consumer never drains.
	for i := 0; i < 5; i++ {
		h.publish(sampleRecord())
	}
	if got := sub.dropped.Load(); got != 3 {
		t.Errorf("dropped = %d, want 3 (5 published - 2 buffered)", got)
	}
	if got := len(sub.ch); got != 2 {
		t.Errorf("buffered = %d, want 2", got)
	}
}

// `access_log off` => newAccessHub(false): subscribe is a no-op, count stays 0.
func TestHubDisabled(t *testing.T) {
	h := newAccessHub(false)
	if h.Enabled() {
		t.Error("disabled hub reports Enabled()=true")
	}
	if sub := h.subscribe(); sub != nil {
		t.Error("disabled hub returned a non-nil subscription")
	}
	if got := h.subscriberCount(); got != 0 {
		t.Errorf("disabled hub subscriberCount = %d, want 0", got)
	}
	// publish is harmless on a disabled hub.
	h.publish(sampleRecord())
}

// unsubscribe drops the count back to 0 and is safe to call twice / with nil.
func TestHubUnsubscribe(t *testing.T) {
	h := newAccessHub(true)
	sub := h.subscribe()
	h.unsubscribe(sub)
	if got := h.subscriberCount(); got != 0 {
		t.Fatalf("after unsubscribe count = %d, want 0", got)
	}
	h.unsubscribe(sub) // idempotent
	h.unsubscribe(nil) // nil-safe
}

// The NDJSON wire line a subscriber would write parses back through logs.ParseLine
// to the SAME fields (the consumer-reuse contract: server wire == logs reader input).
func TestRecordNDJSONRoundTripsThroughLogsParseLine(t *testing.T) {
	rec := sampleRecord()
	line, err := rec.appendNDJSON(nil)
	if err != nil {
		t.Fatalf("appendNDJSON: %v", err)
	}
	if line[len(line)-1] != '\n' {
		t.Error("NDJSON line is not newline-terminated")
	}
	parsed, ok, perr := logs.ParseLine(line)
	if perr != nil || !ok {
		t.Fatalf("ParseLine(wire) ok=%v err=%v line=%s", ok, perr, line)
	}
	if parsed.Method != rec.Method || parsed.Host != rec.Host || parsed.Path != rec.Path ||
		parsed.Status != rec.Status || parsed.Bytes != rec.Bytes || parsed.Cache != rec.Cache ||
		parsed.Upstream != rec.Upstream || parsed.DurMs != rec.DurMs {
		t.Errorf("round-trip mismatch:\n wire rec = %+v\n parsed   = %+v", rec, parsed)
	}
	if !parsed.Time.Equal(rec.Time) {
		t.Errorf("round-trip time mismatch: wire=%v parsed=%v", rec.Time, parsed.Time)
	}
}

// On the server hot path, a request with a subscriber attached publishes one access
// record carrying the request's fields; with no subscriber attached nothing is
// published (the idle no-op invariant).
func TestServeHTTPPublishesToHub(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public")
		_, _ = w.Write([]byte("hello"))
	}))
	defer origin.Close()

	h, _ := buildHandler(t, nil, cfgBasic, origin.URL)

	// Idle: no subscriber → the request serves but publishes nothing.
	if rec := do(h, "GET", "/x", nil); rec.Code != http.StatusOK {
		t.Fatalf("idle request status %d", rec.Code)
	}

	// Attach a subscriber, then a request must fan out exactly one record.
	sub := h.accessHub.subscribe()
	if sub == nil {
		t.Fatal("subscribe returned nil")
	}
	defer h.accessHub.unsubscribe(sub)

	rec := do(h, "GET", "/y", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("request status %d", rec.Code)
	}
	select {
	case got := <-sub.ch:
		if got.Path != "/y" || got.Method != "GET" || got.Status != http.StatusOK {
			t.Errorf("published record = %+v, want path=/y method=GET status=200", got)
		}
	default:
		t.Fatal("expected a published record with a subscriber attached")
	}
}

// With `access_log off` the hub is disabled, so even an explicit subscribe is a
// no-op and a served request fans nothing out.
func TestServeHTTPAccessLogOffNoFanout(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public")
		_, _ = w.Write([]byte("hi"))
	}))
	defer origin.Close()

	h, _ := buildHandler(t, nil, cfgBasic, origin.URL)
	h.accessHub = newAccessHub(false) // simulate `access_log off`

	if sub := h.accessHub.subscribe(); sub != nil {
		t.Fatal("disabled hub returned a subscription")
	}
	if rec := do(h, "GET", "/z", nil); rec.Code != http.StatusOK {
		t.Fatalf("request status %d", rec.Code)
	}
	if got := h.accessHub.subscriberCount(); got != 0 {
		t.Errorf("disabled hub subscriberCount = %d, want 0", got)
	}
}

// A nil hub (defensive) reports 0 subscribers and is not enabled.
func TestNilHubSafe(t *testing.T) {
	var h *AccessHub
	if h.subscriberCount() != 0 {
		t.Error("nil hub subscriberCount != 0")
	}
	if h.Enabled() {
		t.Error("nil hub Enabled() == true")
	}
	if h.subscribe() != nil {
		t.Error("nil hub subscribe() != nil")
	}
	h.unsubscribe(nil) // must not panic
}
