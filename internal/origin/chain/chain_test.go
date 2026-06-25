package chain

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// fakeOrigin is an in-memory origin.Origin that returns a canned response/error
// and counts how many times it was called.
type fakeOrigin struct {
	resp  *origin.Response
	err   error
	calls atomic.Int32
}

func (f *fakeOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// okResp builds a 200 response with body b.
func okResp(b string) *origin.Response {
	return &origin.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		ContentLength: int64(len(b)),
		Body:          io.NopCloser(strings.NewReader(b)),
	}
}

// closeTrackingBody is an io.ReadCloser that records whether Close was called, so
// a chain test can assert the chain closes a negative *Response it falls through.
type closeTrackingBody struct {
	r      io.Reader
	closed atomic.Bool
}

func (b *closeTrackingBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *closeTrackingBody) Close() error               { b.closed.Store(true); return nil }

// negResp builds a negative (404/410-style) full-body *Response with status code
// and body b. The Body is close-tracking so a test can assert it was closed when
// the chain falls through.
func negResp(code int, b string) (*origin.Response, *closeTrackingBody) {
	body := &closeTrackingBody{r: strings.NewReader(b)}
	return &origin.Response{
		StatusCode:    code,
		Header:        http.Header{},
		ContentLength: int64(len(b)),
		Body:          body,
		Negative:      true,
	}, body
}

func statusErr(code int) error { return &origin.StatusError{Status: code, Origin: "fake"} }

// TestChain_NoFallThroughForBodyRequest verifies that a request carrying a body
// (a non-idempotent write whose streamed body is consumed by the first origin
// and is not replayable) does NOT fall through to the next origin: the first
// origin's failure is surfaced and the second origin is never consulted. A
// no-body request to the same chain falls through normally (unchanged).
func TestChain_NoFallThroughForBodyRequest(t *testing.T) {
	// Body request: primary 5xx (normally a fall-through) must NOT fall through.
	primary := &fakeOrigin{err: statusErr(503)}
	fallback := &fakeOrigin{resp: okResp("FALLBACK")}
	c, err := New([]origin.Origin{primary, fallback})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, ferr := c.Fetch(context.Background(), &origin.Request{
		Method:        http.MethodPost,
		Key:           "k",
		Body:          io.NopCloser(strings.NewReader("payload")),
		ContentLength: -1,
	})
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if ferr == nil {
		t.Fatalf("body request: want primary 503 error surfaced, got nil err")
	}
	if origin.StatusOf(ferr) != 503 {
		t.Fatalf("body request error StatusOf = %d, want 503", origin.StatusOf(ferr))
	}
	if got := fallback.calls.Load(); got != 0 {
		t.Fatalf("body request fell through to fallback (calls=%d), want no fall-through", got)
	}

	// No-body request to an identical chain falls through (unchanged).
	primary2 := &fakeOrigin{err: statusErr(503)}
	fallback2 := &fakeOrigin{resp: okResp("FALLBACK")}
	c2, err := New([]origin.Origin{primary2, fallback2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp2, ferr2 := c2.Fetch(context.Background(), &origin.Request{Key: "k"})
	if ferr2 != nil {
		t.Fatalf("no-body request: want fall-through success, got %v", ferr2)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body) != "FALLBACK" {
		t.Fatalf("no-body body = %q, want FALLBACK (fall-through unchanged)", body)
	}
}

// TestChain_NegativeResponseFallThrough pins backlog #21: an origin that returns a
// full-body 404/410 as a negative *Response (not the ErrNotFound error) must be
// treated as a miss — the chain falls through to the next origin AND closes the
// negative body it abandoned (no leaked upstream connection).
func TestChain_NegativeResponseFallThrough(t *testing.T) {
	neg, negBody := negResp(http.StatusNotFound, "404 PAGE")
	primary := &fakeOrigin{resp: neg}
	fallback := &fakeOrigin{resp: okResp("FALLBACK")}

	c, err := New([]origin.Origin{primary, fallback})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, ferr := c.Fetch(context.Background(), &origin.Request{Key: "k"})
	if ferr != nil {
		t.Fatalf("Fetch err = %v, want FALLBACK body", ferr)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "FALLBACK" {
		t.Fatalf("body = %q want FALLBACK (fell through the negative 404)", body)
	}
	if !negBody.closed.Load() {
		t.Fatal("chain did not Close the abandoned negative response body")
	}
	if primary.calls.Load() != 1 || fallback.calls.Load() != 1 {
		t.Fatalf("calls primary=%d fallback=%d want 1/1", primary.calls.Load(), fallback.calls.Load())
	}
}

// TestChain_LastNegativeResponseSurfaced: when every origin misses and the LAST
// one is a negative *Response (full-body 404), that response is surfaced (not an
// error) so the server can negatively cache its real body+headers.
func TestChain_LastNegativeResponseSurfaced(t *testing.T) {
	neg, _ := negResp(http.StatusGone, "GONE PAGE")
	primary := &fakeOrigin{err: origin.ErrNotFound}
	last := &fakeOrigin{resp: neg}

	c, err := New([]origin.Origin{primary, last})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, ferr := c.Fetch(context.Background(), &origin.Request{Key: "k"})
	if ferr != nil {
		t.Fatalf("Fetch err = %v, want the final negative *Response", ferr)
	}
	if resp == nil || resp.StatusCode != http.StatusGone || !resp.Negative {
		t.Fatalf("resp = %+v, want a negative 410 *Response surfaced", resp)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "GONE PAGE" {
		t.Fatalf("body = %q want GONE PAGE", body)
	}
}

func TestChain_TableDriven(t *testing.T) {
	connErr := errors.New("dial tcp: connection refused") // StatusOf == 0

	tests := []struct {
		name       string
		origins    []*fakeOrigin // primary, fallback...
		opts       []Option
		wantBody   string // expected served body ("" => expect error)
		wantStatus int    // origin.StatusOf of the returned error (when wantBody == "")
		wantCalls  []int  // expected call count per origin
	}{
		{
			name:      "primary 200, fallback never called",
			origins:   []*fakeOrigin{{resp: okResp("PRIMARY")}, {resp: okResp("FALLBACK")}},
			wantBody:  "PRIMARY",
			wantCalls: []int{1, 0},
		},
		{
			name:      "primary 404 -> fallback serves",
			origins:   []*fakeOrigin{{err: origin.ErrNotFound}, {resp: okResp("FALLBACK")}},
			wantBody:  "FALLBACK",
			wantCalls: []int{1, 1},
		},
		{
			name:      "primary 5xx -> fallback serves",
			origins:   []*fakeOrigin{{err: statusErr(503)}, {resp: okResp("FALLBACK")}},
			wantBody:  "FALLBACK",
			wantCalls: []int{1, 1},
		},
		{
			name:      "primary connection error -> fallback serves",
			origins:   []*fakeOrigin{{err: connErr}, {resp: okResp("FALLBACK")}},
			wantBody:  "FALLBACK",
			wantCalls: []int{1, 1},
		},
		{
			name:       "all fail -> last error surfaced",
			origins:    []*fakeOrigin{{err: origin.ErrNotFound}, {err: statusErr(502)}},
			wantBody:   "",
			wantStatus: 502, // the LAST origin's error
			wantCalls:  []int{1, 1},
		},
		{
			name:       "default: 403 does NOT fall through (surfaced, fallback not called)",
			origins:    []*fakeOrigin{{err: statusErr(403)}, {resp: okResp("FALLBACK")}},
			wantBody:   "",
			wantStatus: 403,
			wantCalls:  []int{1, 0},
		},
		{
			name:      "custom status set: fall through on 403 too",
			origins:   []*fakeOrigin{{err: statusErr(403)}, {resp: okResp("FALLBACK")}},
			opts:      []Option{WithFallThroughStatuses(404, 403)},
			wantBody:  "FALLBACK",
			wantCalls: []int{1, 1},
		},
		{
			name:       "custom status set: 500 NOT in set -> surfaced, no fall through",
			origins:    []*fakeOrigin{{err: statusErr(500)}, {resp: okResp("FALLBACK")}},
			opts:       []Option{WithFallThroughStatuses(404)},
			wantBody:   "",
			wantStatus: 500,
			wantCalls:  []int{1, 0},
		},
		{
			name:      "custom status set: connection error still falls through",
			origins:   []*fakeOrigin{{err: connErr}, {resp: okResp("FALLBACK")}},
			opts:      []Option{WithFallThroughStatuses(404)},
			wantBody:  "FALLBACK",
			wantCalls: []int{1, 1},
		},
		{
			name:      "three-origin chain: first two 404, third serves",
			origins:   []*fakeOrigin{{err: origin.ErrNotFound}, {err: origin.ErrNotFound}, {resp: okResp("THIRD")}},
			wantBody:  "THIRD",
			wantCalls: []int{1, 1, 1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origins := make([]origin.Origin, len(tc.origins))
			for i, f := range tc.origins {
				origins[i] = f
			}
			c, err := New(origins, tc.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			resp, ferr := c.Fetch(context.Background(), &origin.Request{Key: "k"})

			if tc.wantBody != "" {
				if ferr != nil {
					t.Fatalf("Fetch err = %v, want body %q", ferr, tc.wantBody)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if string(body) != tc.wantBody {
					t.Fatalf("body = %q want %q", body, tc.wantBody)
				}
			} else {
				if ferr == nil {
					resp.Body.Close()
					t.Fatalf("Fetch err = nil, want an error (status %d)", tc.wantStatus)
				}
				if tc.wantStatus != 0 && origin.StatusOf(ferr) != tc.wantStatus {
					t.Fatalf("StatusOf(err) = %d want %d (err=%v)", origin.StatusOf(ferr), tc.wantStatus, ferr)
				}
			}

			for i, want := range tc.wantCalls {
				if got := int(tc.origins[i].calls.Load()); got != want {
					t.Fatalf("origin[%d] calls = %d want %d", i, got, want)
				}
			}
		})
	}
}

func TestNew_RejectsEmpty(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) = nil err, want error")
	}
	if _, err := New([]origin.Origin{}); err == nil {
		t.Fatal("New(empty) = nil err, want error")
	}
}

func TestDefaultFallThrough(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("conn refused"), true}, // status 0
		{origin.ErrNotFound, true},         // 404
		{statusErr(500), true},
		{statusErr(503), true},
		{statusErr(403), false},
		{statusErr(401), false},
		{statusErr(400), false},
	}
	for _, c := range cases {
		if got := DefaultFallThrough(c.err); got != c.want {
			t.Errorf("DefaultFallThrough(%v) = %v want %v", c.err, got, c.want)
		}
	}
}

func TestChain_ContextCancelledBetweenAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	c, err := New([]origin.Origin{&fakeOrigin{err: origin.ErrNotFound}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(ctx, &origin.Request{Key: "k"}); err == nil {
		t.Fatal("Fetch with cancelled ctx = nil err, want context error")
	}
}
