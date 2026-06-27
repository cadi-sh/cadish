package server

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

// trackingBody is an io.ReadCloser that records whether Close was called, so a test
// can assert the server released a live upstream error body.
type trackingBody struct {
	data   string
	off    int
	closed atomic.Bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	if b.off >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

// statusErrOrigin is a fake origin.Origin that always fails with a *StatusError
// carrying the supplied live body — exactly the shape an HTTP origin produces for a
// bodied non-2xx upstream response.
type statusErrOrigin struct {
	status int
	body   *trackingBody
}

func (o *statusErrOrigin) Fetch(_ context.Context, _ *origin.Request) (*origin.Response, error) {
	return nil, &origin.StatusError{
		Status:        o.status,
		Origin:        "fake",
		Body:          o.body,
		ContentLength: int64(len(o.body.data)),
	}
}

// TestMaxStaleOnErrorClosesOriginErrorBody is the BUG-1 regression: when the origin
// returns a bodied non-2xx (*StatusError) AND a within-max_stale cached copy exists,
// handleOriginError serves the stale copy and returns EARLY — but it must STILL close
// the live upstream error body it owns, or the upstream keep-alive connection / FD is
// leaked (FD exhaustion during a sustained outage, exactly when max_stale keeps firing).
func TestMaxStaleOnErrorClosesOriginErrorBody(t *testing.T) {
	clk := newFakeClock()
	// Build with the normal counting origin so we can PRIME a fresh cached copy.
	prime := newCountingOrigin(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "last-good")
	})
	h, cfg := buildHandler(t, clk, cfgMaxStale, prime.srv.URL)

	primeMaxStale(t, h, "/p")

	// Swap the site origin for one that fails with a bodied *StatusError. boundSite
	// embeds the SAME *config.Site pointer the routing table holds, so this mutation is
	// live for the next request.
	body := &trackingBody{data: "upstream is on fire"}
	cfg.Sites[0].Origin = &statusErrOrigin{status: 503, body: body}

	clk.advance(4 * time.Minute) // past grace, within max_stale

	rec := do(h, "GET", "http://test.local/p", nil)
	if rec.Code != 200 || rec.Body.String() != "last-good" {
		t.Fatalf("got %d %q, want 200 last-good (HIT-STALE-ERROR)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Cache"); got != "HIT-STALE-ERROR" {
		t.Fatalf("X-Cache=%q, want HIT-STALE-ERROR", got)
	}
	if !body.closed.Load() {
		t.Fatal("origin-error body was NOT closed on the max_stale early-return path (leaked upstream connection/FD)")
	}
}
