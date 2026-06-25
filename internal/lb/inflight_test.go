package lb

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

// heldOrigin returns a 200 whose in-flight accounting is released only when the caller
// closes the response body, so a test can hold a request "in flight" deterministically.
type heldOrigin struct{}

func (heldOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	return &origin.Response{
		StatusCode:    200,
		Header:        http.Header{},
		ContentLength: 2,
		Body:          io.NopCloser(strings.NewReader("ok")),
	}, nil
}

// TestUpstreamInflightAccounting proves Inflight() counts a held request and returns to
// zero once the response body is closed (release), so the removed-pool drain can observe
// quiescence.
func TestUpstreamInflightAccounting(t *testing.T) {
	factory := func(string, *Target, Timeouts) (origin.Origin, error) {
		return heldOrigin{}, nil
	}
	cfg := staticCfg(t, RoundRobin, "http://a:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Inflight(); got != 0 {
		t.Fatalf("initial Inflight = %d, want 0", got)
	}

	resp, err := u.Fetch(context.Background(), &origin.Request{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The request is in flight until the caller closes the body.
	if got := u.Inflight(); got != 1 {
		t.Fatalf("in-flight Inflight = %d, want 1", got)
	}
	_ = resp.Body.Close()
	if got := u.Inflight(); got != 0 {
		t.Fatalf("after close Inflight = %d, want 0", got)
	}
}

// TestUpstreamInflightConcurrent stresses the counter under parallel fetch/close to
// catch any accounting race (the -race gate is the real assertion here).
func TestUpstreamInflightConcurrent(t *testing.T) {
	factory := func(string, *Target, Timeouts) (origin.Origin, error) {
		return heldOrigin{}, nil
	}
	cfg := staticCfg(t, RoundRobin, "http://a:80", "http://b:80")
	u, err := New(cfg, WithOriginFactory(factory))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, ferr := u.Fetch(context.Background(), &origin.Request{})
			if ferr != nil {
				return
			}
			time.Sleep(time.Millisecond)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	if got := u.Inflight(); got != 0 {
		t.Fatalf("after drain Inflight = %d, want 0", got)
	}
}
