package chain

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cadi-sh/cadish/internal/origin"
)

// benchOrigin returns a canned response or error without any I/O, so the
// benchmark isolates the chain's dispatch/fall-through overhead.
type benchOrigin struct {
	resp *origin.Response
	err  error
}

func (o benchOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	if o.err != nil {
		return nil, o.err
	}
	// Fresh body per call (the caller closes it), mirroring real usage.
	return &origin.Response{
		StatusCode:    o.resp.StatusCode,
		Header:        o.resp.Header,
		ContentLength: o.resp.ContentLength,
		Body:          io.NopCloser(strings.NewReader("ok")),
	}, nil
}

func okOrigin() benchOrigin {
	return benchOrigin{resp: &origin.Response{StatusCode: http.StatusOK, Header: http.Header{}, ContentLength: 2}}
}

// BenchmarkChainHitFirst measures the common case: the primary origin succeeds,
// so the chain returns on the first try (pure dispatch overhead vs a bare
// origin).
func BenchmarkChainHitFirst(b *testing.B) {
	c, err := New([]origin.Origin{okOrigin(), okOrigin()})
	if err != nil {
		b.Fatal(err)
	}
	req := &origin.Request{Key: "videos/clip.mp4"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := c.Fetch(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

// BenchmarkChainFallThrough measures the fallback path: the primary 404s (a
// fall-through condition) and the secondary serves the object — the cost of one
// extra dispatch plus the fall-through predicate.
func BenchmarkChainFallThrough(b *testing.B) {
	primary := benchOrigin{err: origin.ErrNotFound}
	c, err := New([]origin.Origin{primary, okOrigin()})
	if err != nil {
		b.Fatal(err)
	}
	req := &origin.Request{Key: "videos/clip.mp4"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := c.Fetch(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

// BenchmarkChainDeepFallThrough measures fall-through across a longer chain
// (first three miss, fourth hits) — the worst realistic dispatch depth.
func BenchmarkChainDeepFallThrough(b *testing.B) {
	miss := benchOrigin{err: &origin.StatusError{Status: 503}}
	c, err := New([]origin.Origin{miss, miss, miss, okOrigin()})
	if err != nil {
		b.Fatal(err)
	}
	req := &origin.Request{Key: "videos/clip.mp4"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := c.Fetch(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}
