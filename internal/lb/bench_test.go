package lb

import (
	"context"
	"fmt"
	"testing"

	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/origin"
)

// poolSizes are the backend-pool sizes exercised across the lb benchmarks.
var poolSizes = []int{3, 16, 64}

// makeIDs returns n synthetic backend ids (host:port).
func makeIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("10.0.%d.%d:8080", i/256, i%256)
	}
	return ids
}

func benchKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("session-token-%d", i)
	}
	return keys
}

// BenchmarkRingLookup measures the consistent-hash lookup hot path (the per-
// request cost of the sticky / shard policies) across pool sizes, all backends
// eligible.
func BenchmarkRingLookup(b *testing.B) {
	keys := benchKeys(1024)
	for _, n := range poolSizes {
		r := newRing(0, makeIDs(n))
		b.Run(fmt.Sprintf("backends=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r.lookup(keys[i&1023], nil)
			}
		})
	}
}

// BenchmarkRingLookupHalfDown measures lookup when half the pool is ineligible,
// so the ring walks clockwise past dead virtual nodes (the health-aware rehash).
func BenchmarkRingLookupHalfDown(b *testing.B) {
	keys := benchKeys(1024)
	for _, n := range poolSizes {
		ids := makeIDs(n)
		r := newRing(0, ids)
		dead := make(map[string]bool, len(ids))
		for i := 0; i < len(ids); i += 2 {
			dead[ids[i]] = true
		}
		eligible := func(id string) bool { return !dead[id] }
		b.Run(fmt.Sprintf("backends=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				r.lookup(keys[i&1023], eligible)
			}
		})
	}
}

// BenchmarkRingRebuild measures rebuilding the ring after a backend membership
// change (add or remove one) — the cost paid on every dynamic re-resolution that
// changes the set. The whole ring is rebuilt from the new id list.
func BenchmarkRingRebuild(b *testing.B) {
	for _, n := range poolSizes {
		full := makeIDs(n + 1)
		fewer := full[:n] // the "after a remove" / "before an add" set
		b.Run(fmt.Sprintf("backends=%d/remove", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = newRing(0, fewer)
			}
		})
		b.Run(fmt.Sprintf("backends=%d/add", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = newRing(0, full)
			}
		})
	}
}

// BenchmarkStickyPick measures full sticky selection through Upstream.pick
// (state snapshot + ring lookup + eligibility) across pool sizes, with an
// in-memory origin so no I/O is involved.
func BenchmarkStickyPick(b *testing.B) {
	factory := func(string, *Target, Timeouts) (origin.Origin, error) { return nopOrigin{}, nil }
	req := &origin.Request{Key: "videos/clip-42.ts"}
	ctx := WithRoutingKey(context.Background(), "user-123")
	for _, n := range poolSizes {
		cfg := Config{Name: "u", Kind: "upstream", Policy: Sticky}
		for _, id := range makeIDs(n) {
			tgt, err := parseTarget("http://"+id, cadishfile.Pos{})
			if err != nil {
				b.Fatal(err)
			}
			cfg.Backends = append(cfg.Backends, tgt)
		}
		up, err := New(cfg, WithOriginFactory(factory))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("backends=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			tried := map[string]bool{}
			for i := 0; i < b.N; i++ {
				_ = up.pick(ctx, req, tried)
			}
		})
	}
}

// BenchmarkPickPolicies compares the per-request selection cost of the steady-
// state policies on a fixed pool, with an in-memory origin.
func BenchmarkPickPolicies(b *testing.B) {
	factory := func(string, *Target, Timeouts) (origin.Origin, error) { return nopOrigin{}, nil }
	req := &origin.Request{Key: "videos/clip-42.ts"}
	cases := []struct {
		name   string
		policy Policy
		shard  ShardKey
		ctx    context.Context
	}{
		{"round_robin", RoundRobin, ShardNone, context.Background()},
		{"least_conn", LeastConn, ShardNone, context.Background()},
		{"sticky", Sticky, ShardNone, WithRoutingKey(context.Background(), "user-123")},
		{"shard_url", Shard, ShardURL, context.Background()},
	}
	for _, tc := range cases {
		cfg := Config{Name: "u", Kind: "upstream", Policy: tc.policy, Shard: tc.shard}
		for _, id := range makeIDs(16) {
			tgt, err := parseTarget("http://"+id, cadishfile.Pos{})
			if err != nil {
				b.Fatal(err)
			}
			cfg.Backends = append(cfg.Backends, tgt)
		}
		up, err := New(cfg, WithOriginFactory(factory))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			tried := map[string]bool{}
			for i := 0; i < b.N; i++ {
				_ = up.pick(tc.ctx, req, tried)
			}
		})
	}
}

// nopOrigin is a do-nothing origin for selection benchmarks.
type nopOrigin struct{}

func (nopOrigin) Fetch(ctx context.Context, req *origin.Request) (*origin.Response, error) {
	return nil, origin.ErrNotFound
}
