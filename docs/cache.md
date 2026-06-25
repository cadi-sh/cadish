# Two-tier cache (`internal/cache`)

The cache core is a two-tier, bounded, sharded-LRU object store. The
package is pure Go standard library — no external dependencies.

## Tiers

| Tier | Backing | For | Bounded by |
|------|---------|-----|------------|
| RAM  | memory  | small hot objects (HLS `.m3u8`, images) | total byte budget + per-object cap + process-wide in-flight budget |
| Disk | NVMe directory | large media (`.mp4`, `.ts` segments) | total byte budget |

Both tiers implement the `Tier` interface and are safe for concurrent use.
`Store` is the facade the server consumes: it owns both tiers plus a
`RouterConfig` and routes each request to the right tier.

## Routing (RAM vs disk)

`Store` chooses a tier per write from the key's extension and the (possibly
unknown) size:

1. **Always-RAM extensions** — `.m3u8 .jpg .jpeg .webp .png .gif` (case
   insensitive) — go to RAM, **unless** the size is known and exceeds the
   per-object RAM cap (`RAMMaxObjectBytes`), in which case they go to **disk** so
   a giant mislabeled playlist/image is still cached somewhere rather than dropped.
   Unknown size (`-1`) still starts in RAM, protected by the bounded writer.
2. **Other keys** whose size is known and `<= SmallObjectThreshold` go to RAM.
3. **Everything else** (large, or unknown size) goes to disk.

Reads check **RAM first, then disk** and return the first hit. `GetTier` also
reports which tier served the hit (`"ram"` / `"disk"` / `""`) for per-tier
hit-rate metrics.

## Sharding and eviction

Each tier is split into up to **64 independent shards** (fewer for small/test
budgets; a budget `<= 1 MiB` collapses to a single shard with exact global-LRU
semantics). Each shard has its own mutex, map, LRU list, byte counter, and an
equal slice of the tier budget (the per-shard caps sum to exactly the tier
budget). A key always maps to the same shard via an FNV-1a hash.

Because a cache **hit** moves the entry to the front of the LRU list (a write
under the lock), sharding is what keeps the hot read path from serializing on one
global mutex: unrelated keys land in different shards and don't contend.

Eviction is **per-shard approximate-LRU**: when a shard is full it evicts its own
least-recently-used entries until the new object fits. A hot object can be evicted
from its (full) shard while a colder object survives in another, emptier shard —
accepted for a hot-object cache. An object larger than its shard's cap is refused
(streams through uncached) and never wedges the shard. `Bytes()`/`Stats()` sum
lock-free atomic per-shard counters, so reporting never contends with the hot
path.

> **Sizing gotcha — the per-shard cap, not the tier budget, bounds a single
> object.** The largest object a tier can store is roughly `tier_budget /
> shard_count`, **not** the whole tier budget. With 64 shards a `disk 50MiB` tier
> gives ~64 × ~0.8 MiB shards, so a 2 MiB object exceeds its shard cap and is
> **refused — streamed through to the client uncached** (the `DiskOversizeDiscards`
> stat counts these). If you're caching media segments or other multi-MiB objects,
> size the tier so `tier_budget / shard_count` comfortably exceeds your largest
> object (or rely on the small-budget single-shard collapse only for tiny test
> budgets). This is the usual cause of "why isn't my video caching?".

## RAM OOM guard

The RAM tier bounds writes on two **process-wide** axes (never sharded):

- `RAMMaxObjectBytes` — per-object buffer cap. A writer that would exceed it
  "overflows": it frees its buffer and streams the body to the client uncached,
  never committing.
- `RAMInflightBudget` — total bytes all active RAM writers may buffer at once
  (an atomic budget charged as buffers grow, released on commit/abort). A write
  that would push the global total over budget overflows too.

Either way the **client stream is never disturbed** — overflowing writes still
report full success to the caller. These bounds stop a single huge object, or
many concurrent large ones, from OOM-killing the process.

## Persistence and restart (disk tier)

Blob content lives at `<dir>/blobs/<sha256(key)>`. The index (metadata + LRU
order) is persisted to `<dir>/index.json`.

Index writes are **decoupled from the commit hot path**: commits/evictions set a
per-shard dirty flag, and one background goroutine flushes the merged index at
most once per **5s** (debounced), plus a final synchronous flush on `Close`. On
load, every persisted entry is re-homed to its shard by hash and **re-validated
against its blob's on-disk size**; a missing or size-mismatched blob is dropped.
The persisted format is a flat list of `ObjectMeta`, so an index written by a
different shard count (or a pre-sharding build) still loads correctly.

A crash between flushes costs at most a re-fetch of the affected objects — never
a stale or corrupt hit. `Stats().DiskPersistErrors` (from `DiskTier.PersistErrors`)
counts failed background flushes; a growing value is worth alerting on.

## Not in this package

Request **coalescing** (single-flight on misses) lives in the server layer, not
here. This package is purely the cache store; the server wraps `Store.Get` /
`Store.Writer` with that mechanism.

## Public API

```go
// Construction
func NewStore(cfg RouterConfig) (*Store, error)
func DefaultRouterConfig(diskDir string) RouterConfig

type RouterConfig struct {
    RAMMaxBytes          int64             // total RAM tier budget
    DiskMaxBytes         int64             // total disk tier budget
    DiskDir              string            // directory backing the disk tier
    SmallObjectThreshold int64             // known-size objects <= this (non-RAM-ext) go to RAM
    RAMMaxObjectBytes    int64             // per-object RAM buffer cap (0 -> 64 MiB default)
    RAMInflightBudget    int64             // total concurrent RAM buffering (0 -> RAMMaxBytes)
    TierExtensions       map[string]string // per-ext default placement (".mp4" -> "ram"|"disk"); a storage rule overrides
}

// Reads
func (s *Store) Get(key string) (*Reader, bool)
func (s *Store) GetTier(key string) (r *Reader, tier string, ok bool) // tier: "ram"|"disk"|""

// Writes (stream the body into the returned writer, then Commit or Abort)
func (s *Store) Writer(meta ObjectMeta) (TierWriter, error)

// Observability / lifecycle
func (s *Store) Stats() Stats
func (s *Store) Close() error

type Reader struct {           // caller MUST Close
    Meta ObjectMeta
    io.ReadCloser
}

type TierWriter interface {    // exactly one of Commit/Abort
    io.Writer
    Commit() error             // finalize into the tier (size := bytes written)
    Abort() error              // discard the partial write
}

type ObjectMeta struct {
    Key          string
    Size         int64
    ContentType  string
    ETag         string
    LastModified string
    Status       int    // cached HTTP status; 0 == 200 (negative cache entry records its 404/410)
    Tier         string // write-time placement override "ram"|"disk" (not persisted); "" == auto-route
}
func (m ObjectMeta) EffectiveStatus() int // Status, mapping the zero value to 200

type Stats struct {
    RAMObjects, DiskObjects int
    RAMBytes, DiskBytes     int64
    RAMMaxBytes             int64
    DiskMaxBytes            int64
    DiskPersistErrors       int64
}

var ErrNotFound = errors.New("cache: not found")
```

### Usage sketch

```go
st, err := cache.NewStore(cache.DefaultRouterConfig("/var/cache/cadish"))
if err != nil { /* ... */ }
defer st.Close()

// Write
w, _ := st.Writer(cache.ObjectMeta{Key: "p.m3u8", ContentType: "application/vnd.apple.mpegurl"})
io.Copy(w, originBody) // stream from origin
if err := w.Commit(); err != nil { _ = w.Abort() }

// Read
if r, ok := st.Get("p.m3u8"); ok {
    defer r.Close()
    io.Copy(clientWriter, r) // r.Meta has ContentType/ETag/... for response headers
}
```
