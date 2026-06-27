// Package cache implements a two-tier, bounded, sharded-LRU object cache for the
// cadish HTTP cache server.
//
// # Tiers and routing
//
// Objects live in one of two tiers, both safe for concurrent use:
//
//   - RAM tier (ram.go):  in-memory, for small hot objects (HLS .m3u8 playlists,
//     images). Bounded by a total byte budget plus a per-object buffer cap and a
//     process-wide in-flight buffering budget (the "B2" OOM guard, below).
//   - Disk tier (disk.go): NVMe-backed, for large media (.mp4, .ts segments).
//     Blob content lives under <dir>/blobs/<sha256(key)>; the index (metadata +
//     LRU order) is persisted to <dir>/index.json so the cache survives a restart.
//
// Store (router.go) is the facade the server consumes. It owns both tiers and a
// RouterConfig, and on each write picks a tier via pickTier(key, size):
//
//   - Keys with an always-RAM extension (.m3u8 .jpg .jpeg .webp .png .gif) go to
//     RAM — UNLESS their size is known and exceeds the per-object RAM cap
//     (RAMMaxObjectBytes), in which case they go to disk so a giant mislabeled
//     playlist/image is still cached somewhere instead of dropped. Unknown size
//     (-1) still starts in RAM, protected by the bounded writer.
//   - Any other key whose size is known and <= SmallObjectThreshold goes to RAM.
//   - Everything else (large, or unknown size) goes to disk.
//
// Reads (Store.Get / Store.GetTier) check RAM first, then disk, returning the
// first hit and (for GetTier) which tier served it for per-tier hit-rate metrics.
//
// # Sharding and eviction
//
// Each tier is split into shardCount(maxBytes) independent shards (shard.go), up
// to 64, each with its own mutex, map, LRU list and byte counter, and an equal
// slice of the tier budget (shardCaps sums to exactly maxBytes). A key always
// maps to the same shard via FNV-1a hash, so the hot read path — a cache hit does
// an LRU MoveToFront, i.e. a WRITE under the lock — only contends with other keys
// on the SAME shard rather than one global mutex. Eviction is therefore per-shard
// approximate-LRU: when a shard is full, it evicts its own least-recently-used
// entries until the new object fits. A small/test-sized budget (<= 1 MiB)
// collapses to a single shard, preserving exact global-LRU semantics. An object
// larger than its shard's cap is refused (streams through uncached) and never
// wedges the shard. Per-shard byte counts are mirrored into atomics so
// Bytes()/Stats() aggregate without taking any shard lock.
//
// # RAM OOM guard (B2)
//
// The RAM tier bounds writes on two PROCESS-WIDE axes (never sharded) so it can
// never be driven to OOM: a per-object buffer cap (RAMMaxObjectBytes) and a total
// in-flight buffering budget across all active writers (RAMInflightBudget). A
// write that would exceed either makes that writer "overflow" — it frees its
// buffer and streams the body to the client uncached, never committing — so the
// client stream is never disturbed.
//
// # Persistence and restart
//
// Disk index persistence is decoupled from the commit hot path: commits and
// evictions set a per-shard dirty flag and a single background goroutine flushes
// the merged index.json at most once per persistInterval (5s), debounced, plus a
// final synchronous flush on Close. On load() every persisted entry is re-homed
// to its shard by hash and re-validated against its blob's on-disk size; a missing
// or size-mismatched blob is dropped. A crash between flushes costs at most a
// re-fetch, never a stale or corrupt hit. PersistErrors counts failed background
// flushes for observability.
//
// # Not in this package
//
// Request coalescing (single-flight on misses) lives in cadish's server layer,
// not here — this package is purely the cache store. The server is expected to
// wrap Store.Get/Writer with that mechanism.
//
// Each tier implements the Tier interface. Tiers are independently bounded and
// LRU-evicted.
package cache

import (
	"errors"
	"io"
)

// ErrNotFound is returned by Get when the key is absent from the tier.
var ErrNotFound = errors.New("cache: not found")

// Reader is an object's content reader plus its metadata. Callers MUST Close it.
type Reader struct {
	Meta ObjectMeta
	io.ReadCloser
}

// WriteTo lets io.Copy hand the whole object off to the destination in one shot
// when the underlying content reader supports it (the RAM tier's *bytes.Reader,
// the disk tier's *os.File both do), avoiding io.Copy's per-call 32 KiB scratch-
// buffer allocation on the HIT serve path. Embedding the io.ReadCloser *interface*
// only promotes Read/Close — WriterTo is not in that method set, so without this
// delegator io.Copy(dst, reader) falls back to the buffered loop (allocating a
// 32 KiB buffer every HIT) even for a *bytes.Reader source.
func (r *Reader) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := r.ReadCloser.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	// Underlying reader has no WriteTo: copy from the EMBEDDED reader (not r, which
	// would re-enter this method and recurse) via io.Copy's normal buffered loop.
	return io.Copy(w, r.ReadCloser)
}

// Tier is a single bounded cache layer (RAM or disk).
type Tier interface {
	// Get returns a Reader positioned at the start of the object, or ErrNotFound.
	// A successful Get marks the entry most-recently-used.
	Get(key string) (*Reader, bool)

	// Writer returns a WriteCloser that the caller streams the object body into.
	// On Close (without prior abort) the object is committed to the tier and may
	// trigger eviction of older entries. meta.Size may be 0/unknown up front; the
	// tier records the actual bytes written. The caller should call Abort on the
	// returned writer (instead of Close) to discard a partial/failed write.
	Writer(meta ObjectMeta) (TierWriter, error)

	// Delete removes key from the tier (dropping the in-memory entry and, for the
	// disk tier, its blob). It is a no-op when the key is absent. Used by the Store
	// to keep a key in at most ONE tier: when a re-store routes a key to a different
	// tier than a prior copy, the sibling tier's now-superseded copy is deleted so a
	// GET can never serve the stale shadow (cross-tier dedup).
	Delete(key string)

	// Len returns the number of cached objects.
	Len() int

	// Bytes returns the total bytes currently held.
	Bytes() int64

	// Close releases tier resources (flushing disk metadata, etc.).
	Close() error

	// Reset drops every cached object from the tier (and, for the disk tier, removes
	// the blob files and persists an emptied index). Used by the reload flush path
	// (Store.Reset) when a site's cache-key scheme changed, against a store not yet
	// serving traffic.
	Reset()
}

// TierWriter receives a streamed object body. Either Commit or Abort must be
// called exactly once; Abort discards the partial write.
type TierWriter interface {
	io.Writer
	// Commit finalizes the object into the tier (updating size to bytes written).
	Commit() error
	// Abort discards the in-progress write and releases any temp resources.
	Abort() error
	// Stored reports whether the most recent Commit ACTUALLY installed the object in
	// the tier. A nil Commit error does NOT imply storage: a RAM overflow (per-object
	// cap / global in-flight budget / shard cap) or a disk oversize discard returns nil
	// without installing anything. Only meaningful after Commit; false before it. The
	// cross-tier dedup (R14) gates the sibling delete on this so an overflowed re-store
	// never destroys the only real cached copy.
	Stored() bool
}
