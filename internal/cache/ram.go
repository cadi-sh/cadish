package cache

import (
	"bytes"
	"container/list"
	"io"
	"sync"
	"sync/atomic"
)

// ramEntry is one in-memory cached object.
type ramEntry struct {
	meta ObjectMeta
	data []byte
	el   *list.Element // position in the CLOCK ring (eviction order)
	// ref is the CLOCK "referenced" bit: a read (Get) sets it WITHOUT taking the
	// shard write lock or mutating the ring, so concurrent hits to one hot key no
	// longer serialize. Eviction (under the write lock) consults it to grant a
	// recently-read entry one second chance before reclaiming it. atomic so the
	// RLock read path and the Lock eviction path can touch it safely.
	ref atomic.Bool
}

// ramShard is one independent lock domain of the RAM tier: its own mutex, map, LRU
// list and byte counter, bounded by its own slice of the tier budget (maxBytes). The
// tier holds shardCount(maxBytes) of these and routes each key to exactly one by hash.
//
// READ PATH (Get): takes the shard RLock (shared) and sets the entry's atomic CLOCK
// ref bit — it does NOT mutate the ring, so concurrent hits to ONE hot key run in
// parallel instead of serializing on an exclusive lock + MoveToFront (the previous
// design made a single hot key a hard contention point under high concurrency). Writes
// (commit/eviction) still take the exclusive Lock. curBytes is mirrored into an atomic
// so Bytes()/Stats() can sum across shards WITHOUT taking every shard lock (keeping
// Stats off the contention path).
type ramShard struct {
	mu          sync.RWMutex
	maxBytes    int64
	curBytes    int64 // bytes held by this shard, guarded by mu
	atomicBytes int64 // lock-free mirror of curBytes for cheap aggregation (atomic)
	items       map[string]*ramEntry
	lru         *list.List // CLOCK ring; *list.Element.Value is the key (string)
}

// RAMTier is an in-memory, byte-bounded, LRU cache for small hot objects.
//
// SHARDING: the tier is split into shardCount(maxBytes) independent shards (shard.go),
// each with its own RWMutex/map/ring/counter and an equal slice of maxBytes. A key
// always maps to the same shard (shardIndex). The hot read path takes the shard RLock
// (shared) and only sets an atomic CLOCK ref bit, so it neither serializes concurrent
// hits to one hot key nor contends across keys on the same shard. Eviction is per-shard
// approximate-LRU via the CLOCK / second-chance algorithm (see commit + shardCaps for
// the accepted consequence).
//
// B2 OOM guard (UNCHANGED by sharding — these bounds stay PROCESS-WIDE on the tier,
// never sharded): writes are bounded on TWO axes so the RAM tier can never be driven
// to OOM by one huge object or many concurrent large ones.
//   - maxObjectBytes is a per-object buffer cap; a ramWriter that would exceed it
//     overflows (frees its buffer, discards the rest, never commits) so the object
//     streams to the client uncached instead of being buffered whole.
//   - inflightBudget bounds the TOTAL bytes all active ramWriters may buffer at
//     once (an atomic byte budget, inflightBytes <= inflightBudget). A write that
//     would push the global total over budget makes that writer overflow too. This
//     caps concurrent buffering even when each individual object is under the
//     per-object cap. Keeping it process-wide (one atomic on the tier, shared by all
//     shards) is REQUIRED: it bounds total live buffering across the whole process,
//     which a per-shard budget could not do.
type RAMTier struct {
	maxBytes int64
	shards   []*ramShard

	// maxObjectBytes is the per-object buffer cap (B2); 0 disables the per-object
	// bound. inflightBytes is the live total currently reserved by active writers and
	// is charged/released atomically (NOT under any shard lock, so it is
	// contention-free on the hot write path); inflightBudget caps it (0 disables the
	// global bound). These remain PROCESS-WIDE (not sharded) on purpose — see B2 note.
	maxObjectBytes int64
	inflightBytes  int64 // atomic, process-wide
	inflightBudget int64
}

// NewRAMTier creates an in-memory tier bounded to maxBytes, with a per-object buffer
// cap (maxObjectBytes) and a process-wide in-flight buffering budget (inflightBudget),
// both part of the B2 OOM guard. A non-positive maxObjectBytes/inflightBudget disables
// that particular bound (kept permissive so existing callers/tests that construct a
// tier directly are unaffected). The maxBytes budget is split equally across the
// shards (shardCaps), so the sum of per-shard caps stays <= maxBytes.
func NewRAMTier(maxBytes, maxObjectBytes, inflightBudget int64) *RAMTier {
	n := shardCount(maxBytes)
	caps := shardCaps(maxBytes, n)
	r := &RAMTier{
		maxBytes:       maxBytes,
		maxObjectBytes: maxObjectBytes,
		inflightBudget: inflightBudget,
		shards:         make([]*ramShard, n),
	}
	for i := range r.shards {
		r.shards[i] = &ramShard{
			maxBytes: caps[i],
			items:    make(map[string]*ramEntry),
			lru:      list.New(),
		}
	}
	return r
}

// shard returns the shard owning key.
func (r *RAMTier) shard(key string) *ramShard {
	return r.shards[shardIndex(key, len(r.shards))]
}

func (r *RAMTier) Get(key string) (*Reader, bool) {
	s := r.shard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.items[key]
	if !ok {
		return nil, false
	}
	// CLOCK: mark the entry referenced so eviction grants it a second chance. This is
	// a lock-free atomic set under the shared RLock — no ring mutation — so concurrent
	// hits to a single hot key proceed in parallel instead of serializing.
	e.ref.Store(true)
	// Hand out an independent reader over the (immutable) byte slice, recycled from a
	// pool so a warm HIT allocates no reader at all (Close returns it). bytesReadCloser
	// holds the bytes.Reader inline and exposes WriteTo for the zero-copy HIT serve.
	rc := bytesReaderPool.Get().(*bytesReadCloser)
	rc.r.Reset(e.data)
	return &Reader{Meta: e.meta, ReadCloser: rc}, true
}

// bytesReaderPool recycles the per-HIT RAM readers. A reader is taken in Get and
// returned in Close (the serve path closes exactly once, after the body is written),
// so a steady stream of warm HITs reuses readers instead of allocating one each.
var bytesReaderPool = sync.Pool{New: func() any { return new(bytesReadCloser) }}

// bytesReadCloser is a single-allocation io.ReadCloser over an immutable byte
// slice: the bytes.Reader is held by value (not via bytes.NewReader, which heap-
// allocates a second object) and Close is a no-op. It carries through WriteTo and
// the io.Reader fast paths (ReadByte/Seek) of bytes.Reader, so io.Copy still uses
// the buffer-free WriteTo hand-off.
type bytesReadCloser struct {
	r bytes.Reader
}

func (b *bytesReadCloser) Read(p []byte) (int, error)         { return b.r.Read(p) }
func (b *bytesReadCloser) WriteTo(w io.Writer) (int64, error) { return b.r.WriteTo(w) }

// Close recycles the reader. It drops the reference to the cached bytes (so a pooled,
// idle reader never pins an evicted object) and returns itself to the pool. Per the
// io.ReadCloser contract it must be called exactly once and not used afterwards — the
// serve path's single `defer reader.Close()` after the body write satisfies this.
func (b *bytesReadCloser) Close() error {
	b.r.Reset(nil)
	bytesReaderPool.Put(b)
	return nil
}

func (r *RAMTier) Writer(meta ObjectMeta) (TierWriter, error) {
	return &ramWriter{tier: r, meta: meta, buf: getRAMBuf()}, nil
}

// ramPoolMaxObject bounds two things: the largest object that takes the
// pooled-buffer + copy-out commit path (below this, the body is small and hot),
// and the largest buffer capacity worth retaining in the pool. Larger objects
// keep the zero-copy hand-off (the buffer's backing becomes the cached bytes
// directly) and their buffers are never pooled, so the pool only ever holds
// small backings.
const ramPoolMaxObject = 64 << 10 // 64 KiB

// ramBufPool recycles write buffers for the small-object put path, cutting the
// per-put allocation/GC churn under write-heavy load. A buffer is only returned
// to the pool when its body was copied out (Commit small path) or discarded
// (Abort/overflow) — never when its backing was handed to the cache entry.
var ramBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// getRAMBuf returns a reset buffer from the pool.
func getRAMBuf() *bytes.Buffer {
	b := ramBufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

// putRAMBuf returns a buffer to the pool, dropping (letting GC reclaim) any
// buffer whose capacity grew past the small-object bound so the pool never pins
// large backings.
func putRAMBuf(b *bytes.Buffer) {
	if b == nil || b.Cap() > ramPoolMaxObject {
		return
	}
	ramBufPool.Put(b)
}

// reserve tries to charge delta extra bytes to the global in-flight budget. It
// returns false (charging nothing) iff the new total would exceed the budget, so the
// caller must overflow instead of allocating. With inflightBudget <= 0 the global
// bound is disabled and every reservation succeeds. The CAS loop keeps the charge
// correct under concurrent writers (-race): we never overshoot the budget. This is a
// PROCESS-WIDE budget (one atomic on the tier), deliberately not sharded.
func (r *RAMTier) reserve(delta int64) bool {
	if r.inflightBudget <= 0 {
		return true
	}
	for {
		cur := atomic.LoadInt64(&r.inflightBytes)
		if cur+delta > r.inflightBudget {
			return false
		}
		if atomic.CompareAndSwapInt64(&r.inflightBytes, cur, cur+delta) {
			return true
		}
	}
}

// release returns n previously-reserved bytes to the global budget. Must be called
// exactly once per writer for whatever it currently holds (on Commit AND Abort), and
// is a no-op for n == 0, so a never-charged or already-released writer is safe.
func (r *RAMTier) release(n int64) {
	if n > 0 {
		atomic.AddInt64(&r.inflightBytes, -n)
	}
}

// Reset drops every committed object from the RAM tier (clearing each shard's map,
// LRU ring and byte count). It does NOT touch the in-flight reservation budget, which
// belongs to live writers, not committed objects. Used by Store.Reset on the reload
// flush path against a store that is not yet serving; a freshly-opened store's RAM is
// already empty (RAM is never persisted), so this is normally a no-op kept for
// completeness and robustness.
func (r *RAMTier) Reset() {
	for _, s := range r.shards {
		s.mu.Lock()
		s.items = make(map[string]*ramEntry)
		s.lru.Init()
		s.curBytes = 0
		atomic.StoreInt64(&s.atomicBytes, 0)
		s.mu.Unlock()
	}
}

// Delete removes key from its shard if present (no-op otherwise), mirroring the
// replace path in commit. Used for cross-tier dedup by the Store.
func (r *RAMTier) Delete(key string) {
	s := r.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.items[key]
	if !ok {
		return
	}
	s.curBytes -= int64(len(old.data))
	s.lru.Remove(old.el)
	delete(s.items, key)
	atomic.StoreInt64(&s.atomicBytes, s.curBytes)
}

func (r *RAMTier) Len() int {
	n := 0
	for _, s := range r.shards {
		s.mu.Lock()
		n += len(s.items)
		s.mu.Unlock()
	}
	return n
}

// Bytes sums each shard's lock-free atomic byte counter, so it does NOT acquire any
// shard lock and never contends with the hot Get/commit paths.
func (r *RAMTier) Bytes() int64 {
	var n int64
	for _, s := range r.shards {
		n += atomic.LoadInt64(&s.atomicBytes)
	}
	return n
}

func (r *RAMTier) Close() error { return nil }

// commit installs an object into the shard owning its key, evicting that shard's LRU
// entries until it fits within the shard's slice of the budget. It reports whether the
// object was actually installed (false on a shard-cap drop) so the cross-tier dedup can
// tell a real store from a silent discard (R14).
func (r *RAMTier) commit(meta ObjectMeta, data []byte) bool {
	s := r.shard(meta.Key)
	s.mu.Lock()
	defer s.mu.Unlock()

	size := int64(len(data))
	meta.Size = size

	// An object larger than this shard's cap is not cacheable here. This mirrors the
	// pre-sharding "larger than the whole tier" guard: the object streams through
	// uncached and never wedges the shard. (With an N-way split a shard's cap is
	// maxBytes/N, so the effective single-object ceiling is smaller — acceptable for a
	// hot small-object cache; oversized objects belong on disk anyway.)
	if size > s.maxBytes {
		return false
	}

	// Replace existing entry of the same key.
	if old, ok := s.items[meta.Key]; ok {
		s.curBytes -= int64(len(old.data))
		s.lru.Remove(old.el)
		delete(s.items, meta.Key)
	}

	// Evict via CLOCK / second-chance until the new object fits. The ring's back is
	// the oldest insertion; we walk from there toward the front. An entry whose ref
	// bit is set (read since it was last passed) is granted a second chance — its bit
	// is cleared and it is moved to the front (treated as freshly placed) — instead of
	// being reclaimed. An entry with a clear bit is evicted. Termination is guaranteed:
	// commit holds the exclusive Lock, so no concurrent Get can re-set a ref bit during
	// the sweep — after at most one full lap every surviving entry has a clear bit, so
	// the loop always reaches a victim.
	for s.curBytes+size > s.maxBytes {
		back := s.lru.Back()
		if back == nil {
			break
		}
		ek := back.Value.(string)
		ev, ok := s.items[ek]
		if !ok {
			// Stale ring node with no map entry (shouldn't happen): drop it.
			s.lru.Remove(back)
			continue
		}
		if ev.ref.Load() {
			ev.ref.Store(false)      // consume the second chance
			s.lru.MoveToFront(ev.el) // give it another lap before reconsidering
			continue
		}
		s.curBytes -= int64(len(ev.data))
		delete(s.items, ek)
		s.lru.Remove(back)
	}

	el := s.lru.PushFront(meta.Key)
	s.items[meta.Key] = &ramEntry{meta: meta, data: data, el: el}
	s.curBytes += size
	// Mirror the updated count into the atomic so Bytes()/Stats() can read it without
	// taking this shard's lock.
	atomic.StoreInt64(&s.atomicBytes, s.curBytes)
	return true
}

func key(m ObjectMeta) string { return m.Key }

// ramWriter buffers the body in memory; Commit installs it into the tier (into the
// shard owning its key). It is BOUNDED (B2): once buffering would exceed the
// per-object cap OR the global in-flight budget it sets overflow, frees the buffer,
// and discards further writes — the object then streams to the client uncached rather
// than being held in memory. The B2 bounds it consults (tier.maxObjectBytes and the
// process-wide reserve/release budget) live on the TIER, not the shard, so concurrent
// buffering is bounded across the whole process regardless of which shard the object
// will land in. reserved tracks how many budget bytes this writer currently holds so
// it can release exactly that many on Commit/Abort (no double-counting).
type ramWriter struct {
	tier     *RAMTier
	meta     ObjectMeta
	buf      *bytes.Buffer
	reserved int64 // bytes currently charged to the tier's in-flight budget
	overflow bool  // tripped the per-object cap or global budget: no longer caching
	stored   bool  // Commit actually installed the object (false on overflow / shard-cap drop)
}

// Write appends to the in-memory buffer until a bound is hit. On overflow it frees
// the buffer (releasing its global reservation) and from then on silently accepts and
// discards bytes — returning (len(p), nil) so the CLIENT stream is never disturbed by
// the cache giving up. Small objects under both bounds behave exactly as before.
func (w *ramWriter) Write(p []byte) (int, error) {
	if w.overflow {
		return len(p), nil // already gave up caching; swallow to keep the client stream clean
	}
	need := int64(w.buf.Len() + len(p))
	// Per-object cap: a single object larger than maxObjectBytes can never be RAM
	// cached, so stop buffering the moment we know it will exceed the cap.
	if w.tier.maxObjectBytes > 0 && need > w.tier.maxObjectBytes {
		w.dropBuffer()
		return len(p), nil
	}
	// Global in-flight budget: charge only the GROWTH (delta) beyond what we already
	// reserved. If the budget can't absorb it, this writer overflows so concurrent
	// large writes can't collectively exceed the budget (and OOM).
	if delta := need - w.reserved; delta > 0 {
		if !w.tier.reserve(delta) {
			w.dropBuffer()
			return len(p), nil
		}
		w.reserved += delta
	}
	return w.buf.Write(p)
}

// dropBuffer abandons RAM caching for this object: it frees the buffer and returns
// the writer's whole reservation to the global budget. Idempotent via the overflow
// flag (Write stops calling it once set).
func (w *ramWriter) dropBuffer() {
	w.overflow = true
	w.buf = nil
	w.tier.release(w.reserved)
	w.reserved = 0
}

// Commit installs the buffered object, unless the writer overflowed (then it's a
// no-op: the object already streamed to the client uncached). Either way the global
// reservation is released exactly once.
func (w *ramWriter) Commit() error {
	if !w.overflow {
		b := w.buf.Bytes()
		if len(b) <= ramPoolMaxObject {
			// Small object: copy into an exact-size slice the entry owns, then
			// recycle the (small) buffer for the next writer. The entry must not
			// alias the pooled buffer's backing.
			data := make([]byte, len(b))
			copy(data, b)
			w.stored = w.tier.commit(w.meta, data)
			putRAMBuf(w.buf)
		} else {
			// Large object: hand the buffer's backing straight to the entry (zero
			// copy) and do not recycle it — the entry now owns that array.
			w.stored = w.tier.commit(w.meta, b)
		}
	}
	// On overflow w.buf is already nil (dropBuffer), so there is nothing to recycle.
	w.buf = nil
	w.tier.release(w.reserved)
	w.reserved = 0
	return nil
}

// Stored reports whether Commit actually installed the object (false on an overflow —
// per-object cap / global budget / shard-cap drop). See TierWriter.Stored.
func (w *ramWriter) Stored() bool { return w.stored }

// Abort discards the in-progress write and releases the reservation exactly once.
func (w *ramWriter) Abort() error {
	putRAMBuf(w.buf) // recycle the (small) buffer; nil/oversized is dropped
	w.buf = nil
	w.tier.release(w.reserved)
	w.reserved = 0
	return nil
}
