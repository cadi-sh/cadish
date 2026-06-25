package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// oversizeLogInterval rate-limits the per-shard-cap discard log (F6): a workload that
// keeps requesting objects too big for the disk tier would otherwise log on every
// commit. One line per interval is enough to make the misconfiguration observable.
const oversizeLogInterval = 30 * time.Second

// persistInterval bounds how stale the on-disk index can be relative to the
// in-memory state: a background flusher writes the index at most this often when
// dirty. With a graceful shutdown also flushing, the crash window for losing
// index updates (which only ever costs a re-fetch, never serves a stale/missing
// blob — load() re-validates every blob against its recorded size) is bounded by
// this interval.
const persistInterval = 5 * time.Second

// diskShard is one independent lock domain of the disk tier: its own mutex, map, LRU
// list and byte counter, bounded by its own slice of the tier budget. The tier holds
// shardCount(maxBytes) of these and routes each key to exactly one by hash, so reads
// (a hit does an LRU MoveToFront — a WRITE under the lock) and commits on unrelated
// keys do not contend on a single global mutex. curBytes is mirrored into an atomic so
// Bytes()/Stats() can sum across shards without taking every shard lock. dirty is
// per-shard so the flusher can tell whether ANY shard changed without scanning state.
type diskShard struct {
	mu          sync.Mutex
	maxBytes    int64
	curBytes    int64 // guarded by mu
	atomicBytes int64 // lock-free mirror of curBytes for cheap aggregation (atomic)
	items       map[string]*diskEntry
	lru         *list.List // Value = key (string), front = MRU
	dirty       bool       // this shard changed since the last successful index flush
}

// DiskTier is an NVMe-backed, byte-bounded, LRU cache for large media objects.
// Content lives under <dir>/blobs/<sha256(key)>; metadata + LRU order are
// persisted to <dir>/index.json so the cache survives a restart.
//
// SHARDING: the tier is split into shardCount(maxBytes) independent shards, each with
// its own mutex/map/LRU/counter and an equal slice of maxBytes (shardCaps). A key
// always maps to the same shard (shardIndex over the tier's shard count), so the hot
// read path (a cache hit does an LRU MoveToFront, i.e. a WRITE) only contends with
// other keys on the SAME shard instead of one global mutex. Eviction is therefore
// per-shard approximate-LRU (see shardCaps for the accepted consequence). The on-disk
// blob layout is UNCHANGED — sha256(key) filenames — so sharding is invisible on disk;
// only the in-memory index is partitioned.
//
// Index persistence is decoupled from the commit hot path. At ~2 TB/day the disk tier
// sees a high commit rate; marshalling the whole index and renaming it under a lock on
// EVERY commit (the original design) is O(n) work plus lock contention on every cached
// object. Instead, commits/evictions set a per-shard dirty flag and ONE background
// goroutine flushes at most once per persistInterval (debounced), plus a final
// synchronous flush on Close. The index file stays a SINGLE index.json: the flusher
// snapshots every shard (each under its own lock) and merges them into one MRU-first
// list per shard, concatenated. On load() the entries are distributed back to shards by
// hash. (Format note: the persisted file is still a flat list of ObjectMeta — fully
// compatible to READ from a pre-sharding index; entries simply get re-homed to shards
// on load. Within the file, ordering is now MRU-first PER SHARD rather than one global
// order, which only affects approximate-LRU warmth after restart, not correctness.)
type DiskTier struct {
	dir      string
	blobDir  string
	maxBytes int64
	shards   []*diskShard

	persistErrs int64         // atomic; count of background flush failures (observability)
	stop        chan struct{} // closed by Close to stop the flusher
	flusherDone chan struct{} // closed when the flusher goroutine exits
	closeOnce   sync.Once     // makes Close idempotent / race-free

	// oversizeDiscards counts objects refused at commit because they exceed their
	// shard's cap (~DiskMaxBytes/shardCount): they stream through uncached and are
	// cached NOWHERE. Atomic so Stats() reads it lock-free. A growing value means the
	// disk tier is too small for the objects being served — worth alerting on (F6).
	oversizeDiscards int64
	// log is an OPTIONAL observability logger. Nil (the default) keeps the tier
	// silent (the cache package owns no logger); the server attaches one via
	// SetLogger so a per-shard-cap discard is observable. nextOversizeLog rate-limits
	// the discard log so a flood of oversized objects cannot spam the log.
	log             *slog.Logger
	nextOversizeLog atomic.Int64 // unix-nano; next time an oversize discard may log
}

type diskEntry struct {
	meta ObjectMeta
	el   *list.Element
}

// persisted is the on-disk index format. It is a flat list of ObjectMeta. Order is
// MRU-first within each shard, shards concatenated — load() re-homes every entry to its
// shard by hash, so the cross-shard ordering in the file is irrelevant on read.
type persisted struct {
	Entries []ObjectMeta `json:"entries"`
}

// NewDiskTier opens (or creates) a disk tier rooted at dir, bounded to maxBytes.
// It loads any previously persisted index, dropping entries whose blob is missing.
func NewDiskTier(dir string, maxBytes int64) (*DiskTier, error) {
	blobDir := filepath.Join(dir, "blobs")
	// 0o700: the cache dir is private to the cadish process. A world-listable dir is
	// a cache-presence oracle — a blob filename is sha256(known-URL), so a local user
	// could probe which (often tokenized/private) URLs are cached (security review
	// #11). Blob contents are already 0600 via os.CreateTemp.
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return nil, hintPermission(dir, err)
	}
	n := shardCount(maxBytes)
	caps := shardCaps(maxBytes, n)
	d := &DiskTier{
		dir:         dir,
		blobDir:     blobDir,
		maxBytes:    maxBytes,
		shards:      make([]*diskShard, n),
		stop:        make(chan struct{}),
		flusherDone: make(chan struct{}),
	}
	for i := range d.shards {
		d.shards[i] = &diskShard{
			maxBytes: caps[i],
			items:    make(map[string]*diskEntry),
			lru:      list.New(),
		}
	}
	if err := d.load(); err != nil {
		return nil, err
	}
	go d.flushLoop()
	return d, nil
}

// shard returns the shard owning key.
func (d *DiskTier) shard(key string) *diskShard {
	return d.shards[shardIndex(key, len(d.shards))]
}

// flushLoop persists the index periodically when any shard is dirty, decoupling index
// I/O from the commit hot path. It exits when stop is closed.
func (d *DiskTier) flushLoop() {
	defer close(d.flusherDone)
	t := time.NewTicker(persistInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-t.C:
			d.flushIfDirty()
		}
	}
}

// flushIfDirty writes the index iff some shard changed since the last flush. It
// snapshots every shard under that shard's lock (clearing its dirty flag), then does
// the (slower) marshal + file write OUTSIDE all locks so commits/gets are not blocked
// on disk I/O. If any shard was dirty, it writes; on write failure it re-arms all
// shards' dirty flags so the next tick retries.
func (d *DiskTier) flushIfDirty() {
	p, anyDirty := d.snapshotIfDirty()
	if !anyDirty {
		return
	}
	if err := d.writeIndex(p); err != nil {
		// Re-arm the dirty flags so the next tick retries, and record the failure.
		for _, s := range d.shards {
			s.mu.Lock()
			s.dirty = true
			s.mu.Unlock()
		}
		atomic.AddInt64(&d.persistErrs, 1)
	}
}

// snapshotIfDirty builds the persistable index from every shard and reports whether
// any shard was dirty (clearing the dirty flags it observed). It always snapshots the
// WHOLE index — even clean shards — because the index file is a single merged file, so
// a flush triggered by one dirty shard must still capture all shards' current state.
func (d *DiskTier) snapshotIfDirty() (persisted, bool) {
	p := persisted{}
	anyDirty := false
	for _, s := range d.shards {
		s.mu.Lock()
		if s.dirty {
			anyDirty = true
			s.dirty = false
		}
		for el := s.lru.Front(); el != nil; el = el.Next() {
			k := el.Value.(string)
			if e, ok := s.items[k]; ok {
				p.Entries = append(p.Entries, e.meta)
			}
		}
		s.mu.Unlock()
	}
	return p, anyDirty
}

func (d *DiskTier) blobPath(k string) string {
	sum := sha256.Sum256([]byte(k))
	return filepath.Join(d.blobDir, hex.EncodeToString(sum[:]))
}

func (d *DiskTier) indexPath() string { return filepath.Join(d.dir, "index.json") }

// load reads the persisted index and distributes entries to their shards by hash.
// Within a shard, entries are pushed in reverse so the first entry (for that shard) in
// the file ends up at the front (MRU) of the shard's list. A blob that is missing or
// size-mismatched is dropped (and its stray file removed). The file's flat list may
// come from a pre-sharding index or a different shard count — either way each entry is
// re-homed by hash here, so restart is correct regardless of the previous layout.
func (d *DiskTier) load() error {
	b, err := os.ReadFile(d.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		// Corrupt index: start fresh rather than fail to boot.
		return nil
	}
	for i := len(p.Entries) - 1; i >= 0; i-- {
		m := p.Entries[i]
		bp := d.blobPath(m.Key)
		fi, err := os.Stat(bp)
		if err != nil || fi.Size() != m.Size {
			_ = os.Remove(bp) // stale/partial blob
			continue
		}
		s := d.shard(m.Key)
		// Skip an entry that no longer fits its shard's cap (e.g. the tier was
		// reopened smaller, or the shard split changed): drop the blob so we never
		// exceed the per-shard budget on load.
		if m.Size > s.maxBytes {
			_ = os.Remove(bp)
			continue
		}
		el := s.lru.PushFront(m.Key)
		s.items[m.Key] = &diskEntry{meta: m, el: el}
		s.curBytes += m.Size
		atomic.StoreInt64(&s.atomicBytes, s.curBytes)
	}
	return nil
}

// writeIndex marshals and writes the index atomically (temp file + rename). Safe
// to call without any shard lock held since it operates only on its argument.
func (d *DiskTier) writeIndex(p persisted) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := d.indexPath() + ".tmp"
	// 0o600: index.json lists every cached object's full URL/path + metadata, often
	// private or tokenized. Keep it readable only by the cadish process (security
	// review #10).
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.indexPath())
}

func (d *DiskTier) Get(key string) (*Reader, bool) {
	s := d.shard(key)
	// Open the blob WHILE HOLDING the shard lock — atomically with reading e.meta. commit()
	// does its remove+rename of a same-key blob under this same lock, so opening here cannot
	// interleave with a swap: without the lock a Get racing a same-key recommit could open the
	// NEW blob while carrying the OLD meta (Content-Length lie / corrupt body) or open in the
	// remove→rename gap and then spuriously evict the freshly committed entry. On Unix the
	// returned FD pins the inode, so a later rename/unlink does not disturb this reader. Only an
	// open syscall runs under the lock (no body bytes are read here), matching the existing
	// MoveToFront cost. (TOCTOU fix.)
	s.mu.Lock()
	e, ok := s.items[key]
	if !ok {
		s.mu.Unlock()
		return nil, false
	}
	s.lru.MoveToFront(e.el)
	f, err := os.Open(d.blobPath(key))
	if err != nil {
		// Blob vanished underneath us; drop the entry.
		d.removeLocked(s, key)
		s.mu.Unlock()
		return nil, false
	}
	meta := e.meta
	s.mu.Unlock()
	return &Reader{Meta: meta, ReadCloser: f}, true
}

func (d *DiskTier) Writer(meta ObjectMeta) (TierWriter, error) {
	tmp, err := os.CreateTemp(d.blobDir, "wip-*")
	if err != nil {
		return nil, err
	}
	return &diskWriter{tier: d, meta: meta, tmp: tmp}, nil
}

func (d *DiskTier) Len() int {
	n := 0
	for _, s := range d.shards {
		s.mu.Lock()
		n += len(s.items)
		s.mu.Unlock()
	}
	return n
}

// Bytes sums each shard's lock-free atomic byte counter, so it does NOT acquire any
// shard lock and never contends with the hot Get/commit paths.
func (d *DiskTier) Bytes() int64 {
	var n int64
	for _, s := range d.shards {
		n += atomic.LoadInt64(&s.atomicBytes)
	}
	return n
}

// PersistErrors returns how many background index flushes have failed. A nonzero
// and growing value means the disk index is going stale (the cache still serves
// correctly, but more would be lost on a crash) — worth alerting on.
func (d *DiskTier) PersistErrors() int64 {
	return atomic.LoadInt64(&d.persistErrs)
}

// OversizeDiscards returns how many objects were refused at commit for exceeding
// their shard's cap (and thus cached nowhere, streamed through uncached). A nonzero
// and growing value means the disk tier is too small for the objects being served —
// raise DiskMaxBytes or route those objects elsewhere (F6 observability).
func (d *DiskTier) OversizeDiscards() int64 {
	return atomic.LoadInt64(&d.oversizeDiscards)
}

// SetLogger attaches an optional observability logger. Nil keeps the tier silent
// (the default). Used by the server to surface the per-shard-cap oversize discard
// (F6) without making the cache package own a logger. Safe to call once at setup,
// before the tier sees concurrent traffic.
func (d *DiskTier) SetLogger(log *slog.Logger) { d.log = log }

// logOversizeDiscard emits a rate-limited info log for an object refused because it
// exceeds its shard's cap. Nil-logger safe (the common path: no logger attached).
// The rate limit (oversizeLogInterval) is enforced with a single CAS on a unix-nano
// deadline so a flood of oversized objects logs at most once per interval.
func (d *DiskTier) logOversizeDiscard(key string, size, shardCap int64) {
	if d.log == nil {
		return
	}
	now := time.Now().UnixNano()
	next := d.nextOversizeLog.Load()
	if now < next {
		return
	}
	if !d.nextOversizeLog.CompareAndSwap(next, now+oversizeLogInterval.Nanoseconds()) {
		return // another goroutine just logged; skip to keep it rate-limited
	}
	d.log.Info("disk cache: object exceeds per-shard cap, not cached (streamed through uncached)",
		"key", key, "size", size, "shard_cap", shardCap, "tier_max", d.maxBytes,
		"total_oversize_discards", atomic.LoadInt64(&d.oversizeDiscards),
		"hint", "raise the disk tier budget (cache { disk … SIZE }) or route large objects elsewhere")
}

// Close stops the background flusher and writes the index one last time so a
// graceful shutdown loses nothing. Safe to call multiple times. The stop/done
// channels are never reassigned, so the flusher's reads of them never race.
func (d *DiskTier) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.stop)   // signal flusher to exit
		<-d.flusherDone // wait for it so no background flush races the final one
		// Snapshot the full index (every shard) and write it once. We ignore the
		// per-shard dirty flags here: a graceful shutdown always persists the complete
		// current state.
		p, _ := d.snapshotIfDirty()
		err = d.writeIndex(p)
	})
	return err
}

// removeLocked deletes an entry and its blob and marks the shard dirty. Caller holds
// s.mu (the shard owning k).
func (d *DiskTier) removeLocked(s *diskShard, k string) {
	e, ok := s.items[k]
	if !ok {
		return
	}
	s.curBytes -= e.meta.Size
	atomic.StoreInt64(&s.atomicBytes, s.curBytes)
	s.lru.Remove(e.el)
	delete(s.items, k)
	s.dirty = true
	_ = os.Remove(d.blobPath(k))
}

// commit moves a finished temp blob into place, evicting the owning shard's LRU
// entries to fit within that shard's slice of the budget.
func (d *DiskTier) commit(meta ObjectMeta, tmpPath string, n int64) error {
	meta.Size = n
	s := d.shard(meta.Key)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Too big for this shard's cap: discard. Mirrors the pre-sharding "too big for the
	// tier" guard — the object streams through uncached and never wedges the shard.
	// Make it OBSERVABLE (F6): count every discard and emit a rate-limited log so an
	// operator can tell a large object is being served uncached because the disk tier
	// (per-shard cap ~DiskMaxBytes/shardCount) is too small for it — previously a
	// silent `return nil`.
	if n > s.maxBytes {
		_ = os.Remove(tmpPath)
		atomic.AddInt64(&d.oversizeDiscards, 1)
		d.logOversizeDiscard(meta.Key, n, s.maxBytes)
		return nil
	}

	// Replace any existing entry for the key.
	if _, ok := s.items[meta.Key]; ok {
		d.removeLocked(s, meta.Key)
	}

	// Evict this shard's LRU until the new object fits.
	for s.curBytes+n > s.maxBytes {
		back := s.lru.Back()
		if back == nil {
			break
		}
		d.removeLocked(s, back.Value.(string))
	}

	if err := os.Rename(tmpPath, d.blobPath(meta.Key)); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	el := s.lru.PushFront(meta.Key)
	s.items[meta.Key] = &diskEntry{meta: meta, el: el}
	s.curBytes += n
	atomic.StoreInt64(&s.atomicBytes, s.curBytes)
	// Mark this shard dirty; the background flusher persists the merged index off the
	// hot path. A crash before the next flush at most costs a re-fetch of this object.
	s.dirty = true
	return nil
}

// diskWriter streams the body to a temp file; Commit renames it into the tier.
type diskWriter struct {
	tier *DiskTier
	meta ObjectMeta
	tmp  *os.File
	n    int64
}

func (w *diskWriter) Write(p []byte) (int, error) {
	n, err := w.tmp.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *diskWriter) Commit() error {
	name := w.tmp.Name()
	if err := w.tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return w.tier.commit(w.meta, name, w.n)
}

func (w *diskWriter) Abort() error {
	name := w.tmp.Name()
	_ = w.tmp.Close()
	return os.Remove(name)
}
