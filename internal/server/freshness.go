package server

import (
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// freshness is the server-side TTL/grace/hit-for-miss index that the cache.Store
// itself does not carry: cache.ObjectMeta records only Key/Size/ContentType/ETag/
// LastModified, with no notion of expiry. The pipeline decides TTL, grace and
// hit-for-miss per response (EvalResponse); this index remembers those decisions so
// LOOKUP can classify a key as fresh / stale-in-grace / expired, and so a
// hit-for-miss decision suppresses caching for a short window.
//
// It is a sharded map keyed by cache key. Entries are pruned lazily on access (an
// entry whose grace window has fully elapsed is dropped) AND proactively by a
// background reclamation sweeper (sweepLoop) so entries for byte-budget-evicted
// blobs under distinct-key traffic don't accumulate unboundedly. The whole index is
// memory-only, so it is rebuilt naturally as traffic flows. A process restart loses
// it: a disk-persisted object with no freshness entry is treated as expired and
// revalidated on first access (safe — never a stale hit, only a re-fetch).
type freshness struct {
	now    func() time.Time
	shards [freshnessShards]freshnessShard

	// stop terminates the background reclamation sweeper; closed once by Close.
	stop     chan struct{}
	stopOnce sync.Once

	// bans is the cache-wide BAN list (backlog #22 — Varnish ban-lurker parity). An
	// authorized `purge … regex EXPR` appends a (compiled regex, issuedAt) entry; on
	// LOOKUP an entry whose key matches any ban issued AFTER the object was stored is
	// treated as a MISS, so a regex purge invalidates every matching key lazily (no
	// store scan on the purge request). banCount mirrors len(bans.list) as an atomic
	// so the lookup fast path is a single lock-free load when no ban is active — zero
	// datapath cost in the common (no-ban) case.
	bans     banList
	banCount atomic.Int64
	// maxGrace tracks the largest TTL+grace window ever recorded by store, so a ban
	// older than that window can never predate a live object and is pruned. Updated
	// under bans.mu when a ban is added.
	maxGrace atomic.Int64 // nanoseconds
}

// banList is the BAN registry: a slice of compiled patterns with the instant each
// was issued, guarded by its own RWMutex (read on every banned-key lookup, written
// only on a purge). Bans are bounded (maxBans, oldest-dropped) and pruned of entries
// too old to predate any live object.
type banList struct {
	mu   sync.RWMutex
	list []banEntry
}

type banEntry struct {
	re       *regexp.Regexp
	issuedAt time.Time
}

// maxBans caps the BAN list so a flood of purges cannot grow it without bound. When
// full, the oldest ban is dropped (it has been superseded by re-fetches for long
// enough that any object it could have invalidated has either been re-fetched or
// expired). A pruning pass on each add also drops bans older than maxGrace.
const maxBans = 256

const freshnessShards = 64

type freshnessShard struct {
	// mu is an RWMutex so the hot HIT classification (classify) can take the SHARED
	// read lock: a fresh, repeatedly-hit key needs no mutation, so concurrent hits to
	// one hot key no longer serialize. Only the rare expiry/ban/HFM-expiry transition
	// upgrades to the exclusive Lock (classifyPrune) to delete the entry.
	mu      sync.RWMutex
	entries map[string]freshEntry
}

type freshEntry struct {
	// storedAt is when the object was recorded (store / setHitForMiss). A BAN issued
	// AFTER this instant invalidates the entry; a ban issued before it (or an object
	// stored after the ban) does not — so a re-fetch is immune to an older ban.
	storedAt time.Time
	// expires is when the object stops being fresh (storedAt + TTL).
	expires time.Time
	// graceUntil is when the object stops being servable-while-stale
	// (expires + grace). Equal to expires when no grace.
	graceUntil time.Time
	// maxStaleUntil (D60) is when the object stops being servable even as an
	// origin-failure fallback (graceUntil + max_stale). Zero when max_stale is unset
	// — the entry then behaves exactly as today (no error-fallback window), and
	// pruning falls back to graceUntil. It does NOT change classify/lookup on the hot
	// path: a max_stale-window entry still classifies as stateMiss to a HEALTHY
	// request. It only (a) defers pruning so the marker survives the window, and (b)
	// is consulted by staleWithin on the origin-error path.
	maxStaleUntil time.Time
	// hfmUntil, when non-zero, marks a hit-for-miss window: until this instant the
	// key is intentionally NOT cached and every request goes to origin (no store).
	hfmUntil time.Time
}

// state classifies a cached key at instant now.
type freshState int

const (
	// stateMiss: no usable cache entry (expired past grace, or none recorded).
	stateMiss freshState = iota
	// stateFresh: within TTL — serve from cache.
	stateFresh
	// stateStale: past TTL but within grace — serve stale + background revalidate.
	stateStale
)

// freshnessSweepInterval is how often the background reclamation sweeper walks the
// shards to evict entries whose grace/max-stale window has fully elapsed. Cache
// blobs evict by byte budget independently, so without this sweep a freshness entry
// for an evicted blob lingers until the SAME key is re-classified — under
// distinct-key traffic (e.g. ?cachebust=N) those entries accumulate unboundedly
// (slow OOM). 1 minute is frequent enough to bound memory yet cheap (one RLock-free
// length check per shard skips empty shards).
const freshnessSweepInterval = time.Minute

func newFreshness(now func() time.Time) *freshness {
	if now == nil {
		now = time.Now
	}
	f := &freshness{now: now, stop: make(chan struct{})}
	for i := range f.shards {
		f.shards[i].entries = make(map[string]freshEntry)
	}
	go f.sweepLoop(freshnessSweepInterval)
	return f
}

// sweepLoop runs the background reclamation sweep on a ticker until Close. The
// ticker is wall-clock; each sweep evaluates prunability against f.now() so a test
// clock still governs WHAT is reclaimed.
func (f *freshness) sweepLoop(interval time.Duration) {
	if interval <= 0 {
		interval = freshnessSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-f.stop:
			return
		case <-t.C:
			f.sweep()
		}
	}
}

// sweep walks every shard and deletes each entry that can no longer produce any hit
// (fresh, stale-in-grace, max-stale fallback, or active hit-for-miss) at f.now() —
// i.e. an entry whose full retention window has elapsed. It mirrors the lazy
// pruning in lookup/classify but does it proactively so entries for byte-budget-
// evicted blobs under distinct-key traffic don't accumulate. Each shard is locked
// independently and skipped entirely when empty, so an idle index pays almost
// nothing; a banned entry is also reclaimable (its next lookup would MISS anyway).
func (f *freshness) sweep() {
	now := f.now()
	for i := range f.shards {
		sh := &f.shards[i]
		// Cheap pre-check under the shared lock: skip empty shards without taking the
		// write lock (the common case for a sparsely-populated index).
		sh.mu.RLock()
		empty := len(sh.entries) == 0
		sh.mu.RUnlock()
		if empty {
			continue
		}
		sh.mu.Lock()
		for k, e := range sh.entries {
			if f.entryReclaimable(k, e, now) {
				delete(sh.entries, k)
			}
		}
		sh.mu.Unlock()
	}
}

// entryReclaimable reports whether e can be dropped at now: it can never again
// produce a fresh/stale/max-stale hit or an active hit-for-miss bypass. A
// hit-for-miss marker is reclaimable once its window has passed; a positive entry is
// reclaimable once past grace AND (when set) past max_stale; a banned entry is
// reclaimable (its lookup MISSes regardless).
func (f *freshness) entryReclaimable(key string, e freshEntry, now time.Time) bool {
	if f.banned(key, e.storedAt) {
		return true
	}
	if !e.hfmUntil.IsZero() {
		return !now.Before(e.hfmUntil) // expired HFM marker
	}
	if now.Before(e.graceUntil) {
		return false // still fresh or stale-in-grace
	}
	return prunable(e, now) // past grace: reclaimable only once past max_stale too
}

// Close stops the background reclamation sweeper. Idempotent.
func (f *freshness) Close() {
	f.stopOnce.Do(func() { close(f.stop) })
}

func (f *freshness) shard(key string) *freshnessShard {
	return &f.shards[fnv32(key)%freshnessShards]
}

// store records a positive cache decision for key: fresh for ttl, then servable
// stale for an additional grace window, then (D60) servable as an origin-failure
// fallback for a further maxStale window. Clears any hit-for-miss marker.
//
// maxStaleUntil is set to storedAt + ttl + grace + maxStale, or left zero when
// maxStale == 0 (the entry then prunes at graceUntil exactly as before). The
// observed window accounts for the LONGEST retention (incl. maxStale) so the
// ban-lurker prune math still bounds correctly.
func (f *freshness) store(key string, ttl, grace, maxStale time.Duration) {
	now := f.now()
	e := freshEntry{
		storedAt:   now,
		expires:    now.Add(ttl),
		graceUntil: now.Add(ttl + grace),
	}
	if maxStale > 0 {
		e.maxStaleUntil = now.Add(ttl + grace + maxStale)
	}
	sh := f.shard(key)
	sh.mu.Lock()
	sh.entries[key] = e
	sh.mu.Unlock()
	f.observeWindow(ttl + grace + maxStale)
}

// observeWindow widens maxGrace if w exceeds it. maxGrace bounds how long a ban can
// still predate a live object: an object is pruned once past its grace window, so a
// ban older than the largest grace window seen can no longer invalidate anything.
func (f *freshness) observeWindow(w time.Duration) {
	for {
		cur := f.maxGrace.Load()
		if int64(w) <= cur {
			return
		}
		if f.maxGrace.CompareAndSwap(cur, int64(w)) {
			return
		}
	}
}

// setHitForMiss records a "do not cache this key" decision for the given window.
func (f *freshness) setHitForMiss(key string, d time.Duration) {
	now := f.now()
	sh := f.shard(key)
	sh.mu.Lock()
	sh.entries[key] = freshEntry{storedAt: now, hfmUntil: now.Add(d)}
	sh.mu.Unlock()
	f.observeWindow(d)
}

// hitForMiss reports whether key is currently within a hit-for-miss window (and so
// must bypass the cache entirely).
func (f *freshness) hitForMiss(key string) bool {
	now := f.now()
	sh := f.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.entries[key]
	if !ok {
		return false
	}
	if !e.hfmUntil.IsZero() {
		if now.Before(e.hfmUntil) {
			// A BAN issued after this marker invalidates it: drop the marker so the
			// key revalidates (and re-stores) instead of bypassing the cache forever.
			if f.banned(key, e.storedAt) {
				delete(sh.entries, key)
				return false
			}
			return true
		}
		delete(sh.entries, key) // expired HFM marker
	}
	return false
}

// classify is the combined hot-path lookup: it returns BOTH the hit-for-miss bypass
// flag and the fresh/stale/miss classification in a SINGLE shard-lock acquisition,
// replacing the back-to-back hitForMiss(key)+lookup(key) pair (two exclusive locks)
// the serve path used to take per HIT. The common cases — no entry, an active HFM
// window, or a fresh/stale entry — are served entirely under the SHARED RLock with no
// mutation, so concurrent hits to a single hot key run in parallel. Only the cases that
// must DELETE an entry (a banned entry, an expired HFM marker, or a fully-expired
// object) fall through to classifyPrune, which takes the exclusive Lock and re-checks
// before deleting. The (freshState, hitForMiss) result is exactly equivalent to the old
// pair: hitForMiss==true ⇒ bypass; otherwise act on the freshState.
func (f *freshness) classify(key string) (freshState, bool) {
	now := f.now()
	sh := f.shard(key)
	sh.mu.RLock()
	e, ok := sh.entries[key]
	if !ok {
		sh.mu.RUnlock()
		return stateMiss, false
	}
	if !e.hfmUntil.IsZero() {
		// Active, un-banned HFM marker: bypass the cache (no mutation needed).
		if now.Before(e.hfmUntil) && !f.banned(key, e.storedAt) {
			sh.mu.RUnlock()
			return stateMiss, true
		}
		// Banned or expired HFM marker: must drop it — take the write path.
		sh.mu.RUnlock()
		return f.classifyPrune(key)
	}
	if !f.banned(key, e.storedAt) {
		switch {
		case now.Before(e.expires):
			sh.mu.RUnlock()
			return stateFresh, false
		case now.Before(e.graceUntil):
			sh.mu.RUnlock()
			return stateStale, false
		}
	}
	// Banned, or fully expired past grace: must delete — take the write path.
	sh.mu.RUnlock()
	return f.classifyPrune(key)
}

// classifyPrune is classify's slow path for the cases that delete an entry. It takes
// the exclusive Lock and RE-EVALUATES from scratch (the entry may have been re-stored
// between classify's RUnlock and this Lock), mirroring the exact semantics of the old
// hitForMiss+lookup pair, and prunes the entry when its state warrants it.
func (f *freshness) classifyPrune(key string) (freshState, bool) {
	now := f.now()
	sh := f.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.entries[key]
	if !ok {
		return stateMiss, false
	}
	if !e.hfmUntil.IsZero() {
		if now.Before(e.hfmUntil) {
			if f.banned(key, e.storedAt) {
				delete(sh.entries, key) // ban supersedes the HFM marker: revalidate
				return stateMiss, false
			}
			return stateMiss, true // still within the HFM window
		}
		delete(sh.entries, key) // expired HFM marker
		return stateMiss, false
	}
	if f.banned(key, e.storedAt) {
		delete(sh.entries, key)
		return stateMiss, false
	}
	switch {
	case now.Before(e.expires):
		return stateFresh, false
	case now.Before(e.graceUntil):
		return stateStale, false
	case prunable(e, now):
		delete(sh.entries, key) // fully expired (past max_stale too): drop it
		return stateMiss, false
	default:
		// Past grace but still within the max_stale window: this is a stateMiss to a
		// HEALTHY request (go to origin normally), but the marker must SURVIVE so the
		// origin-error path (staleWithin) can find it. Do NOT delete.
		return stateMiss, false
	}
}

// prunable reports whether an entry is past its full retention window and may be
// deleted. With max_stale set (non-zero maxStaleUntil) retention extends to
// maxStaleUntil so the marker survives the error-fallback window; otherwise the rule
// is today's graceUntil. Callers have already established now >= graceUntil.
func prunable(e freshEntry, now time.Time) bool {
	if !e.maxStaleUntil.IsZero() {
		return !now.Before(e.maxStaleUntil)
	}
	return true // no max_stale: past grace is fully expired
}

// lookup classifies key. It prunes an entry that has fully expired past grace (and,
// when max_stale is set, past its max_stale window — the marker survives the
// max_stale window so the origin-error path can serve it).
func (f *freshness) lookup(key string) freshState {
	now := f.now()
	sh := f.shard(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.entries[key]
	if !ok {
		return stateMiss
	}
	if !e.hfmUntil.IsZero() {
		return stateMiss // hit-for-miss: not a cacheable entry
	}
	// Cache-wide BAN (backlog #22): an entry matched by a ban issued after it was
	// stored is invalidated — drop the marker and report MISS so the object is
	// re-fetched. The fast path in banned() is a single atomic load when no ban is
	// active, so a no-ban cache pays nothing here.
	if f.banned(key, e.storedAt) {
		delete(sh.entries, key)
		return stateMiss
	}
	switch {
	case now.Before(e.expires):
		return stateFresh
	case now.Before(e.graceUntil):
		return stateStale
	case prunable(e, now):
		delete(sh.entries, key) // fully expired (past max_stale too): drop it
		return stateMiss
	default:
		// Past grace but within max_stale: stateMiss to a healthy request, but keep
		// the marker so staleWithin can serve it on an origin failure.
		return stateMiss
	}
}

// staleWithin (D60) reports whether key has a stored entry still inside its
// max_stale window at now (graceUntil <= now < maxStaleUntil), i.e. the object is
// past normal serveability but may be served as an origin-failure fallback. It is
// consulted ONLY on the origin-error path (handleOriginError), never on the hot
// path. It is read-only: it takes the SHARED RLock and does NOT prune (the error
// path may want to serve the object; pruning happens on the next normal classify),
// and it does NOT refresh the marker (serving from max_stale must not re-arm grace,
// which would mask a persistently-down origin).
//
// Returns false when max_stale is unset (zero maxStaleUntil) — a single field
// compare, so a site that never opts in pays nothing. Honors bans (a banned entry
// is not a fallback) and a missing entry (restart-safety: no entry => never a
// max_stale hit, the object revalidates instead).
func (f *freshness) staleWithin(key string) bool {
	now := f.now()
	sh := f.shard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	e, ok := sh.entries[key]
	if !ok || e.maxStaleUntil.IsZero() {
		return false
	}
	if !e.hfmUntil.IsZero() {
		return false // a hit-for-miss marker is never a stored object to serve
	}
	if f.banned(key, e.storedAt) {
		return false
	}
	return !now.Before(e.graceUntil) && now.Before(e.maxStaleUntil)
}

// banned reports whether key is invalidated by any active BAN issued after storedAt.
// The hot path is a single atomic load: with no bans registered it returns false
// without taking the ban lock or touching the regex list (zero datapath cost when no
// ban is active). With bans present it takes a read lock and tests each ban whose
// issuedAt post-dates the object — first match wins.
func (f *freshness) banned(key string, storedAt time.Time) bool {
	if f.banCount.Load() == 0 {
		return false
	}
	f.bans.mu.RLock()
	defer f.bans.mu.RUnlock()
	for i := range f.bans.list {
		b := &f.bans.list[i]
		if b.issuedAt.After(storedAt) && b.re.MatchString(key) {
			return true
		}
	}
	return false
}

// ban registers a cache-wide BAN: every cached key matching re that was stored
// before now is invalidated lazily on its next lookup. re must be non-nil and is
// trusted to already be bounded (an operator literal, or a request-sourced pattern
// vetted by pipeline.boundRequestPurgeRegex before it reaches here). The list is
// capped (maxBans, oldest dropped) and pruned of bans too old to predate any live
// object (older than maxGrace), keeping memory bounded under a purge flood.
//
// It returns matched: the number of currently-tracked live freshness entries the
// ban invalidates (objects stored before now whose key matches re). Bans are
// applied lazily on lookup so this is a best-effort count of the in-memory
// freshness index at ban time — not a guarantee of every blob on disk — but a
// matched==0 result tells an operator the pattern matched NOTHING indexed, so
// they do not get false confidence from a 200 on a no-op ban (gap G1).
func (f *freshness) ban(re *regexp.Regexp) (matched int) {
	if re == nil {
		return 0
	}
	now := f.now()
	// Count live entries the ban will invalidate before recording it. Cheap
	// relative to the purge itself (one regex test per tracked key) and only on
	// the rare purge path, never the hot HIT path.
	for i := range f.shards {
		sh := &f.shards[i]
		sh.mu.RLock()
		for key, e := range sh.entries {
			if e.storedAt.Before(now) && re.MatchString(key) {
				matched++
			}
		}
		sh.mu.RUnlock()
	}
	f.bans.mu.Lock()
	// Prune bans that can no longer invalidate anything: an object is dropped once
	// past its grace window, so a ban older than the largest grace window seen has no
	// live object left to predate. Keep a small cushion (2x) to be conservative.
	cutoff := now.Add(-2 * time.Duration(f.maxGrace.Load()))
	kept := f.bans.list[:0]
	for _, b := range f.bans.list {
		if b.issuedAt.After(cutoff) {
			kept = append(kept, b)
		}
	}
	f.bans.list = kept
	// Cap: drop the oldest if still at the limit after pruning.
	if len(f.bans.list) >= maxBans {
		f.bans.list = f.bans.list[len(f.bans.list)-maxBans+1:]
	}
	f.bans.list = append(f.bans.list, banEntry{re: re, issuedAt: now})
	f.banCount.Store(int64(len(f.bans.list)))
	f.bans.mu.Unlock()
	return matched
}

// storedAt returns the instant key's object was recorded, for the Age header
// (RFC 9111 §5.1). It takes the SHARED RLock and does not mutate, so it adds no
// contention to the hot HIT path. Returns (zero, false) when there is no entry or
// the entry is a hit-for-miss marker (not a stored object).
func (f *freshness) storedAt(key string) (time.Time, bool) {
	sh := f.shard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	e, ok := sh.entries[key]
	if !ok || !e.hfmUntil.IsZero() {
		return time.Time{}, false
	}
	return e.storedAt, true
}

// forget drops any entry for key (used by purge).
func (f *freshness) forget(key string) {
	sh := f.shard(key)
	sh.mu.Lock()
	delete(sh.entries, key)
	sh.mu.Unlock()
}

// len reports the total live entry count across all shards (tests / introspection).
func (f *freshness) len() int {
	n := 0
	for i := range f.shards {
		sh := &f.shards[i]
		sh.mu.RLock()
		n += len(sh.entries)
		sh.mu.RUnlock()
	}
	return n
}

// fnv32 is FNV-1a over key, matching the cache's shard hashing style.
func fnv32(key string) uint32 {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	h := uint32(offset)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= prime
	}
	return h
}
