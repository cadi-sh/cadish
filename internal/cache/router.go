package cache

import (
	"log/slog"
	"path"
	"strings"
)

// RouterConfig controls how objects are routed between the RAM and disk tiers.
type RouterConfig struct {
	// RAMMaxBytes bounds the in-memory tier (small hot objects).
	RAMMaxBytes int64
	// DiskMaxBytes bounds the NVMe tier (large media).
	DiskMaxBytes int64
	// DiskDir is the directory backing the disk tier.
	DiskDir string
	// SmallObjectThreshold: objects whose size is known and <= this go to RAM
	// (in addition to always-RAM extensions). Larger objects go to disk.
	SmallObjectThreshold int64
	// RAMMaxObjectBytes is the PER-OBJECT cap on the RAM tier (B2). A ram-extension
	// (.m3u8/.jpg/…) whose size is KNOWN and exceeds this is routed to DISK by
	// pickTier instead of RAM; an unknown-size ram-extension still starts in RAM but
	// is bounded by the ramWriter, which overflows (streams through, drops the cache)
	// once buffering would exceed this cap. This stops a single huge object from
	// OOM-killing the box by being buffered whole before the old commit-time size
	// check. Resolved to a sane default (<= RAMMaxBytes) in NewStore when zero.
	RAMMaxObjectBytes int64
	// RAMInflightBudget bounds the TOTAL bytes all active ramWriters may buffer at
	// once (B2). Each ramWriter charges this process-wide atomic budget as its buffer
	// grows and releases on Commit/Abort; a charge that would exceed the budget makes
	// that writer overflow (stream-through, no cache) instead of allocating. This caps
	// concurrent RAM buffering so N simultaneous large writes cannot collectively OOM,
	// even though each one is individually under RAMMaxObjectBytes. Resolved to a sane
	// default (RAMMaxBytes) in NewStore when zero.
	RAMInflightBudget int64
	// TierExtensions is the per-extension default placement from
	// `cache { tier .ext… -> ram|disk }`: a lower-cased extension (".mp4") maps to
	// "ram"/"disk". It is a DEFAULT — a per-request `storage … -> tier` rule
	// (ObjectMeta.Tier) overrides it. nil/empty means "use the built-in size
	// policy". Honored with the same safety fallbacks as an explicit override.
	TierExtensions map[string]string
}

// defaultRAMMaxObjectBytes is the fallback per-object RAM cap when RAMMaxObjectBytes
// is left zero: 64 MiB comfortably holds playlists/images while bounding a single
// object's buffer far below the whole tier.
const defaultRAMMaxObjectBytes int64 = 64 << 20 // 64 MiB

// DefaultRouterConfig returns sensible defaults for a 64 GB RAM / 400 GB NVMe box
// (the b3-64 the fleet runs on): ~44 GB RAM tier, ~350 GB disk tier, 2 MB
// small-object threshold.
func DefaultRouterConfig(diskDir string) RouterConfig {
	return RouterConfig{
		RAMMaxBytes:          44 << 30,  // 44 GiB
		DiskMaxBytes:         350 << 30, // 350 GiB
		DiskDir:              diskDir,
		SmallObjectThreshold: 2 << 20,                  // 2 MiB
		RAMMaxObjectBytes:    defaultRAMMaxObjectBytes, // 64 MiB per-object RAM cap (B2)
		RAMInflightBudget:    44 << 30,                 // total concurrent RAM buffering = tier size (B2)
	}
}

// ramExtensions are always placed in the RAM tier regardless of size: tiny,
// extremely hot objects (HLS playlists and images).
var ramExtensions = map[string]bool{
	".m3u8": true,
	".jpg":  true,
	".jpeg": true,
	".webp": true,
	".png":  true,
	".gif":  true,
}

// Store is the two-tier cache facade used by the server. It owns both tiers and
// routes reads/writes to the appropriate one.
type Store struct {
	cfg  RouterConfig
	ram  Tier
	disk Tier
}

// NewStore constructs both tiers from cfg.
func NewStore(cfg RouterConfig) (*Store, error) {
	// Resolve the B2 RAM-bounding knobs to sane defaults when left zero, and clamp
	// them so they can never be looser than the tier itself: a per-object cap larger
	// than the whole tier (or an in-flight budget larger than the tier) would defeat
	// the OOM guard. We mutate the local cfg copy so pickTier and the tier agree on
	// the SAME effective caps (otherwise a known-large object could be routed to RAM
	// by a zero cap yet rejected by the writer, dropping it from both tiers).
	if cfg.RAMMaxObjectBytes <= 0 {
		cfg.RAMMaxObjectBytes = defaultRAMMaxObjectBytes
	}
	if cfg.RAMMaxObjectBytes > cfg.RAMMaxBytes {
		cfg.RAMMaxObjectBytes = cfg.RAMMaxBytes
	}
	if cfg.RAMInflightBudget <= 0 {
		cfg.RAMInflightBudget = cfg.RAMMaxBytes
	}

	disk, err := NewDiskTier(cfg.DiskDir, cfg.DiskMaxBytes)
	if err != nil {
		return nil, err
	}
	return &Store{
		cfg:  cfg,
		ram:  NewRAMTier(cfg.RAMMaxBytes, cfg.RAMMaxObjectBytes, cfg.RAMInflightBudget),
		disk: disk,
	}, nil
}

// pickTier chooses RAM vs disk for an object. size < 0 means unknown.
func (s *Store) pickTier(key string, size int64) Tier {
	ext := strings.ToLower(path.Ext(key))
	if ramExtensions[ext] {
		// B2 size-aware routing: a ram-extension whose size is KNOWN and exceeds the
		// per-object RAM cap goes to DISK rather than RAM — otherwise a giant
		// (mislabeled/abusive) .m3u8/.jpg would be routed to RAM and then dropped by
		// the bounded writer, caching it NOWHERE. Sending it to disk keeps it cached.
		// Unknown size (-1) still starts in RAM, protected by the bounded ramWriter.
		if size >= 0 && size > s.cfg.RAMMaxObjectBytes {
			return s.disk
		}
		return s.ram
	}
	// Known-small objects go to RAM; unknown or large go to disk.
	if size >= 0 && size <= s.cfg.SmallObjectThreshold {
		return s.ram
	}
	return s.disk
}

// Get looks the key up in both tiers (RAM first), returning the first hit.
func (s *Store) Get(key string) (*Reader, bool) {
	r, _, ok := s.GetTier(key)
	return r, ok
}

// Tier source identifiers returned by GetTier (for hit-rate metrics).
const (
	TierNone = ""
	TierRAM  = "ram"
	TierDisk = "disk"
)

// GetTier is like Get but also reports which tier served the hit ("ram"/"disk"),
// so the caller can attribute cache hit-rate per tier without a second lookup.
func (s *Store) GetTier(key string) (*Reader, string, bool) {
	if r, ok := s.ram.Get(key); ok {
		return r, TierRAM, true
	}
	if r, ok := s.disk.Get(key); ok {
		return r, TierDisk, true
	}
	return nil, TierNone, false
}

// Writer returns a TierWriter for meta's tier: an explicit meta.Tier override
// (from a `storage … -> ram|disk` rule) when set, otherwise automatic size-based
// routing.
func (s *Store) Writer(meta ObjectMeta) (TierWriter, error) {
	return s.tierFor(meta).Writer(meta)
}

// tierFor resolves the destination tier for a write. An explicit meta.Tier wins
// over the size policy — EXCEPT a forced-RAM object whose KNOWN size exceeds the
// per-object RAM cap is sent to disk instead, because the bounded RAM writer would
// drop it and cache it NOWHERE; disk keeps it cached, which is what the operator
// ultimately wants ("keep this on the fast/large tier"). An unknown-size forced-RAM
// object is honored (the bounded ramWriter still guards against an oversized body).
func (s *Store) tierFor(meta ObjectMeta) Tier {
	// 1. A per-request override (`storage <sel> -> tier`) wins.
	if meta.Tier == TierRAM || meta.Tier == TierDisk {
		return s.resolveTier(meta.Tier, meta.Size)
	}
	// 2. A per-extension default (`cache { tier .ext -> tier }`) is next.
	if len(s.cfg.TierExtensions) > 0 {
		if t, ok := s.cfg.TierExtensions[strings.ToLower(path.Ext(meta.Key))]; ok {
			return s.resolveTier(t, meta.Size)
		}
	}
	// 3. Otherwise the built-in size policy.
	return s.pickTier(meta.Key, meta.Size)
}

// resolveTier maps an explicit "ram"/"disk" choice to a tier, applying the safety
// fallbacks that keep an object from being cached NOWHERE: a force-disk on a
// RAM-only deployment (no disk budget) goes to RAM, and a force-RAM whose known
// size exceeds the per-object RAM cap goes to disk (the bounded RAM writer would
// otherwise drop it).
func (s *Store) resolveTier(tier string, size int64) Tier {
	switch tier {
	case TierDisk:
		if s.cfg.DiskMaxBytes <= 0 {
			return s.ram
		}
		return s.disk
	case TierRAM:
		if size >= 0 && size > s.cfg.RAMMaxObjectBytes {
			return s.disk
		}
		return s.ram
	default:
		return s.pickTier("", size)
	}
}

// Stats reports per-tier usage (for /healthz, /stats and logging).
type Stats struct {
	RAMObjects, DiskObjects int
	RAMBytes, DiskBytes     int64
	RAMMaxBytes             int64
	DiskMaxBytes            int64
	DiskPersistErrors       int64
	DiskOversizeDiscards    int64
}

func (s *Store) Stats() Stats {
	st := Stats{
		RAMObjects:   s.ram.Len(),
		DiskObjects:  s.disk.Len(),
		RAMBytes:     s.ram.Bytes(),
		DiskBytes:    s.disk.Bytes(),
		RAMMaxBytes:  s.cfg.RAMMaxBytes,
		DiskMaxBytes: s.cfg.DiskMaxBytes,
	}
	if d, ok := s.disk.(*DiskTier); ok {
		st.DiskPersistErrors = d.PersistErrors()
		st.DiskOversizeDiscards = d.OversizeDiscards()
	}
	return st
}

// SetLogger attaches an optional observability logger to the disk tier so a
// per-shard-cap oversize discard (an object too big for the disk tier, cached
// nowhere) is logged (F6). Nil keeps the tier silent (the default). A RAM-only or
// non-DiskTier store is a no-op. Call once at setup, before serving traffic.
func (s *Store) SetLogger(log *slog.Logger) {
	if d, ok := s.disk.(*DiskTier); ok {
		d.SetLogger(log)
	}
}

// DiskDir is the directory backing this store's disk tier. It lets a caller (the
// reload path) tell whether a temp directory is still in use by a preserved store
// before removing it.
func (s *Store) DiskDir() string { return s.cfg.DiskDir }

// Close flushes both tiers (persisting disk metadata).
func (s *Store) Close() error {
	_ = s.ram.Close()
	return s.disk.Close()
}
