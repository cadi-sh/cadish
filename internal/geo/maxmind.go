package geo

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// --- MaxMind GeoIP source (D56, extends D11) -------------------------------
//
// An OPTIONAL, operator-provided MaxMind `.mmdb` geo Source keyed on the resolved
// client IP. It supplies country (City + Country editions) and — with a City
// edition — the region/subdivision, WITHOUT needing a CDN/LB geo header. cadish
// bundles NO database: the operator supplies the `.mmdb` (D11's core concern is
// preserved — no heavy bundled DB; the only new dependency is the pure-Go, ISC
// maxminddb reader, always compiled in, no build tag).
//
// {geo.continent} is NOT taken from the DB record: country is authoritative and the
// continent is still derived in-tree via geo.Continent (D28), so the single
// continent mapping (with its deliberate transcontinental pins like RU/TR) stays the
// source of truth and cannot disagree with the DB.

// MaxMindDB is a hot-reloadable holder around one memory-mapped maxminddb reader. It
// is shared read-only across all requests (the reader is safe for concurrent use)
// and supports an atomic reader swap on SIGHUP-driven config reload: a new reader is
// opened, swapped in atomically, and the old one closed. On a reload FAILURE the old
// reader keeps serving (swap-on-success only) — startup is strict, reload is lenient
// (the standard cadish posture, consistent with D32).
//
// SAFETY (use-after-unmap): the reader is a memory-mapped buffer with no refcount;
// closing it munmaps the pages, so an in-flight Lookup that has already loaded the
// old reader and is about to read it would fault (SIGSEGV/SIGBUS, uncatchable) if a
// concurrent Reload/Close munmapped underneath it. We make that impossible
// STRUCTURALLY with an RWMutex: every Lookup holds the RLock across the whole
// load+Lookup+Decode, and Reload/Close take the write Lock before swapping AND
// closing the old reader — so a close can never overlap an in-flight lookup. The
// atomic.Pointer is retained for the load itself, but correctness rests on the lock,
// not the atomic. The RLock is cheap and the geo path is already opt-in (gated behind
// UsesGeoToken), so this adds no cost to the non-geo fast path.
type MaxMindDB struct {
	path string
	mu   sync.RWMutex // guards reader against close-during-lookup; RLock=Lookup, Lock=Reload/Close
	// reader is loaded under mu (RLock) on the read path and stored under mu (Lock)
	// on swap/close. It stays atomic so the load is a plain pointer read.
	reader atomic.Pointer[maxminddb.Reader]
}

// OpenMaxMind memory-maps the .mmdb at path and returns a holder. A missing or
// corrupt database is a FATAL config error (returned here) — a geo source the
// operator asked for that cannot load is a misconfiguration, not a silent degrade.
func OpenMaxMind(path string) (*MaxMindDB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geo: source maxmind: %w", err)
	}
	db := &MaxMindDB{path: path}
	db.reader.Store(r)
	return db, nil
}

// Path returns the .mmdb path this holder was opened from.
func (db *MaxMindDB) Path() string { return db.path }

// DatabaseType returns the DB's edition string from its metadata (e.g.
// "GeoIP2-City", "GeoLite2-Country"), or "" if the reader is closed.
func (db *MaxMindDB) DatabaseType() string {
	if r := db.reader.Load(); r != nil {
		return r.Metadata.DatabaseType
	}
	return ""
}

// HasRegion reports whether this DB is a City edition — i.e. carries subdivisions and
// so can supply {geo.region}. A Country edition has no subdivisions.
func (db *MaxMindDB) HasRegion() bool {
	return strings.Contains(db.DatabaseType(), "City")
}

// MaxMindHasRegion opens the .mmdb at path, reports whether it is a City edition (so it
// supplies {geo.region}), and closes it. A missing/corrupt DB returns false. It is used
// by `cadish check` to decide whether {geo.region} needs a region_header. cadish bundles
// no DB; this only opens an operator-supplied file during a lint.
func MaxMindHasRegion(path string) bool {
	db, err := OpenMaxMind(path)
	if err != nil {
		return false
	}
	defer db.Close()
	return db.HasRegion()
}

// Reload re-opens the holder's .mmdb into a fresh reader and swaps it in atomically,
// closing the previous reader after the swap. On any open error the OLD reader is
// kept (no swap) and the error is returned, so a fat-fingered DB swap never takes the
// site down. Safe to call concurrently with Lookup.
func (db *MaxMindDB) Reload() error {
	nr, err := maxminddb.Open(db.path)
	if err != nil {
		return fmt.Errorf("geo: source maxmind reload: %w", err)
	}
	// Hold the write lock across BOTH the swap and the close of the old reader: the
	// write Lock cannot be acquired until every in-flight Lookup's RLock is
	// released, so when we munmap the old reader no Lookup can still be reading it.
	// The new reader is opened OUTSIDE the lock to keep the critical section short
	// (a pointer swap + a munmap, no I/O). Closing UNDER the lock is the
	// load-bearing part — releasing it before the close would reopen the race.
	db.mu.Lock()
	old := db.reader.Swap(nr)
	if old != nil {
		_ = old.Close()
	}
	db.mu.Unlock()
	return nil
}

// Close releases the memory-mapped reader.
func (db *MaxMindDB) Close() error {
	// Same structural guarantee as Reload: close UNDER the write lock so the munmap
	// can never overlap an in-flight Lookup (the Lock drains all RLock holders).
	db.mu.Lock()
	defer db.mu.Unlock()
	if r := db.reader.Swap(nil); r != nil {
		return r.Close()
	}
	return nil
}

// mmRecord is the minimal slice of a MaxMind record cadish decodes: the country ISO
// code and the first/most-specific subdivision's ISO code. We decode ONLY these
// fields (not the full record) to keep the per-request cost to a few short-string
// reads. The DB's continent.code is intentionally NOT decoded — continent is derived
// in-tree from the country (D28).
type mmRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
}

// lookupRecord resolves the client IP against the current reader and returns the
// decoded minimal record. ok is false on an invalid IP, a no-match, or a decode
// error (all map to Unknown by the callers).
func (db *MaxMindDB) lookupRecord(ip netip.Addr) (mmRecord, bool) {
	var rec mmRecord
	if !ip.IsValid() {
		return rec, false
	}
	// Hold the RLock across the WHOLE read — load, Lookup, AND Decode — because the
	// maxminddb result decodes lazily out of the same mmap, so the buffer must stay
	// mapped until Decode returns. Reload/Close take the write Lock before
	// munmapping, so the buffer cannot be unmapped while this RLock is held. This is
	// the structural fix for the use-after-unmap race. (Validity is checked before
	// taking the lock to keep the no-lock path for the trivial invalid-IP reject.)
	db.mu.RLock()
	defer db.mu.RUnlock()
	r := db.reader.Load()
	if r == nil {
		return rec, false
	}
	res := r.Lookup(ip.Unmap())
	if !res.Found() {
		return rec, false
	}
	if err := res.Decode(&rec); err != nil {
		return rec, false
	}
	return rec, true
}

// --- country source --------------------------------------------------------

type maxmindCountrySource struct{ db *MaxMindDB }

// NewMaxMindCountrySource builds a Source that resolves the {geo} country class
// (country.iso_code) by looking up the resolved client IP in the MaxMind DB. A miss,
// an invalid/empty record, or an invalid IP yields Unknown. The value passes through
// boundGeoClass so cache-key cardinality stays bounded — the same contract as the
// header source (uniform, and cheap on a trusted DB).
func NewMaxMindCountrySource(db *MaxMindDB) Source { return maxmindCountrySource{db: db} }

func (s maxmindCountrySource) Lookup(ip netip.Addr, _ http.Header) string {
	rec, ok := s.db.lookupRecord(ip)
	if !ok || rec.Country.ISOCode == "" {
		return Unknown
	}
	return boundGeoClass(rec.Country.ISOCode)
}

// --- region source ---------------------------------------------------------

type maxmindRegionSource struct{ db *MaxMindDB }

// NewMaxMindRegionSource builds a Source that resolves the {geo.region} class —
// ISO 3166-2 "COUNTRY-SUBDIVISION" (e.g. "US-WA") — from the City edition's
// country.iso_code + subdivisions[0].iso_code. A Country-edition DB has no
// subdivisions, so this yields Unknown there (the operator should pair a
// `region_header` or use a City DB). A miss / invalid IP also yields Unknown.
func NewMaxMindRegionSource(db *MaxMindDB) Source { return maxmindRegionSource{db: db} }

func (s maxmindRegionSource) Lookup(ip netip.Addr, _ http.Header) string {
	rec, ok := s.db.lookupRecord(ip)
	if !ok || rec.Country.ISOCode == "" || len(rec.Subdivisions) == 0 {
		return Unknown
	}
	sub := rec.Subdivisions[0].ISOCode
	if sub == "" {
		return Unknown
	}
	return boundGeoClass(rec.Country.ISOCode + "-" + sub)
}

// --- fallback chain --------------------------------------------------------

type fallbackSource struct{ primary, secondary Source }

// NewFallbackSource composes two Sources into a precedence chain: Lookup tries
// primary and returns its result unless it is Unknown, in which case it falls through
// to secondary. This is the narrow "CDN AND MaxMind" composition (declared-order
// precedence): the FIRST-declared source wins per lookup, the second only fills a
// total miss. It is intentionally a thin two-source chain, not a general N-source
// merge, and never merges at finer granularity (one source answers a given lookup).
func NewFallbackSource(primary, secondary Source) Source {
	return fallbackSource{primary: primary, secondary: secondary}
}

func (f fallbackSource) Lookup(ip netip.Addr, hdr http.Header) string {
	if v := f.primary.Lookup(ip, hdr); v != Unknown {
		return v
	}
	return f.secondary.Lookup(ip, hdr)
}
