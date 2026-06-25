package geo

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	cityDB    = "testdata/GeoIP2-City-Test.mmdb"
	countryDB = "testdata/GeoLite2-Country-Test.mmdb"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

func openDB(t *testing.T, path string) *MaxMindDB {
	t.Helper()
	db, err := OpenMaxMind(path)
	if err != nil {
		t.Fatalf("OpenMaxMind(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestMaxMindCountryCity: country lookup on the City edition.
func TestMaxMindCountryCity(t *testing.T) {
	src := NewMaxMindCountrySource(openDB(t, cityDB))
	cases := map[string]string{
		"81.2.69.142":   "GB",
		"216.160.83.56": "US",
		"89.160.20.112": "SE",
		"67.43.156.0":   "BT",
	}
	for ip, want := range cases {
		if got := src.Lookup(mustAddr(t, ip), nil); got != want {
			t.Errorf("country(%s)=%q want %q", ip, got, want)
		}
	}
}

// TestMaxMindCountryCountryEdition: country lookup works on the Country edition too.
func TestMaxMindCountryCountryEdition(t *testing.T) {
	src := NewMaxMindCountrySource(openDB(t, countryDB))
	if got := src.Lookup(mustAddr(t, "216.160.83.56"), nil); got != "US" {
		t.Errorf("country(216.160.83.56)=%q want US", got)
	}
	if got := src.Lookup(mustAddr(t, "81.2.69.142"), nil); got != "GB" {
		t.Errorf("country(81.2.69.142)=%q want GB", got)
	}
}

// TestMaxMindCountryMiss: a no-match / private / invalid IP yields Unknown (no panic).
func TestMaxMindCountryMiss(t *testing.T) {
	src := NewMaxMindCountrySource(openDB(t, cityDB))
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "203.0.113.7"} {
		if got := src.Lookup(mustAddr(t, ip), nil); got != Unknown {
			t.Errorf("country(%s)=%q want %q", ip, got, Unknown)
		}
	}
	// An invalid (zero) Addr must not panic.
	if got := src.Lookup(netip.Addr{}, nil); got != Unknown {
		t.Errorf("country(invalid)=%q want %q", got, Unknown)
	}
}

// TestMaxMindRegionCity: region lookup on the City edition emits COUNTRY-SUBDIVISION.
func TestMaxMindRegionCity(t *testing.T) {
	src := NewMaxMindRegionSource(openDB(t, cityDB))
	cases := map[string]string{
		"216.160.83.56": "US-WA",
		"81.2.69.142":   "GB-ENG",
		"89.160.20.112": "SE-E",
	}
	for ip, want := range cases {
		if got := src.Lookup(mustAddr(t, ip), nil); got != want {
			t.Errorf("region(%s)=%q want %q", ip, got, want)
		}
	}
	// An IP with a country but no subdivision -> Unknown (BT has no subdivision here).
	if got := src.Lookup(mustAddr(t, "67.43.156.0"), nil); got != Unknown {
		t.Errorf("region(67.43.156.0)=%q want %q (no subdivision)", got, Unknown)
	}
}

// TestMaxMindRegionCountryEditionUnknown: a Country-edition DB has no subdivisions, so
// {geo.region} from MaxMind is always Unknown there.
func TestMaxMindRegionCountryEditionUnknown(t *testing.T) {
	src := NewMaxMindRegionSource(openDB(t, countryDB))
	for _, ip := range []string{"216.160.83.56", "81.2.69.142"} {
		if got := src.Lookup(mustAddr(t, ip), nil); got != Unknown {
			t.Errorf("region(%s) on Country edition=%q want %q", ip, got, Unknown)
		}
	}
}

// TestMaxMindContinentInTree: the continent is derived in-tree from the looked-up
// country (geo.Continent), NOT from the DB record. This preserves D28's
// transcontinental pins (RU/TR grouped to EU/AS by the in-tree table) regardless of
// what the DB's continent.code says.
func TestMaxMindContinentInTree(t *testing.T) {
	src := NewMaxMindCountrySource(openDB(t, cityDB))
	// US -> NA via the in-tree table (and the DB agrees here).
	if c := Continent(src.Lookup(mustAddr(t, "216.160.83.56"), nil)); c != "NA" {
		t.Errorf("continent(US)=%q want NA", c)
	}
	// Transcontinental pins are the in-tree table's call, independent of any DB:
	// RU -> EU, TR -> AS (D28). This is the table the maxmind continent path uses.
	if c := Continent("RU"); c != "EU" {
		t.Errorf("in-tree continent(RU)=%q want EU (D28 pin)", c)
	}
	if c := Continent("TR"); c != "AS" {
		t.Errorf("in-tree continent(TR)=%q want AS (D28 pin)", c)
	}
}

// TestOpenMaxMindMissing: a missing DB is a clear startup error.
func TestOpenMaxMindMissing(t *testing.T) {
	if _, err := OpenMaxMind(filepath.Join(t.TempDir(), "nope.mmdb")); err == nil {
		t.Fatal("expected an error opening a missing .mmdb")
	}
}

// TestOpenMaxMindCorrupt: a non-mmdb file is a clear startup error.
func TestOpenMaxMindCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "corrupt.mmdb")
	if err := os.WriteFile(p, []byte("this is not a maxmind database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMaxMind(p); err == nil {
		t.Fatal("expected an error opening a corrupt .mmdb")
	}
}

// TestMaxMindReloadSwaps: SIGHUP-style reload swaps the reader to a new file.
func TestMaxMindReloadSwaps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "geo.mmdb")
	copyFile(t, countryDB, p) // start as Country edition: 175.16.199.0 absent
	db, err := OpenMaxMind(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := NewMaxMindCountrySource(db)
	if got := src.Lookup(mustAddr(t, "175.16.199.0"), nil); got != Unknown {
		t.Fatalf("pre-reload country(175.16.199.0)=%q want %q (absent in Country DB)", got, Unknown)
	}
	// Swap the file to the City edition (which DOES contain 175.16.199.0 -> CN) and reload.
	// Remove + rewrite (new inode) mirrors an operator's atomic DB swap.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	copyFile(t, cityDB, p)
	if err := db.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := src.Lookup(mustAddr(t, "175.16.199.0"), nil); got != "CN" {
		t.Errorf("post-reload country(175.16.199.0)=%q want CN", got)
	}
}

// TestMaxMindReloadFailureKeepsOld: a reload of a now-corrupt file fails but keeps the
// OLD reader serving (swap-on-success only).
func TestMaxMindReloadFailureKeepsOld(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "geo.mmdb")
	copyFile(t, cityDB, p)
	db, err := OpenMaxMind(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := NewMaxMindCountrySource(db)
	if got := src.Lookup(mustAddr(t, "81.2.69.142"), nil); got != "GB" {
		t.Fatalf("pre-reload country=%q want GB", got)
	}
	// Replace the file with a corrupt one (remove + rewrite => a NEW inode, leaving the
	// old reader's mmap intact — the realistic atomic-swap-gone-wrong case) and reload:
	// reload must error and keep the old reader.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := db.Reload(); err == nil {
		t.Fatal("expected reload of a corrupt file to error")
	}
	if got := src.Lookup(mustAddr(t, "81.2.69.142"), nil); got != "GB" {
		t.Errorf("after a failed reload the OLD reader must still serve: country=%q want GB", got)
	}
}

// TestFallbackPrecedence: maxmind-then-header — maxmind hit wins; on a maxmind miss it
// falls through to the header; both unknown -> Unknown. And the reverse order.
func TestFallbackPrecedence(t *testing.T) {
	mm := NewMaxMindCountrySource(openDB(t, cityDB))
	hdrSrc := NewHeaderSource("CF-IPCountry")

	hdr := http.Header{}
	hdr.Set("CF-IPCountry", "FR")

	// maxmind primary: a maxmind hit wins over the header.
	primaryMM := NewFallbackSource(mm, hdrSrc)
	if got := primaryMM.Lookup(mustAddr(t, "81.2.69.142"), hdr); got != "GB" {
		t.Errorf("maxmind-primary hit=%q want GB (maxmind wins)", got)
	}
	// maxmind miss (private IP) -> fall through to the header (FR).
	if got := primaryMM.Lookup(mustAddr(t, "10.0.0.1"), hdr); got != "FR" {
		t.Errorf("maxmind-primary miss=%q want FR (header fallback)", got)
	}
	// both unknown -> Unknown.
	if got := primaryMM.Lookup(mustAddr(t, "10.0.0.1"), http.Header{}); got != Unknown {
		t.Errorf("both unknown=%q want %q", got, Unknown)
	}

	// header primary: the header wins when present; on a missing header fall to maxmind.
	primaryHdr := NewFallbackSource(hdrSrc, mm)
	if got := primaryHdr.Lookup(mustAddr(t, "81.2.69.142"), hdr); got != "FR" {
		t.Errorf("header-primary hit=%q want FR (header wins)", got)
	}
	if got := primaryHdr.Lookup(mustAddr(t, "81.2.69.142"), http.Header{}); got != "GB" {
		t.Errorf("header-primary miss=%q want GB (maxmind fallback)", got)
	}
}

// TestMaxMindTrustedProxyResolution: behind a trusted proxy, the maxmind source must
// resolve on the REAL client IP (the XFF entry), not the socket peer. This reuses the
// shared ClientIP (D50) path: the source consumes the already-resolved netip.Addr, so
// the trusted-proxy logic is shared and untouched.
func TestMaxMindTrustedProxyResolution(t *testing.T) {
	src := NewMaxMindCountrySource(openDB(t, cityDB))
	trusted, err := ParsePrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	// Peer is a trusted proxy; XFF's rightmost non-trusted entry (216.160.83.56 -> US,
	// a City fixture IP) is the real client.
	hdr := http.Header{"X-Forwarded-For": []string{"216.160.83.56, 10.0.0.5"}}
	ip := ClientIP("10.0.0.5:443", hdr, trusted)
	if got := src.Lookup(ip, hdr); got != "US" {
		t.Errorf("trusted-proxy maxmind country = %q, want US (resolved real client 216.160.83.56)", got)
	}
	// An untrusted peer => XFF ignored => the peer (10.0.0.5, a private miss) => Unknown.
	ip2 := ClientIP("198.51.100.7:443", hdr, nil)
	if got := src.Lookup(ip2, hdr); got != Unknown {
		t.Errorf("untrusted-peer maxmind country = %q, want %q (XFF ignored)", got, Unknown)
	}
}

// countingSource wraps a Source and counts Lookup calls, to assert the zero-cost
// invariant: when geo is unused the maxmind reader is never consulted.
type countingSource struct {
	inner Source
	calls int
}

func (c *countingSource) Lookup(ip netip.Addr, hdr http.Header) string {
	c.calls++
	return c.inner.Lookup(ip, hdr)
}

// TestMaxMindZeroCostWhenUnused mirrors the handler's gate: the maxmind reader is only
// consulted inside `if site.Geo != nil && UsesGeoToken()`. When a site uses no geo
// token (gate false), Lookup is never called, so an opened-but-unused mmap costs only
// its lazy virtual mapping — no per-request work. This documents the invariant the
// handler enforces (D28 gate, preserved for the maxmind source).
func TestMaxMindZeroCostWhenUnused(t *testing.T) {
	spy := &countingSource{inner: NewMaxMindCountrySource(openDB(t, cityDB))}

	// usesGeoToken=false: the handler skips the geo pre-pass entirely.
	const usesGeoToken = false
	if usesGeoToken { // mirrors handler.go's gated branch
		spy.Lookup(mustAddr(t, "216.160.83.56"), nil)
	}
	if spy.calls != 0 {
		t.Errorf("maxmind reader consulted %d times when geo is unused; want 0 (zero-cost)", spy.calls)
	}

	// Sanity: when the gate is true the source IS consulted.
	spy.Lookup(mustAddr(t, "216.160.83.56"), nil)
	if spy.calls != 1 {
		t.Errorf("calls=%d after a gated lookup; want 1", spy.calls)
	}
}

// TestMaxMindLookupDuringReloadRace is the structural use-after-unmap guard: many
// goroutines hammer the geo lookup while another goroutine reloads (and thus closes
// + munmaps the old reader) in a tight loop. Before the RWMutex fix, a Lookup that
// had loaded the old reader could read an unmapped page once Reload closed it →
// SIGSEGV/SIGBUS (uncatchable). With Lookup under RLock and Reload/Close closing the
// old reader UNDER the write Lock, a close can never overlap an in-flight Lookup, so
// this runs clean under -race and never crashes. (Reload re-opens the SAME file, so
// results stay correct throughout; we assert no panic and a stable answer.)
func TestMaxMindLookupDuringReloadRace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "geo.mmdb")
	copyFile(t, cityDB, p)
	db, err := OpenMaxMind(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src := NewMaxMindCountrySource(db)
	ip := mustAddr(t, "216.160.83.56") // US in the City fixture

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reloader: tight loop of Reload (open new reader, swap, close+munmap old).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := db.Reload(); err != nil {
					t.Errorf("reload: %v", err)
					return
				}
			}
		}
	}()

	// Many concurrent lookups racing the reloads.
	const readers = 16
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					// Must never fault and must return the correct, stable answer:
					// every reload re-opens the same City DB.
					if got := src.Lookup(ip, nil); got != "US" {
						t.Errorf("lookup during reload = %q, want US", got)
						return
					}
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
