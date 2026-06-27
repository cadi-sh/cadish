package tlsacme

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// writeJunk writes a non-cert file into an autocert DirCache directory, simulating files
// (account key, transient challenge tokens, truncated writes) that are NOT host certs.
func writeJunk(t *testing.T, cacheDir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
}

// TestRefusedSNIDoesNotProbeDisk (R41): once the new-cert budget is exhausted, a brand-new
// (unknown) SNI must be refused WITHOUT any on-disk issued-cert probe — a random-SNI flood
// must not drive a filesystem lookup per handshake (the "refused cheaply" contract).
func TestRefusedSNIDoesNotProbeDisk(t *testing.T) {
	dir := t.TempDir()
	s := newAutocertSource(dir, "", autocert.HostWhitelist("a.example.com"), "", nil)

	// Exhaust the new-cert budget.
	for s.limiter.allow() { //nolint:revive // drain to empty
	}
	before := s.probes.Load()

	_, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "random-abc123.example.com"})
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected a rate-limit refusal for an unknown SNI, got err=%v", err)
	}
	if got := s.probes.Load(); got != before {
		t.Fatalf("a refused (rate-limited) SNI performed %d disk probe(s); want 0", got-before)
	}
}

// TestWarmIssuedRecognizesOnDiskCert (R41): an already-issued cert on disk at startup is
// memoized by warmIssued into the issued set, so a later handshake takes the issued.Load
// fast path (before the limiter and the disk probe) — this is what makes the
// limiter-before-probe reordering correct for already-issued names even under an exhausted
// budget. We assert the memoization (the fast-path serve itself goes through autocert's
// manager, which a unit test must not drive to the network).
func TestWarmIssuedRecognizesOnDiskCert(t *testing.T) {
	dir := t.TempDir()
	writeCachedACMECert(t, dir, "warm.example.com")
	s := newAutocertSource(dir, "", autocert.HostWhitelist("warm.example.com"), "", nil)

	if _, ok := s.issued.Load("warm.example.com"); !ok {
		t.Fatal("warmIssued must memoize a valid on-disk cert (warm.example.com) so the fast path skips the limiter/probe")
	}
}

// TestWarmIssuedSkipsNonCertFiles (R41 safety): warmIssued must NOT memoize a name from a
// stale, empty, or non-host-cert file — doing so would let a brand-new ACME order bypass the
// rate limiter. An empty file and an account-key-shaped file must leave issued untouched.
func TestWarmIssuedSkipsNonCertFiles(t *testing.T) {
	dir := t.TempDir()
	writeJunk(t, dir, "acme_account+key", "not a cert")
	writeJunk(t, dir, "empty.example.com", "") // a file named like a host but not a valid cert
	s := newAutocertSource(dir, "", autocert.HostWhitelist("empty.example.com"), "", nil)

	if _, ok := s.issued.Load("empty.example.com"); ok {
		t.Fatal("a non-cert file must not falsely memoize a host into the issued set")
	}
}
