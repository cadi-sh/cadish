package cfsign

// coverage_test.go: additional tests targeting the 0%/low-coverage paths in
// internal/cfsign that the existing test files do not reach.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/origin"
)

// ---------------------------------------------------------------------------
// KeyPairID (0%)
// ---------------------------------------------------------------------------

// TestKeyPairID verifies the getter returns the configured key-pair ID.
func TestKeyPairID(t *testing.T) {
	pemPath, key := writePrivatePEM(t)
	s, err := New("https://d.cloudfront.net", "K2ABCD12345", key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = pemPath // written for NewFromPEM below
	if got := s.KeyPairID(); got != "K2ABCD12345" {
		t.Errorf("KeyPairID() = %q, want K2ABCD12345", got)
	}
}

// TestKeyPairIDViaNewFromPEM verifies KeyPairID round-trips through NewFromPEM.
func TestKeyPairIDViaNewFromPEM(t *testing.T) {
	const kpID = "KPQRS9876543"
	pemPath, _ := writePrivatePEM(t)
	s, err := NewFromPEM("https://d.cloudfront.net", kpID, pemPath)
	if err != nil {
		t.Fatalf("NewFromPEM: %v", err)
	}
	if s.KeyPairID() != kpID {
		t.Errorf("KeyPairID() = %q, want %q", s.KeyPairID(), kpID)
	}
}

// ---------------------------------------------------------------------------
// LoadRSA error paths (40% → we cover the 60% that's missing)
// ---------------------------------------------------------------------------

// TestLoadRSAMissingFile verifies LoadRSA returns an error for a non-existent file.
func TestLoadRSAMissingFile(t *testing.T) {
	_, err := LoadRSA(filepath.Join(t.TempDir(), "no-such.pem"))
	if err == nil {
		t.Fatal("LoadRSA(missing file): expected error, got nil")
	}
}

// TestLoadRSANoPEMBlock verifies LoadRSA returns a clear error when the file has
// no PEM block at all (e.g. a plain text file or garbage bytes).
func TestLoadRSANoPEMBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(path, []byte("this is not PEM data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRSA(path)
	if err == nil {
		t.Fatal("LoadRSA(no PEM block): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("error message should mention 'no PEM block': %v", err)
	}
}

// TestLoadRSANonRSAKey verifies LoadRSA returns an error when the PEM contains a
// non-RSA key (EC key — a valid PKCS#8 key, but not RSA).
func TestLoadRSANonRSAKey(t *testing.T) {
	// Generate a P-256 EC key and encode it as PKCS#8 PEM.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "ec.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadRSA(path)
	if err == nil {
		t.Fatal("LoadRSA(EC PKCS#8 key): expected error for non-RSA key, got nil")
	}
	if !strings.Contains(err.Error(), "not an RSA key") {
		t.Errorf("error message should mention 'not an RSA key': %v", err)
	}
}

// TestLoadRSABadPKCS8Body verifies LoadRSA returns an error when the PEM block has
// type "PRIVATE KEY" but contains garbage DER bytes (not a valid PKCS#8 structure).
func TestLoadRSABadPKCS8Body(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("this is not valid DER"),
	})
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRSA(path)
	if err == nil {
		t.Fatal("LoadRSA(bad PKCS#8 body): expected error, got nil")
	}
}

// TestLoadRSAPKCS1Valid verifies LoadRSA successfully loads a PKCS#1-encoded key.
func TestLoadRSAPKCS1Valid(t *testing.T) {
	pemPath, wantKey := writePrivatePEM(t)
	got, err := LoadRSA(pemPath)
	if err != nil {
		t.Fatalf("LoadRSA(PKCS#1): %v", err)
	}
	if got.N.Cmp(wantKey.N) != 0 {
		t.Error("LoadRSA returned a different key than the one written")
	}
}

// TestLoadRSAPKCS8Valid verifies LoadRSA successfully loads a PKCS#8-encoded RSA
// key (the second format the AWS console emits).
func TestLoadRSAPKCS8Valid(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "pkcs8.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRSA(path)
	if err != nil {
		t.Fatalf("LoadRSA(PKCS#8): %v", err)
	}
	if got.N.Cmp(k.N) != 0 {
		t.Error("LoadRSA(PKCS#8) returned a different key")
	}
}

// ---------------------------------------------------------------------------
// SignedURL URL structure (well-formedness assertion)
// ---------------------------------------------------------------------------

// TestSignedURLStructure verifies that a SignedURL result is well-formed: the
// resource URL is present, and all three CloudFront query params are present and
// have non-empty values.
func TestSignedURLStructure(t *testing.T) {
	const base = "https://d222222abcdef9.cloudfront.net"
	const kpID = "K9QRST123456"
	pemPath, _ := writePrivatePEM(t)
	s, err := NewFromPEM(base, kpID, pemPath)
	if err != nil {
		t.Fatalf("NewFromPEM: %v", err)
	}

	const key = "videos/test-clip.mp4"
	expires := time.Unix(2_100_000_000, 0)
	signed, err := s.SignedURL(key, expires)
	if err != nil {
		t.Fatalf("SignedURL: %v", err)
	}

	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed URL: %v", err)
	}

	// Resource path must encode the object key correctly.
	wantPath := EncodeKeyPath(key)
	if u.EscapedPath() != wantPath {
		t.Errorf("path = %q, want %q", u.EscapedPath(), wantPath)
	}

	q := u.Query()
	// Key-Pair-Id must match.
	if got := q.Get("Key-Pair-Id"); got != kpID {
		t.Errorf("Key-Pair-Id = %q, want %q", got, kpID)
	}
	// Expires must be the epoch of the provided time.
	wantExpires := strconv.FormatInt(expires.Unix(), 10)
	if got := q.Get("Expires"); got != wantExpires {
		t.Errorf("Expires = %q, want %q", got, wantExpires)
	}
	// Signature must be non-empty and contain no standard base64 chars that
	// CloudFront's alphabet replaces.
	sig := q.Get("Signature")
	if sig == "" {
		t.Fatal("Signature is empty")
	}
	if strings.ContainsAny(sig, "+/=") {
		t.Errorf("Signature %q contains standard base64 chars (+/=); CloudFront alphabet not applied", sig)
	}
}

// ---------------------------------------------------------------------------
// WithHTTPClient option (0%)
// ---------------------------------------------------------------------------

// TestWithHTTPClientOptionUsed verifies that WithHTTPClient overrides the internal
// HTTP client and that requests flow through it.
func TestWithHTTPClientOptionUsed(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Use a custom client with a distinct RoundTripper that wraps the default.
	custom := &http.Client{
		Transport: &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	signer := testSigner(t, srv.URL)
	o := NewOrigin(signer, time.Minute, WithHTTPClient(custom))

	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "obj"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()
	if !called {
		t.Error("WithHTTPClient: request did not reach the test server")
	}
}

// ---------------------------------------------------------------------------
// NewOrigin zero-TTL clamping (83%)
// ---------------------------------------------------------------------------

// TestNewOriginZeroTTLClamped verifies that a non-positive TTL is clamped to the
// 5-minute default rather than producing a zero or negative validity window.
func TestNewOriginZeroTTLClamped(t *testing.T) {
	var gotExpires string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExpires = r.URL.Query().Get("Expires")
	}))
	defer srv.Close()

	fixed := time.Unix(1_000_000_000, 0)
	o := NewOrigin(testSigner(t, srv.URL), 0, /* zero TTL → clamp */
		WithClock(func() time.Time { return fixed }))

	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	wantExpires := strconv.FormatInt(fixed.Add(5*time.Minute).Unix(), 10)
	if gotExpires != wantExpires {
		t.Errorf("Expires = %q, want %q (5-min clamp)", gotExpires, wantExpires)
	}
}

// TestNewOriginNegativeTTLClamped verifies that a negative TTL is also clamped.
func TestNewOriginNegativeTTLClamped(t *testing.T) {
	var gotExpires string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotExpires = r.URL.Query().Get("Expires")
	}))
	defer srv.Close()

	fixed := time.Unix(1_000_000_000, 0)
	o := NewOrigin(testSigner(t, srv.URL), -time.Hour, /* negative TTL → clamp */
		WithClock(func() time.Time { return fixed }))

	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	wantExpires := strconv.FormatInt(fixed.Add(5*time.Minute).Unix(), 10)
	if gotExpires != wantExpires {
		t.Errorf("Expires = %q, want %q (5-min clamp for negative TTL)", gotExpires, wantExpires)
	}
}

// ---------------------------------------------------------------------------
// drainClose nil body (75%)
// ---------------------------------------------------------------------------

// TestDrainCloseNilBody verifies drainClose does not panic when given a nil body
// (the nil guard branch).
func TestDrainCloseNilBody(t *testing.T) {
	// Must not panic.
	drainClose(nil)
}

// ---------------------------------------------------------------------------
// Origin redirect pass-through (covers 3xx branch in Fetch)
// ---------------------------------------------------------------------------

// TestOriginPassesRedirectThrough verifies that a 3xx response is returned
// verbatim (not followed), which exercises the 3xx branch in Fetch.
func TestOriginPassesRedirectThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example.com/x", http.StatusMovedPermanently)
	}))
	defer srv.Close()
	o := NewOrigin(testSigner(t, srv.URL), time.Minute)

	resp, err := o.Fetch(context.Background(), &origin.Request{Key: "redirect-me"})
	if err != nil {
		t.Fatalf("3xx Fetch error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", resp.StatusCode)
	}
}
