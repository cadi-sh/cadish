package cfsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // verifying the CloudFront RSA-SHA1 contract.
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// writePrivatePEM generates a throwaway RSA key, writes it as a PKCS#1 PEM, and
// returns the path plus the in-memory key (whose public half verifies signatures).
func writePrivatePEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, k
}

// cfBase64Decode reverses cfBase64 (CloudFront's URL-safe alphabet).
func cfBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "=")
	s = strings.ReplaceAll(s, "~", "/")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return b
}

// TestSignVerifyRoundTrip is the core proof of CloudFront compatibility: the
// signature a SignedURL carries must be a valid RSA-SHA1 signature over the exact
// canned policy for the signed resource — which is precisely what CloudFront
// verifies. We reconstruct the policy from the parsed URL and verify it with the
// public key.
func TestSignVerifyRoundTrip(t *testing.T) {
	const base = "https://d111111abcdef8.cloudfront.net"
	const keyPairID = "K1K6G49ZFL99X4"
	pemPath, key := writePrivatePEM(t)

	s, err := NewFromPEM(base, keyPairID, pemPath)
	if err != nil {
		t.Fatalf("NewFromPEM: %v", err)
	}

	// A key with '+' (→ %2B) and a leading slash exercises EncodeKeyPath end-to-end.
	const objKey = "$6/default_profile.png"
	expires := time.Unix(2_000_000_000, 0)
	signed, err := s.SignedURL(objKey, expires)
	if err != nil {
		t.Fatalf("SignedURL: %v", err)
	}

	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed URL %q: %v", signed, err)
	}
	resource := u.Scheme + "://" + u.Host + u.EscapedPath()
	wantResource := base + EncodeKeyPath(objKey)
	if resource != wantResource {
		t.Fatalf("signed resource = %q, want %q", resource, wantResource)
	}

	q := u.Query()
	if got := q.Get("Key-Pair-Id"); got != keyPairID {
		t.Errorf("Key-Pair-Id = %q, want %q", got, keyPairID)
	}
	if got := q.Get("Expires"); got != strconv.FormatInt(expires.Unix(), 10) {
		t.Errorf("Expires = %q, want %d", got, expires.Unix())
	}

	// Verify the signature over the reconstructed canned policy.
	policy := cannedPolicy(resource, expires.Unix())
	sum := sha1.Sum([]byte(policy)) //nolint:gosec // CloudFront contract.
	sig := cfBase64Decode(t, q.Get("Signature"))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, sum[:], sig); err != nil {
		t.Fatalf("signature does not verify (not CloudFront-valid): %v", err)
	}
}

func TestEncodeKeyPath(t *testing.T) {
	tests := map[string]string{
		"img/a.png":      "/img/a.png",
		"$6/default.png": "/$6/default.png",
		"a+b.png":        "/a%2Bb.png",  // '+' must become %2B, not space
		"/feeds.csv":     "//feeds.csv", // key's leading slash preserved
		"space file.png": "/space%20file.png",
	}
	for in, want := range tests {
		if got := EncodeKeyPath(in); got != want {
			t.Errorf("EncodeKeyPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCFBase64Alphabet(t *testing.T) {
	// Bytes that base64 to a string containing +, /, and = so all three
	// substitutions are exercised.
	in := []byte{0xfb, 0xff, 0xbf, 0x00}
	got := cfBase64(in)
	if strings.ContainsAny(got, "+/=") {
		t.Errorf("cfBase64(%v) = %q still contains a +, / or =", in, got)
	}
	// Round-trips back to the same bytes.
	dec := cfBase64Decode(t, got)
	if string(dec) != string(in) {
		t.Errorf("round-trip mismatch: %v -> %q -> %v", in, got, dec)
	}
}

func TestNewValidation(t *testing.T) {
	_, key := writePrivatePEM(t)
	if _, err := New("not a url with no scheme", "K", key); err == nil {
		t.Error("expected error for base URL without scheme/host")
	}
	if _, err := New("https://d.cloudfront.net", "", key); err == nil {
		t.Error("expected error for empty key-pair id")
	}
	if _, err := New("https://d.cloudfront.net", "K", nil); err == nil {
		t.Error("expected error for nil key")
	}
}
