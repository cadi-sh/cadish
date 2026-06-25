// Package cfsign produces AWS CloudFront *canned-policy* signed URLs, and an
// origin.Origin that re-signs and fetches each request through them. It realizes
// the "S3 miss → CloudFront fallback (re-signed)" composition from
// examples/s3-cdn.Cadishfile: a `sign cloudfront …` upstream is wrapped so every
// outgoing request URL is signed with the CloudFront private key before the GET.
//
// It is a stdlib reimplementation of the AWS SDK's feature/cloudfront/sign: a
// CloudFront canned-policy signature is
// an RSA-SHA1 (PKCS#1 v1.5) signature over a compact JSON policy, base64-encoded
// with CloudFront's URL-safe alphabet. Producing the same bytes the SDK does keeps
// it byte-for-byte CloudFront-compatible (proven by the sign↔verify round-trip in
// the test), with no extra dependency.
//
// CloudFront binds a canned-policy signature to the resource URL's host, so the
// signature MUST be generated for the distribution domain (e.g.
// d111111abcdef8.cloudfront.net) — never an alias. The `to` URL of the signed
// upstream is that distribution; cadish signs for it and GETs it directly.
package cfsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // CloudFront canned-policy signatures are defined as RSA-SHA1.
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadRSA parses an RSA private key PEM in PKCS#1 ("RSA PRIVATE KEY") or PKCS#8
// ("PRIVATE KEY") form — the two encodings openssl and the AWS console emit, so the
// same CloudFront private PEMs load unchanged.
func LoadRSA(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("cfsign: no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cfsign: %s is not a PKCS#1 or PKCS#8 RSA private key: %w", path, err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cfsign: %s is not an RSA key", path)
	}
	return rk, nil
}

// EncodeKeyPath builds the CloudFront URL path for an object key. Every byte of it
// is load-bearing:
//
//   - the '+'→'%2B' replacement keeps keys with '+' (e.g. phone-number usernames)
//     from decoding to a space at the S3 origin (which 403s);
//   - the key's OWN leading slash is preserved — a key "/feeds.csv" maps to the
//     URL path "//feeds.csv" — so we prepend the URL's leading "/" without ever
//     trimming the key's.
func EncodeKeyPath(key string) string {
	escaped := (&url.URL{Path: "/" + key}).EscapedPath()
	return strings.ReplaceAll(escaped, "+", "%2B")
}

// Signer mints CloudFront canned-policy signed URLs for one distribution under one
// key-pair. It is immutable and safe for concurrent use.
type Signer struct {
	base      string // distribution base, "scheme://host" (no trailing slash)
	keyPairID string
	key       *rsa.PrivateKey
}

// New builds a Signer for the distribution at base ("https://d111….cloudfront.net")
// signing under keyPairID with key. base must have a scheme and host.
func New(base, keyPairID string, key *rsa.PrivateKey) (*Signer, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return nil, fmt.Errorf("cfsign: parse base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("cfsign: base URL needs a scheme and host, got %q", base)
	}
	if keyPairID == "" {
		return nil, fmt.Errorf("cfsign: empty key-pair id")
	}
	if key == nil {
		return nil, fmt.Errorf("cfsign: nil private key")
	}
	return &Signer{
		base:      u.Scheme + "://" + u.Host,
		keyPairID: keyPairID,
		key:       key,
	}, nil
}

// NewFromPEM is New with the private key loaded from a PEM file.
func NewFromPEM(base, keyPairID, pemPath string) (*Signer, error) {
	key, err := LoadRSA(pemPath)
	if err != nil {
		return nil, err
	}
	return New(base, keyPairID, key)
}

// KeyPairID returns the configured key-pair id (for diagnostics/tests).
func (s *Signer) KeyPairID() string { return s.keyPairID }

// SignedURL returns a CloudFront canned-policy signed URL for objKey, valid until
// expires. The resource is "<base><EncodeKeyPath(objKey)>" and the returned URL
// appends the canned-policy query params (Expires, Signature, Key-Pair-Id).
func (s *Signer) SignedURL(objKey string, expires time.Time) (string, error) {
	resource := s.base + EncodeKeyPath(objKey)
	epoch := expires.Unix()
	policy := cannedPolicy(resource, epoch)

	sig, err := s.signPolicy(policy)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Set("Expires", strconv.FormatInt(epoch, 10))
	q.Set("Signature", sig)
	q.Set("Key-Pair-Id", s.keyPairID)
	// CloudFront's Signature uses its own base64 alphabet which must NOT be
	// percent-encoded, so build the query string by hand rather than via Encode().
	return resource + "?Expires=" + q.Get("Expires") +
		"&Signature=" + sig +
		"&Key-Pair-Id=" + s.keyPairID, nil
}

// cannedPolicy renders the compact CloudFront canned policy JSON for a resource and
// expiry epoch. The exact byte sequence (key order, no whitespace) matches what the
// AWS SDK emits and what CloudFront verifies.
func cannedPolicy(resource string, epoch int64) string {
	return `{"Statement":[{"Resource":"` + resource +
		`","Condition":{"DateLessThan":{"AWS:EpochTime":` +
		strconv.FormatInt(epoch, 10) + `}}}]}`
}

// signPolicy RSA-SHA1 signs the policy and encodes it with CloudFront's URL-safe
// base64 alphabet (+ → -, = → _, / → ~).
func (s *Signer) signPolicy(policy string) (string, error) {
	sum := sha1.Sum([]byte(policy)) //nolint:gosec // RSA-SHA1 is the CloudFront contract.
	raw, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, sum[:])
	if err != nil {
		return "", fmt.Errorf("cfsign: signing policy: %w", err)
	}
	return cfBase64(raw), nil
}

// cfBase64 is standard base64 with CloudFront's URL-safe substitutions.
func cfBase64(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "=", "_")
	s = strings.ReplaceAll(s, "/", "~")
	return s
}
